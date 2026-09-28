package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestStore() *Store { return New(100, 100, 100) }

func TestAuthCodeSingleUse(t *testing.T) {
	s := newTestStore()
	code := &AuthCode{Code: "c1", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateAuthCode(code); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthCode("c1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.ConsumeAuthCode("c1"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("second consume: want ErrCodeNotFound, got %v", err)
	}
}

func TestAuthCodeConcurrentConsumeOnlyOneWins(t *testing.T) {
	s := newTestStore()
	_ = s.CreateAuthCode(&AuthCode{Code: "c1", ExpiresAt: time.Now().Add(time.Minute)})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeAuthCode("c1"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one consume must win, got %d", wins)
	}
}

func TestAuthCodeExpired(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateAuthCode(&AuthCode{Code: "c1", ExpiresAt: now.Add(time.Minute)})
	now = now.Add(2 * time.Minute)
	if _, err := s.ConsumeAuthCode("c1"); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("want ErrCodeExpired, got %v", err)
	}
}

func TestRefreshRotationAndReplayRevokesFamily(t *testing.T) {
	s := newTestStore()
	mk := func(tok string) *RefreshToken {
		return &RefreshToken{Token: tok, ClientID: "c", UserID: "u", Family: "f1", ExpiresAt: time.Now().Add(time.Hour)}
	}
	_ = s.CreateRefreshToken(mk("r1"))
	// 正常轮换 r1 -> r2。
	old, err := s.RotateRefreshToken("r1")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r2", ClientID: old.ClientID, UserID: old.UserID, Family: old.Family, ExpiresAt: old.ExpiresAt})
	// 重放 r1：必须识别并撤销整个族。
	if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("want ErrRefreshReused, got %v", err)
	}
	// 族内新令牌 r2 也随之失效。
	if _, err := s.RotateRefreshToken("r2"); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("family member should be revoked, got %v", err)
	}
}

func TestRefreshReplayDoesNotAffectOtherFamilies(t *testing.T) {
	s := newTestStore()
	mk := func(tok, fam string) *RefreshToken {
		return &RefreshToken{Token: tok, Family: fam, ExpiresAt: time.Now().Add(time.Hour)}
	}
	_ = s.CreateRefreshToken(mk("a1", "famA"))
	_ = s.CreateRefreshToken(mk("b1", "famB"))
	_, _ = s.RotateRefreshToken("a1")
	if _, err := s.RotateRefreshToken("a1"); !errors.Is(err, ErrRefreshReused) {
		t.Fatal("expected reuse detection")
	}
	// famB 不受影响。
	if _, err := s.RotateRefreshToken("b1"); err != nil {
		t.Fatalf("other family must not be affected: %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	s := newTestStore()
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: time.Now().Add(time.Hour)})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []error
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RotateRefreshToken("r1")
			mu.Lock()
			results = append(results, err)
			mu.Unlock()
		}()
	}
	wg.Wait()
	ok, reused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrRefreshReused):
			reused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one rotation must succeed, got %d", ok)
	}
	if reused == 0 {
		t.Fatal("concurrent reuse must be detected")
	}
}

func TestRevokeResultsDistinguishable(t *testing.T) {
	s := newTestStore()
	if r := s.RevokeRefreshToken("nope"); r != RevokeNotFound {
		t.Fatalf("want not_found, got %s", r)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: time.Now().Add(time.Hour)})
	if r := s.RevokeRefreshToken("r1"); r != RevokeOK {
		t.Fatalf("want revoked, got %s", r)
	}
	if r := s.RevokeRefreshToken("r1"); r != RevokeAlreadyInvalid {
		t.Fatalf("want already_invalid, got %s", r)
	}
}

func TestRevokedAccessTokenPropagates(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	s.RecordAccessToken("fam", "jti-1", exp)
	if s.IsAccessRevoked("jti-1") {
		t.Fatal("should not be revoked yet")
	}
	s.RevokeFamily("fam")
	if !s.IsAccessRevoked("jti-1") {
		t.Fatal("family revocation must propagate to derived access tokens")
	}
}

func TestCapacityBounded(t *testing.T) {
	s := New(10, 10, 10)
	for i := 0; i < 20; i++ {
		_ = s.CreateAuthCode(&AuthCode{Code: fmt.Sprintf("c%d", i), ExpiresAt: time.Now().Add(time.Hour)})
	}
	codes, _, _ := s.Stats()
	if codes > 10 {
		t.Fatalf("code store unbounded: %d", codes)
	}
}

// ---------- 会话级撤销 ----------

// newSession 在存储中构造一条完整会话：r1（当前刷新令牌）、
// r1 派生出的访问令牌 jti1，以及 r1 已轮换出的 r2 + jti2。
func newSession(t *testing.T, s *Store, fam string, refreshExp, accessExp time.Time) (r1, r2 string) {
	t.Helper()
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1-" + fam, Family: fam, ClientID: "c", UserID: "u", ExpiresAt: refreshExp})
	s.RecordAccessToken(fam, "jti1-"+fam, accessExp)
	// 模拟 r1 已被轮换：r1 标记 Used，r2 为当前刷新令牌。
	old, err := s.RotateRefreshToken("r1-" + fam)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r2-" + fam, Family: fam, ClientID: old.ClientID, UserID: old.UserID, ExpiresAt: refreshExp})
	s.RecordAccessToken(fam, "jti2-"+fam, accessExp)
	return "r1-" + fam, "r2-" + fam
}

func TestSessionRevokeKillsCurrentAndDerivedTokens(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	future := now.Add(time.Hour)
	r1, r2 := newSession(t, s, "S1", future, future)

	// 用当前刷新令牌撤销整个会话。
	if res := s.RevokeRefreshToken(r2); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	// 已发出的两个访问令牌（含轮换前签发的）都被传播撤销。
	if !s.IsAccessRevoked("jti1-S1") || !s.IsAccessRevoked("jti2-S1") {
		t.Fatal("all access tokens of the session must be revoked")
	}
	// 已被轮换掉的旧刷新令牌与当前刷新令牌都不能再换发。
	if _, err := s.RotateRefreshToken(r1); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("old rotated token replay: want ErrRefreshReused, got %v", err)
	}
	if _, err := s.RotateRefreshToken(r2); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("current token after session revoke: want ErrRefreshRevoked, got %v", err)
	}
	// 撤销之后新写入的后继刷新令牌必须被拒绝——会话不能复活。
	err := s.CreateRefreshToken(&RefreshToken{Token: "r3-S1", Family: "S1", ExpiresAt: future})
	if !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor refresh token must be rejected, got %v", err)
	}
	// 撤销后登记的访问令牌也立即被撤销。
	s.RecordAccessToken("S1", "jti3-S1", future)
	if !s.IsAccessRevoked("jti3-S1") {
		t.Fatal("access token recorded after revoke must be revoked")
	}
}

func TestSessionRevokeByRotatedOldTokenKillsSuccessor(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	future := now.Add(time.Hour)
	r1, r2 := newSession(t, s, "S2", future, future)

	// 用户出示“之前已经被轮换掉”的旧刷新令牌撤销：后继关系全部失效。
	if res := s.RevokeRefreshToken(r1); res != RevokeOK {
		t.Fatalf("want revoked via rotated-old token, got %s", res)
	}
	if _, err := s.RotateRefreshToken(r2); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor token must be unusable, got %v", err)
	}
	if !s.IsAccessRevoked("jti1-S2") || !s.IsAccessRevoked("jti2-S2") {
		t.Fatal("all derived access tokens must be revoked")
	}
	if err := s.CreateRefreshToken(&RefreshToken{Token: "r3-S2", Family: "S2", ExpiresAt: future}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("future successor must be rejected, got %v", err)
	}
}

func TestSessionRevokeIdempotentAndDistinguishable(t *testing.T) {
	s := newTestStore()
	future := time.Now().Add(time.Hour)
	_, r2 := newSession(t, s, "S3", future, future)
	// 首次：确实完成撤销。
	if res := s.RevokeRefreshToken(r2); res != RevokeOK {
		t.Fatalf("first: want revoked, got %s", res)
	}
	// 重复撤销同一令牌：幂等，结论为本来就已无效。
	if res := s.RevokeRefreshToken(r2); res != RevokeAlreadyInvalid {
		t.Fatalf("repeat: want already_invalid, got %s", res)
	}
	// 同会话一张从未见过的令牌串（比如过期后被清理）仍按不存在处理。
	if res := s.RevokeRefreshToken("ghost-token"); res != RevokeNotFound {
		t.Fatalf("want not_found, got %s", res)
	}
	// 向已撤销会话补写刷新令牌会被拒；即便绕过写入，撤销结论也恒为 already_invalid。
	if err := s.CreateRefreshToken(&RefreshToken{Token: "old-S3", Family: "S3", ExpiresAt: future}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("write into revoked family must be rejected, got %v", err)
	}
	if res := s.RevokeRefreshToken("r2-S3"); res != RevokeAlreadyInvalid {
		t.Fatalf("repeat revoke of family member: want already_invalid, got %s", res)
	}
	// 已过期（且未撤销）的令牌撤销：already_invalid，不改变其会话存活状态。
	_ = s.CreateRefreshToken(&RefreshToken{Token: "rX", Family: "LIVE", ExpiresAt: time.Now().Add(-time.Minute)})
	if res := s.RevokeRefreshToken("rX"); res != RevokeAlreadyInvalid {
		t.Fatalf("expired token: want already_invalid, got %s", res)
	}
	if s.IsFamilyRevoked("LIVE") {
		t.Fatal("revoking an expired token must not kill its live session")
	}
}

func TestSessionRevokeIsolatesOtherSessionsAndClients(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	future := now.Add(time.Hour)
	_, r2a := newSession(t, s, "A", future, future)
	_, r2b := newSession(t, s, "B", future, future)

	if res := s.RevokeRefreshToken(r2a); res != RevokeOK {
		t.Fatalf("revoke A: %s", res)
	}
	// 另一会话（即使共享签名密钥——存储层不关心密钥）完全不受影响。
	if s.IsAccessRevoked("jti1-B") || s.IsAccessRevoked("jti2-B") {
		t.Fatal("other session access tokens must remain valid")
	}
	old, err := s.RotateRefreshToken(r2b)
	if err != nil {
		t.Fatalf("other session must still rotate: %v", err)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r3-B", Family: old.Family, ExpiresAt: future})
	if _, err := s.RotateRefreshToken("r3-B"); err != nil {
		t.Fatalf("successor in other session must work: %v", err)
	}
	if s.RevokedFamilies() != 1 {
		t.Fatalf("exactly one session tombstone expected, got %d", s.RevokedFamilies())
	}
}

func TestConcurrentSessionRevokeAndRefreshOneOutcome(t *testing.T) {
	s := newTestStore()
	future := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "F", ExpiresAt: future})
	s.RecordAccessToken("F", "jti0", future)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var refreshOK, refreshRejected, revokeOK, revokeAlready int
	var winnerNext, winnerJTI string
	start := make(chan struct{})
	doRefresh := func() {
		defer wg.Done()
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		tok := "r-next-" + hex.EncodeToString(b)
		next := &RefreshToken{Token: tok, Family: "F", ClientID: "c", UserID: "u", ExpiresAt: future}
		jti := "jti-" + hex.EncodeToString(b[:4])
		<-start
		_, err := s.CommitRotation("r1", next, jti, future)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			refreshOK++
			winnerNext, winnerJTI = tok, jti
		case errors.Is(err, ErrRefreshReused), errors.Is(err, ErrRefreshRevoked):
			refreshRejected++
		default:
			t.Errorf("unexpected refresh result: %v", err)
		}
	}
	doRevoke := func() {
		defer wg.Done()
		<-start
		res := s.RevokeRefreshToken("r1")
		mu.Lock()
		defer mu.Unlock()
		switch res {
		case RevokeOK:
			revokeOK++
		case RevokeAlreadyInvalid:
			revokeAlready++
		default:
			t.Errorf("unexpected revoke result: %s", res)
		}
	}
	wg.Add(4)
	go doRefresh()
	go doRefresh()
	go doRevoke()
	go doRevoke()
	close(start)
	wg.Wait()

	// 两个刷新并发：至多一个成功；撤销至多一次“确实完成”，其余幂等。
	if refreshOK > 1 {
		t.Fatalf("at most one refresh may succeed, got %d", refreshOK)
	}
	if revokeOK > 1 {
		t.Fatalf("at most one revoke may complete, got %d", revokeOK)
	}
	if revokeOK+revokeAlready != 2 {
		t.Fatalf("two revoke attempts must yield OK+already invalid, got %d/%d", revokeOK, revokeAlready)
	}
	// 无论交错顺序如何，最终结论唯一：会话已死。
	if !s.IsFamilyRevoked("F") {
		t.Fatal("session must be revoked regardless of interleaving")
	}
	if !s.IsAccessRevoked("jti0") {
		t.Fatal("access token issued before revoke must be revoked")
	}
	// 若存在轮换赢家：它当时可能拿到了响应，但最终其新刷新令牌与新访问令牌都不可用，
	// 且它无法再换发。这正是“撤销与刷新不能同时成功”的要求。
	if refreshOK == 1 {
		if !s.IsAccessRevoked(winnerJTI) {
			t.Fatal("winner's new access token must end up revoked")
		}
		if _, err := s.CommitRotation(winnerNext,
			&RefreshToken{Token: "r-late", Family: "F", ExpiresAt: future},
			"jti-late", future); !errors.Is(err, ErrRefreshRevoked) {
			t.Fatalf("winner's new refresh token must not rotate again, got %v", err)
		}
	}
}

// TestTombstoneSweepSafe 验证墓碑只在会话所有令牌过期后才清理，
// 且清理前容量淘汰不可能让仍有效的已撤销令牌复活。
func TestTombstoneSweepSafe(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	// 刷新令牌 1h 过期；一张 10m、一张 2h 的访问令牌；keepUntil 取最大值 2h。
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "F", ExpiresAt: now.Add(time.Hour)})
	s.RecordAccessToken("F", "jti1", now.Add(10*time.Minute))
	s.RecordAccessToken("F", "jti2", now.Add(2*time.Hour))
	if res := s.RevokeRefreshToken("r1"); res != RevokeOK {
		t.Fatal(res)
	}
	// 30 分钟后：jti1 自身过期可被回收，但刷新令牌仍在保护窗口，墓碑必须保留，
	// 且未过期的 jti2 依旧被判定撤销，不会被容量/过期清理“复活”。
	now = now.Add(30 * time.Minute)
	s.Sweep()
	if s.RevokedFamilies() != 1 {
		t.Fatal("tombstone must survive while any session token is still within its window")
	}
	if !s.IsAccessRevoked("jti2") {
		t.Fatal("live revoked jti must not be resurrected before window ends")
	}
	// 超过 keepUntil（2h）：墓碑与索引均可安全回收。
	now = now.Add(2*time.Hour + time.Minute)
	s.Sweep()
	if s.RevokedFamilies() != 0 {
		t.Fatal("tombstone must be swept after keepUntil")
	}
	if s.IsAccessRevoked("jti2") {
		t.Fatal("expired jti should be gone together with the tombstone")
	}
}

// TestRevokeAccessTokenRefusesToEvictLiveRecords 验证容量触顶时
// 不会淘汰仍有效的撤销记录（不复活），而是返回 RevokeUnavailable。
func TestRevokeAccessTokenRefusesToEvictLiveRecords(t *testing.T) {
	s := New(100, 100, 2)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	if res := s.RevokeAccessToken("j1", now.Add(time.Minute)); res != RevokeOK {
		t.Fatal(res)
	}
	if res := s.RevokeAccessToken("j2", now.Add(time.Minute)); res != RevokeOK {
		t.Fatal(res)
	}
	// 容量满且无过期项：必须拒绝，而不是淘汰 j1 让它复活。
	if res := s.RevokeAccessToken("j3", now.Add(time.Minute)); res != RevokeUnavailable {
		t.Fatalf("want unavailable, got %s", res)
	}
	if !s.IsAccessRevoked("j1") || !s.IsAccessRevoked("j2") {
		t.Fatal("live revocation records must never be evicted")
	}
	// 过期项被清理后容量恢复，可继续写入。
	now = now.Add(2 * time.Minute)
	if res := s.RevokeAccessToken("j3", now.Add(time.Minute)); res != RevokeOK {
		t.Fatalf("want revoked after sweep frees capacity, got %s", res)
	}
}

// TestRepeatedRevocationStateBounded 验证反复撤销/换发不会让撤销状态无界增长：
// 同一会话的重复撤销只有一块墓碑；过期会话被 Sweep 后墓碑可回收。
func TestRepeatedRevocationStateBounded(t *testing.T) {
	s := New(1000, 1000, 1000)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	accessExp := now.Add(10 * time.Minute)

	// 模拟 50 个会话，每个会话经历多次轮换后撤销；每个会话只产生一块墓碑。
	for i := 0; i < 50; i++ {
		fam := fmt.Sprintf("fam-%d", i)
		tok := fmt.Sprintf("rt-%d-0", i)
		_ = s.CreateRefreshToken(&RefreshToken{Token: tok, Family: fam, ExpiresAt: now.Add(time.Hour)})
		s.RecordAccessToken(fam, fmt.Sprintf("jti-%d-0", i), accessExp)
		cur := tok
		// 几次正常轮换（手动模拟：旧令牌标记 Used，写入新当前令牌）。
		for j := 1; j <= 3; j++ {
			old, err := s.RotateRefreshToken(cur)
			if err != nil {
				t.Fatal(err)
			}
			cur = fmt.Sprintf("rt-%d-%d", i, j)
			_ = s.CreateRefreshToken(&RefreshToken{Token: cur, Family: old.Family, ExpiresAt: old.ExpiresAt})
			s.RecordAccessToken(fam, fmt.Sprintf("jti-%d-%d", i, j), accessExp)
		}
		// 撤销“当前”令牌，随后重复撤销 3 次（幂等，不产生新墓碑）。
		if res := s.RevokeRefreshToken(cur); res != RevokeOK {
			t.Fatalf("revoke %s: %s", cur, res)
		}
		for k := 0; k < 3; k++ {
			if res := s.RevokeRefreshToken(cur); res != RevokeAlreadyInvalid {
				t.Fatalf("repeat %s: %s", cur, res)
			}
		}
	}
	if n := s.RevokedFamilies(); n != 50 {
		t.Fatalf("want exactly 50 tombstones (one per session), got %d", n)
	}
	// 时钟越过所有令牌的保护窗口：全部墓碑必须可回收，长期占用归零。
	now = now.Add(2 * time.Hour)
	s.Sweep()
	if n := s.RevokedFamilies(); n != 0 {
		t.Fatalf("all tombstones must be swept after windows end, got %d", n)
	}
	_, _, revoked := s.Stats()
	if revoked != 0 {
		t.Fatalf("revoked jti records must be swept too, got %d", revoked)
	}
}
