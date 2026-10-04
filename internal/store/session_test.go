package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// 场景一：按当前刷新令牌撤销整个会话——
// 当前访问令牌立即失效，之后用该刷新令牌或其族内任何令牌都不能再换发。
func TestRevokeSessionKillsAccessAndFutureRefresh(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess1", ExpiresAt: exp})
	s.RecordAccessToken("sess1", "jti-1", exp)

	if res, fam := s.RevokeSession("r1"); res != RevokeOK || fam != "sess1" {
		t.Fatalf("want revoked/sess1, got %s/%s", res, fam)
	}
	if !s.IsAccessRevoked("jti-1") {
		t.Fatal("current access token must be rejected after session revoke")
	}
	if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("refresh after revoke must fail with revoked, got %v", err)
	}
	// 原子轮换路径同样必须拒绝，且后继令牌不得入存。
	if _, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("atomic rotation after revoke must fail, got %v", err)
	}
	if _, err := s.RefreshTokenInfo("r2"); !errors.Is(err, ErrRefreshNotFound) {
		t.Fatal("successor must never be stored after session revoke")
	}
}

// 场景二：已轮换掉的旧刷新令牌被拿去撤销，后继令牌与派生访问令牌全失效。
func TestRevokeSessionViaRotatedOldTokenKillsSuccessor(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess1", ExpiresAt: exp})
	s.RecordAccessToken("sess1", "jti-old", exp)
	// 正常原子轮换 r1 -> r2，并登记 r2 派生的新访问令牌。
	old, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	s.RecordAccessToken(old.Family, "jti-new", exp)

	// 用已经轮换掉的旧令牌撤销整个会话。
	if res, _ := s.RevokeSession("r1"); res != RevokeOK {
		t.Fatalf("want revoked via rotated token, got %s", res)
	}
	if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor r2 must be unusable, got %v", err)
	}
	if !s.IsAccessRevoked("jti-old") || !s.IsAccessRevoked("jti-new") {
		t.Fatal("both old and new derived access tokens must be revoked")
	}
}

// 幂等与三态：重复撤销、目标不存在、本来无效。
func TestRevokeSessionIdempotentAndDistinguishable(t *testing.T) {
	s := newTestStore()
	if res, _ := s.RevokeSession("ghost"); res != RevokeNotFound {
		t.Fatalf("want not_found, got %s", res)
	}
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: exp})
	if res, _ := s.RevokeSession("r1"); res != RevokeOK {
		t.Fatalf("first: want revoked, got %s", res)
	}
	// 同请求重复撤销：幂等，结论变为 already_invalid。
	if res, fam := s.RevokeSession("r1"); res != RevokeAlreadyInvalid || fam != "f" {
		t.Fatalf("repeat: want already_invalid/f, got %s/%s", res, fam)
	}
	// 已过期且未被轮换消费的令牌“本来就是无效的”：不算真实撤销，
	// 返回 already_invalid，同会话仍有效的访问令牌不受连累。
	_ = s.CreateRefreshToken(&RefreshToken{Token: "old", Family: "f2", ExpiresAt: time.Now().Add(-time.Minute)})
	s.RecordAccessToken("f2", "jti-f2", time.Now().Add(time.Hour))
	if res, _ := s.RevokeSession("old"); res != RevokeAlreadyInvalid {
		t.Fatalf("expired token in live family: want already_invalid, got %s", res)
	}
	if s.IsAccessRevoked("jti-f2") {
		t.Fatal("expired-token revoke must not kill a still-valid access token of the same login")
	}
	if s.DeadSessions() != 1 {
		t.Fatalf("only family f must be dead, got %d", s.DeadSessions())
	}
	// 重复撤销同一过期令牌：结论稳定，仍然不影响会话。
	if res, _ := s.RevokeSession("old"); res != RevokeAlreadyInvalid {
		t.Fatalf("second revoke of expired token: want already_invalid, got %s", res)
	}
	if s.IsAccessRevoked("jti-f2") {
		t.Fatal("repeat expired-token revoke must not kill the live access token")
	}
}

// 会话隔离：撤销一个会话不影响其它用户/客户端/登录会话（即使共享签名密钥）。
func TestRevokeSessionIsolation(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "a1", ClientID: "clientA", UserID: "alice", Family: "famA", ExpiresAt: exp})
	_ = s.CreateRefreshToken(&RefreshToken{Token: "b1", ClientID: "clientB", UserID: "bob", Family: "famB", ExpiresAt: exp})
	s.RecordAccessToken("famA", "ja", exp)
	s.RecordAccessToken("famB", "jb", exp)

	if res, _ := s.RevokeSession("a1"); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	if !s.IsAccessRevoked("ja") {
		t.Fatal("famA access must be revoked")
	}
	if s.IsAccessRevoked("jb") {
		t.Fatal("famB access must remain valid")
	}
	old, err := s.RotateAtomic("clientB", "b1", &RefreshToken{Token: "b2", ClientID: "clientB", UserID: "bob", ExpiresAt: exp})
	if err != nil {
		t.Fatalf("other session must still rotate: %v", err)
	}
	if old.Family != "famB" {
		t.Fatalf("wrong family: %s", old.Family)
	}
}

// 撤销之后才登记的派生访问令牌也必须被拒绝（撤销与签发交错）。
func TestAccessRecordedAfterRevocationIsRejected(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: exp})
	if res, _ := s.RevokeSession("r1"); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	s.RecordAccessToken("f", "late-jti", exp)
	if !s.IsAccessRevoked("late-jti") {
		t.Fatal("access token recorded after revocation must be rejected")
	}
}

// 并发：同一会话的撤销与刷新只能线性化为两种确定、可解释的结论之一：
// (A) 撤销先于刷新：刷新被拒绝，后继令牌绝不入存；
// (B) 刷新先于撤销：刷新成功，但撤销随后终止整个会话，新后继也立即失效。
// 两种顺序下，操作全部返回后会话都不得存在任何有效派生令牌。
func TestConcurrentRevokeAndRefreshConsistent(t *testing.T) {
	var orderARevokedFirst, orderBRefreshFirst int
	for iter := 0; iter < 500; iter++ {
		s := newTestStore()
		exp := time.Now().Add(time.Hour)
		_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "fam", ExpiresAt: exp})

		var wg sync.WaitGroup
		var rotateErr error
		var revokeRes RevokeResult
		var mu sync.Mutex
		start := make(chan struct{})

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp})
			mu.Lock()
			rotateErr = err
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			<-start
			res, _ := s.RevokeSession("r1")
			mu.Lock()
			revokeRes = res
			mu.Unlock()
		}()
		close(start)
		wg.Wait()

		switch {
		case rotateErr != nil && revokeRes == RevokeOK:
			// 顺序 A：撤销先到。
			orderARevokedFirst++
			if !errors.Is(rotateErr, ErrRefreshRevoked) {
				t.Fatalf("iter %d: order A want revoked, got %v", iter, rotateErr)
			}
			if _, err := s.RefreshTokenInfo("r2"); !errors.Is(err, ErrRefreshNotFound) {
				t.Fatalf("iter %d: order A must not store successor", iter)
			}
		case rotateErr == nil && revokeRes == RevokeOK:
			// 顺序 B：刷新先到，撤销必须仍然终止整条链（含后继 r2）。
			orderBRefreshFirst++
			info, err := s.RefreshTokenInfo("r2")
			if err != nil || !info.Revoked {
				t.Fatalf("iter %d: order B successor must end revoked, err=%v info=%+v", iter, err, info)
			}
			if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
				t.Fatalf("iter %d: order B new successor must not refresh", iter)
			}
		default:
			t.Fatalf("iter %d: non-linearizable outcome rotateErr=%v revoke=%s", iter, rotateErr, revokeRes)
		}

		// 无论哪种顺序，终态都是会话已终止，旧令牌与派生关系全部失效。
		if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshRevoked) && !errors.Is(err, ErrRefreshReused) {
			t.Fatalf("iter %d: old token final state unexpected: %v", iter, err)
		}
	}
	if orderARevokedFirst == 0 || orderBRefreshFirst == 0 {
		// 500 轮下两种顺序通常都会出现；若运行环境极端调度导致缺一种，
		// 仅作提示不判失败（断言重点是每种顺序各自结论一致）。
		t.Logf("order coverage: revoke-first=%d refresh-first=%d", orderARevokedFirst, orderBRefreshFirst)
	}
}

// 容量：逐条访问令牌撤销记录触顶时失败关闭，绝不淘汰复活。
func TestRevokeAccessTokenCapacityFailsClosed(t *testing.T) {
	s := New(100, 100, 2)
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 2; i++ {
		jti := fmt.Sprintf("jti-%d", i)
		if res, err := s.RevokeAccessToken(jti, exp); err != nil || res != RevokeOK {
			t.Fatalf("seed revoke %d: res=%s err=%v", i, res, err)
		}
	}
	// 容量满（且无过期可清理）：返回容量错误而不是淘汰旧记录。
	if _, err := s.RevokeAccessToken("jti-new", exp); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("want ErrStoreFull, got %v", err)
	}
	for i := 0; i < 2; i++ {
		if !s.IsAccessRevoked(fmt.Sprintf("jti-%d", i)) {
			t.Fatalf("revoked token %d must never come back to life", i)
		}
	}
}

// 容量淘汰不影响会话级撤销：即使逐条记录容量已满，族撤销仍然有效。
func TestSessionRevocationUnaffectedByRevokedCapacity(t *testing.T) {
	s := New(100, 100, 1)
	exp := time.Now().Add(time.Hour)
	// 用满逐条撤销容量。
	if _, err := s.RevokeAccessToken("seed", exp); err != nil {
		t.Fatal(err)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "fam", ExpiresAt: exp})
	s.RecordAccessToken("fam", "jti-fam", exp)
	// 会话撤销不依赖逐条容量，必须成功且生效。
	if res, _ := s.RevokeSession("r1"); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	if !s.IsAccessRevoked("jti-fam") {
		t.Fatal("session revocation must work regardless of jti capacity")
	}
}

// 有界增长：终止族标记在族内最后一个令牌过期后可被清理。
func TestDeadFamilySweptAfterHorizon(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "fam", ExpiresAt: now.Add(time.Hour)})
	s.RecordAccessToken("fam", "jti-1", now.Add(30*time.Minute))
	if res, _ := s.RevokeSession("r1"); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	if s.DeadSessions() != 1 {
		t.Fatalf("want 1 dead session, got %d", s.DeadSessions())
	}
	// 未到保留窗口：族标记仍保留。
	now = now.Add(2 * time.Hour)
	s.Sweep()
	if s.DeadSessions() != 0 {
		t.Fatalf("dead family must be swept after horizon, got %d", s.DeadSessions())
	}
}

// 有界增长：仍有效令牌牵挂的族标记不会被提前清理（防复活）。
func TestDeadFamilyNotSweptWhileTokenLive(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "fam", ExpiresAt: now.Add(2 * time.Hour)})
	s.RecordAccessToken("fam", "jti-1", now.Add(time.Hour))
	s.RevokeSession("r1")
	now = now.Add(90 * time.Minute) // 访问令牌已过期，但刷新令牌仍有效
	s.Sweep()
	if s.DeadSessions() != 1 {
		t.Fatalf("family with live refresh token must not be swept, got %d", s.DeadSessions())
	}
	now = now.Add(2 * time.Hour)
	s.Sweep()
	if s.DeadSessions() != 0 {
		t.Fatalf("family must be swept after all tokens expire, got %d", s.DeadSessions())
	}
}
