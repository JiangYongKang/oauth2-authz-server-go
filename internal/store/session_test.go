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

// 场景二：已轮换掉的旧刷新令牌本身就已失效，拿它去撤销不算真实撤销，
// 不波及同会话仍有效的后继令牌与派生访问令牌（沿用逐令牌撤销的历史口径）；
// 用当前有效的刷新令牌撤销才会真实终止整条链。
func TestRevokeSessionViaRotatedOldTokenIsNoop(t *testing.T) {
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

	// 用已经轮换掉的旧令牌撤销：本来就无效，不算真实撤销，不波及任何令牌。
	if res, _ := s.RevokeSession("r1"); res != RevokeAlreadyInvalid {
		t.Fatalf("rotated old token: want already_invalid, got %s", res)
	}
	if s.IsAccessRevoked("jti-old") || s.IsAccessRevoked("jti-new") {
		t.Fatal("no-op revoke must not touch derived access tokens")
	}
	if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ClientID: "c", UserID: "u", ExpiresAt: exp}); err != nil {
		t.Fatalf("successor r2 must survive no-op revoke, got %v", err)
	}

	// 用当前有效的刷新令牌撤销：真实终止整条链，派生访问令牌全部失效。
	if res, _ := s.RevokeSession("r3"); res != RevokeOK {
		t.Fatalf("live token: want revoked, got %s", res)
	}
	if !s.IsAccessRevoked("jti-old") || !s.IsAccessRevoked("jti-new") {
		t.Fatal("real session revoke must kill all derived access tokens")
	}
	// 终态：未使用过的族成员按撤销拒绝；已消费过的旧令牌仍按重放判定。
	if _, err := s.RotateAtomic("c", "r3", &RefreshToken{Token: "r4", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("live family member must be revoked after real revoke, got %v", err)
	}
	if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r5", ExpiresAt: exp}); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("consumed old token must stay replay judgement, got %v", err)
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
	// 已过期令牌本来就无效：撤销它是空操作，不波及同族仍存活的令牌。
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateRefreshToken(&RefreshToken{Token: "old", Family: "f2", ExpiresAt: now.Add(time.Minute)})
	_ = s.CreateRefreshToken(&RefreshToken{Token: "cur", ClientID: "c", Family: "f2", ExpiresAt: now.Add(time.Hour)})
	now = now.Add(2 * time.Minute) // old 已过期但仍在存，cur 仍有效
	if res, _ := s.RevokeSession("old"); res != RevokeAlreadyInvalid {
		t.Fatalf("expired token: want already_invalid, got %s", res)
	}
	if _, err := s.RotateAtomic("c", "cur", &RefreshToken{Token: "cur2", Family: "f2", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("live family member must survive no-op revoke of expired token, got %v", err)
	}
	// 用仍有效的令牌撤销同一会话：真实发生，且幂等。
	if res, _ := s.RevokeSession("cur2"); res != RevokeOK {
		t.Fatalf("live token: want revoked, got %s", res)
	}
	if res, _ := s.RevokeSession("cur2"); res != RevokeAlreadyInvalid {
		t.Fatalf("second revoke of terminated session: want already_invalid, got %s", res)
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
// (A) 撤销先于刷新：撤销真实生效，刷新被拒绝（revoked），后继令牌绝不入存；
// (B) 刷新先于撤销：刷新成功，撤销此时面对的已是被消费掉的旧令牌，
//     按历史口径判定 already_invalid（空操作），新后继不受影响、可继续轮换。
// 两种顺序对外结论都确定可解释，且都不存在“半撤销”的中间状态。
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
			// 顺序 A：撤销先到，真实终止会话。
			orderARevokedFirst++
			if !errors.Is(rotateErr, ErrRefreshRevoked) {
				t.Fatalf("iter %d: order A want revoked, got %v", iter, rotateErr)
			}
			if _, err := s.RefreshTokenInfo("r2"); !errors.Is(err, ErrRefreshNotFound) {
				t.Fatalf("iter %d: order A must not store successor", iter)
			}
			// 终态：会话已终止，旧令牌与任何后继都不可用。
			if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshRevoked) && !errors.Is(err, ErrRefreshReused) {
				t.Fatalf("iter %d: order A old token final state unexpected: %v", iter, err)
			}
		case rotateErr == nil && revokeRes == RevokeAlreadyInvalid:
			// 顺序 B：刷新先到，撤销点名的是已被消费的旧令牌——空操作。
			orderBRefreshFirst++
			info, err := s.RefreshTokenInfo("r2")
			if err != nil || info.Revoked || info.Used {
				t.Fatalf("iter %d: order B successor must stay live, err=%v info=%+v", iter, err, info)
			}
			// 后继仍可正常轮换（会话未被波及）。
			if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ClientID: "c", UserID: "u", ExpiresAt: exp}); err != nil {
				t.Fatalf("iter %d: order B successor must remain usable, got %v", iter, err)
			}
		default:
			t.Fatalf("iter %d: non-linearizable outcome rotateErr=%v revoke=%s", iter, rotateErr, revokeRes)
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

// 回归：过期刷新令牌本来就无效——撤销它是空操作（already_invalid），
// 既不真实终止会话，也不波及同一次登录里仍然有效的访问令牌。
// 复现条件：刷新令牌有效期短于访问令牌。
func TestRevokeExpiredRefreshDoesNotKillLiveAccess(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	// 刷新令牌只活 5 秒，访问令牌活 1 小时。
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: now.Add(5 * time.Second)})
	s.RecordAccessToken("sess", "jti-live", now.Add(time.Hour))

	now = now.Add(time.Minute) // 刷新令牌早已过期，访问令牌仍有效
	if res, _ := s.RevokeSession("r1"); res != RevokeAlreadyInvalid {
		t.Fatalf("expired refresh token: want already_invalid, got %s", res)
	}
	if s.IsAccessRevoked("jti-live") {
		t.Fatal("live access token of the same login must not be affected")
	}
	if s.DeadSessions() != 0 {
		t.Fatalf("no real session termination may be recorded, got %d", s.DeadSessions())
	}
}

// 回归：会话终止之后，再出示已轮换消费过的旧令牌，结论仍是重放
// （ErrRefreshReused），不因会话先被撤销而改判为 revoked。
func TestReplayAfterSessionTerminationStaysReused(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp})
	// 正常轮换 r1 -> r2，随后用仍有效的 r2 终止整个会话。
	if _, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.RevokeSession("r2"); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	// 已用过的 r1 再次出现：无论走哪条轮换路径，结论都是重放。
	if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("RotateRefreshToken: want reused, got %v", err)
	}
	if _, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r3", ExpiresAt: exp}); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("RotateAtomic: want reused, got %v", err)
	}
	if _, err := s.RefreshTokenInfo("r3"); !errors.Is(err, ErrRefreshNotFound) {
		t.Fatal("replayed presentation must never store a successor")
	}
}

// 回归：并发用同一刷新令牌走原子轮换，恰好一个成功，
// 其余全部得到一致的重放结论（不允许混入 revoked）。
func TestConcurrentRotateAtomicLosersAllReused(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		s := newTestStore()
		exp := time.Now().Add(time.Hour)
		_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "f", ExpiresAt: exp})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				next := &RefreshToken{Token: fmt.Sprintf("r-next-%d", i), ClientID: "c", UserID: "u", ExpiresAt: exp}
				_, err := s.RotateAtomic("c", "r1", next)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()
		ok, reused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrRefreshReused):
				reused++
			default:
				t.Fatalf("iter %d: loser must be reuse, got %v", iter, err)
			}
		}
		if ok != 1 || reused != len(errs)-1 {
			t.Fatalf("iter %d: want 1 success + %d reuse, got %d/%d", iter, len(errs)-1, ok, reused)
		}
	}
}
