package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// 回归一：用早已过期（未被轮换消费）的刷新令牌撤销时，只能判定为
// “本来就是无效的”（already_invalid）：既不算一次真实的会话撤销，
// 也不得连累同一次登录中仍然有效的访问令牌与当前刷新令牌。
func TestRegression_RevokeExpiredRefreshDoesNotKillLiveSession(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	accessExp := now.Add(10 * time.Minute) // 访问令牌仍在有效期内
	_ = s.CreateRefreshToken(&RefreshToken{Token: "cur", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: accessExp})
	_ = s.CreateRefreshToken(&RefreshToken{Token: "expired", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: now.Add(-time.Second)})
	s.RecordAccessToken("sess", "jti-live", accessExp)

	res, fam := s.RevokeSession("expired")
	if res != RevokeAlreadyInvalid || fam != "sess" {
		t.Fatalf("want already_invalid/sess, got %s/%s", res, fam)
	}
	if s.IsAccessRevoked("jti-live") {
		t.Fatal("revoking an already-expired refresh token must not revoke the still-valid access token")
	}
	if s.DeadSessions() != 0 {
		t.Fatal("no real session revocation must have happened")
	}
	// 同会话的当前刷新令牌仍可正常轮换。
	if _, err := s.RotateAtomic("c", "cur", &RefreshToken{Token: "next", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: accessExp}); err != nil {
		t.Fatalf("live refresh in the same login must still rotate: %v", err)
	}

	// 把时钟拨到过期令牌被清理之后，再撤销它：结论退化为 not_found，同样不波及会话。
	now = now.Add(time.Hour)
	s.Sweep()
	if res, _ := s.RevokeSession("expired"); res != RevokeNotFound {
		t.Fatalf("swept token: want not_found, got %s", res)
	}
	if s.IsAccessRevoked("jti-live") {
		t.Fatal("post-sweep revoke attempt must not affect the live access token")
	}
}

// 回归一补充：已被轮换消费（Used）但自身也已过期的旧令牌，同样“本来就
// 已经失效”：过期判定优先，不终止仍存活的会话、不连累有效访问令牌。
func TestRegression_RevokeRotatedButExpiredRefreshDoesNotKillSession(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	liveExp := now.Add(10 * time.Minute)
	// r1 是短 TTL 刷新令牌（模拟几秒有效期），先正常轮换 r1 -> r2。
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: now.Add(2 * time.Second)})
	old, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: liveExp})
	if err != nil {
		t.Fatal(err)
	}
	s.RecordAccessToken("sess", "jti-live", liveExp)

	// 旧令牌过期后拿它撤销：already_invalid，会话仍存活。
	now = now.Add(3 * time.Second)
	if res, fam := s.RevokeSession("r1"); res != RevokeAlreadyInvalid || fam != "sess" {
		t.Fatalf("used+expired token: want already_invalid/sess, got %s/%s", res, fam)
	}
	if s.IsAccessRevoked("jti-live") {
		t.Fatal("used+expired token revoke must not kill the still-valid access token")
	}
	if s.DeadSessions() != 0 {
		t.Fatal("session must not be terminated by revoking an expired rotated-old token")
	}
	// 后继 r2 仍可换发，会话功能完好。
	if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ClientID: "c", UserID: "u", ExpiresAt: liveExp}); err != nil {
		t.Fatalf("successor %s must still rotate: %v", old.Token, err)
	}
}

// 回归一配套（保留上一轮会话级撤销能力）：已轮换掉但仍在有效期内的旧令牌
// 仍然代表一次存活的授权链，用它撤销必须真实终止整条链并返回 revoked。
func TestRegression_RevokeRotatedUnexpiredOldTokenStillKillsSession(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp})
	s.RecordAccessToken("sess", "jti-a", exp)
	if _, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	s.RecordAccessToken("sess", "jti-b", exp)

	if res, fam := s.RevokeSession("r1"); res != RevokeOK || fam != "sess" {
		t.Fatalf("unexpired rotated-old token: want revoked/sess, got %s/%s", res, fam)
	}
	if !s.IsAccessRevoked("jti-a") || !s.IsAccessRevoked("jti-b") {
		t.Fatal("both derived access tokens must be revoked")
	}
	if _, err := s.RotateAtomic("c", "r2", &RefreshToken{Token: "r3", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor must be unusable, got %v", err)
	}
	// 幂等：重复撤销返回 already_invalid。
	if res, _ := s.RevokeSession("r1"); res != RevokeAlreadyInvalid {
		t.Fatalf("repeat: want already_invalid, got %s", res)
	}
}

// 回归一变体：已被逐条撤销（但会话仍存活、未被轮换消费）的令牌同样
// “本来就是无效的”，不触发会话级撤销。
func TestRegression_RevokeIndividuallyRevokedRefreshDoesNotKillSession(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "cur", Family: "sess", ExpiresAt: exp})
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r", Family: "sess", ExpiresAt: exp})
	s.RecordAccessToken("sess", "jti-live", exp)
	if r := s.RevokeRefreshToken("r"); r != RevokeOK {
		t.Fatalf("seed: want revoked, got %s", r)
	}

	if res, _ := s.RevokeSession("r"); res != RevokeAlreadyInvalid {
		t.Fatalf("want already_invalid, got %s", res)
	}
	if s.IsAccessRevoked("jti-live") {
		t.Fatal("individually revoked token must not cascade to the session")
	}
	if s.DeadSessions() != 0 {
		t.Fatal("session must stay alive")
	}
}

// 回归二：旧刷新令牌已被轮换消费、随后整个会话又被终止之后，再出示该旧
// 令牌，结论必须与会话未终止时一致——一律是重放（ErrRefreshReused），
// 不能因为会话先被撤掉就改判已撤销（ErrRefreshRevoked）。
func TestRegression_ReplayVerdictStableAfterSessionTerminated(t *testing.T) {
	for _, atomicPath := range []bool{false, true} {
		name := "RotateRefreshToken"
		if atomicPath {
			name = "RotateAtomic"
		}
		t.Run(name, func(t *testing.T) {
			s := newTestStore()
			exp := time.Now().Add(time.Hour)
			_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp})
			// 正常轮换 r1 -> r2。
			old, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp})
			if err != nil {
				t.Fatal(err)
			}
			if old.Family != "sess" {
				t.Fatalf("family mismatch: %s", old.Family)
			}
			// 随后由显式撤销终止整个会话。
			if res, fam := s.RevokeSession("r2"); res != RevokeOK || fam != "sess" {
				t.Fatalf("seed revoke: want revoked/sess, got %s/%s", res, fam)
			}
			// 再出示已用过的旧令牌：结论仍必须是重放。
			rotate := func() error {
				if atomicPath {
					_, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "rX", ExpiresAt: exp})
					return err
				}
				_, err := s.RotateRefreshToken("r1")
				return err
			}
			if err := rotate(); !errors.Is(err, ErrRefreshReused) {
				t.Fatalf("replay after session end must still be reuse, got %v", err)
			}
			if err := rotate(); !errors.Is(err, ErrRefreshReused) {
				t.Fatalf("repeat replay verdict must remain stable, got %v", err)
			}
			// 后继 rX 绝不入存（判重放时不存在写入窗口）。
			if _, err := s.RefreshTokenInfo("rX"); !errors.Is(err, ErrRefreshNotFound) {
				t.Fatalf("reuse attempt must never store a successor, got %v", err)
			}
		})
	}
}

// 回归二变体：先由重放终止会话，再并发出示旧令牌，结论也必须全部一致。
func TestRegression_ConcurrentReplayAfterTerminationAllReuse(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp})
	if _, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "r2", ClientID: "c", UserID: "u", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	// 用显式撤销终止会话（不经过重放路径）。
	if res, _ := s.RevokeSession("r2"); res != RevokeOK {
		t.Fatalf("seed: %s", res)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.RotateAtomic("c", "r1", &RefreshToken{Token: "rx", ExpiresAt: exp})
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, ErrRefreshReused) {
			t.Fatalf("contender %d: want reuse, got %v", i, err)
		}
	}
}

// 回归三：并发用同一刷新令牌换令牌，恰好一个成功，其余失败方结论必须
// 一致且确定——全部为重放（ErrRefreshReused），不允许出现已撤销结论。
func TestRegression_ConcurrentRotateAtomicLosersUniformReuse(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		s := newTestStore()
		exp := time.Now().Add(time.Hour)
		_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp})

		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, err := s.RotateAtomic("c", "r1", &RefreshToken{
					Token: fmt.Sprintf("next-%d-%d", iter, i), ClientID: "c", UserID: "u", Family: "sess", ExpiresAt: exp,
				})
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()

		ok, reused, revoked, other := 0, 0, 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrRefreshReused):
				reused++
			case errors.Is(err, ErrRefreshRevoked):
				revoked++
			default:
				other++
			}
		}
		if ok != 1 {
			t.Fatalf("iter %d: exactly one winner, got %d", iter, ok)
		}
		if reused != len(errs)-1 || revoked != 0 || other != 0 {
			t.Fatalf("iter %d: losers must all be reuse, got reused=%d revoked=%d other=%d", iter, reused, revoked, other)
		}
	}
}

// 回归三附带保证：首个重放者终止会话的会话级撤销效果不被削弱——
// 撤销（此处由重放引发）之后不可能再产生有效后继令牌，其它族不受影响。
func TestRegression_ReuseTerminationStillKillsChainAndIsolates(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	_ = s.CreateRefreshToken(&RefreshToken{Token: "a1", ClientID: "cA", UserID: "alice", Family: "famA", ExpiresAt: exp})
	_ = s.CreateRefreshToken(&RefreshToken{Token: "b1", ClientID: "cB", UserID: "bob", Family: "famB", ExpiresAt: exp})
	s.RecordAccessToken("famA", "ja", exp)
	s.RecordAccessToken("famB", "jb", exp)

	old, err := s.RotateAtomic("cA", "a1", &RefreshToken{Token: "a2", ClientID: "cA", UserID: "alice", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	// 重放 a1：结论重放，整族终止。
	if _, err := s.RotateAtomic("cA", "a1", &RefreshToken{Token: "aX", ExpiresAt: exp}); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("want reuse, got %v", err)
	}
	if !s.IsAccessRevoked("ja") {
		t.Fatal("family access token must be revoked after reuse")
	}
	if _, err := s.RotateAtomic("cA", "a2", &RefreshToken{Token: "a3", ExpiresAt: exp}); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor %s must be revoked, got %v", old.Token, err)
	}
	// 会话终止之后才登记的访问令牌同样必须失效。
	s.RecordAccessToken("famA", "ja-late", exp)
	if !s.IsAccessRevoked("ja-late") {
		t.Fatal("access token recorded after termination must be rejected")
	}
	// 其它用户/客户端/会话不受影响。
	if s.IsAccessRevoked("jb") {
		t.Fatal("other family must not be affected")
	}
	if _, err := s.RotateAtomic("cB", "b1", &RefreshToken{Token: "b2", ClientID: "cB", UserID: "bob", ExpiresAt: exp}); err != nil {
		t.Fatalf("other family must still rotate: %v", err)
	}
}
