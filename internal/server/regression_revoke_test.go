package server_test

import (
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
)

// withControllableClock 让服务器与存储共享同一个可控时钟，返回推进时钟的函数。
func withControllableClock(f *fixture) func(time.Duration) {
	var mu sync.Mutex
	cur := time.Now()
	get := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		mu.Lock()
		cur = cur.Add(d)
		mu.Unlock()
	}
	f.st.SetClock(get)
	f.srv.SetClock(get)
	return advance
}

// 回归一（端到端）：刷新令牌 TTL 设为几秒（远短于访问令牌）。刷新令牌早已
// 过期后拿它撤销，只应得到 already_invalid（“本来就是无效的”）：既不是一次
// 真实的会话撤销，也不能连累同一次登录里仍在有效期内的访问令牌。
func TestRegressionE2E_RevokeExpiredRefreshDoesNotKillAccess(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RefreshTokenTTL = 2 * time.Second
		c.AccessTokenTTL = 10 * time.Minute
	})
	advance := withControllableClock(f)

	tokens := f.fullFlow(t, "openid profile")
	access1 := tokens["access_token"].(string)
	rt1 := tokens["refresh_token"].(string)

	// t=500ms 时正常轮换一次，得到同会话的第二组令牌。
	advance(500 * time.Millisecond)
	status, body := f.refresh(t, rt1)
	if status != 200 {
		t.Fatalf("rotation before refresh expiry must succeed: %d %v", status, body)
	}
	access2 := body["access_token"].(string)
	rt2 := body["refresh_token"].(string)

	// 推进到两个刷新令牌都已过期、但访问令牌仍远在有效期内。
	advance(3 * time.Second)

	status, body = f.revokeForm(t, rt1)
	if status != 200 || body["result"] != "already_invalid" {
		t.Fatalf("revoke expired rt1: want already_invalid, got %d %v", status, body)
	}
	if status, body = f.userinfo(t, access2); status != 200 {
		t.Fatalf("still-valid access token must not be affected by expired-token revoke: %d %v", status, body)
	}

	status, body = f.revokeForm(t, rt2)
	if status != 200 || body["result"] != "already_invalid" {
		t.Fatalf("revoke expired rt2: want already_invalid, got %d %v", status, body)
	}
	if status, body = f.userinfo(t, access1); status != 200 {
		t.Fatalf("first access token must stay valid: %d %v", status, body)
	}

	// 没有任何真实的会话终止发生。
	if f.st.DeadSessions() != 0 {
		t.Fatalf("expired-token revoke must not terminate the session, dead=%d", f.st.DeadSessions())
	}

	// 重复撤销：结论稳定。
	if _, body := f.revokeForm(t, rt1); body["result"] != "already_invalid" {
		t.Fatalf("repeat revoke: want already_invalid, got %v", body)
	}
	if status, body = f.userinfo(t, access1); status != 200 {
		t.Fatalf("access must remain valid after repeat revoke: %d %v", status, body)
	}
}

// 回归二（端到端）：旧刷新令牌已被轮换、随后整个会话又被终止，再出示旧令牌
// 的结论必须与会话存活时一致——一律 refresh_reuse_detected，不因先撤过会话
// 而变成 refresh_revoked。
func TestRegressionE2E_ReplayAfterSessionEndKeepsReuseVerdict(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	rt1 := tokens["refresh_token"].(string)

	// 正常轮换 rt1 -> rt2。
	status, body := f.refresh(t, rt1)
	if status != 200 {
		t.Fatalf("first rotation: %d %v", status, body)
	}
	rt2 := body["refresh_token"].(string)

	// 随后用当前刷新令牌终止整个会话。
	if status, body := f.revokeForm(t, rt2); status != 200 || body["result"] != "revoked" {
		t.Fatalf("session revoke: want revoked, got %d %v", status, body)
	}

	// 会话已结束后再出示已用过的旧令牌：结论仍是重放，且重复出示保持稳定。
	for i := 0; i < 3; i++ {
		status, body = f.refresh(t, rt1)
		if status != 400 || errCode(body) != "invalid_grant:refresh_reuse_detected" {
			t.Fatalf("post-termination replay %d: want reuse verdict, got %d %v", i, status, body)
		}
	}
}

// 回归三（端到端）：并发用同一个刷新令牌换令牌，恰好一个成功，其余失败方的
// 对外结论必须一致——全部 refresh_reuse_detected，不允许夹杂 refresh_revoked。
func TestRegressionE2E_ConcurrentRefreshLosersUniformReuse(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	rt := tokens["refresh_token"].(string)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var statuses []int
	var codes []string
	start := make(chan struct{})
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, b := f.refresh(t, rt)
			mu.Lock()
			statuses = append(statuses, st)
			codes = append(codes, errCode(b))
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	ok, reused, revoked, other := 0, 0, 0, 0
	for i, st := range statuses {
		switch {
		case st == 200:
			ok++
		case codes[i] == "invalid_grant:refresh_reuse_detected":
			reused++
		case codes[i] == "invalid_grant:refresh_revoked":
			revoked++
		default:
			other++
			t.Errorf("unexpected loser verdict: %d %s", st, codes[i])
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one concurrent refresh may succeed, got %d", ok)
	}
	if reused != len(statuses)-1 || revoked != 0 || other != 0 {
		t.Fatalf("all losing requests must report reuse, got reused=%d revoked=%d other=%d", reused, revoked, other)
	}
}
