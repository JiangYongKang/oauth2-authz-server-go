package server_test

import (
	"encoding/json"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
)

// revokeForm POST /revoke，返回状态码与响应体。
func (f *fixture) revokeForm(t *testing.T, tok string) (int, map[string]any) {
	t.Helper()
	resp, err := f.client.PostForm(f.http.URL+"/revoke", url.Values{"token": {tok}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// 场景一：用当前刷新令牌撤销整个会话后，
// 已签发的访问令牌与该刷新令牌本身都不可再用，且无法刷新出新令牌。
func TestSessionRevokeCurrentRefreshKillsChain(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	access1 := tokens["access_token"].(string)
	rt1 := tokens["refresh_token"].(string)

	status, body := f.revokeForm(t, rt1)
	if status != 200 || body["result"] != "revoked" {
		t.Fatalf("want revoked, got %d %v", status, body)
	}

	// 当前访问令牌立即失效。
	status, body = f.userinfo(t, access1)
	if status != 401 || errCode(body) != "invalid_token:revoked" {
		t.Fatalf("access token must be revoked, got %d %v", status, body)
	}

	// 当前刷新令牌不能再换发。
	status, body = f.refresh(t, rt1)
	if status != 400 || errCode(body) != "invalid_grant:refresh_revoked" {
		t.Fatalf("refresh after session revoke must fail, got %d %v", status, body)
	}

	// 重复撤销：幂等，结论为 already_invalid。
	_, body = f.revokeForm(t, rt1)
	if body["result"] != "already_invalid" {
		t.Fatalf("repeat revoke want already_invalid, got %v", body)
	}
}

// 场景二：先正常轮换，再用“已被轮换掉的旧刷新令牌”撤销——旧令牌本来就已失效，
// 撤销是空操作（already_invalid），不波及新访问令牌与新刷新令牌；
// 用当前有效的刷新令牌撤销才真实终止整条链。
func TestSessionRevokeOldRotatedRefreshIsNoop(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	rt1 := tokens["refresh_token"].(string)

	status, body := f.refresh(t, rt1)
	if status != 200 {
		t.Fatalf("first rotation: %d %v", status, body)
	}
	access2 := body["access_token"].(string)
	rt2 := body["refresh_token"].(string)

	// 用已经轮换掉的旧刷新令牌撤销：本来就无效，不算真实撤销。
	status, body = f.revokeForm(t, rt1)
	if status != 200 || body["result"] != "already_invalid" {
		t.Fatalf("rotated old token: want already_invalid, got %d %v", status, body)
	}

	// 轮换后签发的访问令牌与新刷新令牌都不受波及。
	if status, body := f.userinfo(t, access2); status != 200 {
		t.Fatalf("successor access token must survive no-op revoke, got %d %v", status, body)
	}
	status, body = f.refresh(t, rt2)
	if status != 200 {
		t.Fatalf("successor refresh must survive no-op revoke, got %d %v", status, body)
	}
	rt3 := body["refresh_token"].(string)

	// 用当前有效的刷新令牌撤销：真实终止整条链。
	status, body = f.revokeForm(t, rt3)
	if status != 200 || body["result"] != "revoked" {
		t.Fatalf("live token: want revoked, got %d %v", status, body)
	}
	status, body = f.userinfo(t, access2)
	if status != 401 || errCode(body) != "invalid_token:revoked" {
		t.Fatalf("derived access token must be revoked after real revoke, got %d %v", status, body)
	}
}

// 场景三：撤销一个会话不影响其它登录会话（不同授权链，共享签名密钥）。
func TestSessionRevokeDoesNotAffectOtherSessions(t *testing.T) {
	f := newFixture(t, nil)
	s1 := f.fullFlow(t, "openid profile")
	s2 := f.fullFlow(t, "openid profile")

	if _, body := f.revokeForm(t, s1["refresh_token"].(string)); body["result"] != "revoked" {
		t.Fatalf("revoke s1: %v", body)
	}

	// 会话 2 的访问令牌仍可用、刷新仍可轮换。
	if status, body := f.userinfo(t, s2["access_token"].(string)); status != 200 {
		t.Fatalf("other session access must survive, got %d %v", status, body)
	}
	if status, body := f.refresh(t, s2["refresh_token"].(string)); status != 200 {
		t.Fatalf("other session refresh must survive, got %d %v", status, body)
	}
}

// 场景四：撤销与刷新并发，结论必须可解释且确定：
// 撤销先到 -> 撤销 revoked，刷新 400 refresh_revoked，没有有效后继；
// 刷新先到 -> 刷新 200，撤销此时点名的是已被消费的旧令牌，
// 按历史口径判定 already_invalid（空操作），新令牌不受影响、可继续使用。
func TestSessionRevokeConcurrentWithRefresh(t *testing.T) {
	var revokedFirst, refreshFirst int
	for iter := 0; iter < 80; iter++ {
		f := newFixture(t, nil)
		tokens := f.fullFlow(t, "openid profile")
		rt := tokens["refresh_token"].(string)

		var wg sync.WaitGroup
		var refreshStatus int
		var refreshBody map[string]any
		var revokeBody map[string]any
		var mu sync.Mutex
		start := make(chan struct{})

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			st, b := f.refresh(t, rt)
			mu.Lock()
			refreshStatus, refreshBody = st, b
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			<-start
			_, b := f.revokeForm(t, rt)
			mu.Lock()
			revokeBody = b
			mu.Unlock()
		}()
		close(start)
		wg.Wait()

		switch {
		case refreshStatus == 400 && errCode(refreshBody) == "invalid_grant:refresh_revoked":
			// 顺序 A：撤销先到，真实终止会话。
			revokedFirst++
			if revokeBody["result"] != "revoked" {
				t.Fatalf("iter %d: revoke-first want revoked, got %v", iter, revokeBody)
			}
		case refreshStatus == 200:
			// 顺序 B：刷新先到；撤销点名已消费的旧令牌，是空操作。
			refreshFirst++
			if revokeBody["result"] != "already_invalid" {
				t.Fatalf("iter %d: refresh-first revoke must be already_invalid, got %v", iter, revokeBody)
			}
			newAccess := refreshBody["access_token"].(string)
			newRefresh := refreshBody["refresh_token"].(string)
			// 新令牌不被空操作波及：访问令牌可用，刷新令牌可继续轮换。
			if status, b := f.userinfo(t, newAccess); status != 200 {
				t.Fatalf("iter %d: new access must survive no-op revoke, got %d %v", iter, status, b)
			}
			if status, b := f.refresh(t, newRefresh); status != 200 {
				t.Fatalf("iter %d: new refresh must survive no-op revoke, got %d %v", iter, status, b)
			}
		default:
			t.Fatalf("iter %d: unexplainable race outcome %d %v", iter, refreshStatus, refreshBody)
		}
	}
	t.Logf("race order coverage: revoke-first=%d refresh-first=%d", revokedFirst, refreshFirst)
}

// 容量失败关闭：逐条访问令牌撤销记录触顶时返回 503 且错误可区分，
// 已撤销的令牌不得因淘汰而复活。
func TestRevokeCapacityFailsClosed(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxRevokedEntries = 1 })
	s1 := f.fullFlow(t, "openid profile")
	s2 := f.fullFlow(t, "openid profile")

	// 第一条撤销占满容量。
	if _, body := f.revokeForm(t, s1["access_token"].(string)); body["result"] != "revoked" {
		t.Fatalf("first revoke: %v", body)
	}
	// 第二条无法再记录：失败关闭，而非静默放行或淘汰第一条。
	status, body := f.revokeForm(t, s2["access_token"].(string))
	if status != 503 || errCode(body) != "temporarily_unavailable:revocation_capacity" {
		t.Fatalf("want 503 revocation_capacity, got %d %v", status, body)
	}
	// 第一条撤销仍然生效，没有复活。
	if status, body := f.userinfo(t, s1["access_token"].(string)); status != 401 || errCode(body) != "invalid_token:revoked" {
		t.Fatalf("first revocation must survive capacity pressure, got %d %v", status, body)
	}
}

// 场景五：会话撤销对密钥轮换透明——轮换前签发的同会话访问令牌，
// 在密钥轮换后仍因会话撤销而被拒绝（不是 unknown_key，而是 revoked）。
func TestSessionRevokePropagatesAcrossKeyRotation(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	access := tokens["access_token"].(string)
	rt := tokens["refresh_token"].(string)

	if _, err := f.km.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, body := f.revokeForm(t, rt); body["result"] != "revoked" {
		t.Fatalf("want revoked, got %v", body)
	}
	status, body := f.userinfo(t, access)
	if status != 401 || errCode(body) != "invalid_token:revoked" {
		t.Fatalf("pre-rotation access token must be session-revoked, got %d %v", status, body)
	}
}

// 回归（场景六）：刷新令牌比访问令牌先过期时，拿过期的刷新令牌去撤销，
// 结论必须是 already_invalid（本来就无效），且同一次登录里仍然有效的
// 访问令牌不被连累。过期令牌本身也不能再换发新令牌。
func TestRevokeExpiredRefreshDoesNotKillLiveAccess(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RefreshTokenTTL = 5 * time.Second // 刷新令牌远短于访问令牌
		c.AccessTokenTTL = time.Hour
	})
	tokens := f.fullFlow(t, "openid profile")
	access := tokens["access_token"].(string)
	rt := tokens["refresh_token"].(string)
	// 另起一个会话，用于验证过期刷新令牌本身也无法再换发。
	tokens2 := f.fullFlow(t, "openid profile")
	rt2 := tokens2["refresh_token"].(string)

	// 时钟前进到刷新令牌早已过期、访问令牌仍有效的时刻。
	// 服务器与存储使用各自注入的时钟，需一并前进。
	later := time.Now().Add(time.Minute)
	f.srv.SetClock(func() time.Time { return later })
	f.st.SetClock(func() time.Time { return later })

	// 过期刷新令牌的撤销是空操作：本来就无效，不算真实会话撤销。
	status, body := f.revokeForm(t, rt)
	if status != 200 || body["result"] != "already_invalid" {
		t.Fatalf("expired refresh token: want already_invalid, got %d %v", status, body)
	}
	// 同一次登录的有效访问令牌不被连累。
	status, body = f.userinfo(t, access)
	if status != 200 {
		t.Fatalf("live access token must survive no-op revoke, got %d %v", status, body)
	}

	// 过期刷新令牌本身也无法再换发新令牌。
	status, body = f.refresh(t, rt2)
	if status != 400 || errCode(body) != "invalid_grant:refresh_expired" {
		t.Fatalf("expired refresh token must not rotate, got %d %v", status, body)
	}
}

// 回归（场景七）：旧刷新令牌已轮换、会话随后被终止之后，再出示已用过的
// 旧令牌，结论仍是重放（refresh_reuse_detected），不因会话先被撤销而改判。
func TestReplayAfterSessionTerminationStaysReused(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	rt1 := tokens["refresh_token"].(string)

	// 正常轮换 rt1 -> rt2，随后用仍有效的 rt2 终止整个会话。
	status, body := f.refresh(t, rt1)
	if status != 200 {
		t.Fatalf("rotation: %d %v", status, body)
	}
	rt2 := body["refresh_token"].(string)
	if _, body := f.revokeForm(t, rt2); body["result"] != "revoked" {
		t.Fatalf("session revoke: %v", body)
	}

	// 已用过的 rt1 再次出现：结论仍是重放，不是“已撤销”。
	status, body = f.refresh(t, rt1)
	if status != 400 || errCode(body) != "invalid_grant:refresh_reuse_detected" {
		t.Fatalf("used token after session termination must stay reuse, got %d %v", status, body)
	}
}

// 回归（场景八）：并发用同一个刷新令牌换令牌，恰好一个成功，
// 其余所有失败结论一致为重放（refresh_reuse_detected），
// 不允许混入“已撤销”等第二种结论。
func TestConcurrentRefreshFailuresAreUniformlyReplay(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		f := newFixture(t, nil)
		tokens := f.fullFlow(t, "openid profile")
		rt := tokens["refresh_token"].(string)

		const n = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		var successes, replays, others int
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				status, body := f.refresh(t, rt)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case status == 200:
					successes++
				case status == 400 && errCode(body) == "invalid_grant:refresh_reuse_detected":
					replays++
				default:
					others++
				}
			}()
		}
		close(start)
		wg.Wait()
		if successes != 1 {
			t.Fatalf("iter %d: exactly one refresh may succeed, got %d", iter, successes)
		}
		if others != 0 || replays != n-1 {
			t.Fatalf("iter %d: all losers must be replay, got replays=%d others=%d", iter, replays, others)
		}
	}
}
