package server_test

import (
	"encoding/json"
	"net/url"
	"sync"
	"testing"

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

// 场景二：先正常轮换，再用“已被轮换掉的旧刷新令牌”撤销会话；
// 轮换后新签发的访问令牌与新刷新令牌都必须失效。
func TestSessionRevokeOldRotatedRefreshKillsSuccessor(t *testing.T) {
	f := newFixture(t, nil)
	tokens := f.fullFlow(t, "openid profile")
	rt1 := tokens["refresh_token"].(string)

	status, body := f.refresh(t, rt1)
	if status != 200 {
		t.Fatalf("first rotation: %d %v", status, body)
	}
	access2 := body["access_token"].(string)
	rt2 := body["refresh_token"].(string)

	// 用已经轮换掉的旧刷新令牌撤销整个会话。
	status, body = f.revokeForm(t, rt1)
	if status != 200 || body["result"] != "revoked" {
		t.Fatalf("want revoked via old refresh token, got %d %v", status, body)
	}

	// 轮换之后签发的访问令牌也被传播撤销。
	status, body = f.userinfo(t, access2)
	if status != 401 || errCode(body) != "invalid_token:revoked" {
		t.Fatalf("successor access token must be revoked, got %d %v", status, body)
	}

	// 后继刷新令牌不能再换发。
	status, body = f.refresh(t, rt2)
	if status != 400 || errCode(body) != "invalid_grant:refresh_revoked" {
		t.Fatalf("successor refresh must be unusable, got %d %v", status, body)
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

// 场景四：撤销与刷新并发，结论必须可解释且终态一致：
// 撤销先到 -> 刷新 400 refresh_revoked，没有有效后继；
// 刷新先到 -> 刷新 200，但随后撤销终止整条链，新令牌立即失效。
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
			// 顺序 A：撤销先到。
			revokedFirst++
			if revokeBody["result"] != "revoked" {
				t.Fatalf("iter %d: revoke-first want revoked, got %v", iter, revokeBody)
			}
		case refreshStatus == 200:
			// 顺序 B：刷新先到；撤销随后终止整条链，新刷新令牌立即失效。
			refreshFirst++
			newAccess := refreshBody["access_token"].(string)
			newRefresh := refreshBody["refresh_token"].(string)
			status, b := f.refresh(t, newRefresh)
			if status != 400 || errCode(b) != "invalid_grant:refresh_revoked" {
				t.Fatalf("iter %d: new refresh must be revoked after racing revoke, got %d %v", iter, status, b)
			}
			status, b = f.userinfo(t, newAccess)
			if status != 401 || errCode(b) != "invalid_token:revoked" {
				t.Fatalf("iter %d: new access must be revoked after racing revoke, got %d %v", iter, status, b)
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
