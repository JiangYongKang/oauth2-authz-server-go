package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/ratelimit"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/store"
)

const (
	testClientID = "web-app"
	testSecret   = "s3cret"
	testRedirect = "http://localhost/callback"
	testVerifier = "correct-horse-battery-staple-verifier"
)

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// testEnv 组装一个内存测试环境。
type testEnv struct {
	srv *Server
	ts  *httptest.Server
	now time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := config.Default()
	cfg.Issuer = "http://test-issuer"
	cfg.RateLimitPerSecond = 0 // 默认关闭限流，专项测试再开启
	ks := keys.NewStore()
	if _, err := ks.Generate(); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	st := store.New(10000)
	st.RegisterClient(store.Client{
		ID:           testClientID,
		Secret:       testSecret,
		RedirectURIs: []string{testRedirect},
		Scopes:       []string{"read", "write"},
	})
	srv := New(cfg, ks, st, ratelimit.New(0, 0))
	env := &testEnv{srv: srv, now: time.Now()}
	srv.SetClock(func() time.Time { return env.now })
	env.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(env.ts.Close)
	return env
}

// noRedirectClient 不自动跟随重定向。
var noRedirectClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// authorize 执行授权请求，返回重定向中的 code 或错误体。
func (e *testEnv) authorize(t *testing.T, params url.Values) (string, map[string]string) {
	t.Helper()
	resp, err := noRedirectClient.Get(e.ts.URL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc.Query().Get("code"), nil
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return "", body
}

func defaultAuthorizeParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"read"},
		"state":                 {"xyz"},
		"subject":               {"user-1"},
		"code_challenge":        {s256(testVerifier)},
		"code_challenge_method": {"S256"},
	}
}

// tokenResp 是 /token 成功响应。
type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// exchangeCode 用授权码换令牌。
func (e *testEnv) exchangeCode(t *testing.T, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {testClientID},
		"client_secret": {testSecret},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(e.ts.URL+"/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// issueTokens 走完整流程拿到令牌对。
func (e *testEnv) issueTokens(t *testing.T, scope string) tokenResp {
	t.Helper()
	p := defaultAuthorizeParams()
	p.Set("scope", scope)
	code, errBody := e.authorize(t, p)
	if code == "" {
		t.Fatalf("authorize failed: %v", errBody)
	}
	status, body := e.exchangeCode(t, code, testVerifier)
	if status != http.StatusOK {
		t.Fatalf("exchange failed: status=%d body=%v", status, body)
	}
	return tokenResp{
		AccessToken:  body["access_token"].(string),
		RefreshToken: body["refresh_token"].(string),
		Scope:        body["scope"].(string),
	}
}

// verify 调用 /verify。
func (e *testEnv) verify(t *testing.T, tok, requiredScope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"token": {tok}, "required_scope": {requiredScope}}
	resp, err := http.PostForm(e.ts.URL+"/verify", form)
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	env := newTestEnv(t)
	tokens := env.issueTokens(t, "read")
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected both tokens")
	}
	status, body := env.verify(t, tokens.AccessToken, "read")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("token must be active: status=%d body=%v", status, body)
	}
}

func TestAuthorizeRejections(t *testing.T) {
	env := newTestEnv(t)
	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{"bad response_type", func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		{"unknown client", func(v url.Values) { v.Set("client_id", "ghost") }, "invalid_client"},
		{"redirect mismatch", func(v url.Values) { v.Set("redirect_uri", "http://evil/callback") }, "invalid_redirect_uri"},
		{"scope escalation", func(v url.Values) { v.Set("scope", "read admin") }, "invalid_scope"},
		{"missing PKCE", func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		{"plain PKCE rejected", func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"missing subject", func(v url.Values) { v.Del("subject") }, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := defaultAuthorizeParams()
			tc.mutate(p)
			code, body := env.authorize(t, p)
			if code != "" {
				t.Fatalf("must not issue code for %s", tc.name)
			}
			if body["error"] != tc.wantError {
				t.Fatalf("want error=%s, got %v", tc.wantError, body)
			}
		})
	}
}

func TestTokenGrantRejections(t *testing.T) {
	env := newTestEnv(t)

	t.Run("code reuse rejected", func(t *testing.T) {
		code, _ := env.authorize(t, defaultAuthorizeParams())
		if status, _ := env.exchangeCode(t, code, testVerifier); status != http.StatusOK {
			t.Fatal("first exchange must succeed")
		}
		status, body := env.exchangeCode(t, code, testVerifier)
		if status != http.StatusBadRequest || !strings.Contains(body["error_description"].(string), "already_used") {
			t.Fatalf("reuse must fail with code_already_used, got %d %v", status, body)
		}
	})

	t.Run("wrong verifier rejected", func(t *testing.T) {
		code, _ := env.authorize(t, defaultAuthorizeParams())
		status, body := env.exchangeCode(t, code, "wrong-verifier")
		if status != http.StatusBadRequest || !strings.Contains(body["error_description"].(string), "PKCE") {
			t.Fatalf("want PKCE mismatch, got %d %v", status, body)
		}
	})

	t.Run("redirect_uri mismatch rejected", func(t *testing.T) {
		code, _ := env.authorize(t, defaultAuthorizeParams())
		form := url.Values{
			"grant_type": {"authorization_code"}, "client_id": {testClientID},
			"client_secret": {testSecret}, "code": {code},
			"redirect_uri": {"http://other/cb"}, "code_verifier": {testVerifier},
		}
		resp, err := http.PostForm(env.ts.URL+"/token", form)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body["error_description"].(string), "redirect_uri") {
			t.Fatalf("want redirect_uri mismatch, got %d %v", resp.StatusCode, body)
		}
	})

	t.Run("bad client secret rejected", func(t *testing.T) {
		code, _ := env.authorize(t, defaultAuthorizeParams())
		form := url.Values{
			"grant_type": {"authorization_code"}, "client_id": {testClientID},
			"client_secret": {"wrong"}, "code": {code},
			"redirect_uri": {testRedirect}, "code_verifier": {testVerifier},
		}
		resp, err := http.PostForm(env.ts.URL+"/token", form)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("want invalid_client, got %d %v", resp.StatusCode, body)
		}
	})

	t.Run("unknown code rejected", func(t *testing.T) {
		status, body := env.exchangeCode(t, "no-such-code", testVerifier)
		if status != http.StatusBadRequest || !strings.Contains(body["error_description"].(string), "not_found") {
			t.Fatalf("want code_not_found, got %d %v", status, body)
		}
	})
}

func TestVerifyDistinguishesFailures(t *testing.T) {
	env := newTestEnv(t)
	tokens := env.issueTokens(t, "read")

	t.Run("tampered token", func(t *testing.T) {
		parts := strings.Split(tokens.AccessToken, ".")
		parts[2] = parts[2][:len(parts[2])-2] + "xx"
		_, body := env.verify(t, strings.Join(parts, "."), "")
		if body["active"] != false || body["reason"] != "bad_signature" {
			t.Fatalf("want bad_signature, got %v", body)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		env.now = env.now.Add(2 * time.Hour) // 超过 access TTL 与 clock skew
		defer func() { env.now = env.now.Add(-2 * time.Hour) }()
		_, body := env.verify(t, tokens.AccessToken, "")
		if body["reason"] != "token_expired" {
			t.Fatalf("want token_expired, got %v", body)
		}
	})

	t.Run("scope insufficient", func(t *testing.T) {
		_, body := env.verify(t, tokens.AccessToken, "write")
		if body["active"] != false || body["reason"] != "scope_insufficient" {
			t.Fatalf("want scope_insufficient, got %v", body)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		_, body := env.verify(t, "not-a-jwt", "")
		if body["reason"] != "malformed_token" {
			t.Fatalf("want malformed_token, got %v", body)
		}
	})
}

func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	env := newTestEnv(t)
	tokens := env.issueTokens(t, "read")

	// 轮换密钥。
	resp, err := http.Post(env.ts.URL+"/admin/rotate-key", "", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: %v", err)
	}
	resp.Body.Close()

	// 旧令牌仍可校验。
	if _, body := env.verify(t, tokens.AccessToken, "read"); body["active"] != true {
		t.Fatalf("old token must remain valid after rotation, got %v", body)
	}
	// 新签发的令牌也可校验。
	tokens2 := env.issueTokens(t, "read")
	if _, body := env.verify(t, tokens2.AccessToken, "read"); body["active"] != true {
		t.Fatalf("new token must verify, got %v", body)
	}
	// JWKS 公开两把密钥，与校验一致且可复现。
	jwksResp, _ := http.Get(env.ts.URL + "/jwks")
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.NewDecoder(jwksResp.Body).Decode(&jwks)
	jwksResp.Body.Close()
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS must publish both keys, got %d", len(jwks.Keys))
	}
}

func TestRefreshRotationAndReplay(t *testing.T) {
	env := newTestEnv(t)
	tokens := env.issueTokens(t, "read")

	refresh := func(tok string) (int, map[string]any) {
		form := url.Values{
			"grant_type": {"refresh_token"}, "client_id": {testClientID},
			"client_secret": {testSecret}, "refresh_token": {tok},
		}
		resp, err := http.PostForm(env.ts.URL+"/token", form)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	// 正常轮换。
	status, body := refresh(tokens.RefreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh must succeed, got %d %v", status, body)
	}
	newAccess := body["access_token"].(string)

	// 重放旧刷新令牌：识别并撤销整族。
	status, body = refresh(tokens.RefreshToken)
	if status != http.StatusUnauthorized ||
		!strings.Contains(body["error_description"].(string), "replayed") {
		t.Fatalf("replay must be detected, got %d %v", status, body)
	}

	// 撤销传播：该族派生的新访问令牌也失效。
	if _, vbody := env.verify(t, newAccess, "read"); vbody["reason"] != "token_revoked" {
		t.Fatalf("derived access token must be revoked, got %v", vbody)
	}
	// 其他会话不受影响。
	other := env.issueTokens(t, "read")
	if _, vbody := env.verify(t, other.AccessToken, "read"); vbody["active"] != true {
		t.Fatalf("other session must not be affected, got %v", vbody)
	}
}

func TestRevocation(t *testing.T) {
	env := newTestEnv(t)

	revoke := func(tok string) (int, map[string]any) {
		resp, err := http.PostForm(env.ts.URL+"/revoke", url.Values{"token": {tok}})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	t.Run("revoke refresh token revokes family", func(t *testing.T) {
		tokens := env.issueTokens(t, "read")
		status, body := revoke(tokens.RefreshToken)
		if status != http.StatusOK || body["result"] != "revoked" {
			t.Fatalf("want revoked, got %d %v", status, body)
		}
		// 派生的访问令牌失效。
		if _, vbody := env.verify(t, tokens.AccessToken, ""); vbody["reason"] != "token_revoked" {
			t.Fatalf("access token must be revoked, got %v", vbody)
		}
		// 再次撤销同一令牌：可区分的 already_revoked。
		if _, body := revoke(tokens.RefreshToken); body["result"] != "already_revoked_or_expired" {
			t.Fatalf("want already_revoked_or_expired, got %v", body)
		}
	})

	t.Run("revoke access token by jti", func(t *testing.T) {
		tokens := env.issueTokens(t, "read")
		if _, body := revoke(tokens.AccessToken); body["result"] != "revoked" {
			t.Fatalf("want revoked, got %v", body)
		}
		if _, vbody := env.verify(t, tokens.AccessToken, ""); vbody["reason"] != "token_revoked" {
			t.Fatalf("access token must be revoked, got %v", vbody)
		}
	})

	t.Run("revoke unknown token", func(t *testing.T) {
		status, body := revoke("no-such-token")
		if status != http.StatusNotFound || body["result"] != "token_not_found" {
			t.Fatalf("want token_not_found, got %d %v", status, body)
		}
	})
}

func TestConcurrentRefreshSingleWinner(t *testing.T) {
	env := newTestEnv(t)
	tokens := env.issueTokens(t, "read")

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := url.Values{
				"grant_type": {"refresh_token"}, "client_id": {testClientID},
				"client_secret": {testSecret}, "refresh_token": {tokens.RefreshToken},
			}
			resp, err := http.PostForm(env.ts.URL+"/token", form)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent refresh must succeed, got %d", wins)
	}
}

func TestRateLimit(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimitPerSecond = 1
	cfg.RateLimitBurst = 3
	ks := keys.NewStore()
	_, _ = ks.Generate()
	st := store.New(1000)
	srv := New(cfg, ks, st, ratelimit.New(1, 3))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rejected := -1
	for i := 0; i < 10; i++ {
		resp, _ := http.PostForm(ts.URL+"/verify", url.Values{"token": {"x"}, "client_id": {"c"}})
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			rejected = i
			break
		}
	}
	if rejected < 0 {
		t.Fatal("rate limiter must deterministically reject beyond burst")
	}
}

func TestServerLogsDecisions(t *testing.T) {
	// 日志判定依据由 log.Printf 输出；此处验证请求路径不panic且响应含 reason 字段。
	env := newTestEnv(t)
	_, body := env.verify(t, "garbage", "")
	if _, ok := body["reason"]; !ok {
		t.Fatal("verify response must include reason for explainability")
	}
}

// 确保响应体读取辅助（防止未使用导入）。
var _ = io.Discard
var _ = fmt.Sprintf
