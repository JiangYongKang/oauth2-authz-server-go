// Package server 实现授权服务器的 HTTP 端点。
//
// 端点：
//
//	GET  /authorize   授权码签发（强制 PKCE S256）
//	POST /token       授权码换令牌 / 刷新令牌轮换
//	GET  /userinfo    受保护资源（校验签名、有效期、签发方、撤销与范围）
//	POST /revoke      撤销访问或刷新令牌，结论可区分
//	GET  /jwks.json   当前可用于校验的公钥集合
//	POST /rotate      触发签名密钥轮换（本地管理接口）
//
// 所有拒绝均携带可区分的错误码，且写入判定日志。
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/store"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/token"
)

// Server 聚合各依赖并暴露 HTTP 路由。
type Server struct {
	cfg   config.Config
	keys  *keys.Manager
	store *store.Store
	mux   *http.ServeMux
	users map[string]string
	now   func() time.Time

	rlMu      sync.Mutex
	rlBuckets map[string]*bucket
}

// New 构建服务器并注册路由。users 为本地演示账号（用户名->密码）。
func New(cfg config.Config, km *keys.Manager, st *store.Store, users map[string]string) *Server {
	s := &Server{
		cfg:       cfg,
		keys:      km,
		store:     st,
		mux:       http.NewServeMux(),
		users:     users,
		now:       time.Now,
		rlBuckets: make(map[string]*bucket),
	}
	s.mux.HandleFunc("/authorize", s.handleAuthorize)
	s.mux.HandleFunc("/token", s.handleToken)
	s.mux.HandleFunc("/userinfo", s.handleUserinfo)
	s.mux.HandleFunc("/revoke", s.handleRevoke)
	s.mux.HandleFunc("/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("/rotate", s.handleRotate)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s
}

// SetClock 注入时钟（测试用）。
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Handler 返回根 HTTP 处理器（含限流中间件）。
func (s *Server) Handler() http.Handler {
	return s.rateLimit(s.mux)
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthError 返回可区分的错误码并记录判定日志。
func oauthError(w http.ResponseWriter, r *http.Request, status int, code, desc string) {
	log.Printf("decision=deny endpoint=%s error=%s detail=%q", r.URL.Path, code, desc)
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// clientAuth 校验客户端身份：优先 Basic，其次表单字段。
// 公共客户端（无密钥）必须提供 client_id 且不得提供错误密钥。
func (s *Server) clientAuth(r *http.Request) (store.Client, error) {
	id, secret, _ := r.BasicAuth()
	if id == "" {
		id = r.FormValue("client_id")
		secret = r.FormValue("client_secret")
	}
	if id == "" {
		return store.Client{}, errors.New("missing client authentication")
	}
	c, err := s.store.GetClient(id)
	if err != nil {
		return store.Client{}, errors.New("unknown client")
	}
	if c.Secret != "" {
		if subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
			return store.Client{}, errors.New("invalid client secret")
		}
	}
	return c, nil
}

// issueTokens 签发访问令牌与全新的刷新令牌（授权码首次换令牌用），
// 并记录 jti 以支持会话级失效传播。
func (s *Server) issueTokens(clientID, userID, scope, family string) (map[string]any, error) {
	now := s.now()
	refresh, err := randString(32)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateRefreshToken(&store.RefreshToken{
		Token:     refresh,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Family:    family,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	}); err != nil {
		return nil, err
	}
	access, err := s.signAccessToken(clientID, userID, scope, family, now)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.AccessTokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         scope,
	}, nil
}

// rotateTokens 原子地完成刷新轮换：旧刷新令牌的消费与后继刷新令牌的入存
// 在存储层单个临界区内完成，并发的会话级撤销无法插入其间。
// 成功后再签发并登记访问令牌；即使签发/登记与撤销交错，撤销族标记仍是
// 访问令牌校验的最终依据，不会产生撤销后仍有效的后继令牌。
func (s *Server) rotateTokens(clientID, oldToken string) (map[string]any, *store.RefreshToken, error) {
	now := s.now()
	refresh, err := randString(32)
	if err != nil {
		return nil, nil, err
	}
	old, err := s.store.RotateAtomic(clientID, oldToken, &store.RefreshToken{
		Token:     refresh,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	})
	if err != nil {
		return nil, nil, err
	}
	access, err := s.signAccessToken(old.ClientID, old.UserID, old.Scope, old.Family, now)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.AccessTokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         old.Scope,
	}, old, nil
}

// signAccessToken 签发访问 JWT 并把 jti 登记到其会话（令牌族）。
func (s *Server) signAccessToken(clientID, userID, scope, family string, now time.Time) (string, error) {
	jti, err := randString(16)
	if err != nil {
		return "", err
	}
	kid, priv := s.keys.SigningKey()
	claims := token.Claims{
		Issuer:   s.cfg.Issuer,
		Subject:  userID,
		ClientID: clientID,
		Scope:    scope,
		ID:       jti,
		IssuedAt: now.Unix(),
		Expires:  now.Add(s.cfg.AccessTokenTTL).Unix(),
	}
	access, err := token.NewSigner(kid, priv).Sign(claims)
	if err != nil {
		return "", err
	}
	s.store.RecordAccessToken(family, jti, now.Add(s.cfg.AccessTokenTTL))
	return access, nil
}

// ---------- /authorize ----------

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		oauthError(w, r, http.StatusMethodNotAllowed, "invalid_request", "GET required")
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")

	client, err := s.store.GetClient(clientID)
	if err != nil {
		oauthError(w, r, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	// 重定向地址必须精确匹配，否则不得重定向（防止开放重定向）。
	if !client.AllowsRedirectURI(redirectURI) {
		oauthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri not registered")
		return
	}
	// 此后的错误可安全地重定向回客户端。
	deny := func(code, desc string) {
		log.Printf("decision=deny endpoint=/authorize error=%s detail=%q", code, desc)
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		loc := fmt.Sprintf("%s%serror=%s&error_description=%s", redirectURI, sep, code, url.QueryEscape(desc))
		if state != "" {
			loc += "&state=" + url.QueryEscape(state)
		}
		http.Redirect(w, r, loc, http.StatusFound)
	}

	if q.Get("response_type") != "code" {
		deny("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" {
		deny("invalid_request:pkce_required", "code_challenge is required")
		return
	}
	if method != "S256" {
		deny("invalid_request:unsupported_pkce_method", "only S256 code_challenge_method is supported")
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		deny("invalid_scope:empty", "scope is required")
		return
	}
	if !client.AllowsScope(strings.Fields(scope)) {
		deny("invalid_scope:not_allowed", "requested scope exceeds client allowance")
		return
	}
	user, pass := q.Get("user"), q.Get("password")
	if pw, ok := s.users[user]; !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(pass)) != 1 {
		deny("access_denied:invalid_credentials", "user authentication failed")
		return
	}
	code, err := randString(32)
	if err != nil {
		oauthError(w, r, http.StatusInternalServerError, "server_error", "code generation failed")
		return
	}
	ac := &store.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              user,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           s.now().Add(s.cfg.AuthCodeTTL),
	}
	if err := s.store.CreateAuthCode(ac); err != nil {
		oauthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable:capacity", "authorization code store full")
		return
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	loc := fmt.Sprintf("%s%scode=%s", redirectURI, sep, code)
	if state != "" {
		loc += "&state=" + url.QueryEscape(state)
	}
	log.Printf("decision=allow endpoint=/authorize client=%s user=%s scope=%q", clientID, user, scope)
	http.Redirect(w, r, loc, http.StatusFound)
}

// ---------- /token ----------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, r, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, r, http.StatusBadRequest, "invalid_request", "bad form encoding")
		return
	}
	client, err := s.clientAuth(r)
	if err != nil {
		oauthError(w, r, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.grantAuthCode(w, r, client)
	case "refresh_token":
		s.grantRefresh(w, r, client)
	default:
		oauthError(w, r, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

func (s *Server) grantAuthCode(w http.ResponseWriter, r *http.Request, client store.Client) {
	code := r.FormValue("code")
	if code == "" {
		oauthError(w, r, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	ac, err := s.store.ConsumeAuthCode(code)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCodeNotFound):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:code_unknown", "authorization code not found or already consumed")
		case errors.Is(err, store.ErrCodeExpired):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:code_expired", "authorization code expired")
		default:
			oauthError(w, r, http.StatusBadRequest, "invalid_grant", err.Error())
		}
		return
	}
	if ac.ClientID != client.ID {
		oauthError(w, r, http.StatusBadRequest, "invalid_grant:client_mismatch", "code was issued to a different client")
		return
	}
	if r.FormValue("redirect_uri") != ac.RedirectURI {
		oauthError(w, r, http.StatusBadRequest, "invalid_grant:redirect_uri_mismatch", "redirect_uri does not match the authorization request")
		return
	}
	verifier := r.FormValue("code_verifier")
	if verifier == "" {
		oauthError(w, r, http.StatusBadRequest, "invalid_grant:pkce_verifier_missing", "code_verifier is required")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.CodeChallenge)) != 1 {
		oauthError(w, r, http.StatusBadRequest, "invalid_grant:pkce_verification_failed", "code_verifier does not match code_challenge")
		return
	}
	family, err := randString(16)
	if err != nil {
		oauthError(w, r, http.StatusInternalServerError, "server_error", "family id generation failed")
		return
	}
	tokens, err := s.issueTokens(client.ID, ac.UserID, ac.Scope, family)
	if err != nil {
		oauthError(w, r, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	log.Printf("decision=allow endpoint=/token grant=authorization_code client=%s user=%s scope=%q", client.ID, ac.UserID, ac.Scope)
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request, client store.Client) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		oauthError(w, r, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	tokens, old, err := s.rotateTokens(client.ID, rt)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrRefreshNotFound):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:refresh_unknown", "refresh token not found")
		case errors.Is(err, store.ErrRefreshExpired):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:refresh_expired", "refresh token expired")
		case errors.Is(err, store.ErrRefreshRevoked):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:refresh_revoked", "refresh token revoked; session terminated")
		case errors.Is(err, store.ErrRefreshClientMismatch):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:client_mismatch", "refresh token was issued to a different client")
		case errors.Is(err, store.ErrRefreshReused):
			oauthError(w, r, http.StatusBadRequest, "invalid_grant:refresh_reuse_detected", "refresh token reuse detected; session revoked")
		case errors.Is(err, store.ErrStoreFull):
			oauthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable:capacity", "refresh token store full")
		default:
			oauthError(w, r, http.StatusBadRequest, "invalid_grant", err.Error())
		}
		return
	}
	log.Printf("decision=allow endpoint=/token grant=refresh_token client=%s user=%s family=%s rotated", old.ClientID, old.UserID, old.Family)
	writeJSON(w, http.StatusOK, tokens)
}

// ---------- /userinfo ----------

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token:missing"`)
		oauthError(w, r, http.StatusUnauthorized, "invalid_token:missing", "bearer token required")
		return
	}
	claims, err := token.Parse(strings.TrimPrefix(auth, "Bearer "), s.keys.VerifyKey, s.cfg.Issuer, s.cfg.ClockSkew, s.now())
	if err != nil {
		code := "invalid_token"
		switch {
		case errors.Is(err, token.ErrSignature):
			code = "invalid_token:signature"
		case errors.Is(err, token.ErrUnknownKey):
			code = "invalid_token:unknown_key"
		case errors.Is(err, token.ErrExpired):
			code = "invalid_token:expired"
		case errors.Is(err, token.ErrIssuer):
			code = "invalid_token:issuer"
		case errors.Is(err, token.ErrMalformed):
			code = "invalid_token:malformed"
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
		oauthError(w, r, http.StatusUnauthorized, code, err.Error())
		return
	}
	if s.store.IsAccessRevoked(claims.ID) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token:revoked"`)
		oauthError(w, r, http.StatusUnauthorized, "invalid_token:revoked", "token has been revoked")
		return
	}
	if !claims.HasScope("profile") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope" scope="profile"`)
		oauthError(w, r, http.StatusForbidden, "insufficient_scope", "scope 'profile' required")
		return
	}
	log.Printf("decision=allow endpoint=/userinfo sub=%s client=%s", claims.Subject, claims.ClientID)
	writeJSON(w, http.StatusOK, map[string]string{"sub": claims.Subject, "client_id": claims.ClientID, "scope": claims.Scope})
}

// ---------- /revoke ----------

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, r, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, r, http.StatusBadRequest, "invalid_request", "bad form encoding")
		return
	}
	tok := r.FormValue("token")
	if tok == "" {
		oauthError(w, r, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	// 先按刷新令牌处理：撤销刷新令牌即终止其所属的整个会话（授权链）。
	res, family := s.store.RevokeSession(tok)
	scope := "token"
	if res != store.RevokeNotFound {
		scope = "session"
	}
	if res == store.RevokeNotFound {
		// 再按访问令牌（JWT）处理：需验签以防伪造 jti 注入。
		claims, err := token.Parse(tok, s.keys.VerifyKey, s.cfg.Issuer, s.cfg.ClockSkew, s.now())
		switch {
		case err == nil:
			var rerr error
			res, rerr = s.store.RevokeAccessToken(claims.ID, time.Unix(claims.Expires, 0))
			if rerr != nil {
				// 容量不足：失败关闭，不静默放行，不淘汰仍有效的撤销记录。
				oauthError(w, r, http.StatusServiceUnavailable, "temporarily_unavailable:revocation_capacity", "revocation store full; try again later")
				return
			}
		case errors.Is(err, token.ErrExpired):
			res = store.RevokeAlreadyInvalid
		default:
			res = store.RevokeNotFound
		}
	}
	log.Printf("decision=revoke endpoint=/revoke scope=%s family=%s result=%s", scope, family, res)
	writeJSON(w, http.StatusOK, map[string]string{"result": res.String()})
}

// ---------- /jwks.json 与 /rotate ----------

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": s.keys.JWKS()})
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, r, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	kid, err := s.keys.Rotate()
	if err != nil {
		oauthError(w, r, http.StatusInternalServerError, "server_error", "rotation failed")
		return
	}
	log.Printf("decision=rotate endpoint=/rotate new_kid=%s", kid)
	writeJSON(w, http.StatusOK, map[string]string{"active_kid": kid})
}

// ---------- 限流 ----------

// bucket 是每分钟重置的固定窗口计数器。
type bucket struct {
	windowStart time.Time
	count       int
}

// rateLimit 按客户端（Basic/表单 client_id，否则来源 IP）限流，超限返回 429。
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			key = host
		}
		if id, _, ok := r.BasicAuth(); ok && id != "" {
			key = "client:" + id
		} else if id := r.URL.Query().Get("client_id"); id != "" {
			key = "client:" + id
		} else if id := r.FormValue("client_id"); id != "" {
			key = "client:" + id
		}
		if !s.allow(key) {
			log.Printf("decision=deny endpoint=%s error=rate_limited key=%s", r.URL.Path, key)
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error":             "rate_limited",
				"error_description": "request rate exceeds configured limit",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allow(key string) bool {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	now := s.now()
	b, ok := s.rlBuckets[key]
	if !ok || now.Sub(b.windowStart) >= time.Minute {
		b = &bucket{windowStart: now}
		s.rlBuckets[key] = b
		// 防止 bucket 表无界增长：顺带清理过期窗口。
		if len(s.rlBuckets) > 10000 {
			for k, v := range s.rlBuckets {
				if now.Sub(v.windowStart) >= time.Minute {
					delete(s.rlBuckets, k)
				}
			}
		}
	}
	b.count++
	return b.count <= s.cfg.RateLimitPerMin
}
