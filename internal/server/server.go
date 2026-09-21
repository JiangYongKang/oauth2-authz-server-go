// Package server 实现授权服务器的 HTTP 端点。
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/ratelimit"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/store"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/token"
)

// Server 聚合各组件并暴露 HTTP 处理器。
type Server struct {
	cfg     config.Config
	keys    *keys.Store
	store   *store.Store
	limiter *ratelimit.Limiter
	now     func() time.Time // 可注入时钟，便于测试
}

// New 组装服务器。
func New(cfg config.Config, ks *keys.Store, st *store.Store, lim *ratelimit.Limiter) *Server {
	return &Server{cfg: cfg, keys: ks, store: st, limiter: lim, now: time.Now}
}

// SetClock 注入时钟（测试用）。
func (s *Server) SetClock(f func() time.Time) { s.now = f }

// Store 暴露底层存储（测试与管理端点用）。
func (s *Server) Store() *store.Store { return s.store }

// Keys 暴露密钥库。
func (s *Server) Keys() *keys.Store { return s.keys }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, errCode, desc string) {
	log.Printf("decision=deny error=%s reason=%s", errCode, desc)
	writeJSON(w, status, map[string]string{"error": errCode, "error_description": desc})
}

// Handler 返回路由后的 HTTP 处理器。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", s.withRateLimit(s.handleAuthorize))
	mux.HandleFunc("/token", s.withRateLimit(s.handleToken))
	mux.HandleFunc("/verify", s.withRateLimit(s.handleVerify))
	mux.HandleFunc("/revoke", s.withRateLimit(s.handleRevoke))
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/clients", s.handleRegisterClient)
	mux.HandleFunc("/admin/rotate-key", s.handleRotateKey)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// withRateLimit 按 client_id（缺省按远端地址）限流，超限确定性拒绝。
func (s *Server) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.FormValue("client_id")
		if key == "" {
			key = r.RemoteAddr
		}
		if !s.limiter.Allow(key) {
			log.Printf("decision=deny error=rate_limited key=%s path=%s", key, r.URL.Path)
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error":             "rate_limited",
				"error_description": "request rate exceeds configured limit",
			})
			return
		}
		next(w, r)
	}
}

// redirectURIAllowed 校验重定向地址是否与注册值精确匹配。
func redirectURIAllowed(c store.Client, uri string) bool {
	for _, u := range c.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(u), []byte(uri)) == 1 {
			return true
		}
	}
	return false
}

// scopeAllowed 校验请求范围是否为客户端注册范围的子集。
func scopeAllowed(c store.Client, scope string) bool {
	allowed := make(map[string]bool, len(c.Scopes))
	for _, sc := range c.Scopes {
		allowed[sc] = true
	}
	for _, req := range strings.Fields(scope) {
		if !allowed[req] {
			return false
		}
	}
	return true
}

// handleAuthorize 处理授权码请求（GET），强制 PKCE。
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")

	fail := func(status int, code, desc string) {
		log.Printf("decision=deny endpoint=authorize client=%s error=%s reason=%s", clientID, code, desc)
		writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
	}

	if q.Get("response_type") != "code" {
		fail(http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	client, ok := s.store.GetClient(clientID)
	if !ok {
		fail(http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if redirectURI == "" || !redirectURIAllowed(client, redirectURI) {
		// 重定向地址不可信时不得重定向，直接返回错误。
		fail(http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri does not match registered value")
		return
	}
	scope := q.Get("scope")
	if !scopeAllowed(client, scope) {
		fail(http.StatusBadRequest, "invalid_scope", "requested scope exceeds client registration")
		return
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" || method != "S256" {
		fail(http.StatusBadRequest, "invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	subject := q.Get("subject")
	if subject == "" {
		fail(http.StatusBadRequest, "invalid_request", "subject is required (local login stub)")
		return
	}
	code, err := token.NewID()
	if err != nil {
		fail(http.StatusInternalServerError, "server_error", "failed to generate code")
		return
	}
	ac := &store.AuthCode{
		Code:                code,
		ClientID:            clientID,
		Subject:             subject,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           s.now().Add(s.cfg.AuthCodeTTL),
	}
	if err := s.store.SaveAuthCode(ac, s.now()); err != nil {
		fail(http.StatusServiceUnavailable, "temporarily_unavailable", "authorization code store is full")
		return
	}
	log.Printf("decision=allow endpoint=authorize client=%s subject=%s scope=%q", clientID, subject, scope)
	target := redirectURI + "?code=" + code
	if state != "" {
		target += "&state=" + state
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// verifyPKCE 校验 code_verifier 与授权码绑定的 challenge 一致。
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// authenticateClient 校验客户端身份（client_id + client_secret）。
func (s *Server) authenticateClient(r *http.Request) (store.Client, bool) {
	id := r.FormValue("client_id")
	secret := r.FormValue("client_secret")
	c, ok := s.store.GetClient(id)
	if !ok {
		return store.Client{}, false
	}
	if subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		return store.Client{}, false
	}
	return c, true
}

// issueTokens 签发访问令牌与刷新令牌（同一令牌族）。
func (s *Server) issueTokens(clientID, subject, scope, family string) (map[string]any, error) {
	now := s.now()
	key, err := s.keys.Active()
	if err != nil {
		return nil, err
	}
	jti, err := token.NewID()
	if err != nil {
		return nil, err
	}
	claims := token.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		ClientID:  clientID,
		Scope:     scope,
		TokenID:   jti,
		Family:    family,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.cfg.AccessTokenTTL).Unix(),
	}
	accessToken, err := token.Sign(claims, key)
	if err != nil {
		return nil, err
	}
	refreshTok, err := token.NewID()
	if err != nil {
		return nil, err
	}
	rt := &store.RefreshToken{
		Token:     refreshTok,
		ClientID:  clientID,
		Subject:   subject,
		Scope:     scope,
		Family:    family,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	}
	if err := s.store.SaveRefreshToken(rt, now); err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.AccessTokenTTL.Seconds()),
		"refresh_token": refreshTok,
		"scope":         scope,
	}, nil
}

// handleToken 处理令牌请求：authorization_code 与 refresh_token 两种授权类型。
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, client)
	case "refresh_token":
		s.grantRefreshToken(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

// grantAuthorizationCode 用授权码换令牌：校验授权码归属、重定向地址与 PKCE。
func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, client store.Client) {
	code, res := s.store.ConsumeAuthCode(r.FormValue("code"), s.now())
	if res != store.CodeOK {
		// 授权码不存在、已使用或已过期，原因可区分。
		oauthError(w, http.StatusBadRequest, "invalid_grant", string(res))
		return
	}
	if code.ClientID != client.ID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was not issued to this client")
		return
	}
	if r.FormValue("redirect_uri") != code.RedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if !verifyPKCE(r.FormValue("code_verifier"), code.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier mismatch")
		return
	}
	family, err := token.NewID()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to allocate session")
		return
	}
	out, err := s.issueTokens(client.ID, code.Subject, code.Scope, family)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "token issuance failed")
		return
	}
	log.Printf("decision=allow endpoint=token grant=authorization_code client=%s subject=%s scope=%q",
		client.ID, code.Subject, code.Scope)
	writeJSON(w, http.StatusOK, out)
}

// grantRefreshToken 轮换刷新令牌；重放旧令牌将撤销整个令牌族。
func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, client store.Client) {
	presented := r.FormValue("refresh_token")
	if presented == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	newTok, err := token.NewID()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to generate token")
		return
	}
	old, res := s.store.ConsumeRefreshToken(presented, newTok, s.now())
	if res != store.RefreshOK {
		status := http.StatusBadRequest
		if res == store.RefreshReplayed || res == store.RefreshFamilyRevoked {
			status = http.StatusUnauthorized
		}
		oauthError(w, status, "invalid_grant", string(res))
		return
	}
	if old.ClientID != client.ID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was not issued to this client")
		return
	}
	out, err := s.issueTokens(client.ID, old.Subject, old.Scope, old.Family)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "token issuance failed")
		return
	}
	log.Printf("decision=allow endpoint=token grant=refresh_token client=%s subject=%s family=%s",
		client.ID, old.Subject, old.Family)
	writeJSON(w, http.StatusOK, out)
}

// handleVerify 本地校验访问令牌，可选 required_scope；结论与原因可区分。
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	tok := r.FormValue("token")
	requiredScope := r.FormValue("required_scope")
	claims, reason := token.Verify(tok, s.keys, s.cfg.Issuer, s.cfg.ClockSkew, s.now())
	if reason == token.ReasonOK {
		if s.store.IsAccessTokenRevoked(claims.TokenID) {
			reason = token.ReasonRevoked
		} else if claims.Family != "" && s.store.IsFamilyRevoked(claims.Family) {
			// 撤销传播：所属令牌族被撤销后，派生的访问令牌一并失效。
			reason = token.ReasonRevoked
		} else if !token.HasScope(claims.Scope, requiredScope) {
			reason = token.ReasonScopeInsufficient
		}
	}
	active := reason == token.ReasonOK
	log.Printf("decision=%s endpoint=verify jti=%s client=%s reason=%s required_scope=%q",
		map[bool]string{true: "allow", false: "deny"}[active], claims.TokenID, claims.ClientID, reason, requiredScope)
	resp := map[string]any{"active": active, "reason": string(reason)}
	if active {
		resp["claims"] = claims
	}
	status := http.StatusOK
	if !active {
		status = http.StatusUnauthorized
	}
	writeJSON(w, status, resp)
}

// handleRevoke 撤销令牌：刷新令牌撤销整族，访问令牌按 jti 撤销。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	tok := r.FormValue("token")
	if tok == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	var result store.RevokeResult
	if strings.Count(tok, ".") == 2 {
		// 访问令牌（JWT）：先校验签名，再按 jti 撤销。
		claims, reason := token.Verify(tok, s.keys, s.cfg.Issuer, s.cfg.ClockSkew, s.now())
		if reason == token.ReasonExpired {
			result = store.RevokeAlreadyDone
		} else if reason != token.ReasonOK {
			result = store.RevokeNotFound
		} else {
			result = s.store.RevokeAccessToken(claims.TokenID, time.Unix(claims.ExpiresAt, 0))
		}
	} else {
		result = s.store.RevokeRefreshToken(tok, s.now())
	}
	log.Printf("decision=done endpoint=revoke result=%s", result)
	status := http.StatusOK
	if result == store.RevokeNotFound {
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]string{"result": string(result)})
}

// handleJWKS 对外公开密钥信息，与实际校验使用的密钥一致。
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": s.keys.JWKS()})
}

// handleRegisterClient 注册客户端（本地运行用）。
func (s *Server) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	var req struct {
		ID           string   `json:"id"`
		Secret       string   `json:"secret"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Secret == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "id and secret are required")
		return
	}
	s.store.RegisterClient(store.Client{
		ID: req.ID, Secret: req.Secret, RedirectURIs: req.RedirectURIs, Scopes: req.Scopes,
	})
	log.Printf("decision=allow endpoint=clients client=%s scopes=%v", req.ID, req.Scopes)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered", "client_id": req.ID})
}

// handleRotateKey 轮换签名密钥：旧密钥保留用于校验，不再用于签发。
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	k, err := s.keys.Generate()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "key generation failed")
		return
	}
	log.Printf("decision=done endpoint=rotate-key new_kid=%s", k.ID)
	writeJSON(w, http.StatusOK, map[string]string{"active_kid": k.ID})
}
