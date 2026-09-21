// Package store 提供授权码、刷新令牌与撤销状态的并发安全存储。
package store

import (
	"errors"
	"sync"
	"time"
)

// Client 是注册的客户端应用。
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Scopes       []string
}

// AuthCode 表示一次性授权码。
type AuthCode struct {
	Code                string
	ClientID            string
	Subject             string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
}

// RefreshToken 表示可轮换的刷新令牌。
type RefreshToken struct {
	Token      string
	ClientID   string
	Subject    string
	Scope      string
	Family     string // 同一会话的令牌族，重放时整族撤销
	ExpiresAt  time.Time
	Revoked    bool
	ReplacedBy string // 轮换后的新令牌，非空表示已被使用
}

// CodeConsumeResult 区分授权码消费结果。
type CodeConsumeResult string

const (
	CodeOK          CodeConsumeResult = "ok"
	CodeNotFound    CodeConsumeResult = "code_not_found"
	CodeExpired     CodeConsumeResult = "code_expired"
	CodeAlreadyUsed CodeConsumeResult = "code_already_used"
)

// RefreshConsumeResult 区分刷新令牌消费结果。
type RefreshConsumeResult string

const (
	RefreshOK            RefreshConsumeResult = "ok"
	RefreshNotFound      RefreshConsumeResult = "refresh_token_not_found"
	RefreshExpired       RefreshConsumeResult = "refresh_token_expired"
	RefreshReplayed      RefreshConsumeResult = "refresh_token_replayed" // 重放：已撤销整族
	RefreshFamilyRevoked RefreshConsumeResult = "family_revoked"
)

// RevokeResult 区分撤销操作结果。
type RevokeResult string

const (
	RevokeOK          RevokeResult = "revoked"
	RevokeNotFound    RevokeResult = "token_not_found"
	RevokeAlreadyDone RevokeResult = "already_revoked_or_expired"
)

var ErrStoreFull = errors.New("store capacity reached")

// Store 是并发安全的内存存储；所有状态变更在单把互斥锁内原子完成。
type Store struct {
	mu              sync.Mutex
	maxEntries      int
	clients         map[string]Client
	codes           map[string]*AuthCode
	refreshTokens   map[string]*RefreshToken
	revokedJTIs     map[string]time.Time // 被撤销的访问令牌 jti -> 过期时间（到期可清理）
	revokedFamilies map[string]bool
}

// New 创建存储，maxEntries 限制授权码与刷新令牌的总量，防止资源无界增长。
func New(maxEntries int) *Store {
	return &Store{
		maxEntries:      maxEntries,
		clients:         make(map[string]Client),
		codes:           make(map[string]*AuthCode),
		refreshTokens:   make(map[string]*RefreshToken),
		revokedJTIs:     make(map[string]time.Time),
		revokedFamilies: make(map[string]bool),
	}
}

// RegisterClient 注册客户端。
func (s *Store) RegisterClient(c Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

// GetClient 查询客户端。
func (s *Store) GetClient(id string) (Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return c, ok
}

// evictExpiredLocked 清理已过期的授权码与刷新令牌，控制资源占用。
// 调用时必须已持有锁。
func (s *Store) evictExpiredLocked(now time.Time) {
	for k, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, k)
		}
	}
	for k, t := range s.refreshTokens {
		if now.After(t.ExpiresAt) {
			delete(s.refreshTokens, k)
		}
	}
	for jti, exp := range s.revokedJTIs {
		if now.After(exp) {
			delete(s.revokedJTIs, jti)
		}
	}
}

// SaveAuthCode 保存授权码；容量满且无法清理时返回 ErrStoreFull。
func (s *Store) SaveAuthCode(c *AuthCode, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	if len(s.codes)+len(s.refreshTokens) >= s.maxEntries {
		return ErrStoreFull
	}
	s.codes[c.Code] = c
	return nil
}

// ConsumeAuthCode 原子地校验并消费授权码（一次性使用）。
// 无论成功与否，每个授权码至多被成功消费一次。
func (s *Store) ConsumeAuthCode(code string, now time.Time) (*AuthCode, CodeConsumeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, CodeNotFound
	}
	if c.Used {
		return nil, CodeAlreadyUsed
	}
	if now.After(c.ExpiresAt) {
		return nil, CodeExpired
	}
	c.Used = true
	return c, CodeOK
}

// SaveRefreshToken 保存刷新令牌。
func (s *Store) SaveRefreshToken(t *RefreshToken, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	if len(s.codes)+len(s.refreshTokens) >= s.maxEntries {
		return ErrStoreFull
	}
	s.refreshTokens[t.Token] = t
	return nil
}

// ConsumeRefreshToken 原子地校验刷新令牌并将其标记为已轮换。
// 若令牌已被轮换过（重放），则撤销其整个令牌族并返回 RefreshReplayed。
// 成功时返回旧令牌（其 ReplacedBy 已被设置为 newToken）。
func (s *Store) ConsumeRefreshToken(tok, newToken string, now time.Time) (*RefreshToken, RefreshConsumeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refreshTokens[tok]
	if !ok {
		return nil, RefreshNotFound
	}
	if s.revokedFamilies[t.Family] {
		return nil, RefreshFamilyRevoked
	}
	if t.Revoked || t.ReplacedBy != "" {
		// 重放检测：旧令牌被再次使用，撤销整族授权。
		s.revokedFamilies[t.Family] = true
		return nil, RefreshReplayed
	}
	if now.After(t.ExpiresAt) {
		return nil, RefreshExpired
	}
	t.ReplacedBy = newToken
	return t, RefreshOK
}

// IsFamilyRevoked 判断令牌族是否已因重放或撤销而失效。
func (s *Store) IsFamilyRevoked(family string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokedFamilies[family]
}

// RevokeRefreshToken 撤销刷新令牌及其令牌族（派生令牌一并失效）。
func (s *Store) RevokeRefreshToken(tok string, now time.Time) RevokeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refreshTokens[tok]
	if !ok {
		return RevokeNotFound
	}
	if t.Revoked || s.revokedFamilies[t.Family] {
		return RevokeAlreadyDone
	}
	if now.After(t.ExpiresAt) {
		return RevokeAlreadyDone
	}
	t.Revoked = true
	s.revokedFamilies[t.Family] = true
	return RevokeOK
}

// RefreshTokenFamily 返回刷新令牌所属族，供撤销访问令牌时联动。
func (s *Store) RefreshTokenFamily(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refreshTokens[tok]
	if !ok {
		return "", false
	}
	return t.Family, true
}

// RevokeAccessToken 按 jti 撤销访问令牌，记录到其过期时间为止。
func (s *Store) RevokeAccessToken(jti string, expiresAt time.Time) RevokeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if jti == "" {
		return RevokeNotFound
	}
	if _, ok := s.revokedJTIs[jti]; ok {
		return RevokeAlreadyDone
	}
	s.revokedJTIs[jti] = expiresAt
	return RevokeOK
}

// IsAccessTokenRevoked 判断访问令牌是否已被撤销。
func (s *Store) IsAccessTokenRevoked(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revokedJTIs[jti]
	return ok
}
