// Package store 提供并发安全的内存存储：客户端、授权码、刷新令牌与撤销记录。
//
// 一致性语义：
//   - 授权码消费（ConsumeAuthCode）是原子的：同一授权码只会成功一次，
//     重复消费返回 ErrCodeUsed，过期返回 ErrCodeExpired；
//   - 刷新令牌轮换（RotateRefreshToken）是原子的：旧令牌被标记为已用后
//     才允许签发新令牌；已使用的旧令牌再次被出示时判定为重放，
//     撤销其所属令牌族（family）的全部刷新令牌与派生访问令牌；
//   - 所有映射的容量受配置上限约束，过期条目会被定期清理，
//     资源占用不会无界增长。
package store

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// 可区分的失败原因。
var (
	ErrClientNotFound  = errors.New("client not found")
	ErrStoreFull       = errors.New("store capacity reached")
	ErrCodeNotFound    = errors.New("authorization code not found")
	ErrCodeUsed        = errors.New("authorization code already used")
	ErrCodeExpired     = errors.New("authorization code expired")
	ErrRefreshNotFound = errors.New("refresh token not found")
	ErrRefreshExpired  = errors.New("refresh token expired")
	ErrRefreshRevoked  = errors.New("refresh token revoked")
	ErrRefreshReused   = errors.New("refresh token reuse detected; token family revoked")
)

// Client 描述一个已注册的客户端。
type Client struct {
	ID           string
	Secret       string // 空串表示公共客户端（仅 PKCE）
	RedirectURIs []string
	Scopes       []string
}

// AllowsScope 报告请求的每个范围是否都在客户端允许范围内。
func (c Client) AllowsScope(scopes []string) bool {
	allowed := map[string]bool{}
	for _, s := range c.Scopes {
		allowed[s] = true
	}
	for _, s := range scopes {
		if !allowed[s] {
			return false
		}
	}
	return true
}

// AllowsRedirectURI 报告重定向地址是否与注册地址精确匹配。
func (c Client) AllowsRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AuthCode 记录一次授权码签发的上下文。
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// RefreshToken 记录刷新令牌状态。
type RefreshToken struct {
	Token     string // 不透明随机串，同时作为存储键
	ClientID  string
	UserID    string
	Scope     string
	Family    string // 同一次授权派生出的刷新令牌链共享的族标识
	ExpiresAt time.Time
	Used      bool // 已被轮换消费
	Revoked   bool // 被显式撤销或因重放被族撤销
}

// RevokeResult 区分撤销操作的结论。
type RevokeResult int

const (
	RevokeOK             RevokeResult = iota // 撤销成功
	RevokeNotFound                           // 令牌不存在
	RevokeAlreadyInvalid                     // 令牌已失效（已用/已撤销/已过期）
)

func (r RevokeResult) String() string {
	switch r {
	case RevokeOK:
		return "revoked"
	case RevokeNotFound:
		return "not_found"
	default:
		return "already_invalid"
	}
}

// accessRec 记录族派生的访问令牌及其过期时刻。
type accessRec struct {
	jti string
	exp time.Time
}

// Store 是并发安全的内存数据存储。
type Store struct {
	mu           sync.Mutex
	now          func() time.Time
	clients      map[string]Client
	codes        map[string]*AuthCode
	refresh      map[string]*RefreshToken
	revokedJTIs  map[string]time.Time   // 访问令牌 jti -> 其过期时刻
	accessByFami map[string][]accessRec // family -> 派生的访问令牌
	maxCodes     int
	maxRefresh   int
	maxRevoked   int
}

// New 创建空存储，容量由上限参数约束。
func New(maxCodes, maxRefresh, maxRevoked int) *Store {
	return &Store{
		now:          time.Now,
		clients:      make(map[string]Client),
		codes:        make(map[string]*AuthCode),
		refresh:      make(map[string]*RefreshToken),
		revokedJTIs:  make(map[string]time.Time),
		accessByFami: make(map[string][]accessRec),
		maxCodes:     maxCodes,
		maxRefresh:   maxRefresh,
		maxRevoked:   maxRevoked,
	}
}

// SetClock 注入时钟（测试用）。
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// AddClient 注册（或覆盖）一个客户端。
func (s *Store) AddClient(c Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

// GetClient 查找客户端。
func (s *Store) GetClient(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}

// CreateAuthCode 保存授权码；超出容量时先清理过期码，仍满则返回 ErrStoreFull。
func (s *Store) CreateAuthCode(c *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepCodesLocked(s.now())
	if len(s.codes) >= s.maxCodes {
		return ErrStoreFull
	}
	s.codes[c.Code] = c
	return nil
}

// ConsumeAuthCode 原子地取出并作废授权码。每个码最多成功消费一次。
func (s *Store) ConsumeAuthCode(code string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	delete(s.codes, code) // 无论成功与否，码一经出示即作废，防止竞争下重复使用
	if s.now().After(c.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	return c, nil
}

// CreateRefreshToken 保存刷新令牌。
func (s *Store) CreateRefreshToken(t *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepRefreshLocked(s.now())
	if len(s.refresh) >= s.maxRefresh {
		return ErrStoreFull
	}
	s.refresh[t.Token] = t
	return nil
}

// RotateRefreshToken 原子地消费旧刷新令牌并返回其记录，
// 调用方随后用 CreateRefreshToken 存入新令牌（同一 Family）。
// 若旧令牌已被使用，则判定重放并撤销整个令牌族。
func (s *Store) RotateRefreshToken(token string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return nil, ErrRefreshNotFound
	}
	if t.Used {
		s.revokeFamilyLocked(t.Family)
		return nil, ErrRefreshReused
	}
	if t.Revoked {
		return nil, ErrRefreshRevoked
	}
	if s.now().After(t.ExpiresAt) {
		return nil, ErrRefreshExpired
	}
	t.Used = true
	cp := *t
	return &cp, nil
}

// RevokeRefreshToken 撤销指定刷新令牌，结论可区分。
func (s *Store) RevokeRefreshToken(token string) RevokeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return RevokeNotFound
	}
	if t.Revoked || t.Used || s.now().After(t.ExpiresAt) {
		return RevokeAlreadyInvalid
	}
	t.Revoked = true
	return RevokeOK
}

// RevokeFamily 撤销指定令牌族的全部刷新令牌与派生访问令牌。
func (s *Store) RevokeFamily(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family)
}

func (s *Store) revokeFamilyLocked(family string) {
	for _, t := range s.refresh {
		if t.Family == family {
			t.Revoked = true
		}
	}
	for _, rec := range s.accessByFami[family] {
		if _, ok := s.revokedJTIs[rec.jti]; !ok {
			s.revokedJTIs[rec.jti] = rec.exp
		}
	}
}

// RecordAccessToken 记录某族签发的访问令牌 jti 及其过期时刻，用于失效传播。
func (s *Store) RecordAccessToken(family, jti string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessByFami[family] = append(s.accessByFami[family], accessRec{jti: jti, exp: exp})
	// 若该族已被撤销，jti 应已在 revokedJTIs 中；此处不覆盖。
}

// RevokeAccessToken 撤销访问令牌（按 jti），结论可区分。
func (s *Store) RevokeAccessToken(jti string, exp time.Time) RevokeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().After(exp) {
		return RevokeAlreadyInvalid
	}
	if _, ok := s.revokedJTIs[jti]; ok {
		return RevokeAlreadyInvalid
	}
	s.sweepRevokedLocked(s.now())
	if len(s.revokedJTIs) >= s.maxRevoked {
		s.evictOldestRevokedLocked()
	}
	s.revokedJTIs[jti] = exp
	return RevokeOK
}

// IsAccessRevoked 报告访问令牌是否已被撤销。
func (s *Store) IsAccessRevoked(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revokedJTIs[jti]
	return ok
}

// RefreshTokenInfo 返回刷新令牌当前状态快照（用于测试与内省）。
func (s *Store) RefreshTokenInfo(token string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return RefreshToken{}, ErrRefreshNotFound
	}
	return *t, nil
}

// Sweep 清理过期条目，可由后台协程定期调用。
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepCodesLocked(now)
	s.sweepRefreshLocked(now)
	s.sweepRevokedLocked(now)
}

func (s *Store) sweepCodesLocked(now time.Time) {
	for k, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, k)
		}
	}
}

func (s *Store) sweepRefreshLocked(now time.Time) {
	for k, t := range s.refresh {
		if now.After(t.ExpiresAt) {
			delete(s.refresh, k)
		}
	}
}

func (s *Store) sweepRevokedLocked(now time.Time) {
	for k, exp := range s.revokedJTIs {
		if now.After(exp) {
			delete(s.revokedJTIs, k)
		}
	}
}

// evictOldestRevokedLocked 淘汰过期时刻最早的撤销记录，保证容量有界。
func (s *Store) evictOldestRevokedLocked() {
	type kv struct {
		jti string
		exp time.Time
	}
	all := make([]kv, 0, len(s.revokedJTIs))
	for jti, exp := range s.revokedJTIs {
		all = append(all, kv{jti, exp})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
	for i := 0; i < len(all)/2; i++ {
		delete(s.revokedJTIs, all[i].jti)
	}
}

// Stats 返回当前存储规模（用于监控与测试）。
func (s *Store) Stats() (codes, refresh, revoked int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes), len(s.refresh), len(s.revokedJTIs)
}
