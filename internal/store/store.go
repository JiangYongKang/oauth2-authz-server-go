// Package store 提供并发安全的内存存储：客户端、授权码、刷新令牌与撤销记录。
//
// 一致性语义：
//   - 授权码消费（ConsumeAuthCode）是原子的：同一授权码只会成功一次，
//     重复消费返回 ErrCodeNotFound，过期返回 ErrCodeExpired；
//   - 刷新令牌轮换（CommitRotation）是原子的：消费旧令牌、写入新刷新令牌、
//     登记新访问令牌 jti 在同一把锁内完成。并发刷新同一令牌恰好一个成功，
//     其余识别为重放并撤销其所属会话（family）；
//   - 会话级撤销（RevokeSession/RevokeRefreshToken）给整个 family 落墓碑：
//     已发出的访问令牌、轮换链路上的旧刷新令牌、之后任何后继刷新/访问令牌
//     全部失效；与并发刷新的胜负由同一把锁线性确定，不会“撤销与新令牌同时成功”；
//   - 墓碑 keepUntil 取会话内已知令牌最晚过期时刻，此前不会被清理，
//     撤销记录容量触顶时宁可返回 RevokeUnavailable 也不淘汰有效记录，
//     因而过期清理与容量限制都不会让仍有效的已撤销令牌复活；
//   - 撤销按 family 隔离，不影响其它用户/客户端/登录会话。
package store

import (
	"errors"
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
	RevokeUnavailable                        // 撤销记录容量已满且无过期项可回收
)

func (r RevokeResult) String() string {
	switch r {
	case RevokeOK:
		return "revoked"
	case RevokeNotFound:
		return "not_found"
	case RevokeUnavailable:
		return "unavailable"
	default:
		return "already_invalid"
	}
}

// accessRec 记录族派生的访问令牌及其过期时刻。
type accessRec struct {
	jti string
	exp time.Time
}

// familyTombstone 是会话（family）级撤销墓碑。
// 一旦落碑：该会话所有现存/将来的刷新令牌与访问令牌一律失效。
// KeepUntil 为该会话所有已知令牌过期时刻的最大值，墓碑可在此时刻后安全清理，
// 不会让仍有效的已撤销令牌重新生效。
type familyTombstone struct {
	at        time.Time // 撤销发生时刻（日志/可解释性）
	keepUntil time.Time // 最早可安全清理的时刻
}

// RevokeScope 区分一次撤销作用在单个令牌还是整个会话。
type RevokeScope string

const (
	ScopeToken   RevokeScope = "token"   // 单个访问令牌
	ScopeSession RevokeScope = "session" // 整个登录会话（family）
)

// Store 是并发安全的内存数据存储。
type Store struct {
	mu           sync.Mutex
	now          func() time.Time
	clients      map[string]Client
	codes        map[string]*AuthCode
	refresh      map[string]*RefreshToken
	revokedJTIs  map[string]time.Time       // 访问令牌 jti -> 其过期时刻
	accessByFami map[string][]accessRec     // family -> 派生的访问令牌
	revokedFami  map[string]familyTombstone // 会话级撤销墓碑（family -> 墓碑）
	jtiFamily    map[string]string          // 访问令牌 jti -> family（支持按 jti 杀会话）
	maxCodes     int
	maxRefresh   int
	maxRevoked   int
	maxFamilies  int
}

// RevokeDetail 描述一次撤销的可解释结论（供 HTTP 层打日志）。
type RevokeDetail struct {
	Result RevokeResult
	Scope  RevokeScope
	Family string // 命中会话时给出，否则为空
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
		revokedFami:  make(map[string]familyTombstone),
		jtiFamily:    make(map[string]string),
		maxCodes:     maxCodes,
		maxRefresh:   maxRefresh,
		maxRevoked:   maxRevoked,
		maxFamilies:  maxRevoked,
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
// 若其所属会话已被会话级撤销，则拒绝写入——这保证撤销与刷新并发时，
// 撤销落碑后不可能再生成“仍有效”的后继刷新令牌（不会让会话复活）。
func (s *Store) CreateRefreshToken(t *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, dead := s.revokedFami[t.Family]; dead {
		t.Revoked = true
		return ErrRefreshRevoked
	}
	s.sweepRefreshLocked(now)
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
		s.revokeFamilyLocked(t.Family, s.now())
		return nil, ErrRefreshReused
	}
	if t.Revoked {
		return nil, ErrRefreshRevoked
	}
	if _, dead := s.revokedFami[t.Family]; dead {
		t.Revoked = true
		return nil, ErrRefreshRevoked
	}
	if s.now().After(t.ExpiresAt) {
		return nil, ErrRefreshExpired
	}
	t.Used = true
	cp := *t
	return &cp, nil
}

// CommitRotation 原子地完成一次刷新轮换的全部状态变更：
// 校验旧令牌（未用/未撤销/未过期/会话存活、容量未满）→ 标记旧令牌已用 →
// 写入新刷新令牌 → 登记新访问令牌 jti。全部在单锁内完成，因此：
//
//   - 并发刷新同一令牌时恰好一个提交成功，其余识别为重放并撤销整个会话；
//   - 与会话级撤销并发时结论线性确定：先提交则撤销必然覆盖新令牌；
//     先撤销则提交必然被拒（ErrRefreshRevoked），不会出现“撤销与新令牌同时成功”。
//
// next 为已在锁外完成签名的新刷新令牌记录（Token/Family 等由调用方填好）；
// jti/accessExp 为同一响应中访问令牌的标识与过期时刻。返回旧令牌快照。
// 任一步失败都不改变状态（容量满时旧令牌仍可再次使用）。
func (s *Store) CommitRotation(oldToken string, next *RefreshToken, jti string, accessExp time.Time) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.refresh[oldToken]
	if !ok {
		return nil, ErrRefreshNotFound
	}
	if t.Used {
		s.revokeFamilyLocked(t.Family, now)
		return nil, ErrRefreshReused
	}
	if t.Revoked {
		return nil, ErrRefreshRevoked
	}
	if _, dead := s.revokedFami[t.Family]; dead {
		t.Revoked = true
		return nil, ErrRefreshRevoked
	}
	if now.After(t.ExpiresAt) {
		return nil, ErrRefreshExpired
	}
	s.sweepRefreshLocked(now)
	if len(s.refresh) >= s.maxRefresh {
		return nil, ErrStoreFull
	}
	t.Used = true
	s.refresh[next.Token] = next
	s.jtiFamily[jti] = t.Family
	s.accessByFami[t.Family] = append(s.accessByFami[t.Family], accessRec{jti: jti, exp: accessExp})
	cp := *t
	return &cp, nil
}

// RevokeRefreshToken 按当前刷新令牌撤销其所属的整个登录会话（family）。
//
// 会话级语义：用户出示当前（或轮换链路上任意一张仍在有效期内的）刷新令牌后，
// 该次授权链路上已发出的全部访问令牌、已被轮换掉的旧刷新令牌以及之后任何
// 派生的新刷新令牌都立即失效。结论可区分：
//
//   - RevokeOK：会话此前存活，本次确实完成撤销；
//   - RevokeNotFound：令牌不存在（非本服务签发或早已被清理）；
//   - RevokeAlreadyInvalid：会话此前已被撤销，或出示的令牌已过期。
//
// 幂等：对同一会话重复撤销只会得到一次 RevokeOK，之后恒为 RevokeAlreadyInvalid。
func (s *Store) RevokeRefreshToken(token string) RevokeResult {
	return s.RevokeSession(token).Result
}

// RevokeSession 执行会话级撤销并返回可解释的细节（结论、作用域、family）。
func (s *Store) RevokeSession(token string) RevokeDetail {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.refresh[token]
	if !ok {
		return RevokeDetail{Result: RevokeNotFound, Scope: ScopeSession}
	}
	if _, dead := s.revokedFami[t.Family]; dead {
		return RevokeDetail{Result: RevokeAlreadyInvalid, Scope: ScopeSession, Family: t.Family}
	}
	if now.After(t.ExpiresAt) {
		// 已过期：沿用既有语义，不改变会话存活状态。
		return RevokeDetail{Result: RevokeAlreadyInvalid, Scope: ScopeSession, Family: t.Family}
	}
	s.revokeFamilyLocked(t.Family, now)
	return RevokeDetail{Result: RevokeOK, Scope: ScopeSession, Family: t.Family}
}

// RevokeFamily 撤销指定令牌族的全部刷新令牌与派生访问令牌。
func (s *Store) RevokeFamily(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family, s.now())
}

// revokeFamilyLocked 在持锁状态下给一个会话落墓碑：
//   - 全部现存刷新令牌标记为 Revoked；
//   - 全部已记录的派生访问令牌 jti 进入撤销集合；
//   - 写入 family 墓碑，阻止任何后继刷新令牌/访问令牌生效（并发安全的关键）；
//   - keepUntil 取该会话所有已知令牌的最晚过期时刻，墓碑在该时刻前不会被清理，
//     因而容量清理不可能让仍有效的已撤销令牌重新生效。
//
// 幂等：墓碑已存在时不覆盖其原始撤销时刻与结论。
func (s *Store) revokeFamilyLocked(family string, now time.Time) {
	keepUntil := now
	for _, t := range s.refresh {
		if t.Family == family {
			t.Revoked = true
			if t.ExpiresAt.After(keepUntil) {
				keepUntil = t.ExpiresAt
			}
		}
	}
	for _, rec := range s.accessByFami[family] {
		if _, ok := s.revokedJTIs[rec.jti]; !ok {
			s.revokedJTIs[rec.jti] = rec.exp
		}
		if rec.exp.After(keepUntil) {
			keepUntil = rec.exp
		}
	}
	if _, exists := s.revokedFami[family]; !exists {
		s.revokedFami[family] = familyTombstone{at: now, keepUntil: keepUntil}
	}
}

// RecordAccessToken 记录某族签发的访问令牌 jti 及其过期时刻，用于失效传播。
// 若该会话已被撤销，jti 立即进入撤销集合（防止“撤销后签发”的令牌漏网）。
func (s *Store) RecordAccessToken(family, jti string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jtiFamily[jti] = family
	if tb, dead := s.revokedFami[family]; dead {
		if _, ok := s.revokedJTIs[jti]; !ok {
			s.revokedJTIs[jti] = exp
		}
		if exp.After(tb.keepUntil) {
			tb.keepUntil = exp
			s.revokedFami[family] = tb
		}
		return
	}
	s.accessByFami[family] = append(s.accessByFami[family], accessRec{jti: jti, exp: exp})
}

// RevokeAccessToken 撤销单个访问令牌（按 jti），结论可区分。
// 撤销记录只会在其自身过期后被清理；容量触顶时宁可拒绝（RevokeUnavailable）
// 也不淘汰仍有效的记录，避免已撤销令牌因容量淘汰而复活。
func (s *Store) RevokeAccessToken(jti string, exp time.Time) RevokeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.After(exp) {
		return RevokeAlreadyInvalid
	}
	if _, ok := s.revokedJTIs[jti]; ok {
		return RevokeAlreadyInvalid
	}
	s.sweepRevokedLocked(now)
	if len(s.revokedJTIs) >= s.maxRevoked {
		return RevokeUnavailable
	}
	s.revokedJTIs[jti] = exp
	return RevokeOK
}

// IsAccessRevoked 报告访问令牌是否已被撤销：
// 命中显式 jti 撤销集合，或其所属会话已有撤销墓碑。
func (s *Store) IsAccessRevoked(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.revokedJTIs[jti]; ok {
		return true
	}
	family, ok := s.jtiFamily[jti]
	if !ok {
		return false
	}
	_, dead := s.revokedFami[family]
	return dead
}

// IsFamilyRevoked 报告会话是否已被会话级撤销（测试与内省用）。
func (s *Store) IsFamilyRevoked(family string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, dead := s.revokedFami[family]
	return dead
}

// PeekRefreshToken 返回刷新令牌的只读快照，不改变其状态。
// 供调用方在原子提交前做客户端归属等前置检查；权威判定仍由提交方法完成。
func (s *Store) PeekRefreshToken(token string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return RefreshToken{}, ErrRefreshNotFound
	}
	return *t, nil
}

// RefreshTokenInfo 返回刷新令牌当前状态快照（用于测试与内省）。
func (s *Store) RefreshTokenInfo(token string) (RefreshToken, error) {
	return s.PeekRefreshToken(token)
}

// Sweep 清理过期条目，可由后台协程定期调用。
// 清理顺序保证不会让仍有效的已撤销令牌复活：
//   - 先清过期授权码/刷新令牌；
//   - 再清撤销 jti 集合（仅删自身已过期的记录）；
//   - 会话墓碑只在 keepUntil（会话内最晚令牌过期时刻）之后删除；
//   - 最后回收过期的访问令牌派生索引。
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepCodesLocked(now)
	s.sweepRefreshLocked(now)
	s.sweepRevokedLocked(now)
	s.sweepFamiliesLocked(now)
	s.sweepAccessIndexLocked(now)
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

// sweepFamiliesLocked 删除保护窗口已结束的会话墓碑及其 jti 反向索引。
// 墓碑存活到 keepUntil 之后，确保窗口期内任何校验/刷新仍被拦截，
// 而窗口结束后该会话不可能再有有效令牌，删除是安全的。
func (s *Store) sweepFamiliesLocked(now time.Time) {
	for family, tb := range s.revokedFami {
		if now.After(tb.keepUntil) {
			delete(s.revokedFami, family)
			for jti, f := range s.jtiFamily {
				if f == family {
					delete(s.jtiFamily, jti)
				}
			}
			delete(s.accessByFami, family)
		}
	}
}

// sweepAccessIndexLocked 回收存活会话中过期的访问令牌索引，
// 防止 accessByFami / jtiFamily 随长期运行无界增长。
// 已撤销会话的记录与反向索引由 sweepFamiliesLocked 连同墓碑统一回收，
// 保护窗口内保持完整（jti 撤销集合与墓碑双重拦截）。
func (s *Store) sweepAccessIndexLocked(now time.Time) {
	for family, recs := range s.accessByFami {
		if _, dead := s.revokedFami[family]; dead {
			continue
		}
		kept := recs[:0]
		for _, rec := range recs {
			if now.After(rec.exp) {
				if f, ok := s.jtiFamily[rec.jti]; ok && f == family {
					delete(s.jtiFamily, rec.jti)
				}
				continue
			}
			kept = append(kept, rec)
		}
		if len(kept) == 0 {
			delete(s.accessByFami, family)
		} else {
			s.accessByFami[family] = kept
		}
	}
}

// Stats 返回当前存储规模（用于监控与测试）。
func (s *Store) Stats() (codes, refresh, revoked int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes), len(s.refresh), len(s.revokedJTIs)
}

// RevokedFamilies 返回当前存活的会话撤销墓碑数量（用于监控与测试）。
func (s *Store) RevokedFamilies() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.revokedFami)
}
