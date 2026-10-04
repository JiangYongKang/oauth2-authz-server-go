// Package store 提供并发安全的内存存储：客户端、授权码、刷新令牌与撤销记录。
//
// 一致性语义：
//   - 授权码消费（ConsumeAuthCode）是原子的：同一授权码只会成功一次，
//     重复消费返回 ErrCodeUsed，过期返回 ErrCodeExpired；
//   - 刷新令牌轮换（RotateAtomic）是原子的：旧令牌被标记为已用与新令牌
//     入存在同一临界区完成，撤销无法插入其间；已使用的旧令牌再次被出示时
//     无条件判定为重放（无论会话是否已先终止、是否在并发出示，结论不变），
//     会话仍存活时终止其所属会话（令牌族 family）；
//   - 会话级撤销（RevokeSession）原子地终止整条授权链：族内全部刷新令牌、
//     已轮换掉的旧令牌对应的后继关系、以及撤销之后才登记的派生访问令牌
//     都不再可用；族标记是访问令牌失效的最终判定依据，不依赖可能被容量
//     限制拒绝写入的逐条撤销记录，因此撤销状态不会因容量淘汰而“复活”；
//     被点名令牌自身早已失效（已过期，或未被轮换消费却已被逐条撤销）时
//     返回 already_invalid 且不终止会话，不连累同会话仍有效的访问令牌；
//   - 所有映射的容量受配置上限约束，过期条目会被定期清理，
//     资源占用不会无界增长。
package store

import (
	"errors"
	"sync"
	"time"
)

// 可区分的失败原因。
var (
	ErrClientNotFound        = errors.New("client not found")
	ErrStoreFull             = errors.New("store capacity reached")
	ErrCodeNotFound          = errors.New("authorization code not found")
	ErrCodeUsed              = errors.New("authorization code already used")
	ErrCodeExpired           = errors.New("authorization code expired")
	ErrRefreshNotFound       = errors.New("refresh token not found")
	ErrRefreshExpired        = errors.New("refresh token expired")
	ErrRefreshRevoked        = errors.New("refresh token revoked")
	ErrRefreshClientMismatch = errors.New("refresh token client mismatch")
	ErrRefreshReused         = errors.New("refresh token reuse detected; token family revoked")
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
	RevokeOK             RevokeResult = iota // 会话此前存活，本次完成撤销
	RevokeNotFound                           // 令牌不存在（或非本服务签发）
	RevokeAlreadyInvalid                     // 会话此前已终止（重复撤销 / 重放之后），幂等
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
	revokedJTIs  map[string]time.Time   // 单独撤销的访问令牌 jti -> 其过期时刻
	jtiFamily    map[string]string      // 访问令牌 jti -> 所属会话族（用于会话级失效判定）
	accessByFami map[string][]accessRec // family -> 派生的访问令牌
	deadFamilies map[string]deadFamily  // 已终止（撤销/重放）的会话族
	maxCodes     int
	maxRefresh   int
	maxRevoked   int
}

// deadFamily 记录一个被整体终止的会话。
type deadFamily struct {
	at      time.Time // 终止时刻（日志用）
	horizon time.Time // 保留至此时刻：族内最后一个可能仍有效的令牌过期为止
	reason  string    // revoke_session / refresh_reuse（日志用）
}

// New 创建空存储，容量由上限参数约束。
func New(maxCodes, maxRefresh, maxRevoked int) *Store {
	return &Store{
		now:          time.Now,
		clients:      make(map[string]Client),
		codes:        make(map[string]*AuthCode),
		refresh:      make(map[string]*RefreshToken),
		revokedJTIs:  make(map[string]time.Time),
		jtiFamily:    make(map[string]string),
		accessByFami: make(map[string][]accessRec),
		deadFamilies: make(map[string]deadFamily),
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

// RotateRefreshToken 原子地消费旧刷新令牌并返回其记录。
// 若旧令牌已被使用，则再次出示无条件判定为重放（ErrRefreshReused）并在会话
// 仍存活时终止整个会话（令牌族）；会话此前已终止时结论不变（仍为重放）。
// 未用过但所属会话已终止的令牌返回 ErrRefreshRevoked。
//
// 该方法只完成“消费”这一步；服务器正常刷新路径应使用 RotateAtomic，
// 它把消费旧令牌与写入后继令牌合并为一个原子步骤，避免撤销插入窗口。
func (s *Store) RotateRefreshToken(token string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return nil, ErrRefreshNotFound
	}
	// 已用令牌的再次出示无条件判定为重放（沿用历史外部语义）：
	// 无论会话是否已经结束、是否在并发出示，结论都保持 ErrRefreshReused，
	// 不会因为会话先被撤掉而换成 ErrRefreshRevoked。
	// 会话仍存活时由重放终止整族；已终止则幂等保留终止标记。
	if t.Used {
		if _, dead := s.deadFamilies[t.Family]; !dead {
			s.terminateFamilyLocked(t.Family, "refresh_reuse", s.now())
		}
		return nil, ErrRefreshReused
	}
	if _, dead := s.deadFamilies[t.Family]; dead {
		t.Revoked = true
		return nil, ErrRefreshRevoked
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

// RotateAtomic 原子地完成一次刷新轮换：校验并消费旧刷新令牌，同时把后继
// 刷新令牌写入同一族。校验、终止判定与写入在单个临界区内完成，因此并发的
// 撤销与刷新之间不存在中间状态：
//   - 会话已终止（含并发撤销抢先）：返回 ErrRefreshRevoked，后继令牌绝不入存；
//   - 旧令牌被并发轮换过（重放）：终止整族并返回 ErrRefreshReused；
//   - 客户端身份与令牌绑定不符：旧令牌同样被消费（沿用历史语义），
//     返回 ErrRefreshClientMismatch，后继令牌不入存；
//   - 成功：旧令牌标记 Used，next 入存，调用方拿到旧令牌上下文用于签发访问令牌。
//
// 容量不足时返回 ErrStoreFull，且消费尚未发生，不会留下“旧令牌已消费但
// 后继缺失”的半更新状态。
func (s *Store) RotateAtomic(clientID, token string, next *RefreshToken) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepRefreshLocked(now)
	t, ok := s.refresh[token]
	if !ok {
		return nil, ErrRefreshNotFound
	}
	// 已用令牌的再次出示无条件判定为重放（沿用历史外部语义）：
	// 无论会话是否已经结束、是否在并发出示，结论都保持 ErrRefreshReused。
	// 因此并发用同一刷新令牌换令牌时，除唯一的成功者外，其余请求结论一致，
	// 不会出现一部分报重放、一部分报已撤销；首个重放者仍会终止整族。
	if t.Used {
		if _, dead := s.deadFamilies[t.Family]; !dead {
			s.terminateFamilyLocked(t.Family, "refresh_reuse", now)
		}
		return nil, ErrRefreshReused
	}
	if _, dead := s.deadFamilies[t.Family]; dead {
		t.Revoked = true
		return nil, ErrRefreshRevoked
	}
	if t.Revoked {
		return nil, ErrRefreshRevoked
	}
	if now.After(t.ExpiresAt) {
		return nil, ErrRefreshExpired
	}
	// 容量先于消费检查，保证失败时无半更新。
	if len(s.refresh) >= s.maxRefresh {
		return nil, ErrStoreFull
	}
	// 消费旧令牌。即使随后客户端不匹配，旧令牌也已作废（沿用历史语义）。
	t.Used = true
	if t.ClientID != clientID {
		return nil, ErrRefreshClientMismatch
	}
	next.Family = t.Family
	s.refresh[next.Token] = next
	cp := *t
	return &cp, nil
}

// RevokeRefreshToken 撤销单个刷新令牌，结论可区分（保留的细粒度原语）。
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

// RevokeSession 按当前刷新令牌终止其所属的整个会话（令牌族）：
// 族内全部刷新令牌（含之后才会入存的后继）、已轮换掉的旧令牌对应的后继
// 关系，以及族派生的全部访问令牌，一律失效。操作幂等。
//
// 结论按“会话”而非被点名令牌的个体状态划分：
//   - RevokeOK：该会话此前仍然存活，本次调用完成终止
//     （被点名的可以是当前刷新令牌，或已被轮换掉但仍在有效期内的旧令牌——
//     旧令牌仍代表一次存活的授权链，用它撤销即真实终止整条链）；
//   - RevokeAlreadyInvalid：会话此前已终止（重复撤销、重放之后），幂等；
//     或被点名令牌自身早已失效（已过期，或未被轮换消费却已被逐条撤销）——
//     这种令牌“本来就是无效的”，不算一次真实的会话撤销，也不波及同一次
//     登录中仍然有效的访问令牌（沿用历史口径）。过期判定优先于旧令牌撤销；
//   - RevokeNotFound：令牌不存在（非本服务签发或已被过期清理）。
//
// 终止只影响该族；其它用户、客户端、登录会话即使共享签名密钥也不受影响。
func (s *Store) RevokeSession(token string) (RevokeResult, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.refresh[token]
	if !ok {
		return RevokeNotFound, ""
	}
	family := t.Family
	if _, dead := s.deadFamilies[family]; dead {
		return RevokeAlreadyInvalid, family
	}
	// 被点名令牌自身早已失效（已过期，或未被轮换消费但已被逐条撤销）：
	// 它“本来就是无效的”，不终止会话、不连累同会话仍有效的访问令牌。
	// 过期判定优先：即使是已轮换掉的旧令牌，只要它本身已经过期，出示它
	// 同样不算一次真实的会话撤销。
	if now.After(t.ExpiresAt) || (!t.Used && t.Revoked) {
		return RevokeAlreadyInvalid, family
	}
	s.terminateFamilyLocked(family, "revoke_session", now)
	return RevokeOK, family
}

// RevokeFamily 终止指定令牌族（重放传播等内部场景）。
func (s *Store) RevokeFamily(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminateFamilyLocked(family, "refresh_reuse", s.now())
}

// terminateFamilyLocked 终止会话族：登记族终止标记、作废族内全部刷新令牌。
// 访问令牌的失效通过 deadFamilies + jti 反向索引在校验时判定，
// 不依赖逐条撤销记录，因此不受撤销记录容量限制影响，也不会被淘汰复活。
// 调用方必须持有 s.mu。
func (s *Store) terminateFamilyLocked(family, reason string, now time.Time) {
	horizon := now
	for _, t := range s.refresh {
		if t.Family == family {
			t.Revoked = true
			if t.ExpiresAt.After(horizon) {
				horizon = t.ExpiresAt
			}
		}
	}
	for _, rec := range s.accessByFami[family] {
		if rec.exp.After(horizon) {
			horizon = rec.exp
		}
	}
	s.deadFamilies[family] = deadFamily{at: now, horizon: horizon, reason: reason}
}

// RecordAccessToken 记录某会话签发的访问令牌 jti 及其过期时刻，并维护
// jti -> family 反向索引。若该会话此刻已终止，则直接把 jti 记入逐条撤销
// 集合（纵深防御：登记发生在终止之后的竞态下，校验仍必须拒绝）。
func (s *Store) RecordAccessToken(family, jti string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessByFami[family] = append(s.accessByFami[family], accessRec{jti: jti, exp: exp})
	s.jtiFamily[jti] = family
	if d, dead := s.deadFamilies[family]; dead {
		if _, ok := s.revokedJTIs[jti]; !ok {
			s.revokedJTIs[jti] = exp
		}
		if exp.After(d.horizon) {
			d.horizon = exp
			s.deadFamilies[family] = d
		}
	}
}

// RevokeAccessToken 按 jti 撤销单个访问令牌，结论可区分。
// 逐条撤销记录有容量上限：先清理过期记录，仍满则失败关闭返回 ErrStoreFull，
// 绝不淘汰仍有效的撤销记录而让令牌“复活”。
func (s *Store) RevokeAccessToken(jti string, exp time.Time) (RevokeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.After(exp) {
		return RevokeAlreadyInvalid, nil
	}
	if _, ok := s.revokedJTIs[jti]; ok {
		return RevokeAlreadyInvalid, nil
	}
	if family, known := s.jtiFamily[jti]; known {
		if _, dead := s.deadFamilies[family]; dead {
			return RevokeAlreadyInvalid, nil
		}
	}
	s.sweepRevokedLocked(now)
	if len(s.revokedJTIs) >= s.maxRevoked {
		return RevokeNotFound, ErrStoreFull
	}
	s.revokedJTIs[jti] = exp
	return RevokeOK, nil
}

// IsAccessRevoked 报告访问令牌是否已被撤销：命中逐条撤销记录，或其所属
// 会话（令牌族）已被会话级撤销/重放终止。后者由族标记最终判定，不受
// 逐条撤销记录容量淘汰的影响。
func (s *Store) IsAccessRevoked(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.revokedJTIs[jti]; ok {
		return true
	}
	if family, ok := s.jtiFamily[jti]; ok {
		if _, dead := s.deadFamilies[family]; dead {
			return true
		}
	}
	return false
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
	s.sweepFamiliesLocked(now)
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

// sweepFamiliesLocked 清理已无在效令牌牵挂的过期数据：
// 访问令牌索引、jti 反向索引以及超过保留窗口（族内最后一个令牌过期）的
// 终止族标记。仍有效令牌牵挂的族标记绝不清理，撤销状态不会因清理复活。
func (s *Store) sweepFamiliesLocked(now time.Time) {
	for family, recs := range s.accessByFami {
		kept := recs[:0]
		for _, rec := range recs {
			if now.After(rec.exp) {
				delete(s.jtiFamily, rec.jti)
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
	for family, d := range s.deadFamilies {
		if now.After(d.horizon) {
			delete(s.deadFamilies, family)
		}
	}
}

// Stats 返回当前存储规模（用于监控与测试）。
func (s *Store) Stats() (codes, refresh, revoked int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes), len(s.refresh), len(s.revokedJTIs)
}

// DeadSessions 返回当前仍保留的已终止会话数（用于监控与测试）。
func (s *Store) DeadSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.deadFamilies)
}
