// Package keys 管理签名密钥的生成、轮换与历史密钥保留。
//
// 语义：
//   - 任意时刻只有一个活跃密钥用于签发；
//   - 轮换后旧密钥进入历史集合，仅用于校验，不再用于签发；
//   - 历史密钥在校验窗口（访问令牌最大有效期 + 时钟偏移）过后被移除，
//     移除后使用它的令牌将以 unknown_key 被拒绝；
//   - JWKS 只暴露当前可用于校验的公钥，与实际校验行为一致。
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// ErrUnknownKey 表示请求的 kid 不在可校验密钥集合中。
var ErrUnknownKey = errors.New("unknown key id")

// Key 表示一对签名密钥及其标识。
type Key struct {
	KID       string
	CreatedAt time.Time
	RetiredAt time.Time // 零值表示仍活跃
	Priv      *rsa.PrivateKey
}

// Active 报告该密钥是否可用于签发。
func (k *Key) Active() bool { return k.RetiredAt.IsZero() }

// Manager 维护当前活跃密钥与可用于校验的历史密钥。并发安全。
type Manager struct {
	mu        sync.RWMutex
	keys      map[string]*Key
	activeKID string
	bits      int
	retainFor time.Duration // 历史密钥在轮换后保留用于校验的时长
	now       func() time.Time
}

// NewManager 生成初始密钥并返回管理器。retainFor 为历史密钥保留时长。
func NewManager(bits int, retainFor time.Duration) (*Manager, error) {
	m := &Manager{
		keys:      make(map[string]*Key),
		bits:      bits,
		retainFor: retainFor,
		now:       time.Now,
	}
	if _, err := m.Rotate(); err != nil {
		return nil, err
	}
	return m, nil
}

// SetClock 注入时钟（测试用）。
func (m *Manager) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

func newKey(bits int, now time.Time) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	sum := sha256.Sum256(priv.PublicKey.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(sum[:8])
	return &Key{KID: kid, CreatedAt: now, Priv: priv}, nil
}

// Rotate 生成新密钥作为活跃密钥，旧活跃密钥转入历史集合。
// 返回新密钥的 kid。同时清理超出保留期的历史密钥。
func (m *Manager) Rotate() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	k, err := newKey(m.bits, now)
	if err != nil {
		return "", err
	}
	if old, ok := m.keys[m.activeKID]; ok {
		old.RetiredAt = now
	}
	m.keys[k.KID] = k
	m.activeKID = k.KID
	m.pruneLocked(now)
	return k.KID, nil
}

// pruneLocked 移除退役时间超过保留期的历史密钥。
func (m *Manager) pruneLocked(now time.Time) {
	for kid, k := range m.keys {
		if !k.Active() && now.Sub(k.RetiredAt) > m.retainFor {
			delete(m.keys, kid)
		}
	}
}

// ActiveKID 返回当前签发密钥的标识。
func (m *Manager) ActiveKID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeKID
}

// SigningKey 返回当前用于签发的私钥与其 kid。
func (m *Manager) SigningKey() (string, *rsa.PrivateKey) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k := m.keys[m.activeKID]
	return k.KID, k.Priv
}

// VerifyKey 返回指定 kid 的公钥；不存在或已被淘汰时返回 ErrUnknownKey。
func (m *Manager) VerifyKey(kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	return &k.Priv.PublicKey, nil
}

// JWK 是 JWKS 中的一个 RSA 公钥条目。
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS 返回当前可用于校验的全部公钥（活跃 + 保留期内的历史密钥），
// 按 kid 排序以保证输出可复现。
func (m *Manager) JWKS() []JWK {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kids := make([]string, 0, len(m.keys))
	for kid := range m.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	out := make([]JWK, 0, len(kids))
	for _, kid := range kids {
		pub := &m.keys[kid].Priv.PublicKey
		out = append(out, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return out
}
