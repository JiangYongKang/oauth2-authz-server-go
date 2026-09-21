// Package keys 管理签名密钥的轮换与历史密钥并存校验。
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Key 表示一把签名密钥及其元信息。
type Key struct {
	ID        string            // 密钥标识（kid）
	Algorithm string            // 签名算法，如 ES256
	Private   *ecdsa.PrivateKey // 私钥，仅服务端持有
	CreatedAt time.Time
	Retired   bool // 已淘汰：不可再用于签发，但仍可用于校验历史令牌
}

// Public 返回公钥。
func (k *Key) Public() crypto.PublicKey { return k.Private.Public() }

// JWK 是对外公开的密钥信息（JWKS 文档中的单个元素）。
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwk 将公钥导出为 JWK，公开内容与实际校验所用密钥一致。
func (k *Key) jwk() JWK {
	pub := k.Private.PublicKey
	enc := func(b *big.Int) string {
		buf := make([]byte, 32)
		b.FillBytes(buf)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	return JWK{Kty: "EC", Kid: k.ID, Alg: k.Algorithm, Use: "sig", Crv: "P-256", X: enc(pub.X), Y: enc(pub.Y)}
}

// Store 保存当前密钥与历史密钥，支持轮换；并发安全。
type Store struct {
	mu       sync.RWMutex
	keys     map[string]*Key // kid -> key（含已淘汰）
	activeID string
	seq      int
}

// NewStore 创建空密钥库。
func NewStore() *Store {
	return &Store{keys: make(map[string]*Key)}
}

// Generate 生成一把新的 ES256 密钥并设为当前签发密钥；
// 原当前密钥被标记为淘汰（保留用于校验，不再用于签发）。
func (s *Store) Generate() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	k := &Key{
		ID:        fmt.Sprintf("key-%d", s.seq),
		Algorithm: "ES256",
		Private:   priv,
		CreatedAt: time.Now(),
	}
	if old, ok := s.keys[s.activeID]; ok {
		old.Retired = true
	}
	s.keys[k.ID] = k
	s.activeID = k.ID
	return k, nil
}

// Active 返回当前用于签发的密钥。
func (s *Store) Active() (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[s.activeID]
	if !ok {
		return nil, errors.New("no active signing key")
	}
	return k, nil
}

// Get 按 kid 查找密钥（含已淘汰密钥，用于校验历史令牌）。
func (s *Store) Get(kid string) (*Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	return k, ok
}

// JWKS 返回对外公开的全部密钥（含历史密钥），与校验逻辑使用同一数据源。
func (s *Store) JWKS() []JWK {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]JWK, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.jwk())
	}
	return out
}
