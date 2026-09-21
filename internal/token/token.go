// Package token 提供访问令牌的签发与本地校验。
package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
)

// Claims 是令牌携带的可校验声明。
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	TokenID   string `json:"jti"`
	Family    string `json:"fam,omitempty"` // 所属刷新令牌族，用于撤销传播
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Reason 区分令牌校验失败的原因，便于调用方得到可解释的结论。
type Reason string

const (
	ReasonOK                Reason = "ok"
	ReasonMalformed         Reason = "malformed_token"
	ReasonBadSignature      Reason = "bad_signature"
	ReasonExpired           Reason = "token_expired"
	ReasonUnknownKey        Reason = "unknown_key"
	ReasonIssuerMismatch    Reason = "issuer_mismatch"
	ReasonRevoked           Reason = "token_revoked"
	ReasonScopeInsufficient Reason = "scope_insufficient"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Sign 使用给定密钥签发 ES256 JWT。
func Sign(c Claims, k *keys.Key) (string, error) {
	h, err := json.Marshal(header{Alg: "ES256", Typ: "JWT", Kid: k.ID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.Private, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// Verify 校验令牌签名、有效期与签发方，返回声明与可区分的失败原因。
// clockSkew 为可配置的时钟偏移容忍。已淘汰但仍保留的密钥可继续通过校验。
func Verify(tok string, ks *keys.Store, issuer string, clockSkew time.Duration, now time.Time) (Claims, Reason) {
	var claims Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return claims, ReasonMalformed
	}
	enc := base64.RawURLEncoding
	hBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return claims, ReasonMalformed
	}
	var h header
	if err := json.Unmarshal(hBytes, &h); err != nil || h.Alg != "ES256" {
		return claims, ReasonMalformed
	}
	k, ok := ks.Get(h.Kid)
	if !ok {
		return claims, ReasonUnknownKey
	}
	pBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		return claims, ReasonMalformed
	}
	if err := json.Unmarshal(pBytes, &claims); err != nil {
		return claims, ReasonMalformed
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return claims, ReasonBadSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || !ecdsa.Verify(pub, digest[:], r, s) {
		return claims, ReasonBadSignature
	}
	if claims.Issuer != issuer {
		return claims, ReasonIssuerMismatch
	}
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(clockSkew)) {
		return claims, ReasonExpired
	}
	return claims, ReasonOK
}

// HasScope 判断令牌范围是否覆盖所需范围（空格分隔）。
func HasScope(tokenScope, required string) bool {
	if required == "" {
		return true
	}
	set := make(map[string]bool)
	for _, s := range strings.Fields(tokenScope) {
		set[s] = true
	}
	for _, r := range strings.Fields(required) {
		if !set[r] {
			return false
		}
	}
	return true
}

// NewID 生成随机标识（授权码、刷新令牌、jti 等）。
func NewID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("rand read failed")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
