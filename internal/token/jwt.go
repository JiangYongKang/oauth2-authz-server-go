// Package token 实现 RS256 JWT 的签发与校验。
//
// 校验失败原因通过带类型的错误区分：
// ErrMalformed / ErrSignature / ErrUnknownKey / ErrExpired / ErrNotYetValid /
// ErrIssuer。调用方可据此给出可区分的拒绝结论。
package token

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 可区分的校验失败原因。
var (
	ErrMalformed   = errors.New("malformed token")
	ErrSignature   = errors.New("invalid signature")
	ErrUnknownKey  = errors.New("unknown signing key")
	ErrExpired     = errors.New("token expired")
	ErrNotYetValid = errors.New("token not yet valid")
	ErrIssuer      = errors.New("issuer mismatch")
)

// Claims 是访问令牌携带的声明集合。
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	ID        string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	Expires   int64  `json:"exp"`
	NotBefore int64  `json:"nbf,omitempty"`
}

// HasScope 报告令牌是否包含指定范围。
func (c Claims) HasScope(s string) bool {
	for _, sc := range strings.Fields(c.Scope) {
		if sc == s {
			return true
		}
	}
	return false
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Signer 用给定私钥与 kid 签发令牌。
type Signer struct {
	kid  string
	priv *rsa.PrivateKey
}

// NewSigner 创建签发器。
func NewSigner(kid string, priv *rsa.PrivateKey) *Signer {
	return &Signer{kid: kid, priv: priv}
}

// Sign 序列化并签名 claims，返回紧凑格式的 JWT。
func (s *Signer) Sign(c Claims) (string, error) {
	h := header{Alg: "RS256", Typ: "JWT", Kid: s.kid}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	head := base64.RawURLEncoding.EncodeToString(hb)
	body := base64.RawURLEncoding.EncodeToString(cb)
	input := head + "." + body
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, s.priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// KeyFunc 按 kid 查找校验公钥；找不到时应返回错误。
type KeyFunc func(kid string) (*rsa.PublicKey, error)

// Parse 校验并解析令牌。issuer 为空则不校验签发方；skew 为时钟偏移容忍。
// now 为当前时间。失败时返回的 error 可用 errors.Is 与上述哨兵错误比较。
func Parse(tok string, keys KeyFunc, issuer string, skew time.Duration, now time.Time) (Claims, error) {
	var zero Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return zero, ErrMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, fmt.Errorf("%w: bad header encoding", ErrMalformed)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return zero, fmt.Errorf("%w: bad header json", ErrMalformed)
	}
	if h.Alg != "RS256" {
		return zero, fmt.Errorf("%w: unsupported alg %q", ErrMalformed, h.Alg)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, fmt.Errorf("%w: bad claims encoding", ErrMalformed)
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return zero, fmt.Errorf("%w: bad claims json", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return zero, fmt.Errorf("%w: bad signature encoding", ErrMalformed)
	}
	pub, err := keys(h.Kid)
	if err != nil {
		return zero, fmt.Errorf("%w: %s", ErrUnknownKey, h.Kid)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return zero, ErrSignature
	}
	t := now.Unix()
	if issuer != "" && c.Issuer != issuer {
		return zero, fmt.Errorf("%w: got %q", ErrIssuer, c.Issuer)
	}
	if c.Expires != 0 && t > c.Expires+int64(skew.Seconds()) {
		return zero, fmt.Errorf("%w at %s", ErrExpired, time.Unix(c.Expires, 0).UTC())
	}
	if c.NotBefore != 0 && t+int64(skew.Seconds()) < c.NotBefore {
		return zero, ErrNotYetValid
	}
	return c, nil
}
