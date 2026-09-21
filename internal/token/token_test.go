package token

import (
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
)

const testIssuer = "http://test-issuer"

func newKeyStore(t *testing.T) (*keys.Store, *keys.Key) {
	t.Helper()
	ks := keys.NewStore()
	k, err := ks.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return ks, k
}

func validClaims() Claims {
	now := time.Now()
	return Claims{
		Issuer:    testIssuer,
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     "read",
		TokenID:   "jti-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ks, k := newKeyStore(t)
	tok, err := Sign(validClaims(), k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, reason := Verify(tok, ks, testIssuer, 0, time.Now())
	if reason != ReasonOK {
		t.Fatalf("want ok, got %s", reason)
	}
	if claims.Subject != "user-1" || claims.Scope != "read" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	ks, k := newKeyStore(t)
	tok, _ := Sign(validClaims(), k)
	parts := strings.Split(tok, ".")
	// 篡改 payload：把 sub 换掉（简单替换字符即可使签名失效）。
	parts[1] = parts[1][:len(parts[1])-2] + "XX"
	_, reason := Verify(strings.Join(parts, "."), ks, testIssuer, 0, time.Now())
	if reason != ReasonBadSignature && reason != ReasonMalformed {
		t.Fatalf("want bad_signature or malformed, got %s", reason)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	ks, k := newKeyStore(t)
	c := validClaims()
	c.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	tok, _ := Sign(c, k)
	_, reason := Verify(tok, ks, testIssuer, 0, time.Now())
	if reason != ReasonExpired {
		t.Fatalf("want token_expired, got %s", reason)
	}
}

func TestClockSkewTolerance(t *testing.T) {
	ks, k := newKeyStore(t)
	c := validClaims()
	c.ExpiresAt = time.Now().Add(-10 * time.Second).Unix()
	tok, _ := Sign(c, k)
	// 容忍 30s 偏移时仍有效。
	if _, reason := Verify(tok, ks, testIssuer, 30*time.Second, time.Now()); reason != ReasonOK {
		t.Fatalf("want ok within skew, got %s", reason)
	}
	// 不容忍则过期。
	if _, reason := Verify(tok, ks, testIssuer, 0, time.Now()); reason != ReasonExpired {
		t.Fatalf("want expired without skew, got %s", reason)
	}
}

func TestIssuerMismatchRejected(t *testing.T) {
	ks, k := newKeyStore(t)
	tok, _ := Sign(validClaims(), k)
	_, reason := Verify(tok, ks, "http://other-issuer", 0, time.Now())
	if reason != ReasonIssuerMismatch {
		t.Fatalf("want issuer_mismatch, got %s", reason)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, k := newKeyStore(t)
	tok, _ := Sign(validClaims(), k)
	other := keys.NewStore() // 空密钥库不认识该 kid
	_, reason := Verify(tok, other, testIssuer, 0, time.Now())
	if reason != ReasonUnknownKey {
		t.Fatalf("want unknown_key, got %s", reason)
	}
}

func TestKeyRotationOldTokenStillVerifies(t *testing.T) {
	ks, k1 := newKeyStore(t)
	tok, _ := Sign(validClaims(), k1)
	// 轮换：生成新密钥，旧密钥淘汰。
	k2, err := ks.Generate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if k2.ID == k1.ID {
		t.Fatal("rotation must produce a new kid")
	}
	// 旧令牌仍可校验。
	if _, reason := Verify(tok, ks, testIssuer, 0, time.Now()); reason != ReasonOK {
		t.Fatalf("old token must verify after rotation, got %s", reason)
	}
	// 新令牌用新密钥签发且可校验。
	tok2, _ := Sign(validClaims(), k2)
	if _, reason := Verify(tok2, ks, testIssuer, 0, time.Now()); reason != ReasonOK {
		t.Fatalf("new token must verify, got %s", reason)
	}
	// 淘汰密钥不得再用于签发：Active 必须返回新密钥。
	active, _ := ks.Active()
	if active.ID != k2.ID {
		t.Fatalf("active key must be the new one, got %s", active.ID)
	}
	// JWKS 公开信息与校验一致：两个 kid 都在。
	jwks := ks.JWKS()
	seen := map[string]bool{}
	for _, j := range jwks {
		seen[j.Kid] = true
	}
	if !seen[k1.ID] || !seen[k2.ID] {
		t.Fatalf("JWKS must publish both keys, got %v", seen)
	}
}

func TestHasScope(t *testing.T) {
	if !HasScope("read write", "read") {
		t.Fatal("read should be covered")
	}
	if HasScope("read", "write") {
		t.Fatal("write should not be covered")
	}
	if !HasScope("read write", "read write") {
		t.Fatal("both should be covered")
	}
	if !HasScope("read", "") {
		t.Fatal("empty requirement always passes")
	}
}
