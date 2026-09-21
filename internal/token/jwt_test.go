package token

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T) (*rsa.PrivateKey, KeyFunc) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv, func(kid string) (*rsa.PublicKey, error) {
		if kid != "k1" {
			return nil, errors.New("no such key")
		}
		return &priv.PublicKey, nil
	}
}

func baseClaims() Claims {
	return Claims{
		Issuer:   "iss",
		Subject:  "alice",
		ClientID: "c1",
		Scope:    "openid profile",
		ID:       "jti-1",
		IssuedAt: time.Now().Unix(),
		Expires:  time.Now().Add(time.Minute).Unix(),
	}
}

func TestSignParseRoundtrip(t *testing.T) {
	priv, kf := testKeys(t)
	tok, err := NewSigner("k1", priv).Sign(baseClaims())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(tok, kf, "iss", 0, time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Subject != "alice" || !c.HasScope("profile") || c.HasScope("admin") {
		t.Fatalf("unexpected claims: %+v", c)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	priv, kf := testKeys(t)
	tok, _ := NewSigner("k1", priv).Sign(baseClaims())
	parts := strings.Split(tok, ".")
	// 篡改 claims 段（重新编码一个不同的 sub 但不重新签名）。
	parts[1] = parts[1][:len(parts[1])-2] + "XX"
	_, err := Parse(strings.Join(parts, "."), kf, "iss", 0, time.Now())
	if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrSignature/ErrMalformed, got %v", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	priv, kf := testKeys(t)
	c := baseClaims()
	c.Expires = time.Now().Add(-time.Hour).Unix()
	tok, _ := NewSigner("k1", priv).Sign(c)
	_, err := Parse(tok, kf, "iss", 0, time.Now())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestClockSkewTolerance(t *testing.T) {
	priv, kf := testKeys(t)
	c := baseClaims()
	c.Expires = time.Now().Add(-10 * time.Second).Unix()
	tok, _ := NewSigner("k1", priv).Sign(c)
	if _, err := Parse(tok, kf, "iss", 30*time.Second, time.Now()); err != nil {
		t.Fatalf("skew should tolerate: %v", err)
	}
	if _, err := Parse(tok, kf, "iss", 5*time.Second, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired beyond skew, got %v", err)
	}
}

func TestIssuerMismatchRejected(t *testing.T) {
	priv, kf := testKeys(t)
	tok, _ := NewSigner("k1", priv).Sign(baseClaims())
	_, err := Parse(tok, kf, "other-issuer", 0, time.Now())
	if !errors.Is(err, ErrIssuer) {
		t.Fatalf("want ErrIssuer, got %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	priv, kf := testKeys(t)
	tok, _ := NewSigner("kX", priv).Sign(baseClaims())
	_, err := Parse(tok, kf, "iss", 0, time.Now())
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestMalformedRejected(t *testing.T) {
	_, kf := testKeys(t)
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.@@@.###"} {
		if _, err := Parse(bad, kf, "iss", 0, time.Now()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("token %q: want ErrMalformed, got %v", bad, err)
		}
	}
}
