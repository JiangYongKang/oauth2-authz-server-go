package keys

import (
	"errors"
	"testing"
	"time"
)

func TestRotationKeepsHistoryForVerify(t *testing.T) {
	m, err := NewManager(2048, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid1 := m.ActiveKID()
	kid2, err := m.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if kid2 == kid1 {
		t.Fatal("rotation must produce a new kid")
	}
	if m.ActiveKID() != kid2 {
		t.Fatal("active kid not updated")
	}
	// 旧密钥仍可校验。
	if _, err := m.VerifyKey(kid1); err != nil {
		t.Fatalf("retired key should remain verifiable: %v", err)
	}
	// 签发密钥必须是新密钥。
	signKID, _ := m.SigningKey()
	if signKID != kid2 {
		t.Fatal("retired key must not sign")
	}
}

func TestPrunedKeyRejected(t *testing.T) {
	now := time.Now()
	m, err := NewManager(2048, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m.SetClock(func() time.Time { return now })
	kid1 := m.ActiveKID()
	if _, err := m.Rotate(); err != nil {
		t.Fatal(err)
	}
	// 时钟前进超过保留期后再轮换触发清理。
	now = now.Add(2 * time.Minute)
	if _, err := m.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyKey(kid1); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("pruned key: want ErrUnknownKey, got %v", err)
	}
}

func TestJWKSConsistentWithVerify(t *testing.T) {
	m, err := NewManager(2048, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rotate(); err != nil {
		t.Fatal(err)
	}
	jwks := m.JWKS()
	if len(jwks) != 2 {
		t.Fatalf("want 2 jwks, got %d", len(jwks))
	}
	for _, j := range jwks {
		if _, err := m.VerifyKey(j.Kid); err != nil {
			t.Fatalf("jwks kid %s not verifiable: %v", j.Kid, err)
		}
	}
	// 输出可复现：两次调用一致。
	again := m.JWKS()
	for i := range jwks {
		if jwks[i] != again[i] {
			t.Fatal("JWKS output not reproducible")
		}
	}
}

func TestConcurrentRotateAndVerify(t *testing.T) {
	m, err := NewManager(2048, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_, _ = m.Rotate()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_, _ = m.SigningKey()
				_ = m.JWKS()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 12; i++ {
		<-done
	}
}
