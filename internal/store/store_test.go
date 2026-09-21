package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestStore() *Store { return New(100, 100, 100) }

func TestAuthCodeSingleUse(t *testing.T) {
	s := newTestStore()
	code := &AuthCode{Code: "c1", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateAuthCode(code); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthCode("c1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.ConsumeAuthCode("c1"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("second consume: want ErrCodeNotFound, got %v", err)
	}
}

func TestAuthCodeConcurrentConsumeOnlyOneWins(t *testing.T) {
	s := newTestStore()
	_ = s.CreateAuthCode(&AuthCode{Code: "c1", ExpiresAt: time.Now().Add(time.Minute)})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeAuthCode("c1"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one consume must win, got %d", wins)
	}
}

func TestAuthCodeExpired(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateAuthCode(&AuthCode{Code: "c1", ExpiresAt: now.Add(time.Minute)})
	now = now.Add(2 * time.Minute)
	if _, err := s.ConsumeAuthCode("c1"); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("want ErrCodeExpired, got %v", err)
	}
}

func TestRefreshRotationAndReplayRevokesFamily(t *testing.T) {
	s := newTestStore()
	mk := func(tok string) *RefreshToken {
		return &RefreshToken{Token: tok, ClientID: "c", UserID: "u", Family: "f1", ExpiresAt: time.Now().Add(time.Hour)}
	}
	_ = s.CreateRefreshToken(mk("r1"))
	// 正常轮换 r1 -> r2。
	old, err := s.RotateRefreshToken("r1")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r2", ClientID: old.ClientID, UserID: old.UserID, Family: old.Family, ExpiresAt: old.ExpiresAt})
	// 重放 r1：必须识别并撤销整个族。
	if _, err := s.RotateRefreshToken("r1"); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("want ErrRefreshReused, got %v", err)
	}
	// 族内新令牌 r2 也随之失效。
	if _, err := s.RotateRefreshToken("r2"); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("family member should be revoked, got %v", err)
	}
}

func TestRefreshReplayDoesNotAffectOtherFamilies(t *testing.T) {
	s := newTestStore()
	mk := func(tok, fam string) *RefreshToken {
		return &RefreshToken{Token: tok, Family: fam, ExpiresAt: time.Now().Add(time.Hour)}
	}
	_ = s.CreateRefreshToken(mk("a1", "famA"))
	_ = s.CreateRefreshToken(mk("b1", "famB"))
	_, _ = s.RotateRefreshToken("a1")
	if _, err := s.RotateRefreshToken("a1"); !errors.Is(err, ErrRefreshReused) {
		t.Fatal("expected reuse detection")
	}
	// famB 不受影响。
	if _, err := s.RotateRefreshToken("b1"); err != nil {
		t.Fatalf("other family must not be affected: %v", err)
	}
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	s := newTestStore()
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: time.Now().Add(time.Hour)})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []error
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.RotateRefreshToken("r1")
			mu.Lock()
			results = append(results, err)
			mu.Unlock()
		}()
	}
	wg.Wait()
	ok, reused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrRefreshReused):
			reused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one rotation must succeed, got %d", ok)
	}
	if reused == 0 {
		t.Fatal("concurrent reuse must be detected")
	}
}

func TestRevokeResultsDistinguishable(t *testing.T) {
	s := newTestStore()
	if r := s.RevokeRefreshToken("nope"); r != RevokeNotFound {
		t.Fatalf("want not_found, got %s", r)
	}
	_ = s.CreateRefreshToken(&RefreshToken{Token: "r1", Family: "f", ExpiresAt: time.Now().Add(time.Hour)})
	if r := s.RevokeRefreshToken("r1"); r != RevokeOK {
		t.Fatalf("want revoked, got %s", r)
	}
	if r := s.RevokeRefreshToken("r1"); r != RevokeAlreadyInvalid {
		t.Fatalf("want already_invalid, got %s", r)
	}
}

func TestRevokedAccessTokenPropagates(t *testing.T) {
	s := newTestStore()
	exp := time.Now().Add(time.Hour)
	s.RecordAccessToken("fam", "jti-1", exp)
	if s.IsAccessRevoked("jti-1") {
		t.Fatal("should not be revoked yet")
	}
	s.RevokeFamily("fam")
	if !s.IsAccessRevoked("jti-1") {
		t.Fatal("family revocation must propagate to derived access tokens")
	}
}

func TestCapacityBounded(t *testing.T) {
	s := New(10, 10, 10)
	for i := 0; i < 20; i++ {
		_ = s.CreateAuthCode(&AuthCode{Code: fmt.Sprintf("c%d", i), ExpiresAt: time.Now().Add(time.Hour)})
	}
	codes, _, _ := s.Stats()
	if codes > 10 {
		t.Fatalf("code store unbounded: %d", codes)
	}
}
