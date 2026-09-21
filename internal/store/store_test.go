package store

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAuthCodeSingleUse(t *testing.T) {
	s := New(100)
	now := time.Now()
	code := &AuthCode{Code: "c1", ClientID: "cli", ExpiresAt: now.Add(time.Minute)}
	if err := s.SaveAuthCode(code, now); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, res := s.ConsumeAuthCode("c1", now); res != CodeOK {
		t.Fatalf("first consume must succeed, got %s", res)
	}
	if _, res := s.ConsumeAuthCode("c1", now); res != CodeAlreadyUsed {
		t.Fatalf("second consume must be already_used, got %s", res)
	}
	if _, res := s.ConsumeAuthCode("nope", now); res != CodeNotFound {
		t.Fatalf("unknown code must be not_found, got %s", res)
	}
}

func TestAuthCodeExpired(t *testing.T) {
	s := New(100)
	now := time.Now()
	code := &AuthCode{Code: "c2", ExpiresAt: now.Add(-time.Second)}
	_ = s.SaveAuthCode(code, now)
	if _, res := s.ConsumeAuthCode("c2", now); res != CodeExpired {
		t.Fatalf("want expired, got %s", res)
	}
}

func TestRefreshRotationAndReplay(t *testing.T) {
	s := New(100)
	now := time.Now()
	rt := &RefreshToken{Token: "r1", Family: "fam1", ExpiresAt: now.Add(time.Hour)}
	if err := s.SaveRefreshToken(rt, now); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 正常轮换：旧令牌被标记为已替换。
	old, res := s.ConsumeRefreshToken("r1", "r2", now)
	if res != RefreshOK || old.ReplacedBy != "r2" {
		t.Fatalf("rotation failed: res=%s replacedBy=%s", res, old.ReplacedBy)
	}
	// 重放旧令牌：识别并重放撤销整族。
	if _, res := s.ConsumeRefreshToken("r1", "r3", now); res != RefreshReplayed {
		t.Fatalf("replay must be detected, got %s", res)
	}
	if !s.IsFamilyRevoked("fam1") {
		t.Fatal("family must be revoked after replay")
	}
	// 族内新令牌也被拒绝，且不得波及其他族。
	s2 := &RefreshToken{Token: "r2", Family: "fam1", ExpiresAt: now.Add(time.Hour)}
	_ = s.SaveRefreshToken(s2, now)
	if _, res := s.ConsumeRefreshToken("r2", "r4", now); res != RefreshFamilyRevoked {
		t.Fatalf("family member must be rejected, got %s", res)
	}
	other := &RefreshToken{Token: "x1", Family: "fam2", ExpiresAt: now.Add(time.Hour)}
	_ = s.SaveRefreshToken(other, now)
	if _, res := s.ConsumeRefreshToken("x1", "x2", now); res != RefreshOK {
		t.Fatalf("other family must not be affected, got %s", res)
	}
}

func TestRevokeResultsDistinguishable(t *testing.T) {
	s := New(100)
	now := time.Now()
	_ = s.SaveRefreshToken(&RefreshToken{Token: "r1", Family: "f1", ExpiresAt: now.Add(time.Hour)}, now)
	if res := s.RevokeRefreshToken("r1", now); res != RevokeOK {
		t.Fatalf("want revoked, got %s", res)
	}
	if res := s.RevokeRefreshToken("r1", now); res != RevokeAlreadyDone {
		t.Fatalf("want already_revoked, got %s", res)
	}
	if res := s.RevokeRefreshToken("ghost", now); res != RevokeNotFound {
		t.Fatalf("want not_found, got %s", res)
	}
	_ = s.SaveRefreshToken(&RefreshToken{Token: "r2", Family: "f2", ExpiresAt: now.Add(-time.Second)}, now)
	if res := s.RevokeRefreshToken("r2", now); res != RevokeAlreadyDone {
		t.Fatalf("expired token revoke must be already_revoked_or_expired, got %s", res)
	}
}

func TestConcurrentConsumeAuthCode(t *testing.T) {
	s := New(1000)
	now := time.Now()
	_ = s.SaveAuthCode(&AuthCode{Code: "c", ExpiresAt: now.Add(time.Minute)}, now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, res := s.ConsumeAuthCode("c", now); res == CodeOK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one consumer must win, got %d", wins)
	}
}

func TestConcurrentRefreshRotation(t *testing.T) {
	s := New(1000)
	now := time.Now()
	_ = s.SaveRefreshToken(&RefreshToken{Token: "r", Family: "f", ExpiresAt: now.Add(time.Hour)}, now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, res := s.ConsumeRefreshToken("r", fmt.Sprintf("n%d", i), now); res == RefreshOK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one rotation must succeed, got %d", wins)
	}
	if !s.IsFamilyRevoked("f") {
		t.Fatal("concurrent replays must revoke the family")
	}
}

func TestStoreCapacityBound(t *testing.T) {
	s := New(2)
	now := time.Now()
	_ = s.SaveAuthCode(&AuthCode{Code: "a", ExpiresAt: now.Add(time.Minute)}, now)
	_ = s.SaveAuthCode(&AuthCode{Code: "b", ExpiresAt: now.Add(time.Minute)}, now)
	if err := s.SaveAuthCode(&AuthCode{Code: "c", ExpiresAt: now.Add(time.Minute)}, now); err != ErrStoreFull {
		t.Fatalf("want ErrStoreFull, got %v", err)
	}
	// 过期条目被清理后可继续写入。
	later := now.Add(2 * time.Minute)
	if err := s.SaveAuthCode(&AuthCode{Code: "d", ExpiresAt: later.Add(time.Minute)}, later); err != nil {
		t.Fatalf("expired entries must be evicted, got %v", err)
	}
}
