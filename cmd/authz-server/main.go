// Command authz-server 启动本地授权服务器。
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/ratelimit"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/server"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	issuer := flag.String("issuer", "http://localhost:8080", "token issuer (iss)")
	accessTTL := flag.Duration("access-ttl", 15*time.Minute, "access token TTL")
	refreshTTL := flag.Duration("refresh-ttl", 24*time.Hour, "refresh token TTL")
	codeTTL := flag.Duration("code-ttl", 5*time.Minute, "authorization code TTL")
	skew := flag.Duration("clock-skew", 30*time.Second, "clock skew tolerance")
	rps := flag.Int("rate-per-second", 20, "rate limit per client per second (0 = unlimited)")
	burst := flag.Int("rate-burst", 40, "rate limit burst per client")
	maxTokens := flag.Int("max-stored-tokens", 100000, "max stored codes/refresh tokens")
	flag.Parse()

	cfg := config.Config{
		Issuer:             *issuer,
		AuthCodeTTL:        *codeTTL,
		AccessTokenTTL:     *accessTTL,
		RefreshTokenTTL:    *refreshTTL,
		ClockSkew:          *skew,
		RateLimitPerSecond: *rps,
		RateLimitBurst:     *burst,
		MaxStoredTokens:    *maxTokens,
	}

	ks := keys.NewStore()
	k, err := ks.Generate()
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	st := store.New(cfg.MaxStoredTokens)
	// 预置一个演示客户端，便于本地直接验证。
	st.RegisterClient(store.Client{
		ID:           "demo-client",
		Secret:       "demo-secret",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"read", "write", "openid"},
	})

	srv := server.New(cfg, ks, st, ratelimit.New(cfg.RateLimitPerSecond, cfg.RateLimitBurst))
	log.Printf("authz-server listening on %s issuer=%s active_kid=%s", *addr, cfg.Issuer, k.ID)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
