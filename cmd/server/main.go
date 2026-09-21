// Command server 启动本地授权服务器。
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/highcumontoa/oauth2-authz-server-go/internal/config"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/keys"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/server"
	"github.com/highcumontoa/oauth2-authz-server-go/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	cfg := config.FromEnv()

	// 历史密钥保留窗口 = 访问令牌有效期 + 时钟偏移，保证已签发令牌可校验。
	km, err := keys.NewManager(2048, cfg.AccessTokenTTL+cfg.ClockSkew)
	if err != nil {
		log.Fatalf("init keys: %v", err)
	}

	st := store.New(cfg.MaxAuthCodes, cfg.MaxRefreshTokens, cfg.MaxRevokedEntries)
	st.AddClient(store.Client{
		ID:           "demo-client",
		Secret:       "demo-secret",
		RedirectURIs: []string{"http://localhost:8080/callback", "http://127.0.0.1:9000/cb"},
		Scopes:       []string{"openid", "profile", "email"},
	})
	st.AddClient(store.Client{
		ID:           "public-client",
		Secret:       "",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"openid", "profile"},
	})

	users := map[string]string{"alice": "wonderland", "bob": "builder"}

	srv := server.New(cfg, km, st, users)

	// 定期清理过期条目，保证资源占用有界。
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			st.Sweep()
		}
	}()

	log.Printf("authz server listening on %s (issuer=%s)", *addr, cfg.Issuer)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
