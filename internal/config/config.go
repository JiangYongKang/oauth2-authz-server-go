// Package config 定义授权服务器的可配置项。
package config

import (
	"os"
	"strconv"
	"time"
)

// Config 汇总服务器运行所需的全部可调参数。
type Config struct {
	Issuer            string        // 令牌签发方标识（iss）
	AccessTokenTTL    time.Duration // 访问令牌有效期
	RefreshTokenTTL   time.Duration // 刷新令牌有效期
	AuthCodeTTL       time.Duration // 授权码有效期
	ClockSkew         time.Duration // 校验时允许的时钟偏移
	RateLimitPerMin   int           // 每个客户端（或来源 IP）每分钟允许的请求数
	MaxAuthCodes      int           // 授权码存储上限（超出时拒绝新的授权请求）
	MaxRefreshTokens  int           // 刷新令牌存储上限（超出时淘汰最旧的已过期项，否则拒绝）
	MaxRevokedEntries int           // 撤销记录存储上限（按过期时间淘汰）
}

// Default 返回本地运行的默认配置。
func Default() Config {
	return Config{
		Issuer:            "http://localhost:8080",
		AccessTokenTTL:    10 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		AuthCodeTTL:       2 * time.Minute,
		ClockSkew:         30 * time.Second,
		RateLimitPerMin:   120,
		MaxAuthCodes:      10000,
		MaxRefreshTokens:  10000,
		MaxRevokedEntries: 100000,
	}
}

// FromEnv 在默认配置基础上叠加环境变量覆盖：
// AUTHZ_ISSUER, AUTHZ_ACCESS_TTL, AUTHZ_REFRESH_TTL, AUTHZ_CODE_TTL,
// AUTHZ_CLOCK_SKEW（均为 Go duration 字符串），
// AUTHZ_RATE_LIMIT_PER_MIN, AUTHZ_MAX_CODES, AUTHZ_MAX_REFRESH, AUTHZ_MAX_REVOKED（整数）。
func FromEnv() Config {
	cfg := Default()
	if v := os.Getenv("AUTHZ_ISSUER"); v != "" {
		cfg.Issuer = v
	}
	dur := func(env string, dst *time.Duration) {
		if v := os.Getenv(env); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	dur("AUTHZ_ACCESS_TTL", &cfg.AccessTokenTTL)
	dur("AUTHZ_REFRESH_TTL", &cfg.RefreshTokenTTL)
	dur("AUTHZ_CODE_TTL", &cfg.AuthCodeTTL)
	dur("AUTHZ_CLOCK_SKEW", &cfg.ClockSkew)
	num := func(env string, dst *int) {
		if v := os.Getenv(env); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				*dst = n
			}
		}
	}
	num("AUTHZ_RATE_LIMIT_PER_MIN", &cfg.RateLimitPerMin)
	num("AUTHZ_MAX_CODES", &cfg.MaxAuthCodes)
	num("AUTHZ_MAX_REFRESH", &cfg.MaxRefreshTokens)
	num("AUTHZ_MAX_REVOKED", &cfg.MaxRevokedEntries)
	return cfg
}
