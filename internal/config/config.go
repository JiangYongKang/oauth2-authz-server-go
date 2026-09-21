// Package config 定义授权服务器的可调配置项。
package config

import "time"

// Config 汇总有效期、时钟偏移容忍与请求频率限制等配置。
type Config struct {
	Issuer             string        // 令牌签发方标识（iss）
	AuthCodeTTL        time.Duration // 授权码有效期
	AccessTokenTTL     time.Duration // 访问令牌有效期
	RefreshTokenTTL    time.Duration // 刷新令牌有效期
	ClockSkew          time.Duration // 校验时允许的时钟偏移
	RateLimitPerSecond int           // 每个客户端每秒允许的请求数
	RateLimitBurst     int           // 突发请求上限
	MaxStoredTokens    int           // 存储的令牌/授权码上限，防止资源无界增长
}

// Default 返回一份可本地运行的默认配置。
func Default() Config {
	return Config{
		Issuer:             "http://localhost:8080",
		AuthCodeTTL:        5 * time.Minute,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    24 * time.Hour,
		ClockSkew:          30 * time.Second,
		RateLimitPerSecond: 20,
		RateLimitBurst:     40,
		MaxStoredTokens:    100000,
	}
}
