// Package ratelimit 提供按客户端的请求频率限制。
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 按键限制请求速率（令牌桶算法）；并发安全，键数量有上限。
type Limiter struct {
	mu        sync.Mutex
	perSecond float64
	burst     float64
	maxKeys   int
	buckets   map[string]*bucket
}

// New 创建限流器；perSecond<=0 表示不限制。
func New(perSecond, burst int) *Limiter {
	return &Limiter{
		perSecond: float64(perSecond),
		burst:     float64(burst),
		maxKeys:   10000,
		buckets:   make(map[string]*bucket),
	}
}

// Allow 判断该键当前是否允许一次请求；超过上限按确定策略拒绝。
func (l *Limiter) Allow(key string) bool {
	if l.perSecond <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			// 清理最久未使用的桶，防止内存无界增长。
			var oldest string
			var oldestT time.Time
			for k, v := range l.buckets {
				if oldest == "" || v.last.Before(oldestT) {
					oldest, oldestT = k, v.last
				}
			}
			delete(l.buckets, oldest)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.perSecond
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
