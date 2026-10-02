package security

import (
	"sync"
	"time"

	"github.com/gcolin/go-sso/internal/config"
)

type attemptWindow struct {
	count   int
	resetAt time.Time
}

// LoginRateLimiter is an in-memory per-key rate limiter.
type LoginRateLimiter struct {
	cfg *config.AppConfig
	mu  sync.Mutex
	m   map[string]*attemptWindow
}

func NewLoginRateLimiter(cfg *config.AppConfig) *LoginRateLimiter {
	return &LoginRateLimiter{cfg: cfg, m: map[string]*attemptWindow{}}
}

// CheckAndRecord returns retry-after seconds if limited, else 0.
func (l *LoginRateLimiter) CheckAndRecord(key string) int64 {
	max := l.cfg.Security.LoginRateLimitMaxAttempts
	window := l.cfg.Security.LoginRateLimitWindowSeconds
	if max <= 0 || window <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.m[key]
	if !ok || now.After(w.resetAt) {
		l.m[key] = &attemptWindow{count: 1, resetAt: now.Add(time.Duration(window) * time.Second)}
		return 0
	}
	w.count++
	if w.count > max {
		retry := int64(w.resetAt.Sub(now).Seconds())
		if retry < 1 {
			retry = 1
		}
		return retry
	}
	return 0
}
