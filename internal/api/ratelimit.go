package api

import (
	"net"
	"sync"
	"time"
)

// maxClients bounds the limiter's memory. When full, idle clients are pruned;
// if it is still full, new clients are refused rather than tracked.
const maxClients = 100_000

// limiter is a per-client token bucket.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	clients map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	if perMinute <= 0 {
		perMinute = 10
	}
	if burst <= 0 {
		burst = 1
	}
	return &limiter{rate: float64(perMinute) / 60, burst: float64(burst), clients: map[string]*bucket{}, now: time.Now}
}

// allow consumes a token for key and reports whether the request may
// proceed, or else how long until a token is available.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.clients[key]
	if !ok {
		if len(l.clients) >= maxClients {
			l.pruneLocked(now)
			if len(l.clients) >= maxClients {
				return false, time.Minute
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.clients[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// pruneLocked drops clients whose buckets have refilled (they are
// indistinguishable from new clients).
func (l *limiter) pruneLocked(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.clients {
		if now.Sub(b.last) >= full {
			delete(l.clients, k)
		}
	}
}

func (l *limiter) prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(l.now())
}

// clientKey groups IPv6 clients by /64, the smallest block a single
// subscriber is normally assigned, so rotating addresses within it does not
// evade the limit.
func clientKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
