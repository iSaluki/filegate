package api

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newLimiter(60, 3) // 1 token/s, burst 3
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("burst request %d refused", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("over burst: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("other client affected")
	}
	now = now.Add(1100 * time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("token not refilled")
	}
	// Refilled buckets are pruned.
	now = now.Add(time.Minute)
	l.prune()
	if len(l.clients) != 0 {
		t.Fatalf("prune left %d clients", len(l.clients))
	}
}

func TestClientKey(t *testing.T) {
	if clientKey("203.0.113.9") != "203.0.113.9" {
		t.Fatal("ipv4 key")
	}
	a, b := clientKey("2001:db8:1:2:aaaa::1"), clientKey("2001:db8:1:2:bbbb::99")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("ipv6 /64 grouping: %q %q", a, b)
	}
	if clientKey("2001:db8:1:3::1") == a {
		t.Fatal("different /64 grouped together")
	}
}
