package api

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiter_LRUEviction(t *testing.T) {
	const cap = 3
	rl := newIPRateLimiterWithCapacity(10, 10, cap)

	// Add 3 distinct IPs
	rl.getLimiter("192.0.2.1")
	rl.getLimiter("192.0.2.2")
	rl.getLimiter("192.0.2.3")

	if len(rl.entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.entries))
	}

	// Access 192.0.2.1 to make it most recently used
	rl.getLimiter("192.0.2.1")

	// Add 4th IP -> should evict 192.0.2.2 (which is now the least recently used)
	victim := rl.getLimiter("192.0.2.4")
	if !victim.Allow() {
		t.Fatalf("expected new IP to be allowed after eviction, got rate limit deny")
	}

	if len(rl.entries) != 3 {
		t.Fatalf("expected cap of 3 preserved, got %d", len(rl.entries))
	}

	// 192.0.2.2 should have been evicted
	if _, ok := rl.entries["192.0.2.2"]; ok {
		t.Fatalf("expected 192.0.2.2 to be evicted")
	}

	// 192.0.2.1 and 192.0.2.3 and 192.0.2.4 must still be present
	for _, ip := range []string{"192.0.2.1", "192.0.2.3", "192.0.2.4"} {
		if _, ok := rl.entries[ip]; !ok {
			t.Fatalf("expected %s to be present in entries", ip)
		}
	}
}

func TestRateLimiter_NeverDenyOnMapCapacity(t *testing.T) {
	const cap = 50
	rl := newIPRateLimiterWithCapacity(readRate, readBurst, cap)

	// Fill up to cap
	for i := 0; i < cap; i++ {
		rl.getLimiter(fmt.Sprintf("10.0.0.%d", i))
	}

	// Requesting an unknown IP must succeed and allow traffic
	fresh := rl.getLimiter("198.51.100.1")
	if !fresh.Allow() {
		t.Fatalf("expected fresh IP to allow requests, but got rate limit denial (fail-closed bug)")
	}

	// Map size must remain at cap
	if len(rl.entries) != cap {
		t.Fatalf("expected map size to stay at %d, got %d", cap, len(rl.entries))
	}
}

func TestRateLimiter_IPv6SubnetGrouping(t *testing.T) {
	rl := newIPRateLimiterWithCapacity(1, 1, 100)

	// Two addresses in the same /64
	addr1 := "2001:db8:abcd:0012::1"
	addr2 := "2001:db8:abcd:0012::ffff"

	lim1 := rl.getLimiter(addr1)
	lim2 := rl.getLimiter(addr2)

	// Both should share the same rate.Limiter instance
	if lim1 != lim2 {
		t.Fatalf("expected addresses in same /64 to share rate limiter instance")
	}

	// Consume the single token
	if !lim1.Allow() {
		t.Fatalf("first request should be allowed")
	}

	// Second request from addr2 in the same /64 must be throttled
	if lim2.Allow() {
		t.Fatalf("second request from same /64 should be rate limited")
	}

	// Address in a different /64 prefix
	addr3 := "2001:db8:abcd:0013::1"
	lim3 := rl.getLimiter(addr3)
	if lim3 == lim1 {
		t.Fatalf("different /64 should get distinct limiter")
	}
	if !lim3.Allow() {
		t.Fatalf("request from different /64 should be allowed")
	}
}

func TestRateLimiter_SweepExpired(t *testing.T) {
	rl := newIPRateLimiterWithCapacity(10, 10, 100)

	rl.getLimiter("1.1.1.1")
	rl.getLimiter("2.2.2.2")

	// Artificially age 1.1.1.1 past TTL
	rl.mu.Lock()
	rl.entries["1.1.1.1"].lastSeen = time.Now().Add(-rateLimiterTTL - time.Second)
	rl.sweepExpiredLocked(time.Now())
	rl.mu.Unlock()

	if _, ok := rl.entries["1.1.1.1"]; ok {
		t.Fatalf("expected expired entry 1.1.1.1 to be swept")
	}
	if _, ok := rl.entries["2.2.2.2"]; !ok {
		t.Fatalf("expected active entry 2.2.2.2 to remain")
	}
}
