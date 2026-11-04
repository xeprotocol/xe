package api

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestIPRateLimiter_LRUEviction(t *testing.T) {
	// Replicates issue #172: when capacity is reached, LRU entry is evicted
	// and new IPs are NOT denied with rate.NewLimiter(0, 0).
	maxIPs := 5
	rl := &ipRateLimiter{
		entries: make(map[string]*rateLimiterEntry),
		lru:     new(ipRateLimiter).lru, // will be created
		rate:    rate.Limit(10),
		burst:   5,
		max:     maxIPs,
	}
	rl = newIPRateLimiter(rate.Limit(10), 5)
	rl.max = maxIPs

	// 1. Fill limiter with 5 IPs
	for i := 1; i <= maxIPs; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		lim := rl.getLimiter(ip)
		if lim == nil || !lim.Allow() {
			t.Fatalf("expected initial IP %s to be allowed", ip)
		}
	}

	// 2. Touch 10.0.0.1 to make it most recently used
	lim1 := rl.getLimiter("10.0.0.1")
	if lim1 == nil || !lim1.Allow() {
		t.Fatalf("expected 10.0.0.1 to be allowed")
	}

	// 3. Add a 6th IP (10.0.0.6) - capacity is 5, so least recently used (10.0.0.2) must be evicted
	lim6 := rl.getLimiter("10.0.0.6")
	if lim6 == nil || !lim6.Allow() {
		t.Fatalf("expected 10.0.0.6 to be allowed after eviction, not denied with 0/0 limiter (#172)")
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.entries) != maxIPs {
		t.Fatalf("expected exactly %d entries, got %d", maxIPs, len(rl.entries))
	}

	// 10.0.0.2 was LRU and must be evicted
	if _, ok := rl.entries["10.0.0.2"]; ok {
		t.Fatalf("expected 10.0.0.2 to be evicted")
	}

	// 10.0.0.1 was touched and must still be present
	if _, ok := rl.entries["10.0.0.1"]; !ok {
		t.Fatalf("expected 10.0.0.1 to remain in map")
	}

	// 10.0.0.6 must be present
	if _, ok := rl.entries["10.0.0.6"]; !ok {
		t.Fatalf("expected 10.0.0.6 to be in map")
	}
}

func TestIPRateLimiter_NoZeroLimiterOnCapacity(t *testing.T) {
	// Replicates issue #172 cliff test:
	// Verify that reaching max does not cause subsequent new IPs to receive a 0/0 permanent deny limiter.
	maxIPs := 3
	rl := newIPRateLimiter(rate.Limit(100), 10)
	rl.max = maxIPs

	// Add 50 distinct IPs
	for i := 0; i < 50; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		lim := rl.getLimiter(ip)
		if lim == nil {
			t.Fatalf("nil limiter returned for %s", ip)
		}
		if lim.Limit() == 0 {
			t.Fatalf("limiter for IP %s has rate 0 (permanent deny cliff from #172)", ip)
		}
		if !lim.Allow() {
			t.Fatalf("expected first request from new IP %s to be allowed", ip)
		}
	}

	rl.mu.Lock()
	count := len(rl.entries)
	rl.mu.Unlock()

	if count != maxIPs {
		t.Fatalf("expected entries count to be bounded to %d, got %d", maxIPs, count)
	}
}

func TestIPRateLimiter_SweepExpired(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 5)
	rl.getLimiter("10.1.1.1")
	rl.getLimiter("10.1.1.2")

	rl.mu.Lock()
	// Manually age 10.1.1.1 past TTL
	rl.entries["10.1.1.1"].lastSeen = time.Now().Add(-rateLimiterTTL - time.Second)
	cutoff := time.Now().Add(-rateLimiterTTL)
	for ip, e := range rl.entries {
		if e.lastSeen.Before(cutoff) {
			if e.element != nil {
				rl.lru.Remove(e.element)
			}
			delete(rl.entries, ip)
		}
	}
	remaining := len(rl.entries)
	lruLen := rl.lru.Len()
	rl.mu.Unlock()

	if remaining != 1 {
		t.Fatalf("expected 1 remaining entry after sweep, got %d", remaining)
	}
	if lruLen != 1 {
		t.Fatalf("expected 1 item in LRU list after sweep, got %d", lruLen)
	}
}
