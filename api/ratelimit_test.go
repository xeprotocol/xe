package api

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterLRUEviction(t *testing.T) {
	rl := newIPRateLimiter(readRate, readBurst)

	// Populate map up to maxRateLimiterIPs
	for i := 0; i < maxRateLimiterIPs; i++ {
		rl.getLimiter(fmt.Sprintf("10.0.0.%d", i))
	}

	if len(rl.entries) != maxRateLimiterIPs {
		t.Fatalf("expected entries len %d, got %d", maxRateLimiterIPs, len(rl.entries))
	}

	// Touch the first IP (10.0.0.0) to promote it to the front of the LRU
	promoted := rl.getLimiter("10.0.0.0")
	if !promoted.Allow() {
		t.Fatalf("expected promoted IP to allow requests")
	}

	// Request with a brand new IP; should evict the least recently used entry (10.0.0.1)
	freshIP := "203.0.113.1"
	freshLimiter := rl.getLimiter(freshIP)
	if freshLimiter == nil {
		t.Fatalf("expected non-nil limiter for fresh IP")
	}

	// Fresh IP MUST allow requests rather than failing closed with zero rate
	if !freshLimiter.Allow() {
		t.Fatalf("expected fresh IP to allow requests under LRU eviction, got denied")
	}

	// Verify map length remains bounded
	if len(rl.entries) != maxRateLimiterIPs {
		t.Fatalf("expected entries to remain bounded at %d, got %d", maxRateLimiterIPs, len(rl.entries))
	}

	// 10.0.0.0 was promoted, so it must still exist in the map
	rl.mu.Lock()
	if _, ok := rl.entries["10.0.0.0"]; !ok {
		rl.mu.Unlock()
		t.Fatalf("expected promoted IP 10.0.0.0 to still be in entries")
	}

	// 10.0.0.1 was least recently used, so it must have been evicted
	if _, ok := rl.entries["10.0.0.1"]; ok {
		rl.mu.Unlock()
		t.Fatalf("expected LRU IP 10.0.0.1 to have been evicted")
	}

	// Fresh IP must exist in entries
	if _, ok := rl.entries[freshIP]; !ok {
		rl.mu.Unlock()
		t.Fatalf("expected fresh IP %s to be in entries", freshIP)
	}
	rl.mu.Unlock()
}

func TestRateLimiterSweep(t *testing.T) {
	rl := newIPRateLimiter(readRate, readBurst)

	// Add an entry with artificially expired lastSeen
	rl.getLimiter("192.168.1.1")
	rl.getLimiter("192.168.1.2")

	rl.mu.Lock()
	if e, ok := rl.entries["192.168.1.1"]; ok {
		e.lastSeen = time.Now().Add(-rateLimiterTTL - time.Minute)
	}
	rl.mu.Unlock()

	// Perform a sweep by simulating the sweep logic
	rl.mu.Lock()
	cutoff := time.Now().Add(-rateLimiterTTL)
	for elem := rl.lru.Back(); elem != nil; {
		prev := elem.Prev()
		ip, _ := elem.Value.(string)
		e := rl.entries[ip]
		if e != nil && e.lastSeen.Before(cutoff) {
			rl.lru.Remove(elem)
			delete(rl.entries, ip)
			elem = prev
		} else {
			break
		}
	}
	rl.mu.Unlock()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.entries["192.168.1.1"]; ok {
		t.Fatalf("expected expired entry to be swept")
	}
	if _, ok := rl.entries["192.168.1.2"]; !ok {
		t.Fatalf("expected active entry to remain")
	}
}
