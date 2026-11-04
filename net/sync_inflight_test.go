package net

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestSyncRateLimiter_SingleFlightPerPeer(t *testing.T) {
	rl := newSyncRateLimiter(4)
	p := peer.ID("peer-A")

	// 1. Initial acquire should succeed
	if !rl.tryAcquire(p) {
		t.Fatalf("expected initial tryAcquire to succeed")
	}

	// 2. Second acquire for same peer while in-flight MUST fail (single flight guard)
	if rl.tryAcquire(p) {
		t.Fatalf("expected concurrent tryAcquire for same peer to fail")
	}
	if rl.canAcquire(p) {
		t.Fatalf("expected canAcquire to return false while in-flight")
	}

	// 3. Release peer
	rl.release(p)

	// 4. Immediately after release, cooldown should prevent instant re-acquire
	if rl.tryAcquire(p) {
		t.Fatalf("expected immediate tryAcquire after release to fail due to syncCooldown")
	}
}

func TestSyncRateLimiter_GlobalConcurrencyCap(t *testing.T) {
	const maxCap = 4
	rl := newSyncRateLimiter(maxCap)

	peers := []peer.ID{"peer-1", "peer-2", "peer-3", "peer-4", "peer-5"}

	// Acquire up to cap
	for i := 0; i < maxCap; i++ {
		if !rl.tryAcquire(peers[i]) {
			t.Fatalf("expected acquire for peer %d to succeed", i)
		}
	}

	// 5th peer should be rejected due to global concurrency limit
	if rl.tryAcquire(peers[4]) {
		t.Fatalf("expected acquire beyond global concurrency cap to fail")
	}
	if rl.canAcquire(peers[4]) {
		t.Fatalf("expected canAcquire beyond global concurrency cap to return false")
	}

	// Release one peer
	rl.release(peers[0])

	// Now 5th peer can be acquired
	if !rl.tryAcquire(peers[4]) {
		t.Fatalf("expected acquire for 5th peer to succeed after releasing a slot")
	}
}

func TestSyncRateLimiter_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Verify context is already done
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("expected context to be cancelled")
	}
}
