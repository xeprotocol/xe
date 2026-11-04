package net

import (
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestPeerRateLimiter_LRUEviction(t *testing.T) {
	// Replicates issue #47 PoC: active victim should NOT be evicted by newer peers
	maxPeers := 10
	l := newPeerRateLimiter(50, 10, 200, 20, maxPeers)

	victim := peer.ID("victim-peer-id")
	other := peer.ID("other-peer-id")

	// 1. Insert other first
	l.allowPeer(other)

	// 2. Insert victim and consume all tokens
	for i := 0; i < 10; i++ {
		l.allowPeer(victim)
	}
	// Verify victim is exhausted
	if l.allowPeer(victim) {
		t.Fatalf("expected victim to be rate-limited")
	}

	// 3. Insert newer peers up to capacity - 1
	for i := 0; i < maxPeers-2; i++ {
		p := peer.ID(fmt.Sprintf("peer-%d", i))
		l.allowPeer(p)
	}

	// 4. Access victim again (denied, but moves victim to back of LRU!)
	l.allowPeer(victim)

	// 5. Insert one more peer to trigger eviction
	l.allowPeer(peer.ID("overflow-peer"))

	// 6. 'other' was least recently used, so it must be evicted.
	// Victim was recently accessed, so its bucket must remain intact (still exhausted, NOT granted fresh burst)
	if l.allowPeer(victim) {
		t.Fatalf("victim bucket was prematurely evicted, allowing fresh burst!")
	}
}

func TestPeerRateLimiter_PerIPRateLimit(t *testing.T) {
	// Replicates issue #47 attack: 8 peer IDs on 1 IP trying to amplify burst
	l := newPeerRateLimiter(50, 20, 200, 200, 100)

	sharedIP := "198.51.100.1"

	// 8 different peers on the same IP
	totalAllowed := 0
	for pIdx := 0; pIdx < 8; pIdx++ {
		p := peer.ID(fmt.Sprintf("peer-sybil-%d", pIdx))
		for req := 0; req < 10; req++ {
			if l.allowPeerAndIP(p, sharedIP) {
				totalAllowed++
			}
		}
	}

	// With per-IP burst = 20, at most 20 requests should be allowed across ALL 8 peers!
	// Without per-IP limiting, 8 * 10 = 80 requests would pass.
	if totalAllowed > 21 {
		t.Fatalf("expected at most 20 allowed across same IP, got %d (Sybil amplification not prevented)", totalAllowed)
	}
}

func TestRemoteIPFromMultiaddr(t *testing.T) {
	addr, err := ma.NewMultiaddr("/ip4/203.0.113.19/tcp/12345")
	if err != nil {
		t.Fatalf("NewMultiaddr: %v", err)
	}
	if ip := remoteIPFromMultiaddr(addr); ip != "203.0.113.19" {
		t.Fatalf("expected 203.0.113.19, got %q", ip)
	}

	addr6, err := ma.NewMultiaddr("/ip6/2001:db8::1/tcp/12345")
	if err != nil {
		t.Fatalf("NewMultiaddr: %v", err)
	}
	if ip := remoteIPFromMultiaddr(addr6); ip != "2001:db8::1" {
		t.Fatalf("expected 2001:db8::1, got %q", ip)
	}
}
