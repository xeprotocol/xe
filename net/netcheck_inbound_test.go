package net

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func generateTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("peer id from pub key: %v", err)
	}
	return pid
}

func TestInboundCap_Sequential(t *testing.T) {
	g := NewNetworkGater()
	g.SetMaxInboundConns(2)

	p1 := generateTestPeerID(t)
	p2 := generateTestPeerID(t)
	p3 := generateTestPeerID(t)

	if !g.InterceptSecured(network.DirInbound, p1, nil) {
		t.Fatalf("expected p1 to be allowed")
	}
	if !g.InterceptSecured(network.DirInbound, p2, nil) {
		t.Fatalf("expected p2 to be allowed")
	}
	if g.InterceptSecured(network.DirInbound, p3, nil) {
		t.Fatalf("expected p3 to be rejected due to maxInbound=2")
	}

	cur, max, refused := g.InboundStats()
	if cur != 2 {
		t.Errorf("expected current inbound 2, got %d", cur)
	}
	if max != 2 {
		t.Errorf("expected max inbound 2, got %d", max)
	}
	if refused != 1 {
		t.Errorf("expected 1 refused, got %d", refused)
	}
}

func TestInboundCap_Concurrent(t *testing.T) {
	g := NewNetworkGater()
	const maxCap = 5
	g.SetMaxInboundConns(maxCap)

	const totalDials = 50
	var allowed atomic.Int64
	var rejected atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < totalDials; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pid := peer.ID(fmt.Sprintf("peer-%d", idx))
			if g.InterceptSecured(network.DirInbound, pid, nil) {
				allowed.Add(1)
			} else {
				rejected.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if allowed.Load() != maxCap {
		t.Fatalf("expected exactly %d allowed concurrent handshakes, got %d", maxCap, allowed.Load())
	}
	if rejected.Load() != totalDials-maxCap {
		t.Fatalf("expected %d rejected handshakes, got %d", totalDials-maxCap, rejected.Load())
	}

	cur, max, refused := g.InboundStats()
	if cur != maxCap {
		t.Errorf("expected current %d, got %d", maxCap, cur)
	}
	if max != maxCap {
		t.Errorf("expected max %d, got %d", maxCap, max)
	}
	if refused != totalDials-maxCap {
		t.Errorf("expected refused %d, got %d", totalDials-maxCap, refused)
	}
}

func TestInboundCap_ConnectedAndDisconnected(t *testing.T) {
	g := NewNetworkGater()
	g.SetMaxInboundConns(1)

	p1 := generateTestPeerID(t)
	p2 := generateTestPeerID(t)

	if !g.InterceptSecured(network.DirInbound, p1, nil) {
		t.Fatalf("p1 should be allowed")
	}
	if g.InterceptSecured(network.DirInbound, p2, nil) {
		t.Fatalf("p2 should be rejected while p1 holds the slot")
	}

	// Confirm p1 connection
	g.inboundConnected(p1)

	// p1 disconnects
	g.inboundDisconnected(p1)

	cur, _, _ := g.InboundStats()
	if cur != 0 {
		t.Fatalf("expected current inbound 0 after disconnect, got %d", cur)
	}

	// Now p2 should be allowed
	if !g.InterceptSecured(network.DirInbound, p2, nil) {
		t.Fatalf("p2 should be allowed after p1 disconnected")
	}
}

func TestInboundCap_TrustedPeersBypass(t *testing.T) {
	g := NewNetworkGater()
	g.SetMaxInboundConns(1)

	trustedPeer := generateTestPeerID(t)
	g.Trust(trustedPeer)

	p1 := generateTestPeerID(t)
	p2 := generateTestPeerID(t)

	// Trusted peer passes without consuming an inbound slot
	if !g.InterceptSecured(network.DirInbound, trustedPeer, nil) {
		t.Fatalf("trusted peer should be allowed")
	}

	cur, _, _ := g.InboundStats()
	if cur != 0 {
		t.Fatalf("trusted peer should not increment untrusted inbound counter, got %d", cur)
	}

	// p1 passes
	if !g.InterceptSecured(network.DirInbound, p1, nil) {
		t.Fatalf("p1 should be allowed")
	}

	// p2 rejected
	if g.InterceptSecured(network.DirInbound, p2, nil) {
		t.Fatalf("p2 should be rejected")
	}
}

func TestInboundCap_OutboundIgnored(t *testing.T) {
	g := NewNetworkGater()
	g.SetMaxInboundConns(1)

	p1 := generateTestPeerID(t)
	p2 := generateTestPeerID(t)

	if !g.InterceptSecured(network.DirOutbound, p1, nil) {
		t.Fatalf("outbound dial should be allowed")
	}
	if !g.InterceptSecured(network.DirOutbound, p2, nil) {
		t.Fatalf("outbound dial should be allowed")
	}

	cur, _, _ := g.InboundStats()
	if cur != 0 {
		t.Fatalf("outbound connections should not consume inbound slots, got %d", cur)
	}
}

func TestInboundCap_ExpirePendingReservation(t *testing.T) {
	g := NewNetworkGater()
	g.SetMaxInboundConns(1)

	p1 := generateTestPeerID(t)
	if !g.InterceptSecured(network.DirInbound, p1, nil) {
		t.Fatalf("p1 should be allowed")
	}

	cur, _, _ := g.InboundStats()
	if cur != 1 {
		t.Fatalf("expected 1 reserved slot, got %d", cur)
	}

	// Manually trigger expiry on timer
	g.pendingMu.Lock()
	list := g.pendingInbound[p1]
	g.pendingMu.Unlock()

	if len(list) != 1 {
		t.Fatalf("expected 1 pending timer, got %d", len(list))
	}

	g.expirePendingInbound(p1, list[0])

	cur, _, _ = g.InboundStats()
	if cur != 0 {
		t.Fatalf("expected 0 slots after expiry, got %d", cur)
	}

	// Now a new handshake can proceed
	p2 := generateTestPeerID(t)
	if !g.InterceptSecured(network.DirInbound, p2, nil) {
		t.Fatalf("p2 should be allowed after previous reservation expired")
	}
}
