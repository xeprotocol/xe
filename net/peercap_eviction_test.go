package net

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func genTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 256, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	return pid
}

func TestPeerCapTable_ProtectedAgainstThrowawayFlood(t *testing.T) {
	// Replicates the scenario in Issue #301:
	// A legitimate representative advertises "messaging".
	// An attacker floods 4096 throwaway identities.
	// The legitimate representative MUST remain in the table and retain its capabilities.
	table := newPeerCapTable(maxPeerCapEntries)

	legitPeer := genTestPeerID(t)
	connectedPeers := map[peer.ID]bool{
		legitPeer: true,
	}

	table.setRetainPolicy(func(p peer.ID) bool {
		return connectedPeers[p]
	})

	table.record(legitPeer, PeerCapabilities{
		Version:  NetcheckVersion,
		Features: []string{"messaging"},
	})

	// Record 4,096 throwaway peer IDs (simulating disconnected churn)
	for i := 0; i < maxPeerCapEntries; i++ {
		throwaway := peer.ID(fmt.Sprintf("throwaway-peer-%05d", i))
		table.record(throwaway, PeerCapabilities{
			Version:  NetcheckVersion,
			Features: []string{"noop"},
		})
	}

	// Verify table size is exactly maxPeerCapEntries
	all := table.all()
	if len(all) != maxPeerCapEntries {
		t.Fatalf("table size = %d, want %d", len(all), maxPeerCapEntries)
	}

	// Verify the legitimate peer was NOT evicted
	caps, ok := table.get(legitPeer)
	if !ok {
		t.Fatalf("vulnerability reproduced: legitimate peer was evicted after %d throwaway identities", maxPeerCapEntries)
	}
	if !caps.HasFeature("messaging") {
		t.Fatalf("expected legitimate peer to have 'messaging' feature")
	}
}

func TestPeerCapTable_EvictsDisconnectedFirst(t *testing.T) {
	// Small table of capacity 3
	table := newPeerCapTable(3)

	pConn := peer.ID("peer-connected")
	pDisc1 := peer.ID("peer-disconnected-1")
	pDisc2 := peer.ID("peer-disconnected-2")

	connected := map[peer.ID]bool{
		pConn: true,
	}
	table.setRetainPolicy(func(p peer.ID) bool {
		return connected[p]
	})

	table.record(pConn, PeerCapabilities{Version: "1.0.0"})
	table.record(pDisc1, PeerCapabilities{Version: "1.0.0"})
	table.record(pDisc2, PeerCapabilities{Version: "1.0.0"})

	if len(table.all()) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(table.all()))
	}

	// Adding a 4th peer (disconnected) should evict oldest disconnected (pDisc1)
	pDisc3 := peer.ID("peer-disconnected-3")
	table.record(pDisc3, PeerCapabilities{Version: "1.0.0"})

	if _, ok := table.get(pConn); !ok {
		t.Fatalf("pConn should remain protected")
	}
	if _, ok := table.get(pDisc1); ok {
		t.Fatalf("pDisc1 should have been evicted first")
	}
	if _, ok := table.get(pDisc2); !ok {
		t.Fatalf("pDisc2 should remain")
	}
	if _, ok := table.get(pDisc3); !ok {
		t.Fatalf("pDisc3 should be present")
	}

	// Adding a 5th peer (disconnected) should evict next disconnected (pDisc2)
	pDisc4 := peer.ID("peer-disconnected-4")
	table.record(pDisc4, PeerCapabilities{Version: "1.0.0"})

	if _, ok := table.get(pConn); !ok {
		t.Fatalf("pConn must still remain protected")
	}
	if _, ok := table.get(pDisc2); ok {
		t.Fatalf("pDisc2 should have been evicted")
	}
}

func TestPeerCapTable_FallbackWhenAllRetained(t *testing.T) {
	// If all entries are retained, table capacity bound is strictly honored via FIFO
	table := newPeerCapTable(3)
	table.setRetainPolicy(func(p peer.ID) bool {
		return true // all retained
	})

	p1 := peer.ID("p1")
	p2 := peer.ID("p2")
	p3 := peer.ID("p3")
	p4 := peer.ID("p4")

	table.record(p1, PeerCapabilities{Version: "1.0.0"})
	table.record(p2, PeerCapabilities{Version: "1.0.0"})
	table.record(p3, PeerCapabilities{Version: "1.0.0"})
	table.record(p4, PeerCapabilities{Version: "1.0.0"})

	if len(table.all()) != 3 {
		t.Fatalf("table size = %d, want 3", len(table.all()))
	}
	// p1 was oldest, should be evicted as fallback
	if _, ok := table.get(p1); ok {
		t.Fatalf("p1 should be evicted under fallback FIFO")
	}
	if _, ok := table.get(p2); !ok {
		t.Fatalf("p2 should be present")
	}
	if _, ok := table.get(p4); !ok {
		t.Fatalf("p4 should be present")
	}
}

func TestPeerCapTable_LRURefresh(t *testing.T) {
	table := newPeerCapTable(3)

	p1 := peer.ID("p1")
	p2 := peer.ID("p2")
	p3 := peer.ID("p3")
	p4 := peer.ID("p4")

	table.record(p1, PeerCapabilities{Version: "1.0.0"})
	table.record(p2, PeerCapabilities{Version: "1.0.0"})
	table.record(p3, PeerCapabilities{Version: "1.0.0"})

	// Refresh p1: re-recording p1 moves it to back of order
	table.record(p1, PeerCapabilities{Version: "1.0.1"})

	// Record p4: should evict least recently used (p2, not p1)
	table.record(p4, PeerCapabilities{Version: "1.0.0"})

	if _, ok := table.get(p1); !ok {
		t.Fatalf("p1 should have been kept due to LRU refresh")
	}
	if _, ok := table.get(p2); ok {
		t.Fatalf("p2 should have been evicted as least recently used")
	}
	if _, ok := table.get(p3); !ok {
		t.Fatalf("p3 should be present")
	}
	if _, ok := table.get(p4); !ok {
		t.Fatalf("p4 should be present")
	}
}

func TestPeerCapTable_RemovePeer(t *testing.T) {
	table := newPeerCapTable(3)
	p1 := peer.ID("p1")
	table.record(p1, PeerCapabilities{Version: "1.0.0"})

	if _, ok := table.get(p1); !ok {
		t.Fatalf("expected p1 to be present")
	}

	table.remove(p1)
	if _, ok := table.get(p1); ok {
		t.Fatalf("expected p1 to be removed")
	}
	if len(table.all()) != 0 {
		t.Fatalf("expected empty table after remove")
	}
}

func TestNetworkGater_TrustedPeerProtectedFromEviction(t *testing.T) {
	gater := NewNetworkGater()
	gater.SetMaxPeerCapEntries(5)

	trustedPeer := peer.ID("trusted-peer-12345")
	gater.Trust(trustedPeer)

	gater.RecordPeerCapabilities(trustedPeer, PeerCapabilities{
		Version:  NetcheckVersion,
		Features: []string{"messaging"},
	})

	// Flood 10 untrusted peers into table with max 5
	for i := 0; i < 10; i++ {
		untrusted := peer.ID(fmt.Sprintf("untrusted-%d", i))
		gater.RecordPeerCapabilities(untrusted, PeerCapabilities{
			Version: NetcheckVersion,
		})
	}

	caps, ok := gater.PeerCapabilities(trustedPeer)
	if !ok {
		t.Fatalf("trusted peer was evicted from capability table")
	}
	if !caps.HasFeature("messaging") {
		t.Fatalf("expected trusted peer to have messaging feature")
	}
}
