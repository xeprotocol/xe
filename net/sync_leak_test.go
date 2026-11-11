package net

import (
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestSyncTracker_NoResurrectionAfterRemovePeer(t *testing.T) {
	st := newSyncTracker()
	pid := peer.ID("test-peer-12345")

	frontiers := map[string]string{
		"acc1": "hash1",
		"acc2": "hash2",
	}

	// 1. Peer connects
	st.addPeer(pid)

	// 2. Normal sync records frontiers
	st.recordSync(pid, frontiers)
	if len(st.lastFrontiers[pid]) != 2 {
		t.Fatalf("expected 2 frontiers recorded, got %d", len(st.lastFrontiers[pid]))
	}

	// 3. Peer disconnects -> removePeer cleans up
	st.removePeer(pid)
	if len(st.lastFrontiers[pid]) != 0 {
		t.Fatalf("expected frontiers to be cleared on removePeer, got %d", len(st.lastFrontiers[pid]))
	}

	// 4. Delayed recordSync arrives after disconnect -> must NOT resurrect frontiers
	st.recordSync(pid, frontiers)
	if _, ok := st.lastFrontiers[pid]; ok {
		t.Fatalf("BUG: recordSync resurrected lastFrontiers for disconnected peer")
	}

	// 5. Delayed recordRejections arrives after disconnect -> must NOT resurrect rejections
	st.recordRejections(pid, []string{"acc1"})
	if _, ok := st.rejections[pid]; ok {
		t.Fatalf("BUG: recordRejections resurrected rejections for disconnected peer")
	}

	// 6. Delayed markSyncIncapable arrives after disconnect -> must NOT resurrect syncIncapable
	st.markSyncIncapable(pid)
	if _, ok := st.syncIncapable[pid]; ok {
		t.Fatalf("BUG: markSyncIncapable resurrected syncIncapable for disconnected peer")
	}
}

func TestSyncTracker_RejectionListBounded(t *testing.T) {
	st := newSyncTracker()
	pid := peer.ID("test-peer-rejection-cap")

	st.addPeer(pid)

	// Attacker sends 5,000 rejected accounts
	const total = 5000
	rejected := make([]string, total)
	for i := 0; i < total; i++ {
		rejected[i] = fmt.Sprintf("acc-%d", i)
	}

	st.recordRejections(pid, rejected)

	if len(st.rejections[pid]) > maxRejectedAccounts {
		t.Fatalf("expected rejections capped at %d, got %d", maxRejectedAccounts, len(st.rejections[pid]))
	}
	if len(st.rejections[pid]) != maxRejectedAccounts {
		t.Fatalf("expected exactly %d rejections, got %d", maxRejectedAccounts, len(st.rejections[pid]))
	}
}
