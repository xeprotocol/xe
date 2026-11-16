package net

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
)

func TestDialCandidatesConcurrentNonBlocking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mn := mocknet.New()
	h1, err := mn.GenPeer()
	if err != nil {
		t.Fatalf("gen peer: %v", err)
	}

	hGood, err := mn.GenPeer()
	if err != nil {
		t.Fatalf("gen peer: %v", err)
	}

	// Link h1 and hGood so they can connect
	if err := mn.LinkAll(); err != nil {
		t.Fatalf("link all: %v", err)
	}

	ad := &AmbientDiscovery{
		host:   h1,
		target: 10,
	}

	// Candidate 1: Dummy unlinked peer (blackhole / will fail dial)
	hBad, err := mn.GenPeer()
	if err != nil {
		t.Fatalf("gen peer: %v", err)
	}
	// Unlink hBad from h1
	_ = mn.UnlinkPeers(h1.ID(), hBad.ID())

	badCandidate := peer.AddrInfo{
		ID:    hBad.ID(),
		Addrs: hBad.Addrs(),
	}

	goodCandidate := peer.AddrInfo{
		ID:    hGood.ID(),
		Addrs: hGood.Addrs(),
	}

	// Put the failing peer first, followed by the good peer.
	// In the old sequential implementation, if badCandidate stalls or fails, it blocked or took 15s.
	// In concurrent implementation with dialCandidates, good peer connects quickly!
	start := time.Now()
	candidates := []peer.AddrInfo{badCandidate, goodCandidate}
	dialed := ad.dialCandidates(ctx, candidates)
	elapsed := time.Since(start)

	if dialed < 1 {
		t.Fatalf("expected at least 1 successful dial, got %d", dialed)
	}

	if h1.Network().Connectedness(hGood.ID()) != network.Connected {
		t.Fatalf("expected hGood to be connected")
	}

	t.Logf("dialCandidates finished in %v with %d successful connection(s)", elapsed, dialed)
}
