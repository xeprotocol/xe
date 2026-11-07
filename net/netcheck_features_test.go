package net

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestNetcheckRejectsExcessiveDuplicateOrMalformedFeatures(t *testing.T) {
	ours := netcheckMsg{
		NetworkID:   "xe-mainnet",
		Version:     NetcheckVersion,
		GenesisHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Features:    []string{"noop"},
	}

	// Negative control: valid deduplicated features within maxAdvertisedFeatures succeed.
	validMsg := ours
	validMsg.Features = []string{"noop", "lease_renew"}
	if reason, _ := checkPeer(validMsg, ours); reason != "" {
		t.Fatalf("valid netcheckMsg rejected: %s", reason)
	}

	// Duplicate features in netcheck handshake must be rejected or deduplicated.
	dupMsg := ours
	dupMsg.Features = []string{"noop", "noop"}
	if reason, _ := checkPeer(dupMsg, ours); reason == "" {
		t.Fatalf("expected checkPeer to reject duplicate advertised features")
	}

	// More than maxAdvertisedFeatures (8) must be rejected.
	tooMany := ours
	tooMany.Features = []string{"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"}
	if reason, _ := checkPeer(tooMany, ours); reason == "" {
		t.Fatalf("expected checkPeer to reject >%d advertised features", maxAdvertisedFeatures)
	}

	// Invalid feature name charset (uppercase / spaces / empty) must be rejected.
	badName := ours
	badName.Features = []string{"INVALID FEATURE!"}
	if reason, _ := checkPeer(badName, ours); reason == "" {
		t.Fatalf("expected checkPeer to reject invalid feature name")
	}

	// Defense-in-depth: RecordPeerCapabilities sanitizes, deduplicates, and caps stored features.
	gater := NewNetworkGater()
	pid := peer.ID("12D3KooWTestPeerCapSanitize11111111111111111")
	gater.RecordPeerCapabilities(pid, PeerCapabilities{
		Version:  NetcheckVersion,
		Features: []string{"noop", "noop", "BAD!", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"},
	})
	caps, ok := gater.PeerCapabilities(pid)
	if !ok {
		t.Fatalf("expected capabilities to be recorded")
	}
	if len(caps.Features) > maxAdvertisedFeatures {
		t.Fatalf("stored Features len = %d, want <= %d", len(caps.Features), maxAdvertisedFeatures)
	}
	seen := map[string]bool{}
	for _, f := range caps.Features {
		if seen[f] {
			t.Fatalf("stored Features contains duplicate %q: %v", f, caps.Features)
		}
		seen[f] = true
		if f == "BAD!" {
			t.Fatalf("stored Features retained invalid feature name %q", f)
		}
	}
}
