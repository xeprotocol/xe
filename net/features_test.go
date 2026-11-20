package net

import (
	"strconv"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

func TestSanitizePeerCapabilities(t *testing.T) {
	// Unknown features should be completely stripped
	input := PeerCapabilities{
		Version:  "1.0.0",
		Features: []string{"nonexistent-feature-xyz", core.FeatureNoop, "another-fake-feature"},
	}
	sanitized := SanitizePeerCapabilities(input)

	if len(sanitized.Features) != 1 {
		t.Fatalf("expected 1 feature, got %d: %v", len(sanitized.Features), sanitized.Features)
	}
	if sanitized.Features[0] != core.FeatureNoop {
		t.Fatalf("expected feature %s, got %s", core.FeatureNoop, sanitized.Features[0])
	}

	// Duplicates should be pruned
	inputDup := PeerCapabilities{
		Version:  "1.0.0",
		Features: []string{core.FeatureNoop, core.FeatureNoop, core.FeatureNoop},
	}
	sanitizedDup := SanitizePeerCapabilities(inputDup)
	if len(sanitizedDup.Features) != 1 {
		t.Fatalf("expected duplicate features to be deduplicated, got %d", len(sanitizedDup.Features))
	}

	// Feature count should be capped at maxAdvertisedFeatures
	var manyFeatures []string
	for i := 0; i < maxAdvertisedFeatures*2; i++ {
		// Even if multiple known features existed or were repeated
		manyFeatures = append(manyFeatures, "fake-"+strconv.Itoa(i))
	}
	sanitizedMany := SanitizePeerCapabilities(PeerCapabilities{Features: manyFeatures})
	if len(sanitizedMany.Features) != 0 {
		t.Fatalf("expected 0 known features from fakes, got %d", len(sanitizedMany.Features))
	}
}

func TestRecordPeerCapabilitiesSanitization(t *testing.T) {
	gater := NewNetworkGater()
	pid := peer.ID("peer-test-id")

	gater.RecordPeerCapabilities(pid, PeerCapabilities{
		Version:  "1.2.3",
		Features: []string{"fake-feat-1", core.FeatureNoop, "fake-feat-2"},
	})

	caps, ok := gater.PeerCapabilities(pid)
	if !ok {
		t.Fatalf("expected capabilities to be found for peer")
	}
	if caps.Version != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %s", caps.Version)
	}
	if len(caps.Features) != 1 || caps.Features[0] != core.FeatureNoop {
		t.Fatalf("expected only core.FeatureNoop to be stored, got: %v", caps.Features)
	}
}
