package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
)

func TestReadinessIgnoresNonexistentFeatures(t *testing.T) {
	s := store.NewMemStore()
	defer s.Close()

	ledger := core.NewLedger(s, core.LedgerConfig{})

	kpNode, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate node keypair: %v", err)
	}

	kpRep, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate rep keypair: %v", err)
	}

	gater := xenet.NewNetworkGater()
	dir := directory.New(1 * time.Hour)

	peerIDStr := "12D3KooWTestPeerID12345678901234567890123456789012"
	pid, _ := peer.Decode(peerIDStr)

	// Register representative in directory
	reg := directory.NewRegistration(peerIDStr, time.Now().UnixNano(), kpRep)
	_ = dir.Register(reg)

	// Record peer capabilities with an unknown fake feature and a known feature
	fakeFeature := "fake-feature-xyz"
	gater.RecordPeerCapabilities(pid, xenet.PeerCapabilities{
		Version:  "1.0.0",
		Features: []string{fakeFeature, core.FeatureNoop},
	})

	n := &Node{
		Ledger:    ledger,
		KeyPair:   kpNode,
		gater:     gater,
		Directory: dir,
	}

	readiness := n.GetReadiness()

	// Verify that fake feature is neither in FeatureWeight nor FeatureReadyMilli
	if w, exists := readiness.FeatureWeight[fakeFeature]; exists && w > 0 {
		t.Fatalf("expected unknown feature %q to have 0 weight, got %d", fakeFeature, w)
	}
	if milli, exists := readiness.FeatureReadyMilli[fakeFeature]; exists && milli > 0 {
		t.Fatalf("expected unknown feature %q to have 0 ready milli, got %d", fakeFeature, milli)
	}
}
