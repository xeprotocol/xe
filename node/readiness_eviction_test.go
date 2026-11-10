package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
)

func seedLedgerWithDelegatedWeightsHelper(t *testing.T, weights map[string]uint64) *core.Ledger {
	t.Helper()
	ms := store.NewMemStore()

	genesis, err := core.LoadGenesisBlock()
	if err != nil {
		t.Fatalf("LoadGenesisBlock: %v", err)
	}
	if err := ms.CommitBlock(&core.BlockCommit{
		Block:        genesis,
		Account:      genesis.Account,
		Chain:        &core.AccountChain{Blocks: []*core.Block{genesis}},
		FrontierHash: genesis.Hash,
	}); err != nil {
		t.Fatalf("CommitBlock(genesis): %v", err)
	}

	for rep, w := range weights {
		kp, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		acc := kp.Address()
		blk := &core.Block{
			Type:           core.BlockReceive,
			Account:        acc,
			Previous:       "0",
			Balance:        w,
			Timestamp:      1,
			Asset:          "XE",
			Representative: rep,
			PubKey:         kp.PubKeyHex(),
			Hash:           acc,
		}
		if err := ms.CommitBlock(&core.BlockCommit{
			Block:         blk,
			Account:       acc,
			Chain:         &core.AccountChain{Blocks: []*core.Block{blk}},
			FrontierHash:  blk.Hash,
			DelegationRep: rep,
			PutAccountKey: kp.PubKeyHex(),
		}); err != nil {
			t.Fatalf("CommitBlock(%s): %v", acc, err)
		}
	}

	return core.NewLedger(ms, core.LedgerConfig{})
}

func TestReadiness_ThrowawayIdentityFloodDoesNotBlindReadiness(t *testing.T) {
	// Replicates the end-to-end vulnerability described in Issue #301:
	// A representative with 10,000 delegated weight advertises "messaging".
	// An attacker floods 4096 throwaway identities.
	// GetReadiness must resolve the representative, count its weight towards
	// FeatureWeight, and report FeatureReadyMilli at 1000 (100%), not 0 (unready).
	repKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(rep): %v", err)
	}
	localKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(local): %v", err)
	}

	const repWeight uint64 = 10_000
	ledger := seedLedgerWithDelegatedWeightsHelper(t, map[string]uint64{
		repKP.Address(): repWeight,
	})

	dir := directory.New(directory.DefaultTTL)
	now := time.Now().UnixNano()
	repPeer := peer.ID("12D3KooWLegitRepPeer11111111111111111111111111")

	if err := dir.Register(directory.NewRegistration(repPeer.String(), now, repKP)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	gater := xenet.NewNetworkGater()
	n := &Node{
		Ledger:    ledger,
		Directory: dir,
		KeyPair:   localKP,
		gater:     gater,
	}

	// Apply retain policy that protects delegated representative peers
	baseRetain := gater.PeerRetainPolicy()
	gater.SetPeerRetainPolicy(func(p peer.ID) bool {
		if baseRetain != nil && baseRetain(p) {
			return true
		}
		return n.IsDelegatedRepPeer(p.String())
	})

	// Legitimate representative registers capabilities
	gater.RecordPeerCapabilities(repPeer, xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: []string{"messaging"},
	})

	// Attacker floods 4096 throwaway peer handshakes
	for i := 0; i < 4096; i++ {
		throwaway := peer.ID(fmt.Sprintf("throwaway-peer-%05d", i))
		gater.RecordPeerCapabilities(throwaway, xenet.PeerCapabilities{
			Version:  xenet.NetcheckVersion,
			Features: []string{"noop"},
		})
	}

	// Verify readiness
	readiness := n.GetReadiness()
	if readiness.TotalWeight != repWeight {
		t.Fatalf("TotalWeight = %d, want %d", readiness.TotalWeight, repWeight)
	}
	if readiness.UnknownWeight != 0 {
		t.Fatalf("UnknownWeight = %d, want 0 (representative was evicted by throwaways!)", readiness.UnknownWeight)
	}
	if readiness.ResolvedReps != 1 {
		t.Fatalf("ResolvedReps = %d, want 1", readiness.ResolvedReps)
	}
	if got := readiness.FeatureWeight["messaging"]; got != repWeight {
		t.Fatalf("FeatureWeight[\"messaging\"] = %d, want %d", got, repWeight)
	}
	if got := readiness.FeatureReadyMilli["messaging"]; got != 1000 {
		t.Fatalf("FeatureReadyMilli[\"messaging\"] = %d, want 1000 (readiness gate blinded!)", got)
	}
}

func TestReadiness_DirectorySelfRegistrationThrowawaysCannotEvictDelegatedRep(t *testing.T) {
	// Replicates the scenario in Issue #304:
	// A legitimate representative holds delegated weight and registers in the directory.
	// An attacker generates 4096 throwaway keypairs and self-registers each in the directory.
	// Since directory self-registration is free and requires no stake/delegation,
	// the node's retain policy must NOT grant retain protection to throwaways without delegated weight,
	// and incoming throwaways must NOT displace the legitimate representative.
	repKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(rep): %v", err)
	}
	localKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(local): %v", err)
	}

	const repWeight uint64 = 50_000
	ledger := seedLedgerWithDelegatedWeightsHelper(t, map[string]uint64{
		repKP.Address(): repWeight,
	})

	dir := directory.New(directory.DefaultTTL)
	now := time.Now().UnixNano()
	repPeer := peer.ID("12D3KooWLegitDelegatedRepPeer11111111111111111")

	if err := dir.Register(directory.NewRegistration(repPeer.String(), now, repKP)); err != nil {
		t.Fatalf("Register(rep): %v", err)
	}

	gater := xenet.NewNetworkGater()
	n := &Node{
		Ledger:    ledger,
		Directory: dir,
		KeyPair:   localKP,
		gater:     gater,
	}

	baseRetain := gater.PeerRetainPolicy()
	gater.SetPeerRetainPolicy(func(p peer.ID) bool {
		if baseRetain != nil && baseRetain(p) {
			return true
		}
		return n.IsDelegatedRepPeer(p.String())
	})

	// Verify IsDelegatedRepPeer identifies the legitimate rep
	if !n.IsDelegatedRepPeer(repPeer.String()) {
		t.Fatalf("expected IsDelegatedRepPeer to be true for legitimate rep with delegated weight")
	}

	// Record legitimate rep capabilities
	gater.RecordPeerCapabilities(repPeer, xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: []string{"messaging"},
	})

	// Attacker generates and registers 4096 throwaway identities in the directory
	for i := 0; i < 4096; i++ {
		throwawayKP, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair(throwaway): %v", err)
		}
		throwawayPeer := peer.ID(fmt.Sprintf("12D3KooWThrowawayPeer%05d11111111111111111", i))
		if err := dir.Register(directory.NewRegistration(throwawayPeer.String(), now, throwawayKP)); err != nil {
			t.Fatalf("dir.Register(throwaway %d): %v", i, err)
		}

		// Throwaways must NOT have delegated weight
		if n.IsDelegatedRepPeer(throwawayPeer.String()) {
			t.Fatalf("throwaway %d unexpectedly claimed delegated rep protection", i)
		}

		// Attacker completes handshake for each throwaway
		gater.RecordPeerCapabilities(throwawayPeer, xenet.PeerCapabilities{
			Version:  xenet.NetcheckVersion,
			Features: []string{"noop"},
		})
	}

	// Verify readiness: legitimate representative must NOT have been evicted!
	readiness := n.GetReadiness()
	if readiness.TotalWeight != repWeight {
		t.Fatalf("TotalWeight = %d, want %d", readiness.TotalWeight, repWeight)
	}
	if readiness.UnknownWeight != 0 {
		t.Fatalf("UnknownWeight = %d, want 0 (legitimate representative was evicted by directory throwaways!)", readiness.UnknownWeight)
	}
	if readiness.ResolvedReps != 1 {
		t.Fatalf("ResolvedReps = %d, want 1", readiness.ResolvedReps)
	}
	if got := readiness.FeatureWeight["messaging"]; got != repWeight {
		t.Fatalf("FeatureWeight[\"messaging\"] = %d, want %d", got, repWeight)
	}
	if got := readiness.FeatureReadyMilli["messaging"]; got != 1000 {
		t.Fatalf("FeatureReadyMilli[\"messaging\"] = %d, want 1000", got)
	}
}
