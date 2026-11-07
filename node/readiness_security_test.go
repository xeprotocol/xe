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

func seedLedgerWithDelegatedWeights(t *testing.T, weights map[string]uint64) *core.Ledger {
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

func TestReadinessDuplicateFeaturesCannotInflateMinorityRepWeight(t *testing.T) {
	majRepKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(maj): %v", err)
	}
	minRepKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(min): %v", err)
	}
	localKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(local): %v", err)
	}

	// Majority representative holds 99% (9,900 micro-XE) and does NOT advertise "messaging".
	// Minority representative holds 1% (100 micro-XE) and repeats "messaging" 95 times in its netcheck features.
	ledger := seedLedgerWithDelegatedWeights(t, map[string]uint64{
		majRepKP.Address(): 9900,
		minRepKP.Address(): 100,
	})

	dir := directory.New(directory.DefaultTTL)
	now := time.Now().UnixNano()
	majPeer := peer.ID("12D3KooWMajPeer111111111111111111111111111111")
	minPeer := peer.ID("12D3KooWMinPeer222222222222222222222222222222")

	if err := dir.Register(directory.NewRegistration(majPeer.String(), now, majRepKP)); err != nil {
		t.Fatalf("Register(maj): %v", err)
	}
	if err := dir.Register(directory.NewRegistration(minPeer.String(), now, minRepKP)); err != nil {
		t.Fatalf("Register(min): %v", err)
	}

	gater := xenet.NewNetworkGater()
	gater.RecordPeerCapabilities(majPeer, xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: []string{"noop"},
	})

	dupFeatures := make([]string, 95)
	for i := range dupFeatures {
		dupFeatures[i] = "messaging"
	}
	gater.RecordPeerCapabilities(minPeer, xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: dupFeatures,
	})

	n := &Node{
		Ledger:    ledger,
		Directory: dir,
		KeyPair:   localKP,
		gater:     gater,
	}

	readiness := n.GetReadiness()
	if readiness.TotalWeight != 10000 {
		t.Fatalf("TotalWeight = %d, want 10000", readiness.TotalWeight)
	}
	if got := readiness.FeatureWeight["messaging"]; got != 100 {
		t.Fatalf("FeatureWeight[\"messaging\"] = %d, want 100 (1%% minority rep must not amplify weight via duplicate feature entries)", got)
	}
	if got := readiness.FeatureReadyMilli["messaging"]; got != 10 {
		t.Fatalf("FeatureReadyMilli[\"messaging\"] = %d, want 10 (1.0%% readiness, must not reach >=900 DAO gate)", got)
	}
}

func TestReadinessLargeWeightDoesNotOverflowMilliCalculation(t *testing.T) {
	repKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(rep): %v", err)
	}
	localKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(local): %v", err)
	}

	// 20,000,000,000 XE in micro-XE (2e16 > math.MaxUint64 / 1000 = 18,446,744,073,709,551).
	const largeWeight uint64 = 20_000_000_000_000_000
	ledger := seedLedgerWithDelegatedWeights(t, map[string]uint64{
		repKP.Address(): largeWeight,
	})

	dir := directory.New(directory.DefaultTTL)
	now := time.Now().UnixNano()
	repPeer := peer.ID("12D3KooWLargeWeightRepPeer1111111111111111111")
	if err := dir.Register(directory.NewRegistration(repPeer.String(), now, repKP)); err != nil {
		t.Fatalf("Register(rep): %v", err)
	}

	gater := xenet.NewNetworkGater()
	gater.RecordPeerCapabilities(repPeer, xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: []string{"noop"},
	})

	n := &Node{
		Ledger:    ledger,
		Directory: dir,
		KeyPair:   localKP,
		gater:     gater,
	}

	readiness := n.GetReadiness()
	if readiness.TotalWeight != largeWeight {
		t.Fatalf("TotalWeight = %d, want %d", readiness.TotalWeight, largeWeight)
	}
	if got := readiness.FeatureReadyMilli["noop"]; got != 1000 {
		t.Fatalf("FeatureReadyMilli[\"noop\"] = %d, want 1000 (uint64 overflow in w*1000 corrupted readiness)", got)
	}
}
