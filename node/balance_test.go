package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestNode_GetFinalSpendableBalances(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	memStore := store.NewMemStore()
	ledger := core.NewLedger(memStore, core.LedgerConfig{})

	n := &Node{
		KeyPair: kp,
		store:   memStore,
		Ledger:  ledger,
	}

	addr := kp.Address()

	// 1. Initially no blocks
	if b := n.GetFinalSpendableBalances(addr); len(b) != 0 {
		t.Fatalf("expected empty final spendable, got %+v", b)
	}

	// 2. Add block 1
	b1 := &core.Block{
		Hash:      "b1",
		Account:   addr,
		Type:      core.BlockReceive,
		Amount:    500000,
		Balance:   500000,
		Asset:     "XE",
		Timestamp: time.Now().UnixNano(),
	}
	chain := &core.AccountChain{
		Blocks: []*core.Block{b1},
	}
	if err := memStore.PutAccountChain(addr, chain); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}
	if err := memStore.SetFinalHeight(addr, 1); err != nil {
		t.Fatalf("SetFinalHeight: %v", err)
	}

	// Check finalized spendable on node
	fb := n.GetFinalSpendableBalances(addr)
	if fb["XE"] != 500000 {
		t.Fatalf("expected final spendable 500000, got %d", fb["XE"])
	}

	// 3. Add unconfirmed send block 2
	dest, _ := core.GenerateKeyPair()
	b2 := &core.Block{
		Hash:        "b2",
		Previous:    b1.Hash,
		Account:     addr,
		Destination: dest.Address(),
		Type:        core.BlockSend,
		Amount:      200000,
		Balance:     300000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}
	chain.Blocks = append(chain.Blocks, b2)
	if err := memStore.PutAccountChain(addr, chain); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}

	// Final height remains 1
	if n.FinalHeight(addr) != 1 {
		t.Fatalf("expected final height 1, got %d", n.FinalHeight(addr))
	}

	// Spendable on local frontier is 300000
	if sp := n.GetSpendableBalances(addr); sp["XE"] != 300000 {
		t.Fatalf("expected spendable 300000, got %d", sp["XE"])
	}

	// FinalSpendable strictly reflects finalized height 1: 500000
	if fb := n.GetFinalSpendableBalances(addr); fb["XE"] != 500000 {
		t.Fatalf("expected final spendable 500000, got %d", fb["XE"])
	}
}
