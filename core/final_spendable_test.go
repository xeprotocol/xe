package core_test

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestFinalSpendableBalances_EmptyAccount(t *testing.T) {
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{})

	kp, _ := core.GenerateKeyPair()
	res := ledger.FinalSpendableBalances(kp.Address())
	if len(res) != 0 {
		t.Fatalf("expected empty final spendable for empty account, got %+v", res)
	}
}

func TestFinalSpendableBalances_ConfirmedAndUnconfirmedSends(t *testing.T) {
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{})

	sender, _ := core.GenerateKeyPair()
	recipient, _ := core.GenerateKeyPair()

	// Initial funded account via Genesis or Send/Receive
	// For testing FinalSpendableBalances, we can store blocks in mem store and set final height
	b1 := &core.Block{
		Hash:      "hash_block_1",
		Account:   sender.Address(),
		Type:      core.BlockReceive,
		Amount:    1000000,
		Balance:   1000000,
		Asset:     "XE",
		Timestamp: time.Now().Add(-10 * time.Minute).UnixNano(),
	}
	chain := &core.AccountChain{
		Blocks: []*core.Block{b1},
	}
	if err := mem.PutAccountChain(sender.Address(), chain); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}

	// 1. Block 1 is finalized
	if err := mem.SetFinalHeight(sender.Address(), 1); err != nil {
		t.Fatalf("SetFinalHeight: %v", err)
	}

	spendable := ledger.SpendableBalances(sender.Address())
	finalSpendable := ledger.FinalSpendableBalances(sender.Address())

	if spendable["XE"] != 1000000 {
		t.Fatalf("expected spendable 1000000, got %d", spendable["XE"])
	}
	if finalSpendable["XE"] != 1000000 {
		t.Fatalf("expected final spendable 1000000, got %d", finalSpendable["XE"])
	}

	// 2. Add an unconfirmed Send block (B2: send 300000 XE, balance drops to 700000 XE)
	b2 := &core.Block{
		Hash:        "hash_block_2",
		Previous:    b1.Hash,
		Account:     sender.Address(),
		Destination: recipient.Address(),
		Type:        core.BlockSend,
		Amount:      300000,
		Balance:     700000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}
	chain.Blocks = append(chain.Blocks, b2)
	if err := mem.PutAccountChain(sender.Address(), chain); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}

	// Final height remains 1 (block 2 is unconfirmed)
	if ledger.FinalHeight(sender.Address()) != 1 {
		t.Fatalf("expected final height 1, got %d", ledger.FinalHeight(sender.Address()))
	}

	// Spendable balances on local frontier accounts for unconfirmed outflow: 700000 XE
	spendableWithUnconfirmed := ledger.SpendableBalances(sender.Address())
	if spendableWithUnconfirmed["XE"] != 700000 {
		t.Fatalf("expected spendable 700000, got %d", spendableWithUnconfirmed["XE"])
	}

	// FinalSpendableBalances strictly reflects the finalized height 1: 1000000 XE
	finalSpendableAfterUnconfirmed := ledger.FinalSpendableBalances(sender.Address())
	if finalSpendableAfterUnconfirmed["XE"] != 1000000 {
		t.Fatalf("expected final spendable 1000000, got %d", finalSpendableAfterUnconfirmed["XE"])
	}

	// 3. Now block 2 reaches finality (final height advances to 2)
	if err := mem.SetFinalHeight(sender.Address(), 2); err != nil {
		t.Fatalf("SetFinalHeight: %v", err)
	}

	spendableFinalized := ledger.SpendableBalances(sender.Address())
	finalSpendableFinalized := ledger.FinalSpendableBalances(sender.Address())

	if spendableFinalized["XE"] != 700000 {
		t.Fatalf("expected spendable 700000, got %d", spendableFinalized["XE"])
	}
	if finalSpendableFinalized["XE"] != 700000 {
		t.Fatalf("expected final spendable 700000, got %d", finalSpendableFinalized["XE"])
	}
}
