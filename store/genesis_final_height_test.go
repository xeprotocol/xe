package store

import (
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestGenesisCommitIncludesFinalHeightAtomically(t *testing.T) {
	dir := t.TempDir()
	bs, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	defer bs.Close()

	genesis, err := core.LoadGenesisBlock()
	if err != nil {
		t.Fatalf("LoadGenesisBlock: %v", err)
	}

	commit := &core.BlockCommit{
		Block:          genesis,
		Account:        genesis.Account,
		Chain:          &core.AccountChain{Blocks: []*core.Block{genesis}},
		FrontierHash:   genesis.Hash,
		DelegationRep:  genesis.Representative,
		PutAccountKey:  genesis.PubKey,
		SetFinalHeight: 1,
	}
	if err := bs.CommitBlock(commit); err != nil {
		t.Fatalf("CommitBlock: %v", err)
	}

	fh, err := bs.GetFinalHeight(genesis.Account)
	if err != nil {
		t.Fatalf("GetFinalHeight: %v", err)
	}
	if fh != 1 {
		t.Fatalf("expected atomic genesis final height 1 in BadgerStore, got %d", fh)
	}

	ms := NewMemStore()
	if err := ms.CommitBlock(commit); err != nil {
		t.Fatalf("MemStore.CommitBlock: %v", err)
	}
	mfh, err := ms.GetFinalHeight(genesis.Account)
	if err != nil {
		t.Fatalf("MemStore.GetFinalHeight: %v", err)
	}
	if mfh != 1 {
		t.Fatalf("expected atomic genesis final height 1 in MemStore, got %d", mfh)
	}
}

func TestLedgerRestartRepairsTornGenesisFinalHeightAndFinalizesChild(t *testing.T) {
	dir := t.TempDir()
	bs, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	defer bs.Close()

	genesis, err := core.LoadGenesisBlock()
	if err != nil {
		t.Fatalf("LoadGenesisBlock: %v", err)
	}

	// Simulate a kill -9 tear where the genesis block/chain/frontier were committed
	// without the final-height watermark (SetFinalHeight: 0).
	tornCommit := &core.BlockCommit{
		Block:          genesis,
		Account:        genesis.Account,
		Chain:          &core.AccountChain{Blocks: []*core.Block{genesis}},
		FrontierHash:   genesis.Hash,
		DelegationRep:  genesis.Representative,
		PutAccountKey:  genesis.PubKey,
		SetFinalHeight: 0,
	}
	if err := bs.CommitBlock(tornCommit); err != nil {
		t.Fatalf("CommitBlock torn genesis: %v", err)
	}

	fhBefore, err := bs.GetFinalHeight(genesis.Account)
	if err != nil {
		t.Fatalf("GetFinalHeight before restart: %v", err)
	}
	if fhBefore != 0 {
		t.Fatalf("expected torn genesis final height 0 before restart, got %d", fhBefore)
	}

	// Construct Ledger on the non-empty torn store (simulating node restart).
	ledger := core.NewLedger(bs, core.LedgerConfig{Difficulty: 0})
	if got := ledger.FinalHeight(genesis.Account); got != 1 {
		t.Fatalf("expected Ledger restart to repair genesis final height to 1, got %d", got)
	}
	if !ledger.IsFinalized(genesis.Account, genesis.Hash) {
		t.Fatalf("expected genesis block %s to be finalized after restart repair", genesis.Hash)
	}
	if got := ledger.FinalizedFrontier(genesis.Account); got != genesis.Hash {
		t.Fatalf("expected genesis finalized frontier %s, got %s", genesis.Hash, got)
	}
	spendable := ledger.SpendableBalances(genesis.Account)
	if spendable["XE"] != genesis.Balance {
		t.Fatalf("expected genesis spendable XE balance %d, got %d", genesis.Balance, spendable["XE"])
	}
}
