package store

import (
	"errors"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestBadgerStoreCommitCascadeEnforcesLeaseCASAndDeduplicatesPendingByDest(t *testing.T) {
	dir := t.TempDir()
	bs, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	defer func() { _ = bs.Close() }()

	leaseHash := "aaaa111111111111111111111111111111111111111111111111111111111111"
	consumer := "bbbb111111111111111111111111111111111111111111111111111111111111"
	provider := "cccc111111111111111111111111111111111111111111111111111111111111"

	// Put a lease in LeaseAccepted state
	initialLease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer,
		Provider:  provider,
		Duration:  3600,
		Cost:      100_000,
		Stake:     10_000,
		StartTime: 1000,
	}
	if err := bs.PutLease(initialLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Undo 1 deletes the lease in the cascade, while the winner commit expects LeaseCreated.
	// Pre-undo CAS must evaluate the post-undo lease state (nil) and reject BEFORE applying any undo!
	undoDelete := &core.BlockUndo{
		Account:         consumer,
		Chain:           &core.AccountChain{Blocks: []*core.Block{}},
		FrontierHash:    "0",
		DeleteAccount:   true,
		DeleteLeaseHash: leaseHash,
	}
	winnerBlock := &core.Block{
		Type:      core.BlockLeaseAccept,
		Account:   provider,
		Previous:  "0",
		Balance:   40_000,
		Amount:    10_000,
		Source:    leaseHash,
		Timestamp: 2000,
		Asset:     "XUSD",
		Hash:      "dddd111111111111111111111111111111111111111111111111111111111111",
	}
	winnerCommit := &core.BlockCommit{
		Block:            winnerBlock,
		Account:          provider,
		Chain:            &core.AccountChain{Blocks: []*core.Block{winnerBlock}},
		FrontierHash:     winnerBlock.Hash,
		ExpectLeaseHash:  leaseHash,
		ExpectLeaseState: core.LeaseCreated,
	}

	err = bs.CommitCascade([]*core.BlockUndo{undoDelete}, winnerCommit)
	if err == nil || !errors.Is(err, core.ErrLeaseStateConflict) {
		t.Fatalf("expected CommitCascade to fail with ErrLeaseStateConflict when undo deletes expected lease, got: %v", err)
	}

	// Verify pendingByDest deduplication across repeated AddPending writes
	sendHash := "eeee111111111111111111111111111111111111111111111111111111111111"
	ps := &core.PendingSend{
		SendHash:    sendHash,
		Source:      consumer,
		Destination: provider,
		Amount:      50_000,
		Asset:       "XUSD",
	}
	b1 := &core.Block{
		Type:      core.BlockSend,
		Account:   consumer,
		Previous:  "0",
		Balance:   50_000,
		Amount:    50_000,
		Timestamp: 1000,
		Asset:     "XUSD",
		Hash:      sendHash,
	}
	c1 := &core.BlockCommit{
		Block:        b1,
		Account:      consumer,
		Chain:        &core.AccountChain{Blocks: []*core.Block{b1}},
		FrontierHash: b1.Hash,
		AddPending:   ps,
	}
	if err := bs.CommitBlock(c1); err != nil {
		t.Fatalf("CommitBlock c1: %v", err)
	}
	// Apply an undo that re-adds the same pending send (e.g. unwinding a receive/settle when pending already existed)
	uAdd := &core.BlockUndo{
		Account:      provider,
		Chain:        &core.AccountChain{Blocks: []*core.Block{}},
		FrontierHash: "0",
		AddPending:   ps,
	}
	if err := bs.CommitUndo(uAdd); err != nil {
		t.Fatalf("CommitUndo uAdd: %v", err)
	}

	pendingList, err := bs.GetPendingByDest(provider)
	if err != nil {
		t.Fatalf("GetPendingByDest: %v", err)
	}
	if len(pendingList) != 1 {
		t.Fatalf("expected exactly 1 deduplicated pending entry for destination, got %d", len(pendingList))
	}
}
