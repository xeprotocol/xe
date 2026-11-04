package store

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/xeprotocol/xe/core"
)

func newTestBadgerStore(t *testing.T) (*BadgerStore, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "badger-perf-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	s, err := NewBadgerStore(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("NewBadgerStore failed: %v", err)
	}
	cleanup := func() {
		s.Close()
		os.RemoveAll(dir)
	}
	return s, cleanup
}

func TestBadgerStore_AccountChain_Indexed(t *testing.T) {
	s, cleanup := newTestBadgerStore(t)
	defer cleanup()

	account := "xe_test_account_indexed_12345"
	numBlocks := 70 // greater than 64 to test transition beyond legacy monolithic threshold

	// Commit blocks sequentially via applyCommitTxn
	var chain core.AccountChain
	for i := 0; i < numBlocks; i++ {
		b := &core.Block{
			Hash:    fmt.Sprintf("blockhash_%04d", i),
			Account: account,
			Amount:  100,
		}
		chain.Blocks = append(chain.Blocks, b)
		commit := &core.BlockCommit{
			Account: account,
			Block:   b,
			Chain:   &chain,
		}
		err := s.db.Update(func(txn *badger.Txn) error {
			return applyCommitTxn(txn, commit)
		})
		if err != nil {
			t.Fatalf("applyCommitTxn block %d failed: %v", i, err)
		}
	}

	// 1. Verify GetAccountChain retrieves all blocks accurately in exact index order
	retrievedChain, err := s.GetAccountChain(account)
	if err != nil {
		t.Fatalf("GetAccountChain failed: %v", err)
	}
	if retrievedChain == nil {
		t.Fatalf("GetAccountChain returned nil chain")
	}
	if len(retrievedChain.Blocks) != numBlocks {
		t.Fatalf("expected %d blocks, got %d", numBlocks, len(retrievedChain.Blocks))
	}
	for i := 0; i < numBlocks; i++ {
		expectedHash := fmt.Sprintf("blockhash_%04d", i)
		if retrievedChain.Blocks[i].Hash != expectedHash {
			t.Errorf("block %d hash mismatch: want %s, got %s", i, expectedHash, retrievedChain.Blocks[i].Hash)
		}
	}

	// 2. Verify legacy monolithic array was deleted for chains > 64 blocks
	err = s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(prefixedKey(prefixChain, account))
		if err != badger.ErrKeyNotFound {
			t.Errorf("expected legacy key to be deleted for chain > 64, got err: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db.View failed: %v", err)
	}

	// 3. Test legacy migration
	legacyAccount := "xe_legacy_account_999"
	legacyHashes := []string{"legacy_hash_0", "legacy_hash_1", "legacy_hash_2"}
	err = s.db.Update(func(txn *badger.Txn) error {
		for _, h := range legacyHashes {
			b := &core.Block{Hash: h, Account: legacyAccount}
			bData, _ := json.Marshal(b)
			if err := txn.Set(prefixedKey(prefixBlock, h), bData); err != nil {
				return err
			}
		}
		data, _ := json.Marshal(legacyHashes)
		return txn.Set(prefixedKey(prefixChain, legacyAccount), data)
	})
	if err != nil {
		t.Fatalf("inserting legacy chain failed: %v", err)
	}

	// Verify reading legacy chain works transparently
	legacyChain, err := s.GetAccountChain(legacyAccount)
	if err != nil {
		t.Fatalf("GetAccountChain on legacy chain failed: %v", err)
	}
	if len(legacyChain.Blocks) != 3 {
		t.Fatalf("expected 3 legacy blocks, got %d", len(legacyChain.Blocks))
	}

	// Commit a new block onto legacy chain: automatic migration to index
	newBlock := &core.Block{Hash: "legacy_hash_3", Account: legacyAccount}
	legacyChain.Blocks = append(legacyChain.Blocks, newBlock)
	err = s.db.Update(func(txn *badger.Txn) error {
		return applyCommitTxn(txn, &core.BlockCommit{
			Account: legacyAccount,
			Block:   newBlock,
			Chain:   legacyChain,
		})
	})
	if err != nil {
		t.Fatalf("migrating legacy commit failed: %v", err)
	}

	migratedChain, err := s.GetAccountChain(legacyAccount)
	if err != nil || len(migratedChain.Blocks) != 4 {
		t.Fatalf("expected 4 migrated blocks, got %v (err %v)", len(migratedChain.Blocks), err)
	}
}

func TestBadgerStore_LeaseSecondaryIndexes(t *testing.T) {
	s, cleanup := newTestBadgerStore(t)
	defer cleanup()

	providerA := "provider_addr_A"
	providerB := "provider_addr_B"

	// Create 10 Accepted leases on Provider A, 5 Settled leases on Provider B
	for i := 0; i < 10; i++ {
		lease := &core.Lease{
			LeaseHash: fmt.Sprintf("lease_a_%d", i),
			Provider:  providerA,
			Consumer:  "consumer_1",
			State:     core.LeaseAccepted,
			Cost:      1000,
		}
		if err := s.PutLease(lease); err != nil {
			t.Fatalf("PutLease failed: %v", err)
		}
	}

	for i := 0; i < 5; i++ {
		lease := &core.Lease{
			LeaseHash: fmt.Sprintf("lease_b_%d", i),
			Provider:  providerB,
			Consumer:  "consumer_2",
			State:     core.LeaseSettled,
			Settled:   true,
			Cost:      2000,
		}
		if err := s.PutLease(lease); err != nil {
			t.Fatalf("PutLease failed: %v", err)
		}
	}

	// 1. Verify GetLeasesByState
	accepted, err := s.GetLeasesByState(core.LeaseAccepted)
	if err != nil {
		t.Fatalf("GetLeasesByState(Accepted) failed: %v", err)
	}
	if len(accepted) != 10 {
		t.Fatalf("expected 10 accepted leases, got %d", len(accepted))
	}

	settled, err := s.GetLeasesByState(core.LeaseSettled)
	if err != nil {
		t.Fatalf("GetLeasesByState(Settled) failed: %v", err)
	}
	if len(settled) != 5 {
		t.Fatalf("expected 5 settled leases, got %d", len(settled))
	}

	// 2. Verify GetLeasesByProvider
	provALeases, err := s.GetLeasesByProvider(providerA)
	if err != nil {
		t.Fatalf("GetLeasesByProvider(A) failed: %v", err)
	}
	if len(provALeases) != 10 {
		t.Fatalf("expected 10 provider A leases, got %d", len(provALeases))
	}

	provBLeases, err := s.GetLeasesByProvider(providerB)
	if err != nil {
		t.Fatalf("GetLeasesByProvider(B) failed: %v", err)
	}
	if len(provBLeases) != 5 {
		t.Fatalf("expected 5 provider B leases, got %d", len(provBLeases))
	}

	// 3. Settle 3 leases on Provider A via applyCommitTxn
	for i := 0; i < 3; i++ {
		leaseHash := fmt.Sprintf("lease_a_%d", i)
		commit := &core.BlockCommit{
			Account:         providerA,
			Block:           &core.Block{Hash: fmt.Sprintf("settle_blk_%d", i), Account: providerA},
			Chain:           &core.AccountChain{Blocks: []*core.Block{{Hash: fmt.Sprintf("settle_blk_%d", i), Account: providerA}}},
			SettleLeaseHash: leaseHash,
		}
		err := s.db.Update(func(txn *badger.Txn) error {
			return applyCommitTxn(txn, commit)
		})
		if err != nil {
			t.Fatalf("settle lease %s failed: %v", leaseHash, err)
		}
	}

	// Accepted should now be 7, Settled should be 5 + 3 = 8
	acceptedAfter, err := s.GetLeasesByState(core.LeaseAccepted)
	if err != nil || len(acceptedAfter) != 7 {
		t.Fatalf("expected 7 accepted leases after settling, got %d (err %v)", len(acceptedAfter), err)
	}

	settledAfter, err := s.GetLeasesByState(core.LeaseSettled)
	if err != nil || len(settledAfter) != 8 {
		t.Fatalf("expected 8 settled leases after settling, got %d (err %v)", len(settledAfter), err)
	}

	// Total leases for provider A should still be 10
	provALeasesAfter, err := s.GetLeasesByProvider(providerA)
	if err != nil || len(provALeasesAfter) != 10 {
		t.Fatalf("expected 10 provider A leases, got %d (err %v)", len(provALeasesAfter), err)
	}
}
