package store

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/xeprotocol/xe/core"
)

func TestBadgerStore_PendingByDest_IndividualKeys(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore failed: %v", err)
	}
	defer s.Close()

	dest := "dest_account_1234567890abcdef"

	// 1. Add 50 pending sends
	for i := 0; i < 50; i++ {
		sendHash := fmt.Sprintf("send_hash_%04d_abcdef1234567890", i)
		ps := &core.PendingSend{
			SendHash:    sendHash,
			Source:      "source_account",
			Destination: dest,
			Amount:      uint64(100 + i),
			Asset:       "XE",
		}
		if err := s.PutPendingSend(ps); err != nil {
			t.Fatalf("PutPendingSend failed at %d: %v", i, err)
		}
	}

	// 2. Query GetPendingByDest
	pendingList, err := s.GetPendingByDest(dest)
	if err != nil {
		t.Fatalf("GetPendingByDest failed: %v", err)
	}
	if len(pendingList) != 50 {
		t.Fatalf("expected 50 pending sends, got %d", len(pendingList))
	}

	// 3. Delete 10 pending sends
	for i := 0; i < 10; i++ {
		sendHash := fmt.Sprintf("send_hash_%04d_abcdef1234567890", i)
		if err := s.DeletePendingSend(sendHash); err != nil {
			t.Fatalf("DeletePendingSend failed at %d: %v", i, err)
		}
	}

	// 4. Verify count is now 40
	pendingListAfter, err := s.GetPendingByDest(dest)
	if err != nil {
		t.Fatalf("GetPendingByDest after delete failed: %v", err)
	}
	if len(pendingListAfter) != 40 {
		t.Fatalf("expected 40 pending sends after delete, got %d", len(pendingListAfter))
	}
}

func TestBadgerStore_PendingByDest_LegacyMigration(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore failed: %v", err)
	}
	defer s.Close()

	dest := "legacy_dest_account_123456789"

	// 1. Manually write legacy JSON array and pending items
	hashes := []string{"legacy_hash_1", "legacy_hash_2"}
	err = s.db.Update(func(txn *badger.Txn) error {
		for _, h := range hashes {
			ps := &core.PendingSend{
				SendHash:    h,
				Source:      "source",
				Destination: dest,
				Amount:      50,
				Asset:       "XE",
			}
			data, _ := json.Marshal(ps)
			if err := txn.Set(prefixedKey(prefixPending, h), data); err != nil {
				return err
			}
		}

		legacyData, _ := json.Marshal(hashes)
		return txn.Set(prefixedKey(prefixPendingDst, dest), legacyData)
	})
	if err != nil {
		t.Fatalf("failed setting up legacy data: %v", err)
	}

	// 2. Verify GetPendingByDest reads legacy items correctly
	pendingList, err := s.GetPendingByDest(dest)
	if err != nil {
		t.Fatalf("GetPendingByDest legacy read failed: %v", err)
	}
	if len(pendingList) != 2 {
		t.Fatalf("expected 2 legacy pending items, got %d", len(pendingList))
	}

	// 3. Put a new item using modern method - should trigger migration of legacy key
	newPS := &core.PendingSend{
		SendHash:    "modern_hash_3",
		Source:      "source",
		Destination: dest,
		Amount:      100,
		Asset:       "XE",
	}
	if err := s.PutPendingSend(newPS); err != nil {
		t.Fatalf("PutPendingSend failed: %v", err)
	}

	// 4. Verify all 3 items exist
	allPending, err := s.GetPendingByDest(dest)
	if err != nil {
		t.Fatalf("GetPendingByDest failed: %v", err)
	}
	if len(allPending) != 3 {
		t.Fatalf("expected 3 total pending items after migration, got %d", len(allPending))
	}

	// 5. Verify the legacy monolithic key was deleted
	err = s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(prefixedKey(prefixPendingDst, dest))
		if err != badger.ErrKeyNotFound {
			t.Fatalf("expected legacy key to be deleted, got err: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}
