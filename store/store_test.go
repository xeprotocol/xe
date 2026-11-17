package store

import (
	"os"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func runFinalVoteStoreTests(t *testing.T, s core.FinalVoteStore) {
	account := "xe_test_rep_account"
	previous := "prev_hash_1111111111111111111111111111111111111111111111111111111111111111"
	hash1 := "block_hash_accept_dead111111111111111111111111111111111111111111111111"
	hash2 := "block_hash_replacement_222222222222222222222222222222222222222222222222"

	// 1. Initial check: no final vote exists
	h, ok, err := s.GetFinalVote(account, previous)
	if err != nil {
		t.Fatalf("unexpected error getting initial final vote: %v", err)
	}
	if ok || h != "" {
		t.Fatalf("expected empty initial final vote, got ok=%v hash=%q", ok, h)
	}

	// 2. Setting a final vote lock with PutFinalVoteIfAbsent locks the position
	stored, written, err := s.PutFinalVoteIfAbsent(account, previous, hash1)
	if err != nil {
		t.Fatalf("failed to put final vote: %v", err)
	}
	if !written {
		t.Fatalf("expected written=true on first lock, got false")
	}
	if stored != hash1 {
		t.Fatalf("expected stored=%q, got %q", hash1, stored)
	}

	// Verify locked position
	h, ok, err = s.GetFinalVote(account, previous)
	if err != nil {
		t.Fatalf("failed to get final vote: %v", err)
	}
	if !ok || h != hash1 {
		t.Fatalf("expected ok=true and hash=%q, got ok=%v hash=%q", hash1, ok, h)
	}

	// Subsequent put on the same position must fail to overwrite and return existing hash
	stored, written, err = s.PutFinalVoteIfAbsent(account, previous, hash2)
	if err != nil {
		t.Fatalf("failed second put attempt: %v", err)
	}
	if written {
		t.Fatalf("expected written=false for locked position, got true")
	}
	if stored != hash1 {
		t.Fatalf("expected stored to remain %q, got %q", hash1, stored)
	}

	// 3. Invoking DeleteFinalVote unlocks the position so that GetFinalVote returns ok=false
	if err := s.DeleteFinalVote(account, previous); err != nil {
		t.Fatalf("failed to delete final vote: %v", err)
	}

	h, ok, err = s.GetFinalVote(account, previous)
	if err != nil {
		t.Fatalf("failed to get final vote after delete: %v", err)
	}
	if ok || h != "" {
		t.Fatalf("expected ok=false after delete, got ok=%v hash=%q", ok, h)
	}

	// 4. A subsequent PutFinalVoteIfAbsent with a replacement hash succeeds (written=true)
	stored, written, err = s.PutFinalVoteIfAbsent(account, previous, hash2)
	if err != nil {
		t.Fatalf("failed to put replacement final vote: %v", err)
	}
	if !written {
		t.Fatalf("expected written=true for replacement hash, got false")
	}
	if stored != hash2 {
		t.Fatalf("expected stored=%q, got %q", hash2, stored)
	}

	// Verify replacement hash is now the one stored and locked
	h, ok, err = s.GetFinalVote(account, previous)
	if err != nil {
		t.Fatalf("failed to get replacement final vote: %v", err)
	}
	if !ok || h != hash2 {
		t.Fatalf("expected ok=true and hash=%q, got ok=%v hash=%q", hash2, ok, h)
	}

	// Verify idempotent delete on existing and nonexistent key
	if err := s.DeleteFinalVote(account, previous); err != nil {
		t.Fatalf("failed to delete final vote: %v", err)
	}
	if err := s.DeleteFinalVote(account, previous); err != nil {
		t.Fatalf("expected deleting non-existent key to succeed without error, got: %v", err)
	}
}

func TestMemStore_FinalVoteLock(t *testing.T) {
	s := NewMemStore()
	runFinalVoteStoreTests(t, s)
}

func TestBadgerStore_FinalVoteLock(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-test-finalvote-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	s, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("failed to initialize badger store: %v", err)
	}
	defer s.Close()

	runFinalVoteStoreTests(t, s)
}
