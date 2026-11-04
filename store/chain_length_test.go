package store

import (
	"path/filepath"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestMemStore_GetAccountChainLength(t *testing.T) {
	s := NewMemStore()
	defer s.Close()

	account := "test-account-1"
	// Non-existent account
	count, err := s.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error on missing account: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}

	// Add chain with 3 blocks
	chain := &core.AccountChain{
		Blocks: []*core.Block{
			{Hash: "hash-1", Account: account, Type: core.BlockSend},
			{Hash: "hash-2", Account: account, Type: core.BlockReceive},
			{Hash: "hash-3", Account: account, Type: core.BlockSend},
		},
	}
	if err := s.PutAccountChain(account, chain); err != nil {
		t.Fatalf("PutAccountChain failed: %v", err)
	}

	count, err = s.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("GetAccountChainLength failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}
}

func TestBadgerStore_GetAccountChainLength(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "badger-test")
	s, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("failed to create badger store: %v", err)
	}
	defer s.Close()

	account := "test-badger-account"
	// Non-existent
	count, err := s.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error on missing account: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}

	// Put chain with 5 blocks
	chain := &core.AccountChain{
		Blocks: []*core.Block{
			{Hash: "b1", Account: account, Type: core.BlockSend},
			{Hash: "b2", Account: account, Type: core.BlockReceive},
			{Hash: "b3", Account: account, Type: core.BlockSend},
			{Hash: "b4", Account: account, Type: core.BlockReceive},
			{Hash: "b5", Account: account, Type: core.BlockSend},
		},
	}
	if err := s.PutAccountChain(account, chain); err != nil {
		t.Fatalf("PutAccountChain failed: %v", err)
	}

	// Note: PutAccountChain stores only hashes in prefixChain.
	// GetAccountChainLength reads prefixChain without requiring block bodies!
	count, err = s.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("GetAccountChainLength failed: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected count 5, got %d", count)
	}
}
