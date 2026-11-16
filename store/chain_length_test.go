package store

import (
	"os"
	"strconv"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestMemStore_GetAccountChainLength(t *testing.T) {
	ms := NewMemStore()
	account := "xe_test_account"

	// 1. Non-existent account
	len0, err := ms.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error on empty: %v", err)
	}
	if len0 != 0 {
		t.Fatalf("expected 0, got %d", len0)
	}

	// 2. Put chain with 5 blocks
	chain := &core.AccountChain{
		Blocks: make([]*core.Block, 5),
	}
	for i := 0; i < 5; i++ {
		chain.Blocks[i] = &core.Block{
			Hash:    "hash_" + strconv.Itoa(i),
			Account: account,
		}
	}
	if err := ms.PutAccountChain(account, chain); err != nil {
		t.Fatalf("failed to put account chain: %v", err)
	}

	len5, err := ms.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len5 != 5 {
		t.Fatalf("expected 5, got %d", len5)
	}
}

func TestBadgerStore_GetAccountChainLength(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger-chain-len-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	bs, err := NewBadgerStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	account := "xe_test_badger_account"

	// 1. Non-existent account
	len0, err := bs.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error on empty: %v", err)
	}
	if len0 != 0 {
		t.Fatalf("expected 0, got %d", len0)
	}

	// 2. Put chain with 20 blocks
	chain := &core.AccountChain{
		Blocks: make([]*core.Block, 20),
	}
	for i := 0; i < 20; i++ {
		b := &core.Block{
			Hash:    "hash_b_" + strconv.Itoa(i),
			Account: account,
			Type:    core.BlockSend,
		}
		if err := bs.PutBlock(b); err != nil {
			t.Fatalf("failed to put block: %v", err)
		}
		chain.Blocks[i] = b
	}
	if err := bs.PutAccountChain(account, chain); err != nil {
		t.Fatalf("failed to put account chain: %v", err)
	}

	// 3. Verify GetAccountChainLength returns 20
	len20, err := bs.GetAccountChainLength(account)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len20 != 20 {
		t.Fatalf("expected 20, got %d", len20)
	}
}
