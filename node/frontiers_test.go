package node

import (
	"strconv"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestGetFrontiersDetailedPaged_PaginationAndCache(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{
		TimestampWindow: core.DefaultTimestampWindow,
	})

	n := &Node{
		Ledger: l,
		store:  s,
	}

	// 1. Populate multiple accounts with blocks
	const numAccounts = 25
	now := time.Now().UnixNano()

	for i := 0; i < numAccounts; i++ {
		addr := "acc_" + strconv.Itoa(100+i)
		b := &core.Block{
			Type:           core.BlockSend,
			Hash:           "hash_" + addr,
			Account:        addr,
			Representative: "rep_default",
			Timestamp:      now + int64(i),
			Asset:          "XE",
			Amount:         1000,
		}
		s.CommitBlock(&core.BlockCommit{
			Block:        b,
			Account:      addr,
			Chain:        &core.AccountChain{Blocks: []*core.Block{b}},
			FrontierHash: b.Hash,
		})
	}

	// 2. Test full listing via GetFrontiersDetailed()
	all := n.GetFrontiersDetailed()
	if len(all) < numAccounts {
		t.Fatalf("expected at least %d frontiers, got %d", numAccounts, len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Account >= all[i].Account {
			t.Fatalf("frontiers not sorted alphabetically: %s >= %s", all[i-1].Account, all[i].Account)
		}
	}

	// 3. Test paged evaluation: limit=5, offset=0
	page0 := n.GetFrontiersDetailedPaged(0, 5)
	if len(page0) != 5 {
		t.Fatalf("expected 5 frontiers in page 0, got %d", len(page0))
	}
	for i := 0; i < 5; i++ {
		if page0[i].Account != all[i].Account {
			t.Fatalf("page 0 item %d mismatch: got %s, want %s", i, page0[i].Account, all[i].Account)
		}
		if page0[i].BlockCount < 1 {
			t.Fatalf("expected BlockCount >= 1, got %d", page0[i].BlockCount)
		}
		if page0[i].BlockType == "" {
			t.Fatalf("expected non-empty BlockType")
		}
	}

	// 4. Test paged evaluation: limit=5, offset=5
	page1 := n.GetFrontiersDetailedPaged(5, 5)
	if len(page1) != 5 {
		t.Fatalf("expected 5 frontiers in page 1, got %d", len(page1))
	}
	for i := 0; i < 5; i++ {
		if page1[i].Account != all[5+i].Account {
			t.Fatalf("page 1 item %d mismatch: got %s, want %s", i, page1[i].Account, all[5+i].Account)
		}
	}

	// 5. Test out of bounds offset
	pageEmpty := n.GetFrontiersDetailedPaged(len(all)+10, 5)
	if len(pageEmpty) != 0 {
		t.Fatalf("expected empty page for out of bounds offset, got %d", len(pageEmpty))
	}

	// 6. Test cached snapshot avoids rebuilding sorted slice within 1s
	firstSnap := n.cachedFrontiers
	if firstSnap == nil {
		t.Fatalf("expected cachedFrontiers to be populated")
	}
	_ = n.GetFrontiersDetailedPaged(0, 2)
	secondSnap := n.cachedFrontiers
	if firstSnap != secondSnap {
		t.Fatalf("expected cachedFrontiers pointer to remain identical within TTL")
	}
}
