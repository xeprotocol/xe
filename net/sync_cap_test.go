package net

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestSyncServerCapTruncationSignal(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{})
	const account = "synthetic-offline-test"

	// Create 10,001 blocks (1 over the 10,000 maxServerBlocks cap)
	const totalBlocks = 10001
	blocks := make([]*core.Block, totalBlocks)
	for i := range blocks {
		blocks[i] = &core.Block{Account: account, Hash: fmt.Sprintf("%064x", i+1)}
	}
	if err := s.PutAccountChain(account, &core.AccountChain{Blocks: blocks}); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}
	if err := s.PutFrontier(account, blocks[totalBlocks-1].Hash); err != nil {
		t.Fatalf("PutFrontier: %v", err)
	}

	request := l.Frontiers()
	delete(request, account) // remote peer has not seen account

	type pageStats struct {
		count     int
		last      string
		hasMore   bool
		truncated bool
	}

	collect := func(frontiers map[string]string) []pageStats {
		var pages []pageStats
		for resp := range findMissingBlocksPaginated(frontiers, l, 64) {
			last := ""
			if len(resp.Blocks) > 0 {
				last = resp.Blocks[len(resp.Blocks)-1].Hash
			}
			pages = append(pages, pageStats{
				count:     len(resp.Blocks),
				last:      last,
				hasMore:   resp.HasMore,
				truncated: resp.Truncated,
			})
		}
		return pages
	}

	// Round 1: Peer requests from genesis. Server caps at 10,000 blocks.
	pages1 := collect(request)
	totalDelivered1 := 0
	for _, p := range pages1 {
		totalDelivered1 += p.count
	}
	if totalDelivered1 != 10000 {
		t.Fatalf("round 1 expected 10,000 capped blocks, got %d", totalDelivered1)
	}

	lastPage1 := pages1[len(pages1)-1]
	// The final page of round 1 MUST NOT indicate terminal false-completion.
	// It must explicitly flag HasMore: true and Truncated: true.
	if !lastPage1.hasMore {
		t.Fatalf("round 1 final page indicated hasMore=false despite unsent blocks remaining on source chain")
	}
	if !lastPage1.truncated {
		t.Fatalf("round 1 final page missing truncated=true indicator")
	}

	// Round 2: Receiver advances its frontier to block 10,000 and requests again.
	request[account] = lastPage1.last
	pages2 := collect(request)
	totalDelivered2 := 0
	for _, p := range pages2 {
		totalDelivered2 += p.count
	}
	if totalDelivered2 != 1 {
		t.Fatalf("round 2 expected remaining 1 block, got %d", totalDelivered2)
	}

	lastPage2 := pages2[len(pages2)-1]
	if lastPage2.hasMore {
		t.Fatalf("round 2 final page should indicate hasMore=false upon full convergence, got true")
	}
	if lastPage2.truncated {
		t.Fatalf("round 2 final page should indicate truncated=false, got true")
	}
	if lastPage2.last != blocks[totalBlocks-1].Hash {
		t.Fatalf("round 2 final block hash=%s, want %s", lastPage2.last, blocks[totalBlocks-1].Hash)
	}
}

func TestSyncResponseTruncatedJSON(t *testing.T) {
	respTruncated := SyncResponse{
		HasMore:   true,
		Truncated: true,
	}
	data, err := json.Marshal(respTruncated)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"truncated":true`) {
		t.Fatalf("expected JSON to contain 'truncated':true, got %s", string(data))
	}

	respClean := SyncResponse{
		HasMore:   false,
		Truncated: false,
	}
	cleanData, err := json.Marshal(respClean)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(cleanData), `"truncated"`) {
		t.Fatalf("expected omitempty to drop 'truncated' field when false, got %s", string(cleanData))
	}
}

func TestSyncExactCapWithSynchronizedSecondaryAccount(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{})
	const account1 = "synthetic-cap-account-1"
	const account2 = "synthetic-synced-account-2"

	// account1 has exactly 10,000 blocks (maxServerBlocks cap)
	const totalBlocks1 = 10000
	blocks1 := make([]*core.Block, totalBlocks1)
	for i := range blocks1 {
		blocks1[i] = &core.Block{Account: account1, Hash: fmt.Sprintf("%064x", i+1)}
	}
	if err := s.PutAccountChain(account1, &core.AccountChain{Blocks: blocks1}); err != nil {
		t.Fatalf("PutAccountChain acc1: %v", err)
	}
	if err := s.PutFrontier(account1, blocks1[totalBlocks1-1].Hash); err != nil {
		t.Fatalf("PutFrontier acc1: %v", err)
	}

	// account2 has 5 blocks and is already synchronized on remote peer
	const totalBlocks2 = 5
	blocks2 := make([]*core.Block, totalBlocks2)
	for i := range blocks2 {
		blocks2[i] = &core.Block{Account: account2, Hash: fmt.Sprintf("%064x", 100000+i+1)}
	}
	if err := s.PutAccountChain(account2, &core.AccountChain{Blocks: blocks2}); err != nil {
		t.Fatalf("PutAccountChain acc2: %v", err)
	}
	if err := s.PutFrontier(account2, blocks2[totalBlocks2-1].Hash); err != nil {
		t.Fatalf("PutFrontier acc2: %v", err)
	}

	// Request has all other frontiers (including genesis and account2) already matched, but account1 unknown
	request := l.Frontiers()
	delete(request, account1)

	var pages []SyncResponse
	totalDelivered := 0
	for resp := range findMissingBlocksPaginated(request, l, 64) {
		pages = append(pages, resp)
		totalDelivered += len(resp.Blocks)
	}

	if totalDelivered != 10000 {
		t.Fatalf("expected exactly 10,000 delivered blocks, got %d", totalDelivered)
	}

	if len(pages) == 0 {
		t.Fatalf("expected at least one page returned")
	}

	lastPage := pages[len(pages)-1]
	// All missing blocks were delivered. The second account is already synchronized,
	// so the server MUST NOT falsely signal truncation or hasMore: true.
	if lastPage.HasMore {
		t.Fatalf("expected final page to have hasMore=false, got true")
	}
	if lastPage.Truncated {
		t.Fatalf("expected final page to have truncated=false, got true")
	}
}

func TestSyncIdenticalFrontiersTerminalResponse(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{})
	const account = "synced-acc"

	blocks := []*core.Block{
		{Account: account, Hash: fmt.Sprintf("%064x", 1)},
	}
	if err := s.PutAccountChain(account, &core.AccountChain{Blocks: blocks}); err != nil {
		t.Fatalf("PutAccountChain: %v", err)
	}
	if err := s.PutFrontier(account, blocks[0].Hash); err != nil {
		t.Fatalf("PutFrontier: %v", err)
	}

	request := l.Frontiers()
	var pages []SyncResponse
	for resp := range findMissingBlocksPaginated(request, l, 64) {
		pages = append(pages, resp)
	}

	if len(pages) != 1 {
		t.Fatalf("expected exactly 1 terminal page for identical frontiers, got %d", len(pages))
	}
	if pages[0].HasMore {
		t.Fatalf("expected hasMore=false for identical frontiers, got true")
	}
	if pages[0].Truncated {
		t.Fatalf("expected truncated=false for identical frontiers, got true")
	}
	if len(pages[0].Blocks) != 0 {
		t.Fatalf("expected 0 blocks for identical frontiers, got %d", len(pages[0].Blocks))
	}
}
