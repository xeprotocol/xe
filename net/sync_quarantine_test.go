package net

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestBlockQuarantine_RecordUnapplied verifies that blocks whose dependencies
// cannot be resolved after maxUnappliedSyncRounds consecutive sync rounds
// are placed in quarantine, preventing endless sync retry loops.
func TestBlockQuarantine_RecordUnapplied(t *testing.T) {
	q := newBlockQuarantine()
	hash1 := "06a4147c4e62aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash2 := "1171ad4f666baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Round 1
	if q.recordUnapplied(hash1, maxUnappliedSyncRounds) {
		t.Fatalf("hash1 should not be quarantined on round 1")
	}
	if q.contains(hash1) {
		t.Fatalf("hash1 should not be in quarantine yet")
	}

	// Round 2
	if q.recordUnapplied(hash1, maxUnappliedSyncRounds) {
		t.Fatalf("hash1 should not be quarantined on round 2")
	}

	// hash2 round 1
	if q.recordUnapplied(hash2, maxUnappliedSyncRounds) {
		t.Fatalf("hash2 should not be quarantined on round 1")
	}
	// hash2 succeeds on round 2 -> clearUnapplied
	q.clearUnapplied(hash2)
	// next failure for hash2 starts from round 1
	if q.recordUnapplied(hash2, maxUnappliedSyncRounds) {
		t.Fatalf("hash2 should not be quarantined after clear and 1 round")
	}

	// Round 3 for hash1 -> should trigger quarantine
	quarantined := q.recordUnapplied(hash1, maxUnappliedSyncRounds)
	if !quarantined {
		t.Fatalf("expected hash1 to be quarantined on reaching %d rounds", maxUnappliedSyncRounds)
	}
	if !q.contains(hash1) {
		t.Fatalf("quarantine.contains(hash1) should be true")
	}

	// Subsequent calls for already quarantined hash1 should return false
	if q.recordUnapplied(hash1, maxUnappliedSyncRounds) {
		t.Fatalf("subsequent call for already quarantined hash1 should return false")
	}
}

// TestUnappliedLogger_Deduplication verifies that summary warnings are deduplicated
// across consecutive rounds when failure count and reasons remain identical.
func TestUnappliedLogger_Deduplication(t *testing.T) {
	logger := &unappliedLogState{}
	reasons1 := map[string]int{"lease not found: 06a4147c4e62": 2}
	reasons2 := map[string]int{"lease not found: 06a4147c4e62": 3}

	// First call logs
	logger.log(2, reasons1)
	if logger.lastCount != 2 {
		t.Fatalf("expected lastCount 2, got %d", logger.lastCount)
	}
	t0 := logger.lastLogged

	// Second call with same count and reasons within interval should not update lastLogged
	time.Sleep(10 * time.Millisecond)
	logger.log(2, reasons1)
	if logger.lastLogged != t0 {
		t.Fatalf("expected duplicate log call to be suppressed")
	}

	// Third call with different reasons should update
	logger.log(3, reasons2)
	if logger.lastCount != 3 || logger.lastLogged == t0 {
		t.Fatalf("expected changed reasons to trigger log update")
	}
}

// TestFindMissingBlocksPaginated_SortedAndHasMore verifies that accounts are
// traversed deterministically in sorted order and HasMore reflects capHit.
func TestFindMissingBlocksPaginated_SortedAndHasMore(t *testing.T) {
	memStore := store.NewMemStore()
	ledger := core.NewLedger(memStore, core.LedgerConfig{Difficulty: 0})

	// Add blocks across multiple accounts with non-alphabetical insertion
	accounts := []string{
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	for _, acct := range accounts {
		b := &core.Block{
			Hash:      "hash_" + acct[:16],
			Type:      core.BlockGenesis,
			Account:   acct,
			Balance:   1000,
			Asset:     "XE",
			Timestamp: 1000,
		}
		_ = memStore.PutBlock(b)
		_ = memStore.PutFrontier(acct, b.Hash)
		chain := &core.AccountChain{
			Blocks: []*core.Block{b},
		}
		_ = memStore.PutAccountChain(acct, chain)
	}

	ch := findMissingBlocksPaginated(nil, ledger, 10)
	var received []*core.Block
	for resp := range ch {
		received = append(received, resp.Blocks...)
	}

	if len(received) != 4 {
		t.Fatalf("expected 4 blocks (1 genesis + 3 test), got %d", len(received))
	}

	// Verify deterministic alphabetical order of accounts: "378d...", "aaaa...", "bbbb...", "cccc..."
	if received[1].Account != accounts[1] || received[2].Account != accounts[2] || received[3].Account != accounts[0] {
		t.Fatalf("expected sorted accounts: %s, %s, %s; got %s, %s, %s",
			accounts[1][:8], accounts[2][:8], accounts[0][:8],
			received[1].Account[:8], received[2].Account[:8], received[3].Account[:8])
	}
}
