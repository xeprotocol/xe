package chat

import (
	"fmt"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func testEnvelope(id, from, to string, ts int64) *Envelope {
	return &Envelope{ID: id, From: from, To: to, Message: "x", Timestamp: ts}
}

func TestPruneMessagesEvictsStaleBuckets(t *testing.T) {
	s := NewChatStore(10)
	now := core.Now()
	stale := now.Add(-20 * time.Minute).UnixNano() // older than 2*MaxEnvelopeSkew (10m)
	fresh := now.UnixNano()

	// Two stale buckets (To + From keys each) and one fresh bucket.
	if !s.Store(testEnvelope("stale-1", "alice", "bob", stale)) {
		t.Fatal("stale-1 must store")
	}
	if !s.Store(testEnvelope("stale-2", "carol", "dave", stale)) {
		t.Fatal("stale-2 must store")
	}
	if !s.Store(testEnvelope("fresh-1", "erin", "frank", fresh)) {
		t.Fatal("fresh-1 must store")
	}
	// A stale message in a bucket whose newest message is fresh must not
	// evict the bucket — but a bucket holding only that stale message (here
	// mallory, the To side of stale-3) is evicted.
	if !s.Store(testEnvelope("stale-3", "erin", "mallory", stale)) {
		t.Fatal("stale-3 must store")
	}

	if got := len(s.Accounts()); got != 7 {
		t.Fatalf("want 7 accounts before prune, got %d", got)
	}

	s.mu.Lock()
	s.pruneMessagesLocked()
	s.mu.Unlock()

	accounts := s.Accounts()
	if len(accounts) != 2 {
		t.Fatalf("want 2 accounts after prune (erin, frank), got %d: %v", len(accounts), accounts)
	}
	if msgs := s.Messages("erin", 0); len(msgs) != 2 {
		t.Fatalf("fresh bucket must survive with both messages, got %d", len(msgs))
	}
	if msgs := s.Messages("mallory", 0); len(msgs) != 0 {
		t.Fatalf("stale-only bucket must be gone, got %d messages", len(msgs))
	}
	if msgs := s.Messages("alice", 0); len(msgs) != 0 {
		t.Fatalf("stale bucket must be gone, got %d messages", len(msgs))
	}
}

func TestPruneMessagesBoundsDistinctAccounts(t *testing.T) {
	s := NewChatStore(10)
	now := core.Now()
	stale := now.Add(-20 * time.Minute).UnixNano()

	// Issue #247 shape at small scale: many fresh "accounts", none ever pruned.
	for i := 0; i < 2000; i++ {
		to := fmt.Sprintf("%064x", i)
		if !s.Store(testEnvelope(fmt.Sprintf("env-%d", i), "attacker", to, stale)) {
			t.Fatalf("env-%d must store", i)
		}
	}
	if got := len(s.Accounts()); got != 2001 {
		t.Fatalf("want 2001 accounts before prune, got %d", got)
	}

	s.mu.Lock()
	s.pruneMessagesLocked()
	s.mu.Unlock()

	if got := len(s.Accounts()); got != 0 {
		t.Fatalf("want 0 accounts after prune, got %d", got)
	}
}

func TestStorePrunesStaleMessagesWhenSeenFills(t *testing.T) {
	s := NewChatStore(10)
	now := core.Now()
	stale := now.Add(-20 * time.Minute).UnixNano()

	// One stale bucket, then fill seen to the cap with fresh filler IDs.
	if !s.Store(testEnvelope("stale-1", "alice", "bob", stale)) {
		t.Fatal("stale-1 must store")
	}
	for i := 0; i < maxSeenIDs; i++ {
		s.seen[fmt.Sprintf("filler-%d", i)] = now.UnixNano()
	}

	// This Store takes the prune path: seen is full, so both prunes run.
	// The fresh fillers survive the seen prune, so the Store itself is
	// rejected — but the stale message bucket must still be evicted.
	if s.Store(testEnvelope("fresh-1", "erin", "frank", now.UnixNano())) {
		t.Fatal("store must be rejected while seen stays full")
	}
	if msgs := s.Messages("alice", 0); len(msgs) != 0 {
		t.Fatalf("stale bucket must be evicted by the store-triggered prune, got %d messages", len(msgs))
	}
	if got := len(s.Accounts()); got != 0 {
		t.Fatalf("want 0 accounts after store-triggered prune, got %d", got)
	}
}
