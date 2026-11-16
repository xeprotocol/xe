package chat

import (
	"fmt"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func createTestEnvelope(id, from, to string, ts int64) *Envelope {
	return &Envelope{
		ID:        id,
		From:      from,
		To:        to,
		Message:   "hello",
		Timestamp: ts,
	}
}

func TestChatStore_DedupDuplicateRejected(t *testing.T) {
	s := NewChatStore(10)
	now := time.Now().UnixNano()
	env := createTestEnvelope("msg-1", "userA", "userB", now)

	if !s.Store(env) {
		t.Fatalf("first store should succeed")
	}
	if s.Store(env) {
		t.Fatalf("duplicate store must return false")
	}
}

func TestChatStore_FloodDoesNotDisableStore(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := time.Now()
	core.Now = func() time.Time { return fixedNow }

	// Use small limits to test eviction quickly
	const maxSeen = 50
	s := NewChatStoreWithLimits(10, 100, maxSeen)

	// Fill the seen cache with 50 fresh messages (within freshness window)
	for i := 0; i < maxSeen; i++ {
		env := createTestEnvelope(fmt.Sprintf("flood-msg-%d", i), "sender", "receiver", fixedNow.UnixNano())
		if !s.Store(env) {
			t.Fatalf("storing initial flood message %d failed", i)
		}
	}

	if len(s.seen) != maxSeen {
		t.Fatalf("expected seen map to have %d items, got %d", maxSeen, len(s.seen))
	}

	// In issue #258, before the fix, pruneSeenLocked evicted 0 entries (all fresh),
	// causing Store() to permanently fail for any subsequent message.
	// With the fix, oldest seen IDs are evicted by order, allowing new envelopes to succeed.
	for i := maxSeen; i < maxSeen+30; i++ {
		env := createTestEnvelope(fmt.Sprintf("flood-msg-%d", i), "sender", "receiver", fixedNow.UnixNano())
		if !s.Store(env) {
			t.Fatalf("store after capacity failed for message %d; node was locked out", i)
		}
	}

	if len(s.seen) > maxSeen {
		t.Fatalf("seen map size %d exceeded maxSeen %d", len(s.seen), maxSeen)
	}

	// An existing recent message must still be recognized as duplicate
	recentEnv := createTestEnvelope(fmt.Sprintf("flood-msg-%d", maxSeen+25), "sender", "receiver", fixedNow.UnixNano())
	if s.Store(recentEnv) {
		t.Fatalf("recent envelope should be rejected as duplicate")
	}
}

func TestChatStore_AccountMapBounded(t *testing.T) {
	const maxAccts = 15
	s := NewChatStoreWithLimits(10, maxAccts, 200)

	now := time.Now().UnixNano()

	// Store messages to 40 distinct accounts
	for i := 0; i < 40; i++ {
		to := fmt.Sprintf("dest-%02d", i)
		env := createTestEnvelope(fmt.Sprintf("msg-acct-%d", i), "shared-sender", to, now)
		if !s.Store(env) {
			t.Fatalf("store failed for %d", i)
		}
	}

	accts := s.Accounts()
	if len(accts) > maxAccts {
		t.Fatalf("account count %d exceeded maxAccounts %d", len(accts), maxAccts)
	}

	// Active account should remain after refresh
	activeAcct := "dest-39"
	found := false
	for _, a := range accts {
		if a == activeAcct {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("most recently active account %s was not found in accounts", activeAcct)
	}
}

func TestChatStore_TimeBasedPrune(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	initialTime := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	core.Now = func() time.Time { return initialTime }

	const maxSeen = 5
	s := NewChatStoreWithLimits(10, 10, maxSeen)

	// Add 5 old messages
	for i := 0; i < maxSeen; i++ {
		env := createTestEnvelope(fmt.Sprintf("old-msg-%d", i), "sender", "receiver", initialTime.UnixNano())
		if !s.Store(env) {
			t.Fatalf("failed to store %d", i)
		}
	}

	// Advance time past 2*MaxEnvelopeSkew (10 minutes)
	advancedTime := initialTime.Add(15 * time.Minute)
	core.Now = func() time.Time { return advancedTime }

	// Next store triggers time-based prune
	newEnv := createTestEnvelope("new-msg", "sender", "receiver", advancedTime.UnixNano())
	if !s.Store(newEnv) {
		t.Fatalf("failed to store after time advance")
	}

	// The old messages should have been pruned by timestamp
	for i := 0; i < maxSeen; i++ {
		if _, ok := s.seen[fmt.Sprintf("old-msg-%d", i)]; ok {
			t.Fatalf("old-msg-%d should have been pruned by time-based cutoff", i)
		}
	}
}

func TestChatStore_ContactsAndMessages(t *testing.T) {
	s := NewChatStore(10)
	now := time.Now().UnixNano()

	env1 := createTestEnvelope("m1", "alice", "bob", now)
	env2 := createTestEnvelope("m2", "carol", "alice", now+1)
	env3 := createTestEnvelope("m3", "alice", "dave", now+2)

	s.Store(env1)
	s.Store(env2)
	s.Store(env3)

	contacts := s.Contacts("alice")
	if len(contacts) != 3 {
		t.Fatalf("expected 3 contacts for alice, got %d", len(contacts))
	}

	msgs := s.Messages("alice", now)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages since %d, got %d", now, len(msgs))
	}
}
