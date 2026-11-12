package chat

import (
	"fmt"
	"testing"
	"time"
)

func TestChatStore_ZeroOrNegativeMaxPerAccount(t *testing.T) {
	testCases := []struct {
		name          string
		maxPerAccount int
	}{
		{name: "zero", maxPerAccount: 0},
		{name: "negative_one", maxPerAccount: -1},
		{name: "negative_large", maxPerAccount: -100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewChatStore(tc.maxPerAccount)

			for i := 0; i < 5; i++ {
				env := &Envelope{
					ID:        fmt.Sprintf("id-%s-%d", tc.name, i),
					From:      "alice",
					To:        "bob",
					Message:   fmt.Sprintf("msg-%d", i),
					Timestamp: time.Now().UnixNano() + int64(i),
				}
				if !store.Store(env) {
					t.Fatalf("expected envelope %d to be stored successfully", i)
				}
			}

			aliceMsgs := store.Messages("alice", 0)
			if len(aliceMsgs) != 1 {
				t.Fatalf("expected alice to have 1 message retained, got %d", len(aliceMsgs))
			}
			if aliceMsgs[0].Message != "msg-4" {
				t.Fatalf("expected latest message msg-4, got %s", aliceMsgs[0].Message)
			}

			bobMsgs := store.Messages("bob", 0)
			if len(bobMsgs) != 1 {
				t.Fatalf("expected bob to have 1 message retained, got %d", len(bobMsgs))
			}
			if bobMsgs[0].Message != "msg-4" {
				t.Fatalf("expected latest message msg-4, got %s", bobMsgs[0].Message)
			}
		})
	}
}

func TestChatStore_UninitializedZeroValueStruct(t *testing.T) {
	store := &ChatStore{}

	env := &Envelope{
		ID:        "zero-struct-1",
		From:      "alice",
		To:        "bob",
		Message:   "hello",
		Timestamp: time.Now().UnixNano(),
	}

	if !store.Store(env) {
		t.Fatalf("expected store to succeed on zero-value ChatStore")
	}

	msgs := store.Messages("alice", 0)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
}

func TestChatStore_Rotation(t *testing.T) {
	limit := 3
	store := NewChatStore(limit)

	for i := 0; i < 6; i++ {
		env := &Envelope{
			ID:        fmt.Sprintf("rot-%d", i),
			From:      "alice",
			To:        "bob",
			Message:   fmt.Sprintf("msg-%d", i),
			Timestamp: 1000 + int64(i),
		}
		if !store.Store(env) {
			t.Fatalf("expected message %d to be stored", i)
		}
	}

	msgs := store.Messages("alice", 0)
	if len(msgs) != limit {
		t.Fatalf("expected %d messages, got %d", limit, len(msgs))
	}

	expectedMsgs := []string{"msg-3", "msg-4", "msg-5"}
	for i, expected := range expectedMsgs {
		if msgs[i].Message != expected {
			t.Errorf("at index %d expected %s, got %s", i, expected, msgs[i].Message)
		}
	}
}

func TestChatStore_Dedup(t *testing.T) {
	store := NewChatStore(10)
	env := &Envelope{
		ID:        "dedup-1",
		From:      "alice",
		To:        "bob",
		Message:   "first",
		Timestamp: 100,
	}

	if !store.Store(env) {
		t.Fatalf("first store should return true")
	}

	if store.Store(env) {
		t.Fatalf("duplicate store should return false")
	}
}

func TestChatStore_AccountsAndContacts(t *testing.T) {
	store := NewChatStore(10)

	store.Store(&Envelope{
		ID:        "m1",
		From:      "alice",
		To:        "bob",
		Message:   "hi bob",
		Timestamp: 100,
	})
	store.Store(&Envelope{
		ID:        "m2",
		From:      "charlie",
		To:        "alice",
		Message:   "hi alice",
		Timestamp: 200,
	})

	accounts := store.Accounts()
	if len(accounts) != 3 {
		t.Fatalf("expected 3 accounts, got %v", accounts)
	}

	contacts := store.Contacts("alice")
	if len(contacts) != 2 || contacts[0] != "bob" || contacts[1] != "charlie" {
		t.Fatalf("expected contacts [bob, charlie], got %v", contacts)
	}
}
