package chat

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func createTestEnvelope(from, to, msg string, kp *core.KeyPair, ts int64) *Envelope {
	pubKey := kp.PubKeyHex()
	id := ComputeEnvelopeID(from, pubKey, to, msg, ts)
	return &Envelope{
		ID:        id,
		From:      from,
		PubKey:    pubKey,
		To:        to,
		Message:   msg,
		Timestamp: ts,
		Signature: "test-sig",
	}
}

func TestChatStore_BasicStoreAndRetrieve(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	store := NewChatStore(10)
	now := core.Now().UnixNano()

	env := createTestEnvelope(kp.Address(), "recipient1", "hello", kp, now)
	if !store.Store(env) {
		t.Fatalf("expected envelope to be stored")
	}

	// Duplicate should be rejected
	if store.Store(env) {
		t.Fatalf("expected duplicate envelope to be rejected")
	}

	// Verify messages for sender and recipient
	msgsSender := store.Messages(kp.Address(), 0)
	if len(msgsSender) != 1 || msgsSender[0].ID != env.ID {
		t.Errorf("unexpected messages for sender: %v", msgsSender)
	}

	msgsRecipient := store.Messages("recipient1", 0)
	if len(msgsRecipient) != 1 || msgsRecipient[0].ID != env.ID {
		t.Errorf("unexpected messages for recipient: %v", msgsRecipient)
	}

	// Verify Accounts
	accts := store.Accounts()
	if len(accts) != 2 {
		t.Errorf("expected 2 accounts, got %d: %v", len(accts), accts)
	}

	// Verify Contacts
	contacts := store.Contacts(kp.Address())
	if len(contacts) != 1 || contacts[0] != "recipient1" {
		t.Errorf("expected contact 'recipient1', got %v", contacts)
	}
}

func TestChatStore_PruneExpiredMessages(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	retention := 100 * time.Millisecond
	store := NewChatStoreWithLimits(10, 100, retention)

	// Store an old envelope (older than retention)
	oldTS := core.Now().Add(-200 * time.Millisecond).UnixNano()
	oldEnv := createTestEnvelope(kp.Address(), "old-account", "old msg", kp, oldTS)
	store.Store(oldEnv)

	if len(store.Accounts()) != 2 {
		t.Fatalf("expected 2 accounts before prune, got %d", len(store.Accounts()))
	}

	// Trigger prune
	store.Prune()

	// Both accounts should have had their only message pruned, removing the account keys
	accts := store.Accounts()
	if len(accts) != 0 {
		t.Fatalf("expected 0 accounts after prune, got %d: %v", len(accts), accts)
	}
}

func TestChatStore_BoundedAccountsMap(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	const maxAccounts = 5
	store := NewChatStoreWithLimits(10, maxAccounts, 1*time.Hour)

	// Flood with 20 distinct destination accounts from the same sender
	for i := 0; i < 20; i++ {
		to := fmt.Sprintf("dest-%04d", i)
		ts := core.Now().UnixNano() + int64(i)*int64(time.Millisecond)
		env := createTestEnvelope(kp.Address(), to, fmt.Sprintf("msg %d", i), kp, ts)
		store.Store(env)
	}

	accts := store.Accounts()
	if len(accts) > maxAccounts {
		t.Fatalf("expected accounts count <= %d, got %d (%v)", maxAccounts, len(accts), accts)
	}

	// Active sender should be retained because it received the latest activity
	var foundSender bool
	for _, a := range accts {
		if a == kp.Address() {
			foundSender = true
			break
		}
	}
	if !foundSender {
		t.Errorf("expected active sender %s to be preserved in bounded store", kp.Address())
	}
}

func TestChatStore_ConcurrentStoreAndQuery(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	store := NewChatStoreWithLimits(50, 50, 10*time.Minute)

	var wg sync.WaitGroup
	const workers = 8
	const perWorker = 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				to := fmt.Sprintf("worker-%d-dest-%d", workerID, i%5)
				ts := core.Now().UnixNano()
				env := createTestEnvelope(kp.Address(), to, "concurrent", kp, ts)
				store.Store(env)

				_ = store.Messages(to, 0)
				_ = store.Accounts()
				_ = store.Contacts(kp.Address())
			}
		}(w)
	}

	wg.Wait()

	if len(store.Accounts()) > 50 {
		t.Errorf("accounts count exceeded maxAccounts: %d > 50", len(store.Accounts()))
	}
}
