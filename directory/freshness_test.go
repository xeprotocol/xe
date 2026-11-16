package directory

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestRegistrationTimestampFreshnessSkew(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	nodePeer := "12D3KooWTestPeer123456789012345678901234567890123456"

	// 1. Valid timestamp (now) -> PASS
	now := core.Now().UnixNano()
	regValid := NewRegistration(nodePeer, now, kp)
	if err := VerifyRegistration(regValid); err != nil {
		t.Fatalf("expected valid registration to pass, got: %v", err)
	}

	// 2. Timestamp within allowed 5-minute skew (+2 minutes) -> PASS
	regWithinSkew := NewRegistration(nodePeer, now+int64(2*time.Minute), kp)
	if err := VerifyRegistration(regWithinSkew); err != nil {
		t.Fatalf("expected registration within 2min skew to pass, got: %v", err)
	}

	// 3. Far-future timestamp (+1 hour) -> REJECT
	regFuture := NewRegistration(nodePeer, now+int64(1*time.Hour), kp)
	if err := VerifyRegistration(regFuture); err == nil {
		t.Fatalf("expected registration +1h in future to be rejected, but it passed")
	} else if !strings.Contains(err.Error(), "future") {
		t.Fatalf("expected future error message, got: %v", err)
	}

	// 4. Immortal timestamp (+100 years, as in Issue #169) -> REJECT
	regImmortal := NewRegistration(nodePeer, now+int64(100*365*24*time.Hour), kp)
	if err := VerifyRegistration(regImmortal); err == nil {
		t.Fatalf("expected registration +100y in future to be rejected, but it passed")
	}

	// 5. Ancient timestamp (-2 hours, well beyond TTL) -> REJECT
	regAncient := NewRegistration(nodePeer, now-int64(2*time.Hour), kp)
	if err := VerifyRegistration(regAncient); err == nil {
		t.Fatalf("expected ancient registration beyond TTL to be rejected, but it passed")
	}
}

func TestDirectoryPruneAndOverwritesExpiredOrSkewed(t *testing.T) {
	d := New(30 * time.Minute)
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nodePeer := "12D3KooWTestPeer123456789012345678901234567890123456"

	now := time.Now().UnixNano()

	// Direct manual entry insertion simulating an existing skewed/corrupt or expired entry
	d.mu.Lock()
	d.registrations[kp.Address()] = &Registration{
		Account:   kp.Address(),
		PubKey:    kp.PubKeyHex(),
		NodePeer:  nodePeer,
		Timestamp: now + int64(100*365*24*time.Hour),
		Signature: "dummy",
	}
	d.mu.Unlock()

	// Lookup must not return future-skewed entries
	if _, ok := d.Lookup(kp.Address()); ok {
		t.Fatalf("Lookup returned future-skewed entry")
	}

	// List must not include future-skewed entries
	if len(d.List()) != 0 {
		t.Fatalf("List returned future-skewed entry")
	}

	// Prune must delete future-skewed entries
	if pruned := d.Prune(); pruned != 1 {
		t.Fatalf("Prune did not remove future-skewed entry: pruned=%d", pruned)
	}

	// Fresh valid registration succeeds and registers cleanly
	regFresh := NewRegistration(nodePeer, time.Now().UnixNano(), kp)
	if err := d.Register(regFresh); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	stored, ok := d.Lookup(kp.Address())
	if !ok || stored.Timestamp != regFresh.Timestamp {
		t.Fatalf("Lookup failed after fresh register: ok=%v, stored=%v", ok, stored)
	}

	// Test Remove
	d.Remove(kp.Address())
	if _, ok := d.Lookup(kp.Address()); ok {
		t.Fatalf("Remove did not delete entry")
	}
}
