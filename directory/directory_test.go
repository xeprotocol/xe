package directory

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestFutureDatedRegistrationRejected(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// 1 year in future
	futureTime := time.Now().Add(365 * 24 * time.Hour).UnixNano()
	reg := NewRegistration("/ip4/127.0.0.1/tcp/4001/p2p/QmTest", futureTime, kp)

	// VerifyRegistration must reject future timestamp
	if err := VerifyRegistration(reg); err == nil {
		t.Fatalf("expected VerifyRegistration to reject future timestamp, got nil")
	}

	d := New(1 * time.Minute)
	// Register must reject future registration
	if err := d.Register(reg); err == nil {
		t.Fatalf("expected Register to reject future timestamp, got nil")
	}

	// Even if forced into map, Lookup, List, and Prune must reject it
	d.mu.Lock()
	d.registrations[reg.Account] = reg
	d.mu.Unlock()

	if _, ok := d.Lookup(reg.Account); ok {
		t.Errorf("expected Lookup to reject future-dated registration")
	}

	list := d.List()
	if len(list) != 0 {
		t.Errorf("expected List to exclude future-dated registration, got %d items", len(list))
	}

	pruned := d.Prune()
	if pruned != 1 {
		t.Errorf("expected Prune to remove future-dated registration, pruned %d", pruned)
	}

	if _, ok := d.registrations[reg.Account]; ok {
		t.Errorf("expected record to be deleted after Prune")
	}
}

func TestPastExpiredRegistrationRejected(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// 2 hours in past (exceeds DefaultTTL + MaxRegistrationSkew)
	pastTime := time.Now().Add(-2 * time.Hour).UnixNano()
	reg := NewRegistration("/ip4/127.0.0.1/tcp/4001/p2p/QmTest", pastTime, kp)

	if err := VerifyRegistration(reg); err == nil {
		t.Fatalf("expected VerifyRegistration to reject expired past timestamp, got nil")
	}

	d := New(DefaultTTL)
	if err := d.Register(reg); err == nil {
		t.Fatalf("expected Register to reject expired past timestamp, got nil")
	}
}

func TestValidRegistrationLifecycleAndPrune(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	now := time.Now().UnixNano()
	reg := NewRegistration("/ip4/127.0.0.1/tcp/4001/p2p/QmTest", now, kp)

	d := New(100 * time.Millisecond)
	if err := d.Register(reg); err != nil {
		t.Fatalf("Register failed for valid registration: %v", err)
	}

	got, ok := d.Lookup(reg.Account)
	if !ok || got.NodePeer != reg.NodePeer {
		t.Fatalf("Lookup failed to return registered entry")
	}

	list := d.List()
	if len(list) != 1 || list[0].Account != reg.Account {
		t.Fatalf("List failed to return registered entry")
	}

	// Update with newer timestamp
	now2 := time.Now().UnixNano()
	reg2 := NewRegistration("/ip4/127.0.0.1/tcp/4002/p2p/QmTest2", now2, kp)
	if err := d.Register(reg2); err != nil {
		t.Fatalf("Register update failed: %v", err)
	}

	got2, ok2 := d.Lookup(reg.Account)
	if !ok2 || got2.NodePeer != "/ip4/127.0.0.1/tcp/4002/p2p/QmTest2" {
		t.Fatalf("Lookup did not reflect updated registration")
	}

	// Wait for TTL expiration
	time.Sleep(120 * time.Millisecond)

	if _, ok := d.Lookup(reg.Account); ok {
		t.Errorf("expected record to be expired after TTL")
	}

	if len(d.List()) != 0 {
		t.Errorf("expected List to return empty after TTL expiration")
	}

	if pruned := d.Prune(); pruned != 1 {
		t.Errorf("expected Prune to remove 1 expired entry, removed %d", pruned)
	}
}
