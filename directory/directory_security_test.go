package directory

import (
	"math"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestDirectoryRejectsFuturePoisoningAndNegativeTimestampOverflow(t *testing.T) {
	d := New(10 * time.Minute)
	d.maxEntries = 3

	kp, _ := core.GenerateKeyPair()
	now := core.Now().UnixNano()

	// 1. Far-future timestamp (math.MaxInt64) must be rejected to prevent permanent un-prunable registration lockout.
	futureReg := NewRegistration("12D3KooWFuturePeer", math.MaxInt64, kp)
	if err := d.Register(futureReg); err == nil {
		t.Fatalf("expected far-future registration (MaxInt64) to be rejected")
	}

	// 2. Negative timestamp (math.MinInt64) must be rejected so signed int64 subtraction cannot overflow in Lookup/List/Prune.
	negReg := NewRegistration("12D3KooWNegPeer", math.MinInt64, kp)
	if err := d.Register(negReg); err == nil {
		t.Fatalf("expected negative timestamp registration (MinInt64) to be rejected")
	}

	// 3. Already-expired timestamp must be rejected on Register.
	expiredReg := NewRegistration("12D3KooWExpiredPeer", now-int64(20*time.Minute), kp)
	if err := d.Register(expiredReg); err == nil {
		t.Fatalf("expected already-expired registration to be rejected")
	}

	// 4. Valid registration succeeds and can be updated by a newer valid timestamp.
	validReg := NewRegistration("12D3KooWValidPeer1", now, kp)
	if err := d.Register(validReg); err != nil {
		t.Fatalf("expected valid registration to succeed, got: %v", err)
	}
	got, ok := d.Lookup(kp.Address())
	if !ok || got.NodePeer != "12D3KooWValidPeer1" {
		t.Fatalf("expected Lookup to return validReg, got %+v (ok=%v)", got, ok)
	}

	// 5. Capacity bound evicts oldest registration when full.
	for i := 1; i <= 3; i++ {
		otherKP, _ := core.GenerateKeyPair()
		r := NewRegistration("12D3KooWPeer", now+int64(i)*1_000_000, otherKP)
		if err := d.Register(r); err != nil {
			t.Fatalf("Register %d: %v", i, err)
		}
	}
	if len(d.List()) != 3 {
		t.Fatalf("expected Directory size capped at 3, got %d", len(d.List()))
	}
	if _, ok := d.Lookup(kp.Address()); ok {
		t.Fatalf("expected oldest registration to be evicted when maxEntries reached")
	}
}
