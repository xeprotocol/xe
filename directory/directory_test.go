package directory

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

// TestRegistrationFreshnessBound verifies that VerifyRegistration enforces
// freshness bounds and rejects future-dated entries as well as expired entries (#156).
func TestRegistrationFreshnessBound(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	now := core.Now().UnixNano()

	testCases := []struct {
		name        string
		offset      time.Duration
		expectError bool
		errContains string
	}{
		{
			name:        "current timestamp (now)",
			offset:      0,
			expectError: false,
		},
		{
			name:        "recent past (now - 5m)",
			offset:      -5 * time.Minute,
			expectError: false,
		},
		{
			name:        "expired past (now - 36m, exceeds DefaultTTL + 5m skew)",
			offset:      -36 * time.Minute,
			expectError: true,
			errContains: "registration timestamp expired",
		},
		{
			name:        "future past tolerance (now + 10m, exceeds 5m skew)",
			offset:      10 * time.Minute,
			expectError: true,
			errContains: "registration timestamp too far in the future",
		},
		{
			name:        "far future 10 years (#156 PoC attack vector)",
			offset:      10 * 365 * 24 * time.Hour,
			expectError: true,
			errContains: "registration timestamp too far in the future",
		},
		{
			name:        "far future 200 years (#156 PoC attack vector)",
			offset:      200 * 365 * 24 * time.Hour,
			expectError: true,
			errContains: "registration timestamp too far in the future",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := now + tc.offset.Nanoseconds()
			reg := NewRegistration("peer-test-123", ts, kp)

			err := VerifyRegistration(reg)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDirectoryLifecycleAndEviction verifies that valid entries are stored,
// lookup/list respect freshness windows, and Prune removes expired or invalid entries (#156).
func TestDirectoryLifecycleAndEviction(t *testing.T) {
	d := New(30 * time.Minute)

	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()

	now := core.Now().UnixNano()

	// 1. Valid entry
	reg1 := NewRegistration("peer-node-1", now, kp1)
	if err := d.Register(reg1); err != nil {
		t.Fatalf("failed to register valid reg1: %v", err)
	}

	got, ok := d.Lookup(kp1.Address())
	if !ok || got == nil {
		t.Fatalf("expected lookup to find reg1")
	}

	// 2. Future-dated entry registration should be rejected by VerifyRegistration
	futureReg := NewRegistration("peer-future", now+(10*365*24*time.Hour).Nanoseconds(), kp2)
	if err := d.Register(futureReg); err == nil {
		t.Fatalf("expected future registration to be rejected, got nil error")
	}

	// 3. Verify List returns only fresh registrations
	list := d.List()
	if len(list) != 1 || list[0].Account != kp1.Address() {
		t.Fatalf("expected list to contain only reg1, got %d items", len(list))
	}

	// 4. Test Prune with simulated aged entry
	d.mu.Lock()
	// artificially insert an expired entry and a future entry to test defense-in-depth pruning
	d.registrations["expired-account"] = &Registration{
		Account:   "expired-account",
		Timestamp: now - (60 * time.Minute).Nanoseconds(),
	}
	d.registrations["future-account"] = &Registration{
		Account:   "future-account",
		Timestamp: now + (100 * 24 * time.Hour).Nanoseconds(),
	}
	d.mu.Unlock()

	pruned := d.Prune()
	if pruned != 2 {
		t.Fatalf("expected 2 pruned entries, got %d", pruned)
	}

	// reg1 should still remain
	if _, ok := d.Lookup(kp1.Address()); !ok {
		t.Fatalf("expected reg1 to remain after prune")
	}
}
