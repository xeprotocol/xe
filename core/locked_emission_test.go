package core

import (
	"strings"
	"testing"
)

func TestValidateLockedEmissionAt_LiveVsSync(t *testing.T) {
	candidates := []EpochParams{
		{R: 100, PayoutCap: 50, TWAP: 250}, // current active epoch (candidates[0])
		{R: 900, PayoutCap: 50, TWAP: 250}, // stale epoch 1
		{R: 800, PayoutCap: 50, TWAP: 250}, // stale epoch 2
		{R: 700, PayoutCap: 50, TWAP: 250}, // stale epoch 3
	}

	l := &Ledger{
		epochAtFn: func(ns int64) []EpochParams {
			return candidates
		},
	}

	atTime := int64(1_000_000_000)

	// Case 1: Live path (skipSkew = false) with current epoch terms -> SUCCESS
	if err := l.validateLockedEmissionAt(atTime, 100, 50, 250, false, "lease_accept"); err != nil {
		t.Fatalf("expected live path with active epoch to succeed, got: %v", err)
	}

	// Case 2: Live path (skipSkew = false) with stale candidate epoch terms -> MUST FAIL
	err := l.validateLockedEmissionAt(atTime, 900, 50, 250, false, "lease_accept")
	if err == nil {
		t.Fatal("expected live path with stale epoch to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "locked emission mismatch: block (R=900 cap=50 twap=250) != epoch@time (R=100 cap=50 twap=250)") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Case 3: Sync path (skipSkew = true) with stale candidate epoch terms -> MUST SUCCEED (multi-epoch tolerance)
	if err := l.validateLockedEmissionAt(atTime, 900, 50, 250, true, "lease_accept"); err != nil {
		t.Fatalf("expected sync path with in-window stale epoch to succeed, got: %v", err)
	}
	if err := l.validateLockedEmissionAt(atTime, 700, 50, 250, true, "lease_accept"); err != nil {
		t.Fatalf("expected sync path with in-window stale epoch 3 to succeed, got: %v", err)
	}

	// Case 4: Sync path (skipSkew = true) with out-of-window epoch terms -> MUST FAIL
	err = l.validateLockedEmissionAt(atTime, 9999, 50, 250, true, "lease_accept")
	if err == nil {
		t.Fatal("expected sync path with out-of-window epoch to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "locked emission mismatch on sync") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Case 5: When epoch is not yet available
	lEmpty := &Ledger{
		epochAtFn: func(ns int64) []EpochParams {
			return nil
		},
	}
	err = lEmpty.validateLockedEmissionAt(atTime, 100, 50, 250, false, "lease_accept")
	if err == nil || !strings.Contains(err.Error(), "not yet available") {
		t.Fatalf("expected epoch not yet available error, got: %v", err)
	}
}
