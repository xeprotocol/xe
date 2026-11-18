package core

import (
	"math/big"
	"strings"
	"testing"
)

func TestRepresentativesAllowlistCaseInsensitive(t *testing.T) {
	repA := "a2673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	repB := "b3673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	upperB := strings.ToUpper(repB)

	l := &Ledger{
		delegation: map[string]string{},
		weights: map[string]*big.Int{
			repA: big.NewInt(1000),
			repB: big.NewInt(1000),
		},
	}

	// 1. Partial uppercase allowlist: repB configured with uppercase should match lowercase weight
	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{Mode: RepModeAllowlist, Addresses: []string{repA, upperB}}
	})

	if !l.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to be restricted")
	}
	if w := l.GetVoteWeight(repB); w.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("expected repB weight 1000 regardless of case in allowlist, got %s", w)
	}
	if total := l.GetTotalDelegatedWeight(); total.Cmp(big.NewInt(2000)) != 0 {
		t.Fatalf("expected total delegated weight 2000, got %s", total)
	}

	// 2. All-uppercase allowlist: should NOT trigger fail-open because addresses match lowercase weights
	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{Mode: RepModeAllowlist, Addresses: []string{strings.ToUpper(repA), upperB}}
	})

	if !l.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to remain restricted with uppercase addresses")
	}
	if l.RepEligibilityFailedOpen() {
		t.Fatalf("expected RepEligibilityFailedOpen() to be false")
	}
	if total := l.GetTotalDelegatedWeight(); total.Cmp(big.NewInt(2000)) != 0 {
		t.Fatalf("expected total delegated weight 2000, got %s", total)
	}
}
