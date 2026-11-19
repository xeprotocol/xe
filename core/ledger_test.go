package core

import (
	"testing"
)

func TestCapR_FailClosedOnZeroTWAP_Issue372(t *testing.T) {
	// Issue #372: When TWAP is 0, CapR must fail closed and return 0 (not uncapped R)
	if got := CapR(1_000_000_000, 1502, 0); got != 0 {
		t.Fatalf("CapR with twap=0 failed to fail closed: expected 0, got %d", got)
	}

	if got := CapR(2000, 1502, 0); got != 0 {
		t.Fatalf("CapR with twap=0 failed to fail closed: expected 0, got %d", got)
	}
}

func TestCapR_FailClosedOnZeroPayoutCap(t *testing.T) {
	if got := CapR(2000, 0, 250); got != 0 {
		t.Fatalf("CapR with payoutCap=0 failed to fail closed: expected 0, got %d", got)
	}
}

func TestCapR_NormalAndCapped(t *testing.T) {
	// payoutCap=1500, twap=250 -> scaled = 1500 * 1000 = 1,500,000
	// rCapMax = ceilDiv(1,500,000, 250) = 6000
	payoutCap := uint64(1500)
	twap := uint64(250)

	// Under cap: r=2000 < 6000 -> returns 2000
	if got := CapR(2000, payoutCap, twap); got != 2000 {
		t.Errorf("expected 2000, got %d", got)
	}

	// At cap: r=6000 == 6000 -> returns 6000
	if got := CapR(6000, payoutCap, twap); got != 6000 {
		t.Errorf("expected 6000, got %d", got)
	}

	// Over cap: r=10000 > 6000 -> clamped to 6000
	if got := CapR(10000, payoutCap, twap); got != 6000 {
		t.Errorf("expected 6000, got %d", got)
	}
}

func TestLeaseEmissionWithFailClosedCapR(t *testing.T) {
	// Issue #372 PoC scenario:
	// A $31 lease (cost = 31,000 mXUSD).
	cost := uint64(31000)

	// If an attacker sets twap=0 with r=1e9:
	effectiveR := CapR(1_000_000_000, 1502, 0)
	emission, err := LeaseEmissionChecked(cost, effectiveR)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Emission should be floored safely at 1 mXE, NOT 31,000 XE (31,000,000,000 mXE)!
	if emission != 1 {
		t.Fatalf("expected fail-closed emission of 1 mXE, got %d", emission)
	}

	// Also verify LeaseTotalEmission with zero LockedTWAP
	lease := &Lease{
		Cost:            cost,
		LockedR:         1_000_000_000,
		LockedPayoutCap: 1502,
		LockedTWAP:      0,
	}
	total, err := LeaseTotalEmission(lease)
	if err != nil {
		t.Fatalf("LeaseTotalEmission error: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total emission 1, got %d", total)
	}
}
