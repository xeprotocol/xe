package node

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestLeaseAcceptPolicyCostThresholds(t *testing.T) {
	// A small lease of 517 micro-XUSD (0.000517 XUSD)
	smallLease := &core.Block{
		Amount:   517,
		Duration: 3600,
	}

	// 1. MinCostXUSD = 5 (intended 5 XUSD floor = 5,000,000 uXUSD)
	// Must reject smallLease (517 uXUSD < 5,000,000 uXUSD)
	minPolicy := LeaseAcceptPolicy{
		MinCostXUSD: 5,
	}
	err := minPolicy.Allow(smallLease, 0)
	if err == nil {
		t.Fatalf("expected min-cost policy to reject 517 uXUSD lease against min 5 XUSD")
	}
	expectedMinErr := "cost 0.000517 XUSD < policy min 5 XUSD"
	if err.Error() != expectedMinErr {
		t.Fatalf("expected error %q, got %q", expectedMinErr, err.Error())
	}

	// 2. MaxCostXUSD = 100 (intended 100 XUSD cap = 100,000,000 uXUSD)
	// Must accept smallLease (517 uXUSD <= 100,000,000 uXUSD)
	maxPolicy := LeaseAcceptPolicy{
		MaxCostXUSD: 100,
	}
	if err := maxPolicy.Allow(smallLease, 0); err != nil {
		t.Fatalf("expected max-cost policy to accept 517 uXUSD lease against max 100 XUSD, got err: %v", err)
	}

	// 3. A lease of 2,000,000 micro-XUSD (2 XUSD)
	largeLease := &core.Block{
		Amount:   2_000_000,
		Duration: 3600,
	}
	cap1XUSD := LeaseAcceptPolicy{
		MaxCostXUSD: 1,
	}
	err = cap1XUSD.Allow(largeLease, 0)
	if err == nil {
		t.Fatalf("expected cap 1 XUSD to reject 2 XUSD lease")
	}
	expectedMaxErr := "cost 2 XUSD > policy max 1 XUSD"
	if err.Error() != expectedMaxErr {
		t.Fatalf("expected error %q, got %q", expectedMaxErr, err.Error())
	}

	// 4. In-range lease: min 1 XUSD, max 10 XUSD, lease cost 5 XUSD
	rangePolicy := LeaseAcceptPolicy{
		MinCostXUSD: 1,
		MaxCostXUSD: 10,
	}
	midLease := &core.Block{
		Amount:   5_000_000,
		Duration: 3600,
	}
	if err := rangePolicy.Allow(midLease, 0); err != nil {
		t.Fatalf("expected range policy to accept 5 XUSD lease, got: %v", err)
	}
}

func TestLeaseAcceptPolicyValidate(t *testing.T) {
	// Valid zero policy
	var zeroPolicy LeaseAcceptPolicy
	if err := zeroPolicy.Validate(); err != nil {
		t.Fatalf("zero policy should be valid: %v", err)
	}
	if !zeroPolicy.IsZero() {
		t.Fatalf("expected IsZero to be true")
	}

	// Inverted cost: min > max
	invertedCost := LeaseAcceptPolicy{
		MinCostXUSD: 10,
		MaxCostXUSD: 5,
	}
	if err := invertedCost.Validate(); err == nil || !strings.Contains(err.Error(), "must be ≤ max-lease-cost") {
		t.Fatalf("expected min > max cost validation error, got: %v", err)
	}

	// Inverted duration: min > max
	invertedDur := LeaseAcceptPolicy{
		MinDurationSec: 3600,
		MaxDurationSec: 1800,
	}
	if err := invertedDur.Validate(); err == nil || !strings.Contains(err.Error(), "must be ≤ max-lease-duration") {
		t.Fatalf("expected min > max duration validation error, got: %v", err)
	}
}

func TestLeaseAcceptPolicyDurationAndConcurrency(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MinDurationSec: 100,
		MaxDurationSec: 500,
		MaxConcurrent:  2,
	}

	// Duration too short
	shortBlock := &core.Block{Duration: 50}
	if err := policy.Allow(shortBlock, 0); err == nil || !strings.Contains(err.Error(), "duration 50s < policy min 100s") {
		t.Fatalf("expected duration too short error, got: %v", err)
	}

	// Duration too long
	longBlock := &core.Block{Duration: 600}
	if err := policy.Allow(longBlock, 0); err == nil || !strings.Contains(err.Error(), "duration 600s > policy max 500s") {
		t.Fatalf("expected duration too long error, got: %v", err)
	}

	// Concurrency cap reached
	okBlock := &core.Block{Duration: 300}
	if err := policy.Allow(okBlock, 2); err == nil || !strings.Contains(err.Error(), "active leases 2 ≥ policy cap 2") {
		t.Fatalf("expected concurrency cap error, got: %v", err)
	}

	// All conditions met
	if err := policy.Allow(okBlock, 1); err != nil {
		t.Fatalf("expected allow to succeed, got: %v", err)
	}
}
