package node

import (
	"math"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestPolicyValidation(t *testing.T) {
	valid := LeaseAcceptPolicy{
		MinDurationSec: 60,
		MaxDurationSec: 3600,
		MinCostXUSD:    1000,
		MaxCostXUSD:    500000,
		MaxConcurrent:  10,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid policy, got: %v", err)
	}

	invalidDuration := LeaseAcceptPolicy{
		MinDurationSec: 7200,
		MaxDurationSec: 3600,
	}
	if err := invalidDuration.Validate(); err == nil || !strings.Contains(err.Error(), "min-lease-duration") {
		t.Fatalf("expected min duration validation error, got: %v", err)
	}

	invalidCost := LeaseAcceptPolicy{
		MinCostXUSD: 100000,
		MaxCostXUSD: 50000,
	}
	if err := invalidCost.Validate(); err == nil || !strings.Contains(err.Error(), "min-lease-cost") {
		t.Fatalf("expected min cost validation error, got: %v", err)
	}
}

func TestPolicyAllowInitialLease(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MinDurationSec: 60,
		MaxDurationSec: 3600,
		MinCostXUSD:    1000,
		MaxCostXUSD:    500000,
		MaxConcurrent:  5,
	}

	// Within bounds
	okBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 1800,
		Amount:   200000,
	}
	if err := policy.Allow(okBlock, 2); err != nil {
		t.Fatalf("expected block to be allowed, got: %v", err)
	}

	// Below min duration
	shortBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 30,
		Amount:   200000,
	}
	if err := policy.Allow(shortBlock, 2); err == nil || !strings.Contains(err.Error(), "duration 30s < policy min") {
		t.Fatalf("expected min duration rejection, got: %v", err)
	}

	// Above max duration
	longBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 7200,
		Amount:   200000,
	}
	if err := policy.Allow(longBlock, 2); err == nil || !strings.Contains(err.Error(), "duration 7200s > policy max") {
		t.Fatalf("expected max duration rejection, got: %v", err)
	}

	// Below min cost
	cheapBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 1800,
		Amount:   500,
	}
	if err := policy.Allow(cheapBlock, 2); err == nil || !strings.Contains(err.Error(), "cost 500 XUSD < policy min") {
		t.Fatalf("expected min cost rejection, got: %v", err)
	}

	// Above max cost
	priceyBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 1800,
		Amount:   600000,
	}
	if err := policy.Allow(priceyBlock, 2); err == nil || !strings.Contains(err.Error(), "cost 600000 XUSD > policy max") {
		t.Fatalf("expected max cost rejection, got: %v", err)
	}

	// Concurrent cap
	if err := policy.Allow(okBlock, 5); err == nil || !strings.Contains(err.Error(), "active leases 5 ≥ policy cap") {
		t.Fatalf("expected active cap rejection, got: %v", err)
	}
}

func TestPolicyAllowRenewal(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MinDurationSec: 60,
		MaxDurationSec: 7200,
		MinCostXUSD:    1000,
		MaxCostXUSD:    200000,
	}

	baseLease := &core.Lease{
		LeaseHash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		State:     core.LeaseAccepted,
		Duration:  3600,
		Cost:      80000,
	}

	// Renewal within caps: +1800s (projected 5400s <= 7200s), cost 40000 (projected 120000 <= 200000)
	if err := policy.AllowRenewal(baseLease, 1800, 40000); err != nil {
		t.Fatalf("expected renewal within policy to be accepted, got: %v", err)
	}

	// Renewal exceeding MaxDurationSec: +4000s -> projected 7600s > 7200s
	if err := policy.AllowRenewal(baseLease, 4000, 40000); err == nil || !strings.Contains(err.Error(), "projected cumulative duration 7600s > policy max 7200s") {
		t.Fatalf("expected duration cap error, got: %v", err)
	}

	// Renewal exceeding MaxCostXUSD: +1800s, cost 150000 -> projected 230000 > 200000
	if err := policy.AllowRenewal(baseLease, 1800, 150000); err == nil || !strings.Contains(err.Error(), "projected cumulative cost 230000 XUSD > policy max 200000 XUSD") {
		t.Fatalf("expected cost cap error, got: %v", err)
	}

	// Renewal below MinDurationSec: +30s < 60s
	if err := policy.AllowRenewal(baseLease, 30, 40000); err == nil || !strings.Contains(err.Error(), "duration 30s < policy min 60s") {
		t.Fatalf("expected min duration error, got: %v", err)
	}

	// Renewal below MinCostXUSD: cost 500 < 1000
	if err := policy.AllowRenewal(baseLease, 1800, 500); err == nil || !strings.Contains(err.Error(), "cost 500 XUSD < policy min 1000 XUSD") {
		t.Fatalf("expected min cost error, got: %v", err)
	}
}

func TestPolicyCumulativeMultiStepRenewals(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MaxDurationSec: 6000,
		MaxCostXUSD:    150000,
	}

	// Initial lease: 1800s, 40000 XUSD
	lease := &core.Lease{
		LeaseHash: "aaaa",
		Duration:  1800,
		Cost:      40000,
		Renewals: []core.LeaseSegment{
			// Segment 1: +1800s, 40000 XUSD -> cumulative 3600s, 80000 XUSD
			{
				Duration: 1800,
				Cost:     40000,
			},
			// Segment 2: +1800s, 40000 XUSD -> cumulative 5400s, 120000 XUSD
			{
				Duration: 1800,
				Cost:     40000,
			},
		},
	}

	if lease.EffectiveDurationSecs() != 5400 {
		t.Fatalf("expected cumulative duration 5400s, got %d", lease.EffectiveDurationSecs())
	}
	if lease.TotalCost() != 120000 {
		t.Fatalf("expected total cost 120000, got %d", lease.TotalCost())
	}

	// Renewal 3 with +500s (projected 5900s <= 6000s) and cost 10000 (projected 130000 <= 150000) -> Allowed
	if err := policy.AllowRenewal(lease, 500, 10000); err != nil {
		t.Fatalf("expected valid 3rd renewal to be allowed, got: %v", err)
	}

	// Renewal 3 with +700s (projected 6100s > 6000s) -> Rejected
	if err := policy.AllowRenewal(lease, 700, 10000); err == nil || !strings.Contains(err.Error(), "projected cumulative duration 6100s > policy max 6000s") {
		t.Fatalf("expected cumulative duration rejection on 3rd renewal, got: %v", err)
	}

	// Renewal 3 with +500s and cost 35000 (projected 155000 > 150000) -> Rejected
	if err := policy.AllowRenewal(lease, 500, 35000); err == nil || !strings.Contains(err.Error(), "projected cumulative cost 155000 XUSD > policy max 150000 XUSD") {
		t.Fatalf("expected cumulative cost rejection on 3rd renewal, got: %v", err)
	}
}

func TestPolicyReproductionPoC_Issue162(t *testing.T) {
	// Replicating the exact parameters from issue #162:
	// MaxDurationSec = 3600 (1 hour)
	// MaxCostXUSD = 500000000 (500 XUSD in micro-units)
	policy := LeaseAcceptPolicy{
		MaxDurationSec: 3600,
		MaxCostXUSD:    500000000,
	}

	// Initial 1h lease (cost 80000 micro-XUSD)
	initBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 3600,
		Amount:   80000,
	}
	if err := policy.Allow(initBlock, 0); err != nil {
		t.Fatalf("policy should allow the 1h lease: %v", err)
	}

	// Control: fresh lease_open for 31536000s (1 year) is rejected
	fullYearBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 31536000,
		Amount:   700800000,
	}
	if err := policy.Allow(fullYearBlock, 0); err == nil || !strings.Contains(err.Error(), "duration 31536000s > policy max 3600s") {
		t.Fatalf("policy must reject 1-year lease_open, got: %v", err)
	}

	// Previously, a unilateral lease_renew for +31532400s (cost 700720000) bypassed policy caps.
	// With AllowRenewal, the projected lease (duration 31536000s, cost 700800000) is evaluated:
	lease := &core.Lease{
		LeaseHash: "test_lease_hash",
		Duration:  3600,
		Cost:      80000,
		State:     core.LeaseAccepted,
	}

	renewBlock := &core.Block{
		Type:     core.BlockLeaseRenew,
		Source:   lease.LeaseHash,
		Duration: 31532400,
		Amount:   700720000,
	}

	err := policy.AllowRenewalBlock(lease, renewBlock)
	if err == nil {
		t.Fatal("expected renewal bypassing policy caps to be rejected, but it was accepted")
	}
	if !strings.Contains(err.Error(), "projected cumulative duration 31536000s > policy max 3600s") {
		t.Fatalf("expected cumulative duration rejection error, got: %v", err)
	}
}

func TestPolicyAllowProjected(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MaxDurationSec: 3600,
		MaxCostXUSD:    100000,
		MaxConcurrent:  2,
	}

	// BlockLease dispatch
	leaseBlock := &core.Block{
		Type:     core.BlockLease,
		Duration: 1800,
		Amount:   50000,
	}
	if err := policy.AllowProjected(leaseBlock, 1, nil); err != nil {
		t.Fatalf("expected lease block to be allowed: %v", err)
	}

	// BlockLeaseRenew without lease -> error
	renewBlock := &core.Block{
		Type:     core.BlockLeaseRenew,
		Duration: 1800,
		Amount:   50000,
	}
	if err := policy.AllowProjected(renewBlock, 1, nil); err == nil {
		t.Fatal("expected error when lease is nil for BlockLeaseRenew")
	}

	// BlockLeaseRenew with valid lease
	existingLease := &core.Lease{
		Duration: 1000,
		Cost:     20000,
	}
	if err := policy.AllowProjected(renewBlock, 1, existingLease); err != nil {
		t.Fatalf("expected valid renewal to be allowed: %v", err)
	}

	// BlockLeaseRenew exceeding duration
	excessRenewBlock := &core.Block{
		Type:     core.BlockLeaseRenew,
		Duration: 3000, // 1000 + 3000 = 4000 > 3600
		Amount:   50000,
	}
	if err := policy.AllowProjected(excessRenewBlock, 1, existingLease); err == nil || !strings.Contains(err.Error(), "projected cumulative duration 4000s > policy max 3600s") {
		t.Fatalf("expected cumulative duration rejection, got: %v", err)
	}
}

func TestPolicyArithmeticOverflow(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MaxDurationSec: 10000,
		MaxCostXUSD:    100000,
	}

	lease := &core.Lease{
		Duration: math.MaxUint64 - 10,
		Cost:     math.MaxUint64 - 10,
	}

	// Duration overflow
	if err := policy.AllowRenewal(lease, 20, 100); err == nil || !strings.Contains(err.Error(), "cumulative duration overflow") {
		t.Fatalf("expected duration overflow error, got: %v", err)
	}

	// Cost overflow
	safeDurLease := &core.Lease{
		Duration: 100,
		Cost:     math.MaxUint64 - 10,
	}
	if err := policy.AllowRenewal(safeDurLease, 100, 20); err == nil || !strings.Contains(err.Error(), "cumulative cost overflow") {
		t.Fatalf("expected cost overflow error, got: %v", err)
	}
}
