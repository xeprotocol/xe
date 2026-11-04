package node

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

func TestPolicyAllowRenewal(t *testing.T) {
	policy := LeaseAcceptPolicy{
		MaxDurationSec: 3600,      // 1 hour cap
		MaxCostXUSD:    500000000, // 500 XUSD cap
	}

	lease := &core.Lease{
		LeaseHash: "1111111111111111111111111111111111111111111111111111111111111111",
		Duration:  1800,
		Cost:      200000000,
		State:     core.LeaseAccepted,
	}

	// Case 1: Renewal within caps (1800s + 1800s = 3600s <= 3600s, 200M + 200M = 400M <= 500M)
	validRenew := &core.Block{
		Duration: 1800,
		Amount:   200000000,
	}
	if err := policy.AllowRenewal(lease, validRenew); err != nil {
		t.Fatalf("expected valid renewal to pass policy, got: %v", err)
	}

	// Case 2: Renewal exceeds duration cap (1800s + 1801s = 3601s > 3600s)
	overDurationRenew := &core.Block{
		Duration: 1801,
		Amount:   100000000,
	}
	err := policy.AllowRenewal(lease, overDurationRenew)
	if err == nil {
		t.Fatalf("expected renewal exceeding duration cap to fail")
	}
	if !strings.Contains(err.Error(), "cumulative duration") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Case 3: Renewal exceeds cost cap (200M + 300M + 1 = 500000001 > 500000000)
	overCostRenew := &core.Block{
		Duration: 1000,
		Amount:   300000001,
	}
	err = policy.AllowRenewal(lease, overCostRenew)
	if err == nil {
		t.Fatalf("expected renewal exceeding cost cap to fail")
	}
	if !strings.Contains(err.Error(), "cumulative cost") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Case 4: Multiple renewals cumulation test
	leaseWithPriorRenewals := &core.Lease{
		LeaseHash: "2222222222222222222222222222222222222222222222222222222222222222",
		Duration:  1000,
		Cost:      100000000,
		Renewals: []core.LeaseSegment{
			{Duration: 1000, Cost: 100000000},
			{Duration: 1000, Cost: 100000000},
		}, // Already 3000s and 300M
	}

	// Additional 600s is exactly 3600s -> allowed
	okRenew := &core.Block{Duration: 600, Amount: 50000000}
	if err := policy.AllowRenewal(leaseWithPriorRenewals, okRenew); err != nil {
		t.Fatalf("expected cumulative 3600s renewal to pass, got: %v", err)
	}

	// Additional 601s makes 3601s -> rejected
	badRenew := &core.Block{Duration: 601, Amount: 50000000}
	if err := policy.AllowRenewal(leaseWithPriorRenewals, badRenew); err == nil {
		t.Fatalf("expected cumulative 3601s renewal to fail")
	}

	// Case 5: Zero policy allows any valid renewal
	var zeroPolicy LeaseAcceptPolicy
	if err := zeroPolicy.AllowRenewal(lease, overDurationRenew); err != nil {
		t.Fatalf("zero policy should allow renewal, got: %v", err)
	}

	// Case 6: Integer overflow defense (wrapping attempt)
	overflowDurationRenew := &core.Block{
		Duration: math.MaxUint64 - 500,
		Amount:   100,
	}
	if err := policy.AllowRenewal(lease, overflowDurationRenew); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("expected duration overflow detection, got: %v", err)
	}
}

func TestCleanupOrphanedVMRespectsCommittedCapAndIgnoresZeroStartTime(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	st := store.NewMemStore()
	mockVM := vm.NewMockManager()

	// Provider's current local policy is strict (1800s), but lease was accepted with committed cap of 86400s
	n := &Node{
		KeyPair:   providerKP,
		store:     st,
		VMManager: mockVM,
		acceptPolicy: LeaseAcceptPolicy{
			MaxDurationSec: 1800, // tightened locally later
		},
	}

	now := core.Now().UnixNano()

	// 1. LeaseAccepted with StartTime == 0 (accepted block in flight / VM just provisioned):
	// MUST NOT be torn down!
	acceptedZeroStartHash := "1111111111111111111111111111111111111111111111111111111111111111"
	acceptedZeroStartLease := &core.Lease{
		LeaseHash: acceptedZeroStartHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
		Duration:  3600,
		StartTime: 0, // Not yet started
	}
	st.PutLease(acceptedZeroStartLease)
	mockVM.Provision(acceptedZeroStartHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "dummy")

	// 2. Lease with committed CapDuration = 86400s, running 3600s (> local 1800s policy, but <= 86400s committed cap and < EffectiveExpiry):
	// MUST NOT be torn down!
	committedCapHash := "2222222222222222222222222222222222222222222222222222222222222222"
	committedCapLease := &core.Lease{
		LeaseHash:   committedCapHash,
		State:       core.LeaseAccepted,
		Consumer:    consumerKP.Address(),
		Provider:    providerKP.Address(),
		Duration:    7200,
		CapSet:      true,
		CapDuration: 86400,
		StartTime:   now - int64(3600*time.Second), // started 1h ago, expires 1h in future
	}
	st.PutLease(committedCapLease)
	mockVM.Provision(committedCapHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "dummy")

	// 3. Lease that has truly exceeded committed cap AND reached EffectiveExpiry:
	// MUST BE torn down!
	trulyExpiredHash := "3333333333333333333333333333333333333333333333333333333333333333"
	trulyExpiredLease := &core.Lease{
		LeaseHash:   trulyExpiredHash,
		State:       core.LeaseAccepted,
		Consumer:    consumerKP.Address(),
		Provider:    providerKP.Address(),
		Duration:    3600,
		CapSet:      true,
		CapDuration: 3600,
		StartTime:   now - int64(4000*time.Second), // expired 400s ago
	}
	st.PutLease(trulyExpiredLease)
	mockVM.Provision(trulyExpiredHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "dummy")

	// Run cleanup
	n.cleanupOrphanedVMs()

	// Check 1: Accepted with StartTime == 0 -> MUST STILL EXIST
	if _, err := mockVM.Get(acceptedZeroStartHash); err != nil {
		t.Fatalf("expected accepted VM with StartTime=0 to NOT be torn down: %v", err)
	}

	// Check 2: Committed Cap VM within expiry -> MUST STILL EXIST
	if _, err := mockVM.Get(committedCapHash); err != nil {
		t.Fatalf("expected committed cap VM within expiry to NOT be torn down: %v", err)
	}

	// Check 3: Truly expired VM beyond cap and expiry -> MUST BE TORN DOWN
	if _, err := mockVM.Get(trulyExpiredHash); err == nil {
		t.Fatalf("expected truly expired VM beyond cap and expiry to be torn down")
	}
}
