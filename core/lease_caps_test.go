package core_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestLeaseCapsCanonicalHashCompatibility ensures historical and capped blocks round-trip with exact PoWNonce.
func TestLeaseCapsCanonicalHashCompatibility(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := hex.EncodeToString(pub)

	// 1. Historical lease_accept block (without LeaseCapSet)
	histAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         addr,
		Previous:        "0",
		Balance:         1000,
		Timestamp:       1000000,
		Asset:           "XUSD",
		Source:          "0000000000000000000000000000000000000000000000000000000000000001",
		Amount:          100,
		LockedR:         10,
		LockedPayoutCap: 20,
		LockedTWAP:      30,
		PoWNonce:        12345678,
	}

	bytes1, err := core.MarshalBlock(histAccept)
	if err != nil {
		t.Fatalf("MarshalBlock failed: %v", err)
	}

	unmarshaled, err := core.UnmarshalBlock(bytes1)
	if err != nil {
		t.Fatalf("UnmarshalBlock failed: %v", err)
	}
	if unmarshaled.LeaseCapSet {
		t.Errorf("Expected historical block to have LeaseCapSet=false, got true")
	}
	if unmarshaled.PoWNonce != 12345678 {
		t.Fatalf("Expected historical block PoWNonce=12345678, got %d", unmarshaled.PoWNonce)
	}

	// 2. New lease_accept block with caps and non-zero PoWNonce
	newAccept := &core.Block{
		Type:             core.BlockLeaseAccept,
		Account:          addr,
		Previous:         "0",
		Balance:          1000,
		Timestamp:        1000000,
		Asset:            "XUSD",
		Source:           "0000000000000000000000000000000000000000000000000000000000000001",
		Amount:           100,
		LockedR:          10,
		LockedPayoutCap:  20,
		LockedTWAP:       30,
		LeaseCapSet:      true,
		LeaseCapDuration: 3600,
		LeaseCapCost:     500000000,
		PoWNonce:         987654321,
	}
	newBytes, err := core.MarshalBlock(newAccept)
	if err != nil {
		t.Fatalf("MarshalBlock new block failed: %v", err)
	}
	unmarshaledNew, err := core.UnmarshalBlock(newBytes)
	if err != nil {
		t.Fatalf("UnmarshalBlock new block failed: %v", err)
	}
	if !unmarshaledNew.LeaseCapSet || unmarshaledNew.LeaseCapDuration != 3600 || unmarshaledNew.LeaseCapCost != 500000000 {
		t.Fatalf("New block unmarshal caps mismatch: set=%v, dur=%d, cost=%d",
			unmarshaledNew.LeaseCapSet, unmarshaledNew.LeaseCapDuration, unmarshaledNew.LeaseCapCost)
	}
	// Assert exact PoWNonce round-trip preservation
	if unmarshaledNew.PoWNonce != 987654321 {
		t.Fatalf("PoWNonce lost in unmarshal with caps: expected 987654321, got %d", unmarshaledNew.PoWNonce)
	}
	_ = priv
}

// TestLeaseWithinRenewalCaps verifies all boundary cases and overflow defense.
func TestLeaseWithinRenewalCaps(t *testing.T) {
	lease := &core.Lease{
		Duration:    3600,
		Cost:        100000,
		CapSet:      true,
		CapDuration: 7200,
		CapCost:     300000,
		Renewals: []core.LeaseSegment{
			{Duration: 1800, Cost: 50000},
		},
	}
	// Initial total: duration = 3600 + 1800 = 5400s; cost = 100000 + 50000 = 150000

	// 1. Within caps (duration +1800 = 7200 == CapDuration; cost +50000 = 200000 <= 300000)
	if err := lease.WithinRenewalCaps(1800, 50000); err != nil {
		t.Fatalf("Expected renewal within caps to pass, got: %v", err)
	}

	// 2. Exact match on duration and cost
	if err := lease.WithinRenewalCaps(1800, 150000); err != nil {
		t.Fatalf("Expected exact boundary match to pass, got: %v", err)
	}

	// 3. Exceed duration cap (5400 + 1801 = 7201 > 7200)
	if err := lease.WithinRenewalCaps(1801, 10000); err == nil {
		t.Fatalf("Expected exceed duration cap to fail, but passed")
	}

	// 4. Exceed cost cap (150000 + 150001 = 300001 > 300000)
	if err := lease.WithinRenewalCaps(100, 150001); err == nil {
		t.Fatalf("Expected exceed cost cap to fail, but passed")
	}

	// 5. Uncommitted lease (CapSet == false)
	uncommitted := &core.Lease{CapSet: false}
	if err := uncommitted.WithinRenewalCaps(100, 100); err == nil {
		t.Fatalf("Expected uncommitted lease to fail WithinRenewalCaps")
	}

	// 6. Zero caps (CapSet == true with 0, 0: explicitly only bound by protocol caps)
	uncapped := &core.Lease{
		Duration:    3600,
		Cost:        100000,
		CapSet:      true,
		CapDuration: 0,
		CapCost:     0,
	}
	if err := uncapped.WithinRenewalCaps(86400, 999999999); err != nil {
		t.Fatalf("Expected zero caps to allow arbitrary valid commitments, got: %v", err)
	}

	// 7. Uint64 overflow defense
	if err := lease.WithinRenewalCaps(^uint64(0), 100); err == nil {
		t.Fatalf("Expected duration overflow to be rejected")
	}
	if err := lease.WithinRenewalCaps(100, ^uint64(0)); err == nil {
		t.Fatalf("Expected cost overflow to be rejected")
	}
}

// TestValidateStagedBlockForCaps tests conflict staging validation for lease_cap and lease_renew.
func TestValidateStagedBlockForCaps(t *testing.T) {
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{})

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Valid staged lease_cap
	capBlock := &core.Block{
		Type:        core.BlockLeaseCap,
		Account:     kp.Address(),
		Balance:     5000,
		Amount:      0,
		LeaseCapSet: true,
	}
	if err := core.SignBlock(capBlock, kp); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateStagedBlock(capBlock, 5000); err != nil {
		t.Fatalf("ValidateStagedBlock for valid lease_cap failed: %v", err)
	}

	// 2. Invalid staged lease_cap with amount != 0
	badCapBlock := &core.Block{
		Type:        core.BlockLeaseCap,
		Account:     kp.Address(),
		Balance:     5000,
		Amount:      100,
		LeaseCapSet: true,
	}
	if err := core.SignBlock(badCapBlock, kp); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateStagedBlock(badCapBlock, 5000); err == nil {
		t.Fatalf("ValidateStagedBlock should fail when lease_cap has non-zero amount")
	}

	// 3. Valid staged lease_renew
	renewBlock := &core.Block{
		Type:     core.BlockLeaseRenew,
		Account:  kp.Address(),
		Balance:  4000,
		Amount:   1000,
		Duration: 3600,
	}
	if err := core.SignBlock(renewBlock, kp); err != nil {
		t.Fatal(err)
	}
	if err := l.ValidateStagedBlock(renewBlock, 5000); err != nil {
		t.Fatalf("ValidateStagedBlock for valid lease_renew failed: %v", err)
	}

	// 4. Staged lease_renew insufficient balance
	if err := l.ValidateStagedBlock(renewBlock, 800); err == nil {
		t.Fatalf("ValidateStagedBlock should fail when parentBalance < Amount for lease_renew")
	}
}

// TestLeaseCapFinalizationDependencies verifies lease_cap does not stall block finalization.
func TestLeaseCapFinalizationDependencies(t *testing.T) {
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{})

	capBlock := &core.Block{
		Type:        core.BlockLeaseCap,
		Account:     "provider1",
		Source:      "0000000000000000000000000000000000000000000000000000000000000001",
		LeaseCapSet: true,
	}

	// The block must not produce unknown-type empty dependency
	if l.BlockDependenciesHasUnknownType(capBlock) {
		t.Fatalf("BlockDependencies produced unknown-type empty dependency for lease_cap")
	}
}
