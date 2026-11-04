package core_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestLeaseStakeDivisorAndCollateralEnforcement(t *testing.T) {
	if core.LeaseStakeDivisor != 5 {
		t.Fatalf("LeaseStakeDivisor = %d, want 5", core.LeaseStakeDivisor)
	}

	cases := []struct {
		cost uint64
		want uint64
	}{
		{0, 1}, // min 1 µXUSD clamp
		{1, 1},
		{2, 1},
		{5, 1},
		{6, 2},
		{10, 2},
		{100, 20},
		{500, 100},
		{1_000_000, 200_000},
	}
	for _, tc := range cases {
		if got := core.LeaseStake(tc.cost); got != tc.want {
			t.Fatalf("LeaseStake(%d) = %d, want %d", tc.cost, got, tc.want)
		}
	}

	testNow := time.Unix(1_700_000_000, 0)
	core.Now = func() time.Time { return testNow }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	consumer := core.KeyPairFromSeed(bytes.Repeat([]byte{0x01}, 32))
	provider := core.KeyPairFromSeed(bytes.Repeat([]byte{0x02}, 32))
	timekeeper := core.KeyPairFromSeed(bytes.Repeat([]byte{0x03}, 32))
	certHash := hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: core.DefaultTimestampWindow,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{timekeeper.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            testNow.UnixNano() + int64(365*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 0}}
		},
		FeatureActiveFn: func(string) bool { return false },
	})

	seedAsset := func(kp *core.KeyPair, prev, asset string, bal, amt uint64) string {
		b := &core.Block{
			Type:      core.BlockMint,
			Account:   kp.Address(),
			Previous:  prev,
			Balance:   bal,
			Amount:    amt,
			Asset:     asset,
			Timestamp: testNow.UnixNano(),
		}
		if prev == "0" {
			b.PubKey = kp.PubKeyHex()
		}
		if err := core.SignBlock(b, kp); err != nil {
			t.Fatalf("sign mint: %v", err)
		}
		if err := ledger.SeedAssetForTesting(b); err != nil {
			t.Fatalf("seed %s: %v", asset, err)
		}
		return b.Hash
	}

	consPrev := seedAsset(consumer, "0", "XE", 1_000_000, 1_000_000)
	consPrev = seedAsset(consumer, consPrev, "XUSD", 1_000_000, 1_000_000)
	provPrev := seedAsset(provider, "0", "XE", 1, 1)

	cost, err := core.LeaseCost(1, 1024, 0, 60, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	expectedStake := core.LeaseStake(cost)
	if expectedStake != 100 {
		t.Fatalf("expected stake 100 for cost %d, got %d", cost, expectedStake)
	}

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         consumer.Address(),
		Previous:        consPrev,
		Balance:         1_000_000 - cost,
		Asset:           "XUSD",
		Destination:     provider.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          0,
		Duration:        60,
		CertificateHash: certHash,
		Timestamp:       testNow.UnixNano(),
	}
	if err := core.SignBlock(leaseBlock, consumer); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock(leaseBlock): %v", err)
	}

	att1, err := core.SignAttestation(leaseBlock.Hash, testNow.UnixNano(), timekeeper)
	if err != nil {
		t.Fatalf("sign accept attestation: %v", err)
	}

	// 1. lease_accept with amount=0 must be rejected.
	zeroStakeAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          0,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       testNow.UnixNano(),
	}
	if err := core.SignBlock(zeroStakeAccept, provider); err != nil {
		t.Fatalf("sign zeroStakeAccept: %v", err)
	}
	if err := ledger.AddBlock(zeroStakeAccept); err == nil || !strings.Contains(err.Error(), "stake mismatch") {
		t.Fatalf("expected lease_accept with amount=0 to fail with stake mismatch, got: %v", err)
	}

	// 2. lease_accept with required stake when provider holds 0 XUSD must be rejected.
	noBalAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          expectedStake,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       testNow.UnixNano(),
	}
	if err := core.SignBlock(noBalAccept, provider); err != nil {
		t.Fatalf("sign noBalAccept: %v", err)
	}
	if err := ledger.AddBlock(noBalAccept); err == nil || !strings.Contains(err.Error(), "insufficient XUSD balance for stake") {
		t.Fatalf("expected lease_accept with 0 XUSD balance to fail, got: %v", err)
	}

	// 3. Fund provider with XUSD and accept with expectedStake; verify locked_stake in SupplyAuditor.
	provPrev = seedAsset(provider, provPrev, "XUSD", expectedStake, expectedStake)
	validAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          expectedStake,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       testNow.UnixNano(),
	}
	if err := core.SignBlock(validAccept, provider); err != nil {
		t.Fatalf("sign validAccept: %v", err)
	}
	if err := ledger.AddBlock(validAccept); err != nil {
		t.Fatalf("expected validAccept to succeed, got: %v", err)
	}

	auditor := core.NewSupplyAuditor(ledger)
	rep := auditor.Report()
	if !rep.Conserved {
		t.Fatalf("expected supply to be conserved, notes: %v", rep.Notes)
	}
	if rep.Assets["XUSD"].LockedStake != expectedStake {
		t.Fatalf("expected LockedStake=%d, got %d", expectedStake, rep.Assets["XUSD"].LockedStake)
	}
}
