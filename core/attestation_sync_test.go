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

func seedAssetForSyncTest(t *testing.T, l *core.Ledger, kp *core.KeyPair, prev, asset string, balance, amount uint64, ts int64) string {
	t.Helper()
	b := &core.Block{
		Type:      core.BlockMint,
		Account:   kp.Address(),
		Previous:  prev,
		Balance:   balance,
		Amount:    amount,
		Asset:     asset,
		Timestamp: ts,
	}
	if prev == "0" {
		b.PubKey = kp.PubKeyHex()
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign mint: %v", err)
	}
	if err := l.SeedAssetForTesting(b); err != nil {
		t.Fatalf("seed %s: %v", asset, err)
	}
	return b.Hash
}

func TestSyncIngestionEnforcesAttestationFreshnessAndPreventsAcceptReuse(t *testing.T) {
	t0 := time.Unix(1_792_778_684, 491_395_990)
	now := t0
	core.Now = func() time.Time { return now }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	consumer := core.KeyPairFromSeed(bytes.Repeat([]byte{0x11}, 32))
	provider := core.KeyPairFromSeed(bytes.Repeat([]byte{0x22}, 32))
	tk1 := core.KeyPairFromSeed(bytes.Repeat([]byte{0x31}, 32))
	tk2 := core.KeyPairFromSeed(bytes.Repeat([]byte{0x32}, 32))
	certHash := hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: core.DefaultTimestampWindow,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{
				Keys:      []string{tk1.PubKeyHex(), tk2.PubKeyHex()},
				Threshold: 2,
			}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            t0.Add(365 * 24 * time.Hour).UnixNano(),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 2000, PayoutCap: 0, TWAP: 0}}
		},
		EpochRFn:        func() uint64 { return 2000 },
		FeatureActiveFn: func(string) bool { return false },
	})

	// Open consumer and provider accounts and fund consumer with 100,000,000 micro-XUSD.
	consPrev := seedAssetForSyncTest(t, ledger, consumer, "0", "XE", 1_000_000, 1_000_000, now.UnixNano())
	consPrev = seedAssetForSyncTest(t, ledger, consumer, consPrev, "XUSD", 100_000_000, 100_000_000, now.UnixNano())
	provPrev := seedAssetForSyncTest(t, ledger, provider, "0", "XE", 1_000_000, 1_000_000, now.UnixNano())
	provPrev = seedAssetForSyncTest(t, ledger, provider, provPrev, "XUSD", 1_000_000, 1_000_000, now.UnixNano())

	cost, err := core.LeaseCost(1, 1024, 10, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	if cost != 40_000 {
		t.Fatalf("expected cost 40000, got %d", cost)
	}

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         consumer.Address(),
		Previous:        consPrev,
		Balance:         100_000_000 - cost,
		Asset:           "XUSD",
		Destination:     provider.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        3600,
		CertificateHash: certHash,
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(leaseBlock, consumer); err != nil {
		t.Fatalf("sign leaseBlock: %v", err)
	}
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock(leaseBlock): %v", err)
	}

	att1, err := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), tk1)
	if err != nil {
		t.Fatalf("sign att1: %v", err)
	}
	att2, err := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), tk2)
	if err != nil {
		t.Fatalf("sign att2: %v", err)
	}
	stake := core.LeaseStake(cost)
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         1_000_000 - stake,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         2000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    []core.TimekeeperAttestation{*att1, *att2},
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(acceptBlock, provider); err != nil {
		t.Fatalf("sign acceptBlock: %v", err)
	}
	if err := ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock(acceptBlock): %v", err)
	}

	storedAccept := ledger.GetBlock(acceptBlock.Hash)
	if storedAccept == nil || len(storedAccept.Attestations) != 2 {
		t.Fatalf("expected stored accept block with 2 attestations")
	}
	recoveredAtts := storedAccept.Attestations

	// Bound 1: Even within MaxAttestationSkew (1 minute later), replaying the T0 accept attestations
	// on lease_renew must be rejected on both live and sync paths because renewTime == lease.StartTime.
	now = t0.Add(1 * time.Minute)
	inWindowReplayRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumer.Address(),
		Previous:        leaseBlock.Hash,
		Balance:         100_000_000 - 2*cost,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    recoveredAtts,
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(inWindowReplayRenew, consumer); err != nil {
		t.Fatalf("sign inWindowReplayRenew: %v", err)
	}
	if err := ledger.AddBlock(inWindowReplayRenew); err == nil {
		t.Fatalf("expected AddBlock to reject lease_renew replaying accept attestations at T0")
	}
	if err := ledger.AddSyncedBlock(inWindowReplayRenew); err == nil {
		t.Fatalf("expected AddSyncedBlock to reject lease_renew replaying accept attestations at T0")
	}

	// Bound 2 (Issue #19 experiment): Move clock to T0 + 3 days (72h old against 10m MaxAttestationSkew).
	// Both AddBlock and AddSyncedBlock must reject the stale attestation set with the freshness error.
	now = t0.Add(72 * time.Hour)
	staleRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumer.Address(),
		Previous:        leaseBlock.Hash,
		Balance:         100_000_000 - 2*cost,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    recoveredAtts,
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(staleRenew, consumer); err != nil {
		t.Fatalf("sign staleRenew: %v", err)
	}

	liveErr := ledger.AddBlock(staleRenew)
	if liveErr == nil || !strings.Contains(liveErr.Error(), "only 0 valid attestations from trusted timekeepers, need 2") {
		t.Fatalf("expected live AddBlock to fail attestation freshness check, got: %v", liveErr)
	}

	syncErr := ledger.AddSyncedBlock(staleRenew)
	if syncErr == nil || !strings.Contains(syncErr.Error(), "only 0 valid attestations from trusted timekeepers, need 2") {
		t.Fatalf("expected AddSyncedBlock to fail attestation freshness check identically, got: %v", syncErr)
	}

	// Confirm lease state and consumer balance were untouched.
	lease, err := ms.GetLease(leaseBlock.Hash)
	if err != nil || lease == nil {
		t.Fatalf("GetLease: %v", err)
	}
	if len(lease.Renewals) != 0 {
		t.Fatalf("expected 0 renewals committed, got %d", len(lease.Renewals))
	}
	if got := ledger.GetAssetBalances(consumer.Address())["XUSD"]; got != 100_000_000-cost {
		t.Fatalf("expected consumer XUSD balance %d, got %d", 100_000_000-cost, got)
	}

	// Bound 3: Operation-bound attestations for lease_accept cannot be used on lease_renew.
	now = t0.Add(10 * time.Minute)
	opAtt1, err := core.SignAttestationForOp(leaseBlock.Hash, string(core.BlockLeaseAccept), now.UnixNano(), tk1)
	if err != nil {
		t.Fatalf("SignAttestationForOp 1: %v", err)
	}
	opAtt2, err := core.SignAttestationForOp(leaseBlock.Hash, string(core.BlockLeaseAccept), now.UnixNano(), tk2)
	if err != nil {
		t.Fatalf("SignAttestationForOp 2: %v", err)
	}
	crossOpRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumer.Address(),
		Previous:        leaseBlock.Hash,
		Balance:         100_000_000 - 2*cost,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    []core.TimekeeperAttestation{*opAtt1, *opAtt2},
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(crossOpRenew, consumer); err != nil {
		t.Fatalf("sign crossOpRenew: %v", err)
	}
	if err := ledger.AddSyncedBlock(crossOpRenew); err == nil {
		t.Fatalf("expected cross-operation attestation set to be rejected on lease_renew")
	}

	// Positive control: A fresh lease_renew with valid lease_renew attestations while lease is live succeeds.
	validAtt1, err := core.SignAttestationForOp(leaseBlock.Hash, string(core.BlockLeaseRenew), now.UnixNano(), tk1)
	if err != nil {
		t.Fatalf("SignAttestationForOp renew 1: %v", err)
	}
	validAtt2, err := core.SignAttestationForOp(leaseBlock.Hash, string(core.BlockLeaseRenew), now.UnixNano(), tk2)
	if err != nil {
		t.Fatalf("SignAttestationForOp renew 2: %v", err)
	}
	validRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumer.Address(),
		Previous:        leaseBlock.Hash,
		Balance:         100_000_000 - 2*cost,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    []core.TimekeeperAttestation{*validAtt1, *validAtt2},
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(validRenew, consumer); err != nil {
		t.Fatalf("sign validRenew: %v", err)
	}
	if err := ledger.AddSyncedBlock(validRenew); err != nil {
		t.Fatalf("expected valid fresh lease_renew on sync to succeed, got: %v", err)
	}
}
