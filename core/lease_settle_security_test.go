package core_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func setupLeaseLifecycleEnv(t *testing.T, now *time.Time) (*core.Ledger, *store.MemStore, *core.KeyPair, *core.KeyPair, *core.KeyPair, string, string, string) {
	t.Helper()
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
				ExpiresAt:            now.UnixNano() + int64(365*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 0}}
		},
		FeatureActiveFn: func(string) bool { return false },
	})

	seed := func(kp *core.KeyPair, prev, asset string, bal, amt uint64) string {
		b := &core.Block{
			Type:      core.BlockMint,
			Account:   kp.Address(),
			Previous:  prev,
			Balance:   bal,
			Amount:    amt,
			Asset:     asset,
			Timestamp: now.UnixNano(),
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

	consPrev := seed(consumer, "0", "XE", 1_000_000, 1_000_000)
	consPrev = seed(consumer, consPrev, "XUSD", 1_000_000, 1_000_000)
	provPrev := seed(provider, "0", "XE", 1, 1)
	provPrev = seed(provider, provPrev, "XUSD", 100, 100)

	return ledger, ms, consumer, provider, timekeeper, certHash, consPrev, provPrev
}

func TestSettleWithoutDeliveryForfeitsStakeAndPenalizesReputation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	core.Now = func() time.Time { return now }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	ledger, ms, consumer, provider, timekeeper, certHash, consPrev, provPrev := setupLeaseLifecycleEnv(t, &now)

	cost, err := core.LeaseCost(1, 1024, 0, 60, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	stake := core.LeaseStake(cost)
	if stake == 0 {
		t.Fatalf("expected non-zero stake, got 0")
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
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(leaseBlock, consumer); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock(lease): %v", err)
	}

	att1, err := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	if err != nil {
		t.Fatalf("sign accept attestation: %v", err)
	}
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       now.UnixNano(),
	}
	if err := core.SignBlock(acceptBlock, provider); err != nil {
		t.Fatalf("sign accept: %v", err)
	}
	if err := ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock(accept): %v", err)
	}

	now = now.Add(61 * time.Second)
	att2, err := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	if err != nil {
		t.Fatalf("sign settle attestation: %v", err)
	}

	// Settle WITHOUT consumer delivery attestation: stake must be forfeited and reputation marked unfulfilled.
	settleBlock := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      provider.Address(),
		Previous:     acceptBlock.Hash,
		Balance:      1 + cost,
		Asset:        "XE",
		Source:       leaseBlock.Hash,
		Amount:       cost,
		Attestations: []core.TimekeeperAttestation{*att2},
		Timestamp:    now.UnixNano(),
	}
	if err := core.SignBlock(settleBlock, provider); err != nil {
		t.Fatalf("sign settle: %v", err)
	}
	if err := ledger.AddBlock(settleBlock); err != nil {
		t.Fatalf("AddBlock(settle): %v", err)
	}

	provBal := ledger.GetAssetBalances(provider.Address())
	if provBal["XUSD"] != 0 {
		t.Fatalf("expected provider stake (%d XUSD) to be forfeited on settle without delivery proof, got XUSD=%d", stake, provBal["XUSD"])
	}

	storedLease, err := ms.GetLease(leaseBlock.Hash)
	if err != nil || storedLease == nil {
		t.Fatalf("GetLease: %v", err)
	}
	if !storedLease.StakeForfeited {
		t.Fatalf("expected storedLease.StakeForfeited to be true")
	}

	rep := ledger.GetReputation(provider.Address())
	if rep == nil {
		t.Fatalf("expected reputation record for provider")
	}
	if rep.LeasesSettledAsProvider != 0 || rep.LeasesUnfulfilledAsProvider != 1 {
		t.Fatalf("expected provider reputation (settled=0, unfulfilled=1), got (settled=%d, unfulfilled=%d)",
			rep.LeasesSettledAsProvider, rep.LeasesUnfulfilledAsProvider)
	}

	supply := core.NewSupplyAuditor(ledger).Report()
	if !supply.Conserved {
		t.Fatalf("expected supply conservation, notes: %v", supply.Notes)
	}
	if supply.Assets["XUSD"].StakeForfeited != stake {
		t.Fatalf("expected StakeForfeited=%d, got %d", stake, supply.Assets["XUSD"].StakeForfeited)
	}
}

func TestSettleWithDeliveryProofRefundsStakeAndCreditsReputation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	core.Now = func() time.Time { return now }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	ledger, _, consumer, provider, timekeeper, certHash, consPrev, provPrev := setupLeaseLifecycleEnv(t, &now)

	cost, _ := core.LeaseCost(1, 1024, 0, 60, 1000)
	stake := core.LeaseStake(cost)

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
		Timestamp:       now.UnixNano(),
	}
	_ = core.SignBlock(leaseBlock, consumer)
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock(lease): %v", err)
	}

	att1, _ := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       now.UnixNano(),
	}
	_ = core.SignBlock(acceptBlock, provider)
	if err := ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock(accept): %v", err)
	}

	now = now.Add(61 * time.Second)
	att2, _ := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	deliveryAtt, err := core.SignDeliveryAttestation(leaseBlock.Hash, now.UnixNano(), consumer)
	if err != nil {
		t.Fatalf("SignDeliveryAttestation: %v", err)
	}

	settleBlock := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      provider.Address(),
		Previous:     acceptBlock.Hash,
		Balance:      1 + cost,
		Asset:        "XE",
		Source:       leaseBlock.Hash,
		Amount:       cost,
		Attestations: []core.TimekeeperAttestation{*att2, *deliveryAtt},
		Timestamp:    now.UnixNano(),
	}
	_ = core.SignBlock(settleBlock, provider)
	if err := ledger.AddBlock(settleBlock); err != nil {
		t.Fatalf("AddBlock(settle with delivery): %v", err)
	}

	provBal := ledger.GetAssetBalances(provider.Address())
	if provBal["XUSD"] != stake {
		t.Fatalf("expected provider stake (%d XUSD) to be refunded with delivery proof, got XUSD=%d", stake, provBal["XUSD"])
	}

	rep := ledger.GetReputation(provider.Address())
	if rep.LeasesSettledAsProvider != 1 || rep.LeasesUnfulfilledAsProvider != 0 {
		t.Fatalf("expected provider reputation (settled=1, unfulfilled=0), got (settled=%d, unfulfilled=%d)",
			rep.LeasesSettledAsProvider, rep.LeasesUnfulfilledAsProvider)
	}

	supply := core.NewSupplyAuditor(ledger).Report()
	if !supply.Conserved {
		t.Fatalf("expected supply conservation, notes: %v", supply.Notes)
	}
}

func TestConsumerForceSettleOpensAtExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	core.Now = func() time.Time { return now }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	ledger, _, consumer, provider, timekeeper, certHash, consPrev, provPrev := setupLeaseLifecycleEnv(t, &now)

	cost, _ := core.LeaseCost(1, 1024, 0, 60, 1000)
	stake := core.LeaseStake(cost)

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
		Timestamp:       now.UnixNano(),
	}
	_ = core.SignBlock(leaseBlock, consumer)
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock(lease): %v", err)
	}

	att1, _ := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        provPrev,
		Balance:         0,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		Attestations:    []core.TimekeeperAttestation{*att1},
		Timestamp:       now.UnixNano(),
	}
	_ = core.SignBlock(acceptBlock, provider)
	if err := ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock(accept): %v", err)
	}

	// Advance to exact expiry (60s), without waiting LeaseSettleGrace + LeaseForceSettleGap.
	now = now.Add(60 * time.Second)
	attForce, _ := core.SignAttestation(leaseBlock.Hash, now.UnixNano(), timekeeper)
	forceBlock := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      consumer.Address(),
		Previous:     leaseBlock.Hash,
		Balance:      1_000_000,
		Asset:        "XUSD",
		Source:       leaseBlock.Hash,
		Amount:       cost,
		Attestations: []core.TimekeeperAttestation{*attForce},
		Timestamp:    now.UnixNano(),
	}
	_ = core.SignBlock(forceBlock, consumer)
	if err := ledger.AddBlock(forceBlock); err != nil {
		t.Fatalf("expected consumer force-settle to succeed at expiry, got: %v", err)
	}

	if got := ledger.GetAssetBalances(consumer.Address())["XUSD"]; got != 1_000_000 {
		t.Fatalf("expected consumer XUSD refunded to 1000000, got %d", got)
	}
	if got := ledger.GetAssetBalances(provider.Address())["XUSD"]; got != 0 {
		t.Fatalf("expected provider stake forfeited (0 XUSD), got %d", got)
	}
}
