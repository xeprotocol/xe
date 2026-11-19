package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func mustKP(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func mustSign(t *testing.T, b *core.Block, kp *core.KeyPair) *core.Block {
	t.Helper()
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign %s: %v", b.Type, err)
	}
	return b
}

func TestLeaseCancel_RefundsFullPendingEscrowIncludingRenewals(t *testing.T) {
	consumer := mustKP(t)
	provider := mustKP(t)
	tk := mustKP(t)

	nowNs := time.Now().UnixNano()
	certHash := strings.Repeat("b", 64)
	st := store.NewMemStore()

	led := core.NewLedger(st, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{tk.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            nowNs + int64(7*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 1500, TWAP: 1000}}
		},
	})

	const fund uint64 = 1_000_000 // micro-XCU
	for _, kp := range []*core.KeyPair{consumer, provider} {
		mint := mustSign(t, &core.Block{
			Type: core.BlockMint, Asset: "XCU", Account: kp.Address(),
			Previous: "0", Balance: fund, Amount: fund,
			Timestamp: nowNs,
		}, kp)
		if err := led.SeedAssetForTesting(mint); err != nil {
			t.Fatalf("seed %s: %v", kp.Address()[:12], err)
		}
	}

	cost, err := core.LeaseCost(1, 1024, 1, 60, 1000)
	if err != nil || cost != 517 {
		t.Fatalf("LeaseCost = %d, err %v (expected 517)", cost, err)
	}

	// 1) consumer creates lease
	lease := mustSign(t, &core.Block{
		Type: core.BlockLease, Asset: "XCU", Account: consumer.Address(),
		Previous: led.GetChain(consumer.Address())[0].Hash,
		Balance:  fund - cost, Amount: cost,
		Destination: provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: certHash, Timestamp: nowNs + int64(time.Second),
	}, consumer)
	if err := led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// 2) provider accepts
	att0, err := core.SignAttestation(lease.Hash, nowNs, tk)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	accept := mustSign(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XCU", Account: provider.Address(),
		Previous: led.GetChain(provider.Address())[0].Hash,
		Balance:  fund, Amount: 0,
		Source: lease.Hash, CertificateHash: certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*att0},
		Timestamp:    nowNs + 2*int64(time.Second),
	}, provider)
	if err := led.AddBlock(accept); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// 3) consumer renews lease (adding renewal escrow)
	att1, err := core.SignAttestation(lease.Hash, nowNs+2*int64(time.Second), tk)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	renew := mustSign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XCU", Account: consumer.Address(),
		Previous: lease.Hash,
		Balance:  fund - 2*cost, Amount: cost, Duration: 60,
		Source: lease.Hash, CertificateHash: certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*att1},
		Timestamp:    nowNs + 3*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(renew); err != nil {
		t.Fatalf("renew: %v", err)
	}

	pending := led.GetPendingForAccount(provider.Address())
	if len(pending) != 1 || pending[0].Amount != 2*cost {
		t.Fatalf("escrow after renew: got %+v, want one pending of %d", pending, 2*cost)
	}

	// 4) consumer cancels lease
	cancel := mustSign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XCU", Account: consumer.Address(),
		Previous: renew.Hash,
		Balance:  fund, // Expect full refund of base + renewal
		Source: lease.Hash,
		Timestamp: nowNs + 4*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	balAfter := led.GetAssetBalances(consumer.Address())["XCU"]
	if balAfter != fund {
		t.Fatalf("balance mismatch: expected %d, got %d", fund, balAfter)
	}

	// Verify pending send deleted
	if p := led.GetPendingForAccount(provider.Address()); len(p) != 0 {
		t.Fatalf("expected 0 pending sends after cancel, got %d", len(p))
	}

	// Verify lease state in store is cancelled with nil renewals
	leaseAfter, err := st.GetLease(lease.Hash)
	if err != nil || leaseAfter == nil {
		t.Fatalf("GetLease failed: %v", err)
	}
	if leaseAfter.State != core.LeaseCancelled {
		t.Fatalf("expected lease state cancelled, got %s", leaseAfter.State)
	}
	if len(leaseAfter.Renewals) != 0 {
		t.Fatalf("expected 0 renewals on cancelled lease, got %d", len(leaseAfter.Renewals))
	}
}

func TestLeaseCancel_MultipleRenewalsFullRefund(t *testing.T) {
	consumer := mustKP(t)
	provider := mustKP(t)
	tk := mustKP(t)

	nowNs := time.Now().UnixNano()
	certHash := strings.Repeat("b", 64)
	st := store.NewMemStore()

	led := core.NewLedger(st, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{tk.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            nowNs + int64(7*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 1500, TWAP: 1000}}
		},
	})

	const fund uint64 = 2_000_000
	for _, kp := range []*core.KeyPair{consumer, provider} {
		mint := mustSign(t, &core.Block{
			Type: core.BlockMint, Asset: "XCU", Account: kp.Address(),
			Previous: "0", Balance: fund, Amount: fund,
			Timestamp: nowNs,
		}, kp)
		if err := led.SeedAssetForTesting(mint); err != nil {
			t.Fatalf("seed %s: %v", kp.Address()[:12], err)
		}
	}

	cost, _ := core.LeaseCost(1, 1024, 1, 60, 1000)

	// Create lease
	lease := mustSign(t, &core.Block{
		Type: core.BlockLease, Asset: "XCU", Account: consumer.Address(),
		Previous: led.GetChain(consumer.Address())[0].Hash,
		Balance:  fund - cost, Amount: cost,
		Destination: provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: certHash, Timestamp: nowNs + int64(time.Second),
	}, consumer)
	if err := led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// Accept
	att0, _ := core.SignAttestation(lease.Hash, nowNs, tk)
	accept := mustSign(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XCU", Account: provider.Address(),
		Previous: led.GetChain(provider.Address())[0].Hash,
		Balance:  fund, Amount: 0,
		Source: lease.Hash, CertificateHash: certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*att0},
		Timestamp:    nowNs + 2*int64(time.Second),
	}, provider)
	if err := led.AddBlock(accept); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Renew 1
	att1, _ := core.SignAttestation(lease.Hash, nowNs+2*int64(time.Second), tk)
	renew1 := mustSign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XCU", Account: consumer.Address(),
		Previous: lease.Hash,
		Balance:  fund - 2*cost, Amount: cost, Duration: 60,
		Source: lease.Hash, CertificateHash: certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*att1},
		Timestamp:    nowNs + 3*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(renew1); err != nil {
		t.Fatalf("renew1: %v", err)
	}

	// Renew 2
	att2, _ := core.SignAttestation(lease.Hash, nowNs+3*int64(time.Second), tk)
	renew2 := mustSign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XCU", Account: consumer.Address(),
		Previous: renew1.Hash,
		Balance:  fund - 3*cost, Amount: cost, Duration: 60,
		Source: lease.Hash, CertificateHash: certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*att2},
		Timestamp:    nowNs + 4*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(renew2); err != nil {
		t.Fatalf("renew2: %v", err)
	}

	pending := led.GetPendingForAccount(provider.Address())
	if len(pending) != 1 || pending[0].Amount != 3*cost {
		t.Fatalf("escrow after 2 renewals: got %+v, want %d", pending, 3*cost)
	}

	// Cancel: refunds base + both renewals
	cancel := mustSign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XCU", Account: consumer.Address(),
		Previous: renew2.Hash,
		Balance:  fund,
		Source: lease.Hash,
		Timestamp: nowNs + 5*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	balAfter := led.GetAssetBalances(consumer.Address())["XCU"]
	if balAfter != fund {
		t.Fatalf("balance mismatch: expected %d, got %d", fund, balAfter)
	}
}

func TestLeaseCancel_WithoutRenewalsRefundsBase(t *testing.T) {
	consumer := mustKP(t)
	provider := mustKP(t)

	nowNs := time.Now().UnixNano()
	certHash := strings.Repeat("b", 64)
	st := store.NewMemStore()

	led := core.NewLedger(st, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            nowNs + int64(7*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
	})

	const fund uint64 = 1_000_000
	mint := mustSign(t, &core.Block{
		Type: core.BlockMint, Asset: "XCU", Account: consumer.Address(),
		Previous: "0", Balance: fund, Amount: fund,
		Timestamp: nowNs,
	}, consumer)
	if err := led.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cost, _ := core.LeaseCost(1, 1024, 1, 60, 1000)

	// Create lease
	lease := mustSign(t, &core.Block{
		Type: core.BlockLease, Asset: "XCU", Account: consumer.Address(),
		Previous: mint.Hash,
		Balance:  fund - cost, Amount: cost,
		Destination: provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: certHash, Timestamp: nowNs + int64(time.Second),
	}, consumer)
	if err := led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// Cancel directly without accept or renewals
	cancel := mustSign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XCU", Account: consumer.Address(),
		Previous: lease.Hash,
		Balance:  fund,
		Source: lease.Hash,
		Timestamp: nowNs + 2*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	if bal := led.GetAssetBalances(consumer.Address())["XCU"]; bal != fund {
		t.Fatalf("balance mismatch: expected %d, got %d", fund, bal)
	}
}
