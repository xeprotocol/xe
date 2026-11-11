package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func mustTestKeyPair(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func mustSignTestBlock(t *testing.T, b *core.Block, kp *core.KeyPair) *core.Block {
	t.Helper()
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign %s: %v", b.Type, err)
	}
	return b
}

func TestCancelAfterRenewalRefundsFullEscrow(t *testing.T) {
	consumer := mustTestKeyPair(t)
	provider := mustTestKeyPair(t)
	tk := mustTestKeyPair(t)

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

	const fund uint64 = 1_000_000 // micro-XUSD
	for _, kp := range []*core.KeyPair{consumer, provider} {
		mint := mustSignTestBlock(t, &core.Block{
			Type: core.BlockMint, Asset: "XUSD", Account: kp.Address(),
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

	// 1) Consumer creates lease (escrow 517)
	lease := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLease, Asset: "XUSD", Account: consumer.Address(),
		Previous: led.GetChain(consumer.Address())[0].Hash,
		Balance:  fund - cost, Amount: cost,
		Destination: provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: certHash, Timestamp: nowNs + int64(time.Second),
	}, consumer)
	if err := led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// 2) Provider accepts
	att0, err := core.SignAttestation(lease.Hash, nowNs, tk)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	accept := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XUSD", Account: provider.Address(),
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

	// 3) Consumer renews for another 60s (escrow tops up by another 517)
	att1, err := core.SignAttestation(lease.Hash, nowNs+2*int64(time.Second), tk)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	renew := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XUSD", Account: consumer.Address(),
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

	// Verify escrow before cancel is 2 * cost (1034)
	pending := led.GetPendingForAccount(provider.Address())
	if len(pending) != 1 || pending[0].Amount != 2*cost {
		t.Fatalf("escrow after renew: got %+v, want one pending of %d", pending, 2*cost)
	}

	// 4) Consumer cancels
	balBefore := led.GetAssetBalances(consumer.Address())["XUSD"]
	cancel := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XUSD", Account: consumer.Address(),
		Previous: renew.Hash,
		Balance:  balBefore + pending[0].Amount, // full escrow refund
		Source: lease.Hash,
		Timestamp: nowNs + 4*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	balAfter := led.GetAssetBalances(consumer.Address())["XUSD"]
	leaseAfter, _ := st.GetLease(lease.Hash)
	if leaseAfter == nil || leaseAfter.State != core.LeaseCancelled {
		t.Fatalf("expected lease state LeaseCancelled, got %+v", leaseAfter)
	}

	if balAfter != fund {
		t.Fatalf("expected consumer balance restored to %d micro-XUSD, got %d", fund, balAfter)
	}
}

func TestCancelAfterRenewalConflictResolution(t *testing.T) {
	consumer := mustTestKeyPair(t)
	provider := mustTestKeyPair(t)
	tk := mustTestKeyPair(t)

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

	const fund uint64 = 1_000_000 // micro-XUSD
	for _, kp := range []*core.KeyPair{consumer, provider} {
		mint := mustSignTestBlock(t, &core.Block{
			Type: core.BlockMint, Asset: "XUSD", Account: kp.Address(),
			Previous: "0", Balance: fund, Amount: fund,
			Timestamp: nowNs,
		}, kp)
		if err := led.SeedAssetForTesting(mint); err != nil {
			t.Fatalf("seed %s: %v", kp.Address()[:12], err)
		}
	}

	cost, _ := core.LeaseCost(1, 1024, 1, 60, 1000)

	// Consumer lease
	lease := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLease, Asset: "XUSD", Account: consumer.Address(),
		Previous: led.GetChain(consumer.Address())[0].Hash,
		Balance:  fund - cost, Amount: cost,
		Destination: provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: certHash, Timestamp: nowNs + int64(time.Second),
	}, consumer)
	if err := led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// Provider accepts
	att0, _ := core.SignAttestation(lease.Hash, nowNs, tk)
	accept := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XUSD", Account: provider.Address(),
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

	// Consumer renews
	att1, _ := core.SignAttestation(lease.Hash, nowNs+2*int64(time.Second), tk)
	renew := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XUSD", Account: consumer.Address(),
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
	totalEscrow := pending[0].Amount

	// Sibling 1: a send block at renew frontier
	siblingSend := mustSignTestBlock(t, &core.Block{
		Type: core.BlockSend, Asset: "XUSD", Account: consumer.Address(),
		Previous: renew.Hash,
		Balance:  (fund - 2*cost) - 10, Amount: 10,
		Destination: provider.Address(),
		Timestamp:   nowNs + 4*int64(time.Second),
	}, consumer)
	if err := led.AddBlock(siblingSend); err != nil {
		t.Fatalf("siblingSend: %v", err)
	}

	// Sibling 2: lease_cancel candidate with full refund
	cancelCandidate := mustSignTestBlock(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XUSD", Account: consumer.Address(),
		Previous: renew.Hash,
		Balance:  (fund - 2*cost) + totalEscrow,
		Source:   lease.Hash,
		Timestamp: nowNs + 5*int64(time.Second),
	}, consumer)

	// Candidate must stage successfully
	if err := led.AddBlock(cancelCandidate); err != nil {
		t.Fatalf("cancelCandidate should stage as conflict candidate: %v", err)
	}

	// SwapBlock should promote cancelCandidate successfully (no ErrWinnerFullValidation)
	if err := led.SwapBlock(consumer.Address(), siblingSend.Hash, cancelCandidate.Hash, cancelCandidate); err != nil {
		t.Fatalf("SwapBlock failed to promote cancel candidate: %v", err)
	}

	chain := led.GetChain(consumer.Address())
	if chain[len(chain)-1].Hash != cancelCandidate.Hash {
		t.Fatalf("expected cancel candidate to be chain tip, got %s", chain[len(chain)-1].Hash)
	}

	if bal := led.GetAssetBalances(consumer.Address())["XUSD"]; bal != fund {
		t.Fatalf("expected balance after swap to be %d, got %d", fund, bal)
	}
}
