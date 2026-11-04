package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestInvalidLeaseCancelDoesNotUnwindProviderAccept(t *testing.T) {
	ms := store.NewMemStore()

	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair consumer: %v", err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair provider: %v", err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair tk: %v", err)
	}

	certHash := strings.Repeat("c", 64)
	nowNs := core.Now().UnixNano()

	ledger := core.NewLedger(ms, core.LedgerConfig{
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{
				Threshold: 1,
				Keys: []string{
					tkKP.PubKeyHex(),
				},
			}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			if hash != certHash {
				return nil
			}
			return &core.CertificateInfo{
				Provider:             providerKP.Address(),
				ExpiresAt:            nowNs + int64(24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
	})

	// Seed consumer and provider with XUSD.
	seedConsumer := &core.Block{
		Type:           core.BlockMint,
		Asset:          "XUSD",
		Account:        consumerKP.Address(),
		Previous:       "0",
		Balance:        10_000_000,
		Amount:         10_000_000,
		Representative: consumerKP.Address(),
		Timestamp:      nowNs,
		PubKey:         consumerKP.PubKeyHex(),
	}
	if err := core.SignBlock(seedConsumer, consumerKP); err != nil {
		t.Fatalf("SignBlock seedConsumer: %v", err)
	}
	if err := ledger.MintForTesting(seedConsumer); err != nil {
		t.Fatalf("MintForTesting consumer: %v", err)
	}

	seedProvider := &core.Block{
		Type:           core.BlockMint,
		Asset:          "XUSD",
		Account:        providerKP.Address(),
		Previous:       "0",
		Balance:        10_000_000,
		Amount:         10_000_000,
		Representative: providerKP.Address(),
		Timestamp:      nowNs,
		PubKey:         providerKP.PubKeyHex(),
	}
	if err := core.SignBlock(seedProvider, providerKP); err != nil {
		t.Fatalf("SignBlock seedProvider: %v", err)
	}
	if err := ledger.MintForTesting(seedProvider); err != nil {
		t.Fatalf("MintForTesting provider: %v", err)
	}

	// Create a valid lease.
	vcpus, memMB, diskGB, durSecs := uint64(2), uint64(2048), uint64(20), uint64(3600)
	cost, err := core.LeaseCost(vcpus, memMB, diskGB, durSecs, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Asset:           "XUSD",
		Account:         consumerKP.Address(),
		Previous:        seedConsumer.Hash,
		Balance:         seedConsumer.Balance - cost,
		Destination:     providerKP.Address(),
		Amount:          cost,
		VCPUs:           vcpus,
		MemoryMB:        memMB,
		DiskGB:          diskGB,
		Duration:        durSecs,
		CertificateHash: certHash,
		Representative:  consumerKP.Address(),
		Timestamp:       nowNs + 100,
	}
	if err := core.SignBlock(leaseBlock, consumerKP); err != nil {
		t.Fatalf("SignBlock leaseBlock: %v", err)
	}
	if err := ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock leaseBlock: %v", err)
	}

	// Provider accepts the lease (not yet finalized).
	stake := core.LeaseStake(cost)
	att, err := core.SignAttestation(leaseBlock.Hash, nowNs+200, tkKP)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Asset:           "XUSD",
		Account:         providerKP.Address(),
		Previous:        seedProvider.Hash,
		Balance:         seedProvider.Balance - stake,
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*att},
		LockedR:         1000,
		LockedPayoutCap: 1000,
		LockedTWAP:      1000,
		Representative:  providerKP.Address(),
		Timestamp:       nowNs + 200,
	}
	if err := core.SignBlock(acceptBlock, providerKP); err != nil {
		t.Fatalf("SignBlock acceptBlock: %v", err)
	}
	if err := ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock acceptBlock: %v", err)
	}

	assertProviderAcceptIntact := func(t *testing.T, context string) {
		t.Helper()
		lease, err := ms.GetLease(leaseBlock.Hash)
		if err != nil || lease == nil {
			t.Fatalf("%s: GetLease: err=%v lease=%v", context, err, lease)
		}
		if lease.State != core.LeaseAccepted {
			t.Fatalf("%s: lease state = %s, want %s", context, lease.State, core.LeaseAccepted)
		}
		pchain := ledger.GetChain(providerKP.Address())
		if len(pchain) != 2 || pchain[len(pchain)-1].Hash != acceptBlock.Hash {
			t.Fatalf("%s: provider frontier was unwound: chain len=%d", context, len(pchain))
		}
		status, err := ms.GetBlockStatus(acceptBlock.Hash)
		if err != nil {
			t.Fatalf("%s: GetBlockStatus: %v", context, err)
		}
		if status == core.StatusRejected {
			t.Fatalf("%s: accept block marked StatusRejected", context)
		}
		rep := ledger.GetReputation(providerKP.Address())
		if rep == nil || rep.LeasesAcceptedAsProvider != 1 {
			t.Fatalf("%s: provider reputation LeasesAcceptedAsProvider = %+v, want 1", context, rep)
		}
		restarted := core.NewLedger(ms, core.LedgerConfig{})
		restartedRep := restarted.GetReputation(providerKP.Address())
		if restartedRep == nil || restartedRep.LeasesAcceptedAsProvider != 1 {
			t.Fatalf("%s: provider reputation after restart LeasesAcceptedAsProvider = %+v, want 1", context, restartedRep)
		}
	}

	assertProviderAcceptIntact(t, "initial")

	// Submit invalid lease_cancel variants: wrong_balance, wrong_previous, timestamp_before_prev.
	invalidCases := []struct {
		name  string
		block *core.Block
	}{
		{
			name: "wrong_balance",
			block: &core.Block{
				Type:           core.BlockLeaseCancel,
				Asset:          "XUSD",
				Account:        consumerKP.Address(),
				Previous:       leaseBlock.Hash,
				Balance:        seedConsumer.Balance + 999, // wrong balance
				Source:         leaseBlock.Hash,
				Representative: consumerKP.Address(),
				Timestamp:      leaseBlock.Timestamp + 10,
			},
		},
		{
			name: "wrong_previous",
			block: &core.Block{
				Type:           core.BlockLeaseCancel,
				Asset:          "XUSD",
				Account:        consumerKP.Address(),
				Previous:       seedConsumer.Hash, // wrong previous
				Balance:        seedConsumer.Balance,
				Source:         leaseBlock.Hash,
				Representative: consumerKP.Address(),
				Timestamp:      leaseBlock.Timestamp + 20,
			},
		},
		{
			name: "timestamp_before_prev",
			block: &core.Block{
				Type:           core.BlockLeaseCancel,
				Asset:          "XUSD",
				Account:        consumerKP.Address(),
				Previous:       leaseBlock.Hash,
				Balance:        seedConsumer.Balance,
				Source:         leaseBlock.Hash,
				Representative: consumerKP.Address(),
				Timestamp:      leaseBlock.Timestamp - 1, // timestamp before previous block
			},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := core.SignBlock(tc.block, consumerKP); err != nil {
				t.Fatalf("SignBlock(%s): %v", tc.name, err)
			}
			err := ledger.AddBlock(tc.block)
			if err == nil {
				t.Fatalf("expected AddBlock(%s) to fail, got nil", tc.name)
			}
			assertProviderAcceptIntact(t, tc.name)
		})
	}

	// Verify that a valid lease_cancel still wins over a non-finalized accept.
	t.Run("valid_cancel_wins_over_unfinalized_accept", func(t *testing.T) {
		validCancel := &core.Block{
			Type:           core.BlockLeaseCancel,
			Asset:          "XUSD",
			Account:        consumerKP.Address(),
			Previous:       leaseBlock.Hash,
			Balance:        seedConsumer.Balance,
			Source:         leaseBlock.Hash,
			Representative: consumerKP.Address(),
			Timestamp:      leaseBlock.Timestamp + 50,
		}
		if err := core.SignBlock(validCancel, consumerKP); err != nil {
			t.Fatalf("SignBlock(validCancel): %v", err)
		}
		if err := ledger.AddBlock(validCancel); err != nil {
			t.Fatalf("AddBlock(validCancel) failed: %v", err)
		}
		lease, err := ms.GetLease(leaseBlock.Hash)
		if err != nil || lease == nil {
			t.Fatalf("GetLease after valid cancel: err=%v lease=%v", err, lease)
		}
		if lease.State != core.LeaseCancelled {
			t.Fatalf("lease state after valid cancel = %s, want %s", lease.State, core.LeaseCancelled)
		}
		pchain := ledger.GetChain(providerKP.Address())
		if len(pchain) != 1 || pchain[0].Hash != seedProvider.Hash {
			t.Fatalf("expected provider accept to be unwound by valid cancel, got chain len=%d", len(pchain))
		}
		rep := ledger.GetReputation(providerKP.Address())
		if rep != nil && rep.LeasesAcceptedAsProvider != 0 {
			t.Fatalf("expected provider LeasesAcceptedAsProvider=0 after valid cancel, got %d", rep.LeasesAcceptedAsProvider)
		}
	})
}
