package core_test

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestValidateStagedBlock_LeaseSettle(t *testing.T) {
	memStore := store.NewMemStore()
	ledger := core.NewLedger(memStore, core.LedgerConfig{})

	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key: %v", err)
	}

	_ = memStore.PutAccountChain(providerKP.Address(), &core.AccountChain{
		Blocks: []*core.Block{{
			Type:     core.BlockReceive,
			Account:  providerKP.Address(),
			Previous: "0",
			PubKey:   providerKP.PubKeyHex(),
		}},
	})
	_ = memStore.PutAccountChain(consumerKP.Address(), &core.AccountChain{
		Blocks: []*core.Block{{
			Type:     core.BlockReceive,
			Account:  consumerKP.Address(),
			Previous: "0",
			PubKey:   consumerKP.PubKeyHex(),
		}},
	})

	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	prevHash := "0000000000000000000000000000000000000000000000000000000000000001"
	leaseCost := uint64(500)
	parentBalance := uint64(1000)

	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Provider:  providerKP.Address(),
		Consumer:  consumerKP.Address(),
		Cost:      leaseCost,
		Duration:  3600,
		LockedR:   1000,
	}
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	if err := memStore.PutPendingSend(&core.PendingSend{
		SendHash:    leaseHash,
		Amount:      leaseCost,
		Destination: providerKP.Address(),
	}); err != nil {
		t.Fatalf("put pending send: %v", err)
	}

	expectedXE, err := core.LeaseTotalEmission(lease)
	if err != nil {
		t.Fatalf("calculate lease total emission: %v", err)
	}

	t.Run("valid staged settle", func(t *testing.T) {
		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    leaseHash,
			Asset:     "XE",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		if err := ledger.ValidateStagedBlock(b, parentBalance); err != nil {
			t.Fatalf("expected valid staged settle block to pass, got: %v", err)
		}
	})

	t.Run("invalid asset rejected", func(t *testing.T) {
		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    leaseHash,
			Asset:     "XUSD",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "must have asset=XE") {
			t.Fatalf("expected asset=XE error, got: %v", err)
		}
	})

	t.Run("forged amount rejected", func(t *testing.T) {
		forgedAmount := expectedXE + 999999
		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    leaseHash,
			Asset:     "XE",
			Amount:    forgedAmount,
			Balance:   parentBalance + forgedAmount,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "amount mismatch") {
			t.Fatalf("expected amount mismatch error, got: %v", err)
		}
	})

	t.Run("provider mismatch rejected", func(t *testing.T) {
		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   consumerKP.Address(),
			Previous:  prevHash,
			Source:    leaseHash,
			Asset:     "XE",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, consumerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "provider account mismatch") {
			t.Fatalf("expected provider mismatch error, got: %v", err)
		}
	})

	t.Run("unaccepted lease state rejected", func(t *testing.T) {
		createdLeaseHash := "2222222222222222222222222222222222222222222222222222222222222222"
		_ = memStore.PutLease(&core.Lease{
			LeaseHash: createdLeaseHash,
			State:     core.LeaseCreated,
			Provider:  providerKP.Address(),
			Cost:      leaseCost,
			Duration:  3600,
		})
		_ = memStore.PutPendingSend(&core.PendingSend{
			SendHash:    createdLeaseHash,
			Amount:      leaseCost,
			Destination: providerKP.Address(),
		})

		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    createdLeaseHash,
			Asset:     "XE",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "not settleable") {
			t.Fatalf("expected not settleable error, got: %v", err)
		}
	})

	t.Run("missing lease rejected", func(t *testing.T) {
		missingLeaseHash := "3333333333333333333333333333333333333333333333333333333333333333"
		_ = memStore.PutPendingSend(&core.PendingSend{
			SendHash:    missingLeaseHash,
			Amount:      leaseCost,
			Destination: providerKP.Address(),
		})

		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    missingLeaseHash,
			Asset:     "XE",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "lease not found") {
			t.Fatalf("expected lease not found error, got: %v", err)
		}
	})

	t.Run("balance mismatch rejected", func(t *testing.T) {
		b := &core.Block{
			Type:      core.BlockLeaseSettle,
			Account:   providerKP.Address(),
			Previous:  prevHash,
			Source:    leaseHash,
			Asset:     "XE",
			Amount:    expectedXE,
			Balance:   parentBalance + expectedXE + 1,
			Timestamp: core.Now().UnixNano(),
		}
		core.MustSignBlock(b, providerKP)

		err := ledger.ValidateStagedBlock(b, parentBalance)
		if err == nil || !strings.Contains(err.Error(), "balance mismatch") {
			t.Fatalf("expected balance mismatch error, got: %v", err)
		}
	})
}
