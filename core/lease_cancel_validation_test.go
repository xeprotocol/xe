package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestLeaseCancel_InvalidCancelDoesNotUnwindAccept(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()

	certHash := strings.Repeat("ab", 32)
	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen provider: %v", err)
	}

	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen timekeeper: %v", err)
	}
	tkConfig := &core.TimekeeperConfig{
		Keys:      []string{tkKP.PubKeyHex()},
		Threshold: 1,
	}

	l := core.NewLedger(ms, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return tkConfig
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			if hash != certHash {
				return nil
			}
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				ExpiresAt:            core.Now().UnixNano() + int64(time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
	})

	consumer, _ := core.GenerateKeyPair()

	// Fund consumer and provider with XUSD
	const fundAmount = 1_000_000_000
	consumerOpen := &core.Block{
		Type:           core.BlockMint,
		Account:        consumer.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XUSD",
		PubKey:         consumer.PubKeyHex(),
		Representative: consumer.Address(),
	}
	_ = core.SignBlock(consumerOpen, consumer)
	_ = l.MintForTesting(consumerOpen)
	_ = ms.SetFinalHeight(consumer.Address(), 1)

	providerOpen := &core.Block{
		Type:           core.BlockMint,
		Account:        provider.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XUSD",
		PubKey:         provider.PubKeyHex(),
		Representative: provider.Address(),
	}
	_ = core.SignBlock(providerOpen, provider)
	_ = l.MintForTesting(providerOpen)
	_ = ms.SetFinalHeight(provider.Address(), 1)

	// Consumer creates lease
	cost, _ := core.LeaseCost(1, 0, 0, 60, 1000)
	lease := &core.Block{
		Type:            core.BlockLease,
		Account:         consumer.Address(),
		Previous:        consumerOpen.Hash,
		Balance:         fundAmount - cost,
		Amount:          cost,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     provider.Address(),
		CertificateHash: certHash,
		VCPUs:           1,
		Duration:        60,
	}
	_ = core.SignBlock(lease, consumer)
	if err := l.AddBlock(lease); err != nil {
		t.Fatalf("add lease: %v", err)
	}

	// Provider accepts lease
	attTs := core.Now().UnixNano()
	att, err := core.SignAttestation(lease.Hash, attTs, tkKP)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}

	accept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        providerOpen.Hash,
		Balance:         fundAmount,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Source:          lease.Hash,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*att},
		LockedR:         1,
	}
	_ = core.SignBlock(accept, provider)
	if err := l.AddBlock(accept); err != nil {
		t.Fatalf("add accept: %v", err)
	}

	// Verify lease is accepted
	curLease, _ := ms.GetLease(lease.Hash)
	if curLease == nil || curLease.State != core.LeaseAccepted {
		t.Fatalf("expected lease to be LeaseAccepted")
	}

	// 1. Invalid cancel: Wrong Balance
	junkCancelBadBal := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumer.Address(),
		Previous:  lease.Hash,
		Balance:   fundAmount + 999999, // WRONG balance
		Timestamp: core.Now().UnixNano(),
		Asset:     "XUSD",
		Source:    lease.Hash,
	}
	_ = core.SignBlock(junkCancelBadBal, consumer)
	err = l.AddBlock(junkCancelBadBal)
	if err == nil {
		t.Fatalf("expected junk cancel with bad balance to be rejected")
	}

	// Verify provider accept was NOT unwound!
	pChain := l.GetChain(provider.Address())
	if len(pChain) != 2 || pChain[1].Hash != accept.Hash {
		t.Fatalf("FATAL: provider accept was unwound by rejected cancel! Chain length: %d", len(pChain))
	}
	curLease, _ = ms.GetLease(lease.Hash)
	if curLease.State != core.LeaseAccepted {
		t.Fatalf("FATAL: lease state mutated to %s after rejected cancel!", curLease.State)
	}

	// 2. Invalid cancel: Wrong Previous
	junkCancelBadPrev := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumer.Address(),
		Previous:  "9999999999999999999999999999999999999999999999999999999999999999", // WRONG previous
		Balance:   fundAmount,
		Timestamp: core.Now().UnixNano(),
		Asset:     "XUSD",
		Source:    lease.Hash,
	}
	_ = core.SignBlock(junkCancelBadPrev, consumer)
	err = l.AddBlock(junkCancelBadPrev)
	if err == nil {
		t.Fatalf("expected junk cancel with bad previous to be rejected")
	}

	// Verify provider accept is STILL intact
	pChain = l.GetChain(provider.Address())
	if len(pChain) != 2 || pChain[1].Hash != accept.Hash {
		t.Fatalf("FATAL: provider accept was unwound by rejected cancel! Chain length: %d", len(pChain))
	}
	curLease, _ = ms.GetLease(lease.Hash)
	if curLease.State != core.LeaseAccepted {
		t.Fatalf("FATAL: lease state mutated to %s after rejected cancel!", curLease.State)
	}

	// 3. Invalid cancel: Timestamp before previous
	junkCancelBadTs := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumer.Address(),
		Previous:  lease.Hash,
		Balance:   fundAmount,
		Timestamp: lease.Timestamp - 1000, // WRONG timestamp
		Asset:     "XUSD",
		Source:    lease.Hash,
	}
	_ = core.SignBlock(junkCancelBadTs, consumer)
	err = l.AddBlock(junkCancelBadTs)
	if err == nil {
		t.Fatalf("expected junk cancel with bad timestamp to be rejected")
	}

	// Verify provider accept is STILL intact
	pChain = l.GetChain(provider.Address())
	if len(pChain) != 2 || pChain[1].Hash != accept.Hash {
		t.Fatalf("FATAL: provider accept was unwound by rejected cancel! Chain length: %d", len(pChain))
	}
	curLease, _ = ms.GetLease(lease.Hash)
	if curLease.State != core.LeaseAccepted {
		t.Fatalf("FATAL: lease state mutated to %s after rejected cancel!", curLease.State)
	}

	// 4. Now submit a completely VALID cancel
	validCancel := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumer.Address(),
		Previous:  lease.Hash,
		Balance:   fundAmount,
		Timestamp: core.Now().UnixNano(),
		Asset:     "XUSD",
		Source:    lease.Hash,
	}
	_ = core.SignBlock(validCancel, consumer)
	if err := l.AddBlock(validCancel); err != nil {
		t.Fatalf("expected valid cancel to succeed, got: %v", err)
	}

	// NOW the valid cancel should unwind the racing accept and cancel the lease
	pChain = l.GetChain(provider.Address())
	if len(pChain) != 1 {
		t.Fatalf("expected provider accept to be unwound after valid cancel, chain length: %d", len(pChain))
	}
	curLease, _ = ms.GetLease(lease.Hash)
	if curLease.State != core.LeaseCancelled {
		t.Fatalf("expected lease state to be LeaseCancelled, got: %s", curLease.State)
	}
	bal := l.GetAssetBalances(consumer.Address())["XUSD"]
	if bal != fundAmount {
		t.Fatalf("expected consumer balance refunded to %d, got %d", fundAmount, bal)
	}
}
