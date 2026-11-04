package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type testHarness struct {
	ledger      *core.Ledger
	mem         *store.MemStore
	tk          *core.KeyPair
	consumer    *core.KeyPair
	provider    *core.KeyPair
	certs       map[string]*core.CertificateInfo
	currentCert map[string]*core.CertificateInfo
	lastTs      map[string]int64
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	tk, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate timekeeper key: %v", err)
	}
	consumer, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key: %v", err)
	}
	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}

	h := &testHarness{
		mem:         store.NewMemStore(),
		tk:          tk,
		consumer:    consumer,
		provider:    provider,
		certs:       make(map[string]*core.CertificateInfo),
		currentCert: make(map[string]*core.CertificateInfo),
		lastTs:      make(map[string]int64),
	}

	h.ledger = core.NewLedger(h.mem, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{tk.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return h.certs[hash]
		},
		CurrentCertificateLookupFn: func(provider string, at int64) *core.CertificateInfo {
			return h.currentCert[provider]
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 0}}
		},
	})

	return h
}

func (h *testHarness) nextTs(acct string) int64 {
	now := time.Now().UnixNano()
	prev := h.lastTs[acct]
	if now <= prev {
		now = prev + int64(time.Millisecond)
	}
	h.lastTs[acct] = now
	return now
}

func (h *testHarness) frontier(acct string) string {
	chain := h.ledger.GetChain(acct)
	if len(chain) == 0 {
		return "0"
	}
	return chain[len(chain)-1].Hash
}

func (h *testHarness) balance(acct string) uint64 {
	return h.ledger.GetAssetBalances(acct)["XUSD"]
}

func (h *testHarness) seed(t *testing.T, kp *core.KeyPair, amount uint64) {
	t.Helper()
	b := &core.Block{
		Type:      core.BlockMint,
		Account:   kp.Address(),
		Previous:  "0",
		Balance:   amount,
		Timestamp: h.nextTs(kp.Address()),
		Asset:     "XUSD",
		Amount:    amount,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign mint: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(b); err != nil {
		t.Fatalf("seed mint: %v", err)
	}
}

func (h *testHarness) attest(t *testing.T, source string, at int64) []core.TimekeeperAttestation {
	t.Helper()
	a, err := core.SignAttestation(source, at, h.tk)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	return []core.TimekeeperAttestation{*a}
}

func TestLeaseRenew_EnforcesCurrentCertificate(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now()

	oldCertHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newCertHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	oldCert := &core.CertificateInfo{
		Hash:                 oldCertHash,
		Provider:             h.provider.Address(),
		IssuedAt:             now.Add(-24 * time.Hour).UnixNano(),
		ExpiresAt:            now.Add(6 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 500,
	}
	newCert := &core.CertificateInfo{
		Hash:                 newCertHash,
		Provider:             h.provider.Address(),
		IssuedAt:             now.UnixNano(),
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 10000,
	}

	h.certs[oldCertHash] = oldCert
	h.certs[newCertHash] = newCert
	// Initially, provider's current cert is oldCert
	h.currentCert[h.provider.Address()] = oldCert

	h.seed(t, h.consumer, 10_000_000)
	h.seed(t, h.provider, 1_000_000)

	oldCost, err := core.LeaseCost(1, 1024, 1, 3600, 500)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	newCost, err := core.LeaseCost(1, 1024, 1, 3600, 10000)
	if err != nil {
		t.Fatalf("LeaseCost new: %v", err)
	}

	// 1. Create lease with old cert
	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - oldCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provider.Address(),
		Amount:          oldCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: oldCertHash,
	}
	if err := core.SignBlock(leaseBlock, h.consumer); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	// 2. Accept lease
	acceptTs := time.Now().UnixNano()
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provider.Address(),
		Previous:        h.frontier(h.provider.Address()),
		Balance:         h.balance(h.provider.Address()) - core.LeaseStake(oldCost),
		Timestamp:       h.nextTs(h.provider.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          core.LeaseStake(oldCost),
		CertificateHash: oldCertHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	if err := core.SignBlock(acceptBlock, h.provider); err != nil {
		t.Fatalf("sign accept: %v", err)
	}
	if err := h.ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock accept: %v", err)
	}

	// 3. Provider reprices upward: provider's current cert is now newCert (mult 10000)
	h.currentCert[h.provider.Address()] = newCert

	// 4. Consumer attempts renewal using stale oldCert (paying oldCost 15500 instead of newCost 310000)
	renewTs := time.Now().UnixNano()
	staleRenewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - oldCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          oldCost,
		Duration:        3600,
		CertificateHash: oldCertHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, renewTs),
	}
	if err := core.SignBlock(staleRenewBlock, h.consumer); err != nil {
		t.Fatalf("sign stale renew: %v", err)
	}

	err = h.ledger.AddBlock(staleRenewBlock)
	if err == nil {
		t.Fatalf("expected AddBlock with stale cert to FAIL, but it succeeded")
	}
	if !strings.Contains(err.Error(), "not provider's current certificate") &&
		!strings.Contains(err.Error(), "lower than provider's current multiplier") {
		t.Fatalf("unexpected error message for stale cert: %v", err)
	}

	// 5. Consumer renews using current newCert (paying newCost)
	validRenewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - newCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          newCost,
		Duration:        3600,
		CertificateHash: newCertHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, renewTs),
	}
	if err := core.SignBlock(validRenewBlock, h.consumer); err != nil {
		t.Fatalf("sign valid renew: %v", err)
	}
	if err := h.ledger.AddBlock(validRenewBlock); err != nil {
		t.Fatalf("expected AddBlock with current cert to succeed, got: %v", err)
	}

	// Check lease state
	lease, err := h.mem.GetLease(leaseBlock.Hash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if len(lease.Renewals) != 1 {
		t.Fatalf("expected 1 renewal segment, got %d", len(lease.Renewals))
	}
	if lease.Renewals[0].CertificateHash != newCertHash {
		t.Fatalf("expected renewal cert to be %s, got %s", newCertHash, lease.Renewals[0].CertificateHash)
	}
	if lease.Renewals[0].Cost != newCost {
		t.Fatalf("expected renewal cost %d, got %d", newCost, lease.Renewals[0].Cost)
	}
}

func TestLeaseRenew_RejectsWhenProviderCurrentCertExpired(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now()

	certHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cost, _ := core.LeaseCost(1, 1024, 1, 3600, 1000)

	cert := &core.CertificateInfo{
		Hash:                 certHash,
		Provider:             h.provider.Address(),
		IssuedAt:             now.Add(-48 * time.Hour).UnixNano(),
		ExpiresAt:            now.Add(24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	h.certs[certHash] = cert
	h.currentCert[h.provider.Address()] = cert

	h.seed(t, h.consumer, 10_000_000)
	h.seed(t, h.provider, 1_000_000)

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - cost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provider.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	_ = core.SignBlock(leaseBlock, h.consumer)
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	acceptTs := time.Now().UnixNano()
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provider.Address(),
		Previous:        h.frontier(h.provider.Address()),
		Balance:         h.balance(h.provider.Address()) - core.LeaseStake(cost),
		Timestamp:       h.nextTs(h.provider.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          core.LeaseStake(cost),
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	_ = core.SignBlock(acceptBlock, h.provider)
	if err := h.ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock accept: %v", err)
	}

	// Provider's current cert expires
	h.currentCert[h.provider.Address()] = &core.CertificateInfo{
		Hash:                 certHash,
		Provider:             h.provider.Address(),
		IssuedAt:             now.Add(-48 * time.Hour).UnixNano(),
		ExpiresAt:            now.Add(-1 * time.Hour).UnixNano(), // expired!
		PriceMultiplierMilli: 1000,
	}

	renewTs := time.Now().UnixNano()
	renewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - cost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, renewTs),
	}
	_ = core.SignBlock(renewBlock, h.consumer)

	err := h.ledger.AddBlock(renewBlock)
	if err == nil {
		t.Fatalf("expected AddBlock with expired current cert to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected error mentioning expired, got: %v", err)
	}
}

func TestLeaseRenew_RejectsWhenNoCurrentCert(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now()

	certHash := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	cost, _ := core.LeaseCost(1, 1024, 1, 3600, 1000)

	cert := &core.CertificateInfo{
		Hash:                 certHash,
		Provider:             h.provider.Address(),
		IssuedAt:             now.Add(-24 * time.Hour).UnixNano(),
		ExpiresAt:            now.Add(24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	h.certs[certHash] = cert
	h.currentCert[h.provider.Address()] = cert

	h.seed(t, h.consumer, 10_000_000)
	h.seed(t, h.provider, 1_000_000)

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - cost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provider.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	_ = core.SignBlock(leaseBlock, h.consumer)
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	acceptTs := time.Now().UnixNano()
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provider.Address(),
		Previous:        h.frontier(h.provider.Address()),
		Balance:         h.balance(h.provider.Address()) - core.LeaseStake(cost),
		Timestamp:       h.nextTs(h.provider.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          core.LeaseStake(cost),
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	_ = core.SignBlock(acceptBlock, h.provider)
	if err := h.ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock accept: %v", err)
	}

	// Provider no longer has current certificate
	h.currentCert[h.provider.Address()] = nil

	renewTs := time.Now().UnixNano()
	renewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - cost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          cost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, renewTs),
	}
	_ = core.SignBlock(renewBlock, h.consumer)

	err := h.ledger.AddBlock(renewBlock)
	if err == nil {
		t.Fatalf("expected AddBlock when provider has no current cert to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "no current certificate") {
		t.Fatalf("expected error mentioning no current certificate, got: %v", err)
	}
}
