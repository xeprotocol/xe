package core_test

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type cancelTestHarness struct {
	ledger   *core.Ledger
	mem      *store.MemStore
	tk       *core.KeyPair
	consumer *core.KeyPair
	provider *core.KeyPair
	certs    map[string]*core.CertificateInfo
	lastTs   map[string]int64
}

func newCancelTestHarness(t *testing.T) *cancelTestHarness {
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

	h := &cancelTestHarness{
		mem:      store.NewMemStore(),
		tk:       tk,
		consumer: consumer,
		provider: provider,
		certs:    make(map[string]*core.CertificateInfo),
		lastTs:   make(map[string]int64),
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
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 0}}
		},
	})

	return h
}

func (h *cancelTestHarness) nextTs(acct string) int64 {
	now := time.Now().UnixNano()
	prev := h.lastTs[acct]
	if now <= prev {
		now = prev + int64(time.Millisecond)
	}
	h.lastTs[acct] = now
	return now
}

func (h *cancelTestHarness) frontier(acct string) string {
	chain := h.ledger.GetChain(acct)
	if len(chain) == 0 {
		return "0"
	}
	return chain[len(chain)-1].Hash
}

func (h *cancelTestHarness) balance(acct string) uint64 {
	return h.ledger.GetAssetBalances(acct)["XUSD"]
}

func (h *cancelTestHarness) seed(t *testing.T, kp *core.KeyPair, amount uint64) {
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

func (h *cancelTestHarness) attest(t *testing.T, source string, at int64) []core.TimekeeperAttestation {
	t.Helper()
	a, err := core.SignAttestation(source, at, h.tk)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	return []core.TimekeeperAttestation{*a}
}

func TestLeaseCancel_RefundsFullPendingEscrowIncludingRenewals(t *testing.T) {
	h := newCancelTestHarness(t)
	now := time.Now()

	certHash := "1111111111111111111111111111111111111111111111111111111111111111"
	cert := &core.CertificateInfo{
		Provider:             h.provider.Address(),
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}
	h.certs[certHash] = cert

	const initialConsumerBal = 10_000_000
	h.seed(t, h.consumer, initialConsumerBal)
	h.seed(t, h.provider, 2_000_000)

	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	renewCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost renew: %v", err)
	}

	// 1. Create lease
	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         initialConsumerBal - baseCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provider.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
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
		Balance:         h.balance(h.provider.Address()) - core.LeaseStake(baseCost),
		Timestamp:       h.nextTs(h.provider.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          core.LeaseStake(baseCost),
		CertificateHash: certHash,
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

	// 3. Renew lease (top-up)
	renewTs := time.Now().UnixNano()
	renewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - renewCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          renewCost,
		Duration:        3600,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, renewTs),
	}
	if err := core.SignBlock(renewBlock, h.consumer); err != nil {
		t.Fatalf("sign renew: %v", err)
	}
	if err := h.ledger.AddBlock(renewBlock); err != nil {
		t.Fatalf("AddBlock renew: %v", err)
	}

	// Verify consumer spent both baseCost and renewCost
	balAfterRenew := h.balance(h.consumer.Address())
	if balAfterRenew != initialConsumerBal-baseCost-renewCost {
		t.Fatalf("balance after renew: got %d, want %d", balAfterRenew, initialConsumerBal-baseCost-renewCost)
	}

	// 4. Cancel lease: should refund entire pending escrow (baseCost + renewCost)
	cancelBlock := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   h.consumer.Address(),
		Previous:  h.frontier(h.consumer.Address()),
		Balance:   initialConsumerBal, // Consumer expects full refund of base + renewals
		Timestamp: h.nextTs(h.consumer.Address()),
		Asset:     "XUSD",
		Source:    leaseBlock.Hash,
	}
	if err := core.SignBlock(cancelBlock, h.consumer); err != nil {
		t.Fatalf("sign cancel: %v", err)
	}
	if err := h.ledger.AddBlock(cancelBlock); err != nil {
		t.Fatalf("AddBlock cancel failed: %v", err)
	}

	if finalBal := h.balance(h.consumer.Address()); finalBal != initialConsumerBal {
		t.Fatalf("final balance mismatch after cancel: got %d, want %d (supply loss of %d)",
			finalBal, initialConsumerBal, initialConsumerBal-finalBal)
	}

	lease, err := h.mem.GetLease(leaseBlock.Hash)
	if err != nil || lease == nil {
		t.Fatalf("GetLease failed: %v", err)
	}
	if lease.State != core.LeaseCancelled {
		t.Fatalf("lease state: got %s, want %s", lease.State, core.LeaseCancelled)
	}
	if len(lease.Renewals) != 0 {
		t.Fatalf("lease renewals: got %d, want 0 (stale renewals not cleared)", len(lease.Renewals))
	}
	pending, err := h.mem.GetPendingSend(leaseBlock.Hash)
	if err != nil {
		t.Fatalf("GetPendingSend: %v", err)
	}
	if pending != nil {
		t.Fatalf("pending escrow still present after cancel")
	}
}
