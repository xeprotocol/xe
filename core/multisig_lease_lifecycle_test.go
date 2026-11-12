package core_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestIsSpendingOp(t *testing.T) {
	expectedTrue := []core.BlockType{
		core.BlockSend,
		core.BlockBurn,
		core.BlockLease,
		core.BlockLeaseAccept,
		core.BlockLeaseSettle,
		core.BlockLeaseCancel,
		core.BlockLeaseForceSettle,
		core.BlockLeaseRenew,
		core.BlockMultisigOpen,
		core.BlockMultisigUpdate,
		core.BlockMint,
	}
	for _, bt := range expectedTrue {
		if !core.IsSpendingOp(bt) {
			t.Errorf("expected IsSpendingOp(%q) to be true", bt)
		}
	}

	expectedFalse := []core.BlockType{
		core.BlockReceive,
		core.BlockGenesis,
		core.BlockType("unknown"),
		core.BlockType(""),
	}
	for _, bt := range expectedFalse {
		if core.IsSpendingOp(bt) {
			t.Errorf("expected IsSpendingOp(%q) to be false", bt)
		}
	}
}

type msLifecycleHarness struct {
	ledger      *core.Ledger
	mem         *store.MemStore
	tk          *core.KeyPair
	funder      *core.KeyPair
	provKey1    *core.KeyPair
	provKey2    *core.KeyPair
	provAddr    string
	provKeyset  *core.Keyset
	consKey1    *core.KeyPair
	consKey2    *core.KeyPair
	consAddr    string
	consKeyset  *core.Keyset
	certs       map[string]*core.CertificateInfo
	lastTs      map[string]int64
}

func newMSLifecycleHarness(t *testing.T) *msLifecycleHarness {
	t.Helper()
	tk, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate timekeeper key: %v", err)
	}
	funder, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate funder key: %v", err)
	}

	provKey1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key 1: %v", err)
	}
	provKey2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key 2: %v", err)
	}
	provKeyset := &core.Keyset{
		Threshold: 2,
		Keys:      []string{provKey1.PubKeyHex(), provKey2.PubKeyHex()},
	}
	provAddr, err := core.DeriveMultisigAddress(provKeyset)
	if err != nil {
		t.Fatalf("derive provider multisig address: %v", err)
	}

	consKey1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key 1: %v", err)
	}
	consKey2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key 2: %v", err)
	}
	consKeyset := &core.Keyset{
		Threshold: 2,
		Keys:      []string{consKey1.PubKeyHex(), consKey2.PubKeyHex()},
	}
	consAddr, err := core.DeriveMultisigAddress(consKeyset)
	if err != nil {
		t.Fatalf("derive consumer multisig address: %v", err)
	}

	h := &msLifecycleHarness{
		mem:        store.NewMemStore(),
		tk:         tk,
		funder:     funder,
		provKey1:   provKey1,
		provKey2:   provKey2,
		provAddr:   provAddr,
		provKeyset: provKeyset,
		consKey1:   consKey1,
		consKey2:   consKey2,
		consAddr:   consAddr,
		consKeyset: consKeyset,
		certs:      make(map[string]*core.CertificateInfo),
		lastTs:     make(map[string]int64),
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

func (h *msLifecycleHarness) nextTs(acct string) int64 {
	now := time.Now().UnixNano()
	prev := h.lastTs[acct]
	if now <= prev {
		now = prev + int64(time.Millisecond)
	}
	h.lastTs[acct] = now
	return now
}

func (h *msLifecycleHarness) frontier(acct string) string {
	chain := h.ledger.GetChain(acct)
	if len(chain) == 0 {
		return "0"
	}
	return chain[len(chain)-1].Hash
}

func (h *msLifecycleHarness) balance(acct string, asset string) uint64 {
	return h.ledger.GetAssetBalances(acct)[asset]
}

func (h *msLifecycleHarness) attest(t *testing.T, source string, at int64) []core.TimekeeperAttestation {
	t.Helper()
	a, err := core.SignAttestation(source, at, h.tk)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	return []core.TimekeeperAttestation{*a}
}

func signMS(t *testing.T, b *core.Block, signers ...*core.KeyPair) {
	t.Helper()
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h
	hashBytes, err := core.DecodeHash(h)
	if err != nil {
		t.Fatalf("DecodeHash: %v", err)
	}
	b.Signatures = nil
	for _, k := range signers {
		sig := ed25519.Sign(k.Private, hashBytes)
		b.Signatures = append(b.Signatures, core.BlockSignature{
			PublicKey: k.PubKeyHex(),
			Sig:       hex.EncodeToString(sig),
		})
	}
}

func TestMultisig_LeaseAccept_RequiresThreshold(t *testing.T) {
	h := newMSLifecycleHarness(t)
	now := time.Now()

	certHash := "2222222222222222222222222222222222222222222222222222222222222222"
	h.certs[certHash] = &core.CertificateInfo{
		Provider:             h.provAddr,
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// 1. Open 2-of-2 provider
	openProv := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   h.provAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XE",
		MSKeyset:  h.provKeyset,
	}
	signMS(t, openProv, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(openProv); err != nil {
		t.Fatalf("AddBlock prov open: %v", err)
	}

	// 2. Fund provider with XUSD for stake
	funderSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   h.funder.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(h.funder.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(funderSeed, h.funder); err != nil {
		t.Fatalf("sign funder: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(funderSeed); err != nil {
		t.Fatalf("seed funder: %v", err)
	}

	sendToProv := &core.Block{
		Type:        core.BlockSend,
		Account:     h.funder.Address(),
		Previous:    h.frontier(h.funder.Address()),
		Balance:     h.balance(h.funder.Address(), "XUSD") - 5_000_000,
		Amount:      5_000_000,
		Destination: h.provAddr,
		Timestamp:   h.nextTs(h.funder.Address()),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendToProv, h.funder); err != nil {
		t.Fatalf("sign send: %v", err)
	}
	if err := h.ledger.AddBlock(sendToProv); err != nil {
		t.Fatalf("AddBlock send: %v", err)
	}

	recvProv := &core.Block{
		Type:      core.BlockReceive,
		Account:   h.provAddr,
		Previous:  h.frontier(h.provAddr),
		Balance:   5_000_000,
		Source:    sendToProv.Hash,
		Amount:    5_000_000,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XUSD",
	}
	signMS(t, recvProv, h.provKey1)
	if err := h.ledger.AddBlock(recvProv); err != nil {
		t.Fatalf("AddBlock recv: %v", err)
	}

	// 3. Consumer creates lease
	consumer, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("consumer key: %v", err)
	}
	consumerSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   consumer.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(consumer.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(consumerSeed, consumer); err != nil {
		t.Fatalf("sign consumer seed: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(consumerSeed); err != nil {
		t.Fatalf("seed consumer: %v", err)
	}

	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	stake := core.LeaseStake(baseCost)

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         consumer.Address(),
		Previous:        h.frontier(consumer.Address()),
		Balance:         h.balance(consumer.Address(), "XUSD") - baseCost,
		Timestamp:       h.nextTs(consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provAddr,
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	if err := core.SignBlock(leaseBlock, consumer); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	// 4. Provider attempts lease_accept with only 1 signature (should FAIL)
	acceptTs := time.Now().UnixNano()
	accept1Sig := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provAddr,
		Previous:        h.frontier(h.provAddr),
		Balance:         h.balance(h.provAddr, "XUSD") - stake,
		Timestamp:       h.nextTs(h.provAddr),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	signMS(t, accept1Sig, h.provKey1)
	err = h.ledger.AddBlock(accept1Sig)
	if err == nil {
		t.Fatalf("expected error for 1-of-2 lease_accept on multisig account, got success")
	}
	if !strings.Contains(err.Error(), "insufficient signatures") {
		t.Fatalf("expected insufficient signatures error, got: %v", err)
	}

	// 5. Provider submits lease_accept with 2-of-2 signatures (should SUCCEED)
	accept2Sig := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provAddr,
		Previous:        h.frontier(h.provAddr),
		Balance:         h.balance(h.provAddr, "XUSD") - stake,
		Timestamp:       h.nextTs(h.provAddr),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	signMS(t, accept2Sig, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(accept2Sig); err != nil {
		t.Fatalf("expected 2-of-2 lease_accept to succeed, got: %v", err)
	}
}

func TestMultisig_LeaseCancel_RequiresThreshold(t *testing.T) {
	h := newMSLifecycleHarness(t)
	now := time.Now()

	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	certHash := "3333333333333333333333333333333333333333333333333333333333333333"
	h.certs[certHash] = &core.CertificateInfo{
		Provider:             provider.Address(),
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// 1. Open 2-of-2 multisig consumer
	openCons := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   h.consAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XE",
		MSKeyset:  h.consKeyset,
	}
	signMS(t, openCons, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(openCons); err != nil {
		t.Fatalf("AddBlock cons open: %v", err)
	}

	// 2. Fund consumer with XUSD
	funderSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   h.funder.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(h.funder.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(funderSeed, h.funder); err != nil {
		t.Fatalf("sign funder: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(funderSeed); err != nil {
		t.Fatalf("seed funder: %v", err)
	}

	sendToCons := &core.Block{
		Type:        core.BlockSend,
		Account:     h.funder.Address(),
		Previous:    h.frontier(h.funder.Address()),
		Balance:     h.balance(h.funder.Address(), "XUSD") - 5_000_000,
		Amount:      5_000_000,
		Destination: h.consAddr,
		Timestamp:   h.nextTs(h.funder.Address()),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendToCons, h.funder); err != nil {
		t.Fatalf("sign send: %v", err)
	}
	if err := h.ledger.AddBlock(sendToCons); err != nil {
		t.Fatalf("AddBlock send: %v", err)
	}

	recvCons := &core.Block{
		Type:      core.BlockReceive,
		Account:   h.consAddr,
		Previous:  h.frontier(h.consAddr),
		Balance:   5_000_000,
		Source:    sendToCons.Hash,
		Amount:    5_000_000,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XUSD",
	}
	signMS(t, recvCons, h.consKey1)
	if err := h.ledger.AddBlock(recvCons); err != nil {
		t.Fatalf("AddBlock recv: %v", err)
	}

	// 3. Consumer creates lease with 2-of-2 signatures
	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consAddr,
		Previous:        h.frontier(h.consAddr),
		Balance:         h.balance(h.consAddr, "XUSD") - baseCost,
		Timestamp:       h.nextTs(h.consAddr),
		Asset:           "XUSD",
		Destination:     provider.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	signMS(t, leaseBlock, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	// 4. Consumer attempts lease_cancel with 1 signature (should FAIL)
	cancel1Sig := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   h.consAddr,
		Previous:  h.frontier(h.consAddr),
		Balance:   h.balance(h.consAddr, "XUSD") + baseCost,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XUSD",
		Source:    leaseBlock.Hash,
	}
	signMS(t, cancel1Sig, h.consKey1)
	err = h.ledger.AddBlock(cancel1Sig)
	if err == nil {
		t.Fatalf("expected error for 1-of-2 lease_cancel on multisig consumer, got success")
	}
	if !strings.Contains(err.Error(), "insufficient signatures") {
		t.Fatalf("expected insufficient signatures error, got: %v", err)
	}

	// 5. Consumer submits lease_cancel with 2-of-2 signatures (should SUCCEED)
	cancel2Sig := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   h.consAddr,
		Previous:  h.frontier(h.consAddr),
		Balance:   h.balance(h.consAddr, "XUSD") + baseCost,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XUSD",
		Source:    leaseBlock.Hash,
	}
	signMS(t, cancel2Sig, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(cancel2Sig); err != nil {
		t.Fatalf("expected 2-of-2 lease_cancel to succeed, got: %v", err)
	}

	// Verify refund restored consumer balance
	if h.balance(h.consAddr, "XUSD") != 5_000_000 {
		t.Fatalf("expected balance to be fully refunded to 5_000_000, got: %d", h.balance(h.consAddr, "XUSD"))
	}
}

func TestMultisig_LeaseSettle_RequiresThreshold(t *testing.T) {
	h := newMSLifecycleHarness(t)
	now := time.Now()

	certHash := "4444444444444444444444444444444444444444444444444444444444444444"
	h.certs[certHash] = &core.CertificateInfo{
		Provider:             h.provAddr,
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// 1. Open 2-of-2 provider
	openProv := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   h.provAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XE",
		MSKeyset:  h.provKeyset,
	}
	signMS(t, openProv, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(openProv); err != nil {
		t.Fatalf("AddBlock prov open: %v", err)
	}

	// 2. Fund provider with XUSD
	funderSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   h.funder.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(h.funder.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(funderSeed, h.funder); err != nil {
		t.Fatalf("sign funder: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(funderSeed); err != nil {
		t.Fatalf("seed funder: %v", err)
	}

	sendToProv := &core.Block{
		Type:        core.BlockSend,
		Account:     h.funder.Address(),
		Previous:    h.frontier(h.funder.Address()),
		Balance:     h.balance(h.funder.Address(), "XUSD") - 5_000_000,
		Amount:      5_000_000,
		Destination: h.provAddr,
		Timestamp:   h.nextTs(h.funder.Address()),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendToProv, h.funder); err != nil {
		t.Fatalf("sign send: %v", err)
	}
	if err := h.ledger.AddBlock(sendToProv); err != nil {
		t.Fatalf("AddBlock send: %v", err)
	}

	recvProv := &core.Block{
		Type:      core.BlockReceive,
		Account:   h.provAddr,
		Previous:  h.frontier(h.provAddr),
		Balance:   5_000_000,
		Source:    sendToProv.Hash,
		Amount:    5_000_000,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XUSD",
	}
	signMS(t, recvProv, h.provKey1)
	if err := h.ledger.AddBlock(recvProv); err != nil {
		t.Fatalf("AddBlock recv: %v", err)
	}

	// 3. Consumer creates lease
	consumer, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("consumer key: %v", err)
	}
	consumerSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   consumer.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(consumer.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(consumerSeed, consumer); err != nil {
		t.Fatalf("sign consumer seed: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(consumerSeed); err != nil {
		t.Fatalf("seed consumer: %v", err)
	}

	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	stake := core.LeaseStake(baseCost)

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         consumer.Address(),
		Previous:        h.frontier(consumer.Address()),
		Balance:         h.balance(consumer.Address(), "XUSD") - baseCost,
		Timestamp:       h.nextTs(consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provAddr,
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	if err := core.SignBlock(leaseBlock, consumer); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	// 4. Provider accepts lease with 2-of-2 signatures
	acceptTs := time.Now().UnixNano()
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provAddr,
		Previous:        h.frontier(h.provAddr),
		Balance:         h.balance(h.provAddr, "XUSD") - stake,
		Timestamp:       h.nextTs(h.provAddr),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	signMS(t, acceptBlock, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock accept: %v", err)
	}

	// 5. Build lease settle block
	lease, err := h.mem.GetLease(leaseBlock.Hash)
	if lease == nil || err != nil {
		t.Fatalf("GetLease: %v (lease=%v)", err, lease)
	}
	emission, err := core.LeaseTotalEmission(lease)
	if err != nil {
		t.Fatalf("LeaseTotalEmission: %v", err)
	}

	settleTs := lease.EffectiveExpiry() + 10 // slightly past expiry

	origNow := core.Now
	core.Now = func() time.Time { return time.Unix(0, settleTs) }
	defer func() { core.Now = origNow }()

	settle1Sig := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      h.provAddr,
		Previous:     h.frontier(h.provAddr),
		Balance:      h.balance(h.provAddr, "XE") + emission,
		Timestamp:    h.nextTs(h.provAddr),
		Asset:        "XE",
		Source:       leaseBlock.Hash,
		Amount:       emission,
		Attestations: h.attest(t, leaseBlock.Hash, settleTs),
	}

	// Settle with 1 signature (should FAIL)
	signMS(t, settle1Sig, h.provKey1)
	err = h.ledger.AddBlock(settle1Sig)
	if err == nil {
		t.Fatalf("expected error for 1-of-2 lease_settle on multisig provider, got success")
	}
	if !strings.Contains(err.Error(), "insufficient signatures") {
		t.Fatalf("expected insufficient signatures error, got: %v", err)
	}

	// Settle with 2-of-2 signatures (should SUCCEED)
	settle2Sig := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      h.provAddr,
		Previous:     h.frontier(h.provAddr),
		Balance:      h.balance(h.provAddr, "XE") + emission,
		Timestamp:    h.nextTs(h.provAddr),
		Asset:        "XE",
		Source:       leaseBlock.Hash,
		Amount:       emission,
		Attestations: h.attest(t, leaseBlock.Hash, settleTs),
	}
	signMS(t, settle2Sig, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(settle2Sig); err != nil {
		t.Fatalf("expected 2-of-2 lease_settle to succeed, got: %v", err)
	}
}

func TestMultisig_LeaseForceSettle_RequiresThreshold(t *testing.T) {
	h := newMSLifecycleHarness(t)
	now := time.Now()

	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	certHash := "5555555555555555555555555555555555555555555555555555555555555555"
	h.certs[certHash] = &core.CertificateInfo{
		Provider:             provider.Address(),
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// 1. Open 2-of-2 multisig consumer
	openCons := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   h.consAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XE",
		MSKeyset:  h.consKeyset,
	}
	signMS(t, openCons, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(openCons); err != nil {
		t.Fatalf("AddBlock cons open: %v", err)
	}

	// 2. Fund consumer with XUSD
	funderSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   h.funder.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(h.funder.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(funderSeed, h.funder); err != nil {
		t.Fatalf("sign funder: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(funderSeed); err != nil {
		t.Fatalf("seed funder: %v", err)
	}

	sendToCons := &core.Block{
		Type:        core.BlockSend,
		Account:     h.funder.Address(),
		Previous:    h.frontier(h.funder.Address()),
		Balance:     h.balance(h.funder.Address(), "XUSD") - 5_000_000,
		Amount:      5_000_000,
		Destination: h.consAddr,
		Timestamp:   h.nextTs(h.funder.Address()),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendToCons, h.funder); err != nil {
		t.Fatalf("sign send: %v", err)
	}
	if err := h.ledger.AddBlock(sendToCons); err != nil {
		t.Fatalf("AddBlock send: %v", err)
	}

	recvCons := &core.Block{
		Type:      core.BlockReceive,
		Account:   h.consAddr,
		Previous:  h.frontier(h.consAddr),
		Balance:   5_000_000,
		Source:    sendToCons.Hash,
		Amount:    5_000_000,
		Timestamp: h.nextTs(h.consAddr),
		Asset:     "XUSD",
	}
	signMS(t, recvCons, h.consKey1)
	if err := h.ledger.AddBlock(recvCons); err != nil {
		t.Fatalf("AddBlock recv: %v", err)
	}

	// 3. Fund single-key provider with stake
	provSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   provider.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(provider.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(provSeed, provider); err != nil {
		t.Fatalf("sign provider seed: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(provSeed); err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	// 4. Consumer creates lease with 2-of-2 signatures
	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	stake := core.LeaseStake(baseCost)

	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consAddr,
		Previous:        h.frontier(h.consAddr),
		Balance:         h.balance(h.consAddr, "XUSD") - baseCost,
		Timestamp:       h.nextTs(h.consAddr),
		Asset:           "XUSD",
		Destination:     provider.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          1,
		Duration:        3600,
		CertificateHash: certHash,
	}
	signMS(t, leaseBlock, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(leaseBlock); err != nil {
		t.Fatalf("AddBlock lease: %v", err)
	}

	// 5. Provider accepts lease
	acceptTs := time.Now().UnixNano()
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         provider.Address(),
		Previous:        h.frontier(provider.Address()),
		Balance:         h.balance(provider.Address(), "XUSD") - stake,
		Timestamp:       h.nextTs(provider.Address()),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      0,
		Attestations:    h.attest(t, leaseBlock.Hash, acceptTs),
	}
	if err := core.SignBlock(acceptBlock, provider); err != nil {
		t.Fatalf("sign accept: %v", err)
	}
	if err := h.ledger.AddBlock(acceptBlock); err != nil {
		t.Fatalf("AddBlock accept: %v", err)
	}

	// 6. Consumer attempts force-settle past eligibleAt
	lease, err := h.mem.GetLease(leaseBlock.Hash)
	if lease == nil || err != nil {
		t.Fatalf("GetLease: %v (lease=%v)", err, lease)
	}
	expiry := lease.EffectiveExpiry()
	forceTs := expiry + core.LeaseSettleGrace + core.LeaseForceSettleGap + 10

	origNow := core.Now
	core.Now = func() time.Time { return time.Unix(0, forceTs) }
	defer func() { core.Now = origNow }()

	force1Sig := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      h.consAddr,
		Previous:     h.frontier(h.consAddr),
		Balance:      h.balance(h.consAddr, "XUSD") + baseCost,
		Timestamp:    h.nextTs(h.consAddr),
		Asset:        "XUSD",
		Source:       leaseBlock.Hash,
		Attestations: h.attest(t, leaseBlock.Hash, forceTs),
	}

	// Force-settle with 1 signature (should FAIL)
	signMS(t, force1Sig, h.consKey1)
	err = h.ledger.AddBlock(force1Sig)
	if err == nil {
		t.Fatalf("expected error for 1-of-2 lease_force_settle on multisig consumer, got success")
	}
	if !strings.Contains(err.Error(), "insufficient signatures") {
		t.Fatalf("expected insufficient signatures error, got: %v", err)
	}

	// Force-settle with 2-of-2 signatures (should SUCCEED)
	force2Sig := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      h.consAddr,
		Previous:     h.frontier(h.consAddr),
		Balance:      h.balance(h.consAddr, "XUSD") + baseCost,
		Timestamp:    h.nextTs(h.consAddr),
		Asset:        "XUSD",
		Source:       leaseBlock.Hash,
		Attestations: h.attest(t, leaseBlock.Hash, forceTs),
	}
	signMS(t, force2Sig, h.consKey1, h.consKey2)
	if err := h.ledger.AddBlock(force2Sig); err != nil {
		t.Fatalf("expected 2-of-2 lease_force_settle to succeed, got: %v", err)
	}

	if h.balance(h.consAddr, "XUSD") != 5_000_000 {
		t.Fatalf("expected balance to be restored to 5_000_000, got: %d", h.balance(h.consAddr, "XUSD"))
	}
}
