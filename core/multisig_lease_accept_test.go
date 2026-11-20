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

type msTestHarness struct {
	ledger   *core.Ledger
	mem      *store.MemStore
	tk       *core.KeyPair
	consumer *core.KeyPair
	funder   *core.KeyPair
	provKey1 *core.KeyPair
	provKey2 *core.KeyPair
	provAddr string
	keyset   *core.Keyset
	certs    map[string]*core.CertificateInfo
	lastTs   map[string]int64
}

func newMSTestHarness(t *testing.T) *msTestHarness {
	t.Helper()
	tk, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate timekeeper key: %v", err)
	}
	consumer, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key: %v", err)
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

	keyset := &core.Keyset{
		Threshold: 2,
		Keys:      []string{provKey1.PubKeyHex(), provKey2.PubKeyHex()},
	}
	provAddr, err := core.DeriveMultisigAddress(keyset)
	if err != nil {
		t.Fatalf("derive multisig address: %v", err)
	}

	h := &msTestHarness{
		mem:      store.NewMemStore(),
		tk:       tk,
		consumer: consumer,
		funder:   funder,
		provKey1: provKey1,
		provKey2: provKey2,
		provAddr: provAddr,
		keyset:   keyset,
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

func (h *msTestHarness) nextTs(acct string) int64 {
	now := time.Now().UnixNano()
	prev := h.lastTs[acct]
	if now <= prev {
		now = prev + int64(time.Millisecond)
	}
	h.lastTs[acct] = now
	return now
}

func (h *msTestHarness) frontier(acct string) string {
	chain := h.ledger.GetChain(acct)
	if len(chain) == 0 {
		return "0"
	}
	return chain[len(chain)-1].Hash
}

func (h *msTestHarness) balance(acct string) uint64 {
	return h.ledger.GetAssetBalances(acct)["XUSD"]
}

func (h *msTestHarness) attest(t *testing.T, source string, at int64) []core.TimekeeperAttestation {
	t.Helper()
	a, err := core.SignAttestation(source, at, h.tk)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	return []core.TimekeeperAttestation{*a}
}

func signMultisig(t *testing.T, b *core.Block, signers ...*core.KeyPair) {
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

func TestMultisig_LeaseAcceptRequiresFullThreshold(t *testing.T) {
	h := newMSTestHarness(t)
	now := time.Now()

	certHash := "2222222222222222222222222222222222222222222222222222222222222222"
	cert := &core.CertificateInfo{
		Provider:             h.provAddr,
		ExpiresAt:            now.Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}
	h.certs[certHash] = cert

	// 1. Open 2-of-2 multisig provider account
	openBlock := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   h.provAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XE",
		MSKeyset:  h.keyset,
	}
	signMultisig(t, openBlock, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(openBlock); err != nil {
		t.Fatalf("AddBlock multisig open: %v", err)
	}

	// 2. Fund funder and consumer accounts
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

	consumerSeed := &core.Block{
		Type:      core.BlockMint,
		Account:   h.consumer.Address(),
		Previous:  "0",
		Balance:   10_000_000,
		Amount:    10_000_000,
		Timestamp: h.nextTs(h.consumer.Address()),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(consumerSeed, h.consumer); err != nil {
		t.Fatalf("sign consumer: %v", err)
	}
	if err := h.ledger.SeedAssetForTesting(consumerSeed); err != nil {
		t.Fatalf("seed consumer: %v", err)
	}

	// 3. Funder sends 5_000_000 XUSD to multisig provider account
	const provFundAmount = 5_000_000
	sendToProv := &core.Block{
		Type:        core.BlockSend,
		Account:     h.funder.Address(),
		Previous:    h.frontier(h.funder.Address()),
		Balance:     h.balance(h.funder.Address()) - provFundAmount,
		Amount:      provFundAmount,
		Destination: h.provAddr,
		Timestamp:   h.nextTs(h.funder.Address()),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendToProv, h.funder); err != nil {
		t.Fatalf("sign send to prov: %v", err)
	}
	if err := h.ledger.AddBlock(sendToProv); err != nil {
		t.Fatalf("AddBlock send to prov: %v", err)
	}

	// Multisig provider receives the funds (1 signature sufficient for receive)
	recvBlock := &core.Block{
		Type:      core.BlockReceive,
		Account:   h.provAddr,
		Previous:  h.frontier(h.provAddr),
		Balance:   provFundAmount,
		Source:    sendToProv.Hash,
		Amount:    provFundAmount,
		Timestamp: h.nextTs(h.provAddr),
		Asset:     "XUSD",
	}
	signMultisig(t, recvBlock, h.provKey1)
	if err := h.ledger.AddBlock(recvBlock); err != nil {
		t.Fatalf("AddBlock recv on multisig: %v", err)
	}

	baseCost, err := core.LeaseCost(1, 1024, 1, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	stake := core.LeaseStake(baseCost)

	// 4. Consumer creates lease targeting multisig provider
	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         h.consumer.Address(),
		Previous:        h.frontier(h.consumer.Address()),
		Balance:         h.balance(h.consumer.Address()) - baseCost,
		Timestamp:       h.nextTs(h.consumer.Address()),
		Asset:           "XUSD",
		Destination:     h.provAddr,
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

	// 5. Provider attempts lease_accept with only ONE signature (1-of-2)
	acceptTs := time.Now().UnixNano()
	acceptBlock1Sig := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provAddr,
		Previous:        h.frontier(h.provAddr),
		Balance:         h.balance(h.provAddr) - stake,
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
	// Sign with only provKey1
	signMultisig(t, acceptBlock1Sig, h.provKey1)

	err = h.ledger.AddBlock(acceptBlock1Sig)
	if err == nil {
		t.Fatalf("VULNERABILITY DETECTED: 1-of-2 signature was accepted for lease_accept on 2-of-2 multisig account!")
	}
	if !strings.Contains(err.Error(), "insufficient signatures") {
		t.Fatalf("unexpected error for 1-of-2 accept: %v", err)
	}

	// 6. Provider submits lease_accept with BOTH signatures (2-of-2)
	acceptBlock2Sig := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         h.provAddr,
		Previous:        h.frontier(h.provAddr),
		Balance:         h.balance(h.provAddr) - stake,
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
	signMultisig(t, acceptBlock2Sig, h.provKey1, h.provKey2)
	if err := h.ledger.AddBlock(acceptBlock2Sig); err != nil {
		t.Fatalf("AddBlock with 2-of-2 signatures failed: %v", err)
	}
}
