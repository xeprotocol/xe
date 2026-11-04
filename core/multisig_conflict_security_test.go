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

func signMultisig(t *testing.T, b *core.Block, kps ...*core.KeyPair) {
	t.Helper()
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h
	hb, err := core.DecodeHash(h)
	if err != nil {
		t.Fatalf("DecodeHash: %v", err)
	}
	b.Signatures = nil
	for _, kp := range kps {
		sig := ed25519.Sign(kp.Private, hb)
		b.Signatures = append(b.Signatures, core.BlockSignature{
			PublicKey: kp.PubKeyHex(),
			Sig:       hex.EncodeToString(sig),
		})
	}
}

func TestMultisigReceiveRepresentativeHijackRejected(t *testing.T) {
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()
	funder, _ := core.GenerateKeyPair()
	honestRep, _ := core.GenerateKeyPair()
	attackerRep, _ := core.GenerateKeyPair()

	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	msAddr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	now := core.Now().UnixNano()

	// Seed funder with XE and send two dust transfers to the multisig account.
	mintFunder := &core.Block{
		Type:      core.BlockMint,
		Account:   funder.Address(),
		Previous:  "0",
		Balance:   10_000,
		Amount:    10_000,
		Asset:     "XE",
		Timestamp: now,
	}
	core.MustSignBlock(mintFunder, funder)
	if err := ledger.SeedAssetForTesting(mintFunder); err != nil {
		t.Fatalf("SeedAssetForTesting funder: %v", err)
	}

	send1 := &core.Block{
		Type:        core.BlockSend,
		Account:     funder.Address(),
		Previous:    mintFunder.Hash,
		Balance:     5_000,
		Amount:      5_000,
		Destination: msAddr,
		Asset:       "XE",
		Timestamp:   now + 1,
	}
	core.MustSignBlock(send1, funder)
	if err := ledger.AddBlock(send1); err != nil {
		t.Fatalf("AddBlock send1: %v", err)
	}

	send2 := &core.Block{
		Type:        core.BlockSend,
		Account:     funder.Address(),
		Previous:    send1.Hash,
		Balance:     4_999,
		Amount:      1,
		Destination: msAddr,
		Asset:       "XE",
		Timestamp:   now + 2,
	}
	core.MustSignBlock(send2, funder)
	if err := ledger.AddBlock(send2); err != nil {
		t.Fatalf("AddBlock send2: %v", err)
	}

	// Open multisig account with honestRep delegated (signed by 2-of-2).
	openMS := &core.Block{
		Type:           core.BlockMultisigOpen,
		Account:        msAddr,
		Previous:       "0",
		Balance:        0,
		Representative: honestRep.Address(),
		MSKeyset:       ks,
		Asset:          "XE",
		Timestamp:      now + 3,
	}
	signMultisig(t, openMS, kp1, kp2)
	if err := ledger.AddBlock(openMS); err != nil {
		t.Fatalf("AddBlock openMS: %v", err)
	}

	// 1-of-2 signer CAN receive funds without changing representative.
	recv1 := &core.Block{
		Type:      core.BlockReceive,
		Account:   msAddr,
		Previous:  openMS.Hash,
		Balance:   5_000,
		Source:    send1.Hash,
		Asset:     "XE",
		Timestamp: now + 4,
	}
	signMultisig(t, recv1, kp1)
	if err := ledger.AddBlock(recv1); err != nil {
		t.Fatalf("AddBlock recv1 (no rep change, 1-of-2): %v", err)
	}
	if got := ledger.GetVoteWeight(honestRep.Address()).Uint64(); got != 5_000 {
		t.Fatalf("expected honestRep weight 5000, got %d", got)
	}

	// 1-of-2 rogue signer attempts to hijack representative delegation on BlockReceive -> MUST fail!
	hijackRecv := &core.Block{
		Type:           core.BlockReceive,
		Account:        msAddr,
		Previous:       recv1.Hash,
		Balance:        5_001,
		Source:         send2.Hash,
		Representative: attackerRep.Address(),
		Asset:          "XE",
		Timestamp:      now + 5,
	}
	signMultisig(t, hijackRecv, kp1)
	if err := ledger.AddBlock(hijackRecv); err == nil {
		t.Fatalf("expected 1-of-2 BlockReceive changing Representative to be rejected, but it succeeded")
	}
	if got := ledger.GetRepresentative(msAddr); got != honestRep.Address() {
		t.Fatalf("representative was hijacked: got %s, want %s", got, honestRep.Address())
	}

	// With full 2-of-2 threshold signatures, representative change on BlockReceive succeeds.
	validRepChangeRecv := *hijackRecv
	signMultisig(t, &validRepChangeRecv, kp1, kp2)
	if err := ledger.AddBlock(&validRepChangeRecv); err != nil {
		t.Fatalf("expected 2-of-2 BlockReceive with rep change to succeed, got: %v", err)
	}
	if got := ledger.GetRepresentative(msAddr); got != attackerRep.Address() {
		t.Fatalf("expected representative %s after 2-of-2 approval, got %s", attackerRep.Address(), got)
	}
}

func TestMultisigLeaseAcceptAndCancelRequireThreshold(t *testing.T) {
	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()
	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}

	for _, bt := range []core.BlockType{
		core.BlockLeaseAccept,
		core.BlockLeaseCancel,
		core.BlockLeaseForceSettle,
		core.BlockLeaseSettle,
	} {
		if !core.IsSpendingOp(bt) {
			t.Fatalf("expected %s to require threshold multisig in IsSpendingOp", bt)
		}
		b := &core.Block{Type: bt}
		if !core.RequiresThresholdMultisig(b, "") {
			t.Fatalf("expected RequiresThresholdMultisig(%s) to be true", bt)
		}
	}

	ms := store.NewMemStore()
	tk, _ := core.GenerateKeyPair()
	const certHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	kpConsumer, _ := core.GenerateKeyPair()

	providerAddr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	ledger := core.NewLedger(ms, core.LedgerConfig{
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{tk.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             providerAddr,
				ExpiresAt:            core.Now().Add(24 * time.Hour).UnixNano(),
				PriceMultiplierMilli: 1000,
			}
		},
	})

	now := core.Now().UnixNano()

	// Open multisig provider and fund with XUSD for stake.
	openProv := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   providerAddr,
		Previous:  "0",
		Balance:   0,
		MSKeyset:  ks,
		Asset:     "XE",
		Timestamp: now,
	}
	signMultisig(t, openProv, kp1, kp2)
	if err := ledger.AddBlock(openProv); err != nil {
		t.Fatalf("AddBlock openProv: %v", err)
	}

	mintProv := &core.Block{
		Type:      core.BlockMint,
		Account:   providerAddr,
		Previous:  openProv.Hash,
		Balance:   100_000,
		Amount:    100_000,
		Asset:     "XUSD",
		Timestamp: now + 1,
	}
	signMultisig(t, mintProv, kp1, kp2)
	if err := ledger.MintForTesting(mintProv); err != nil {
		t.Fatalf("MintForTesting provider: %v", err)
	}

	// Open consumer and create lease to multisig provider.
	mintConsumer := &core.Block{
		Type:      core.BlockMint,
		Account:   kpConsumer.Address(),
		Previous:  "0",
		Balance:   100_000,
		Amount:    100_000,
		Asset:     "XUSD",
		Timestamp: now + 2,
	}
	core.MustSignBlock(mintConsumer, kpConsumer)
	if err := ledger.MintForTesting(mintConsumer); err != nil {
		t.Fatalf("MintForTesting consumer: %v", err)
	}

	cost, err := core.LeaseCost(1, 1024, 10, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         kpConsumer.Address(),
		Previous:        mintConsumer.Hash,
		Destination:     providerAddr,
		Amount:          cost,
		Balance:         100_000 - cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        3600,
		CertificateHash: certHash,
		Asset:           "XUSD",
		Timestamp:       now + 3,
	}
	core.MustSignBlock(leaseBlk, kpConsumer)
	if err := ledger.AddBlock(leaseBlk); err != nil {
		t.Fatalf("AddBlock leaseBlk: %v", err)
	}

	stake := core.LeaseStake(cost)
	att, err := core.SignAttestation(leaseBlk.Hash, now+4, tk)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	// 1-of-2 rogue signer tries to lock provider's XUSD stake via BlockLeaseAccept -> MUST be rejected!
	accept1of2 := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerAddr,
		Previous:        mintProv.Hash,
		Source:          leaseBlk.Hash,
		Amount:          stake,
		Balance:         100_000 - stake,
		CertificateHash: certHash,
		LockedR:         core.RFallback,
		Attestations:    []core.TimekeeperAttestation{*att},
		Asset:           "XUSD",
		Timestamp:       now + 4,
	}
	signMultisig(t, accept1of2, kp1)
	if err := ledger.AddBlock(accept1of2); err == nil {
		t.Fatalf("expected 1-of-2 BlockLeaseAccept to be rejected, but it succeeded")
	}

	// 2-of-2 threshold signatures succeed.
	accept2of2 := *accept1of2
	signMultisig(t, &accept2of2, kp1, kp2)
	if err := ledger.AddBlock(&accept2of2); err != nil {
		t.Fatalf("expected 2-of-2 BlockLeaseAccept to succeed, got: %v", err)
	}
}

func TestMultisigUpdateConflictDetectionAndSwapBlockUnwind(t *testing.T) {
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()
	kp3, _ := core.GenerateKeyPair()
	kp4, _ := core.GenerateKeyPair()
	dest, _ := core.GenerateKeyPair()

	ks1 := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	ks2 := &core.Keyset{
		Keys:      []string{kp3.PubKeyHex(), kp4.PubKeyHex()},
		Threshold: 2,
	}
	msAddr, err := core.DeriveMultisigAddress(ks1)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	now := core.Now().UnixNano()

	openMS := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   msAddr,
		Previous:  "0",
		Balance:   0,
		MSKeyset:  ks1,
		Asset:     "XE",
		Timestamp: now,
	}
	signMultisig(t, openMS, kp1, kp2)
	if err := ledger.AddBlock(openMS); err != nil {
		t.Fatalf("AddBlock openMS: %v", err)
	}

	mintMS := &core.Block{
		Type:      core.BlockMint,
		Account:   msAddr,
		Previous:  openMS.Hash,
		Balance:   10_000,
		Amount:    10_000,
		Asset:     "XE",
		Timestamp: now + 1,
	}
	signMultisig(t, mintMS, kp1, kp2)
	if err := ledger.SeedAssetForTesting(mintMS); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	// Block A at height 3: unfinalized BlockMultisigUpdate rotating keyset ks1 -> ks2.
	updateBlk := &core.Block{
		Type:      core.BlockMultisigUpdate,
		Account:   msAddr,
		Previous:  mintMS.Hash,
		Balance:   10_000,
		MSKeyset:  ks2,
		Asset:     "XE",
		Timestamp: now + 2,
	}
	signMultisig(t, updateBlk, kp1, kp2)
	if err := ledger.AddBlock(updateBlk); err != nil {
		t.Fatalf("AddBlock updateBlk: %v", err)
	}

	// Block B at height 3 (conflict sibling with Previous == mintMS.Hash): BlockSend signed by ks1 (parent keyset).
	sendBlk := &core.Block{
		Type:        core.BlockSend,
		Account:     msAddr,
		Previous:    mintMS.Hash,
		Balance:     9_000,
		Amount:      1_000,
		Destination: dest.Address(),
		Asset:       "XE",
		Timestamp:   now + 3,
	}
	signMultisig(t, sendBlk, kp1, kp2)
	if err := ledger.AddBlock(sendBlk); err != nil {
		t.Fatalf("expected conflict sibling signed by parent keyset ks1 to be staged, got error: %v", err)
	}

	conflict := ledger.GetConflict(msAddr, mintMS.Hash)
	if conflict == nil || len(conflict.BlockHashes) != 2 {
		t.Fatalf("expected conflict with 2 candidates at parent %s, got %+v", mintMS.Hash, conflict)
	}

	// Resolve conflict in favor of sendBlk -> SwapBlock must unwind updateBlk and restore ks1!
	if err := ledger.SwapBlock(msAddr, updateBlk.Hash, sendBlk.Hash, sendBlk); err != nil {
		t.Fatalf("SwapBlock unwinding BlockMultisigUpdate failed: %v", err)
	}

	restoredKs := ledger.GetKeyset(msAddr)
	if restoredKs == nil || len(restoredKs.Keys) != 2 || restoredKs.Keys[0] != ks1.Keys[0] {
		t.Fatalf("expected restored keyset ks1 after SwapBlock, got %+v", restoredKs)
	}
	if gotBal := ledger.GetBalance(msAddr); gotBal != 9_000 {
		t.Fatalf("expected XE balance 9000 after SwapBlock, got %d", gotBal)
	}
}

func TestMultisigAndAttestationCaseInsensitiveDeduplication(t *testing.T) {
	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()

	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	msgHash := strings.Repeat("ab", 32)
	hb, _ := core.DecodeHash(msgHash)
	sig := hex.EncodeToString(ed25519.Sign(kp1.Private, hb))

	// Same signer submitted twice with lowercase and uppercase PublicKey must be rejected.
	dupSigs := []core.BlockSignature{
		{PublicKey: strings.ToLower(kp1.PubKeyHex()), Sig: sig},
		{PublicKey: strings.ToUpper(kp1.PubKeyHex()), Sig: sig},
	}
	if err := core.VerifyMultisig(msgHash, dupSigs, ks); err == nil {
		t.Fatalf("expected VerifyMultisig to reject case-variant duplicate signer")
	}

	// Same timekeeper submitted twice with lowercase and uppercase PublicKey must be rejected.
	now := core.Now().UnixNano()
	att, err := core.SignAttestation(msgHash, now, kp1)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	attUpper := *att
	attUpper.PublicKey = strings.ToUpper(att.PublicKey)

	tkCfg := &core.TimekeeperConfig{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	if _, err := core.ValidateAttestations([]core.TimekeeperAttestation{*att, attUpper}, msgHash, tkCfg, true); err == nil {
		t.Fatalf("expected ValidateAttestations to reject case-variant duplicate timekeeper attestation")
	}
}
