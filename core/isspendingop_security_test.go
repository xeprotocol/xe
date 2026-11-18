package core_test

import (
	"crypto/ed25519"
	"encoding/hex"
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

// TestIsSpendingOpClassification pins the XE-17229 fix: BlockReceive and the
// four lease lifecycle ops are spending-class and require full multisig
// threshold. Previously-spending types stay spending; BlockGenesis stays
// non-spending.
func TestIsSpendingOpClassification(t *testing.T) {
	spending := []core.BlockType{
		core.BlockSend,
		core.BlockBurn,
		core.BlockLease,
		core.BlockLeaseRenew,
		core.BlockLeaseAccept,
		core.BlockLeaseCancel,
		core.BlockLeaseForceSettle,
		core.BlockLeaseSettle,
		core.BlockReceive,
		core.BlockMultisigOpen,
		core.BlockMultisigUpdate,
		core.BlockMint,
	}
	for _, bt := range spending {
		if !core.IsSpendingOp(bt) {
			t.Fatalf("expected %s to be a spending op (require threshold multisig)", bt)
		}
	}
	for _, bt := range []core.BlockType{core.BlockGenesis} {
		if core.IsSpendingOp(bt) {
			t.Fatalf("expected %s NOT to be a spending op", bt)
		}
	}
}

// TestMultisigReceiveRequiresThreshold is adapted from PR #7's
// TestMultisigReceiveRepresentativeHijackRejected, with one deliberate
// difference: this fix classifies BlockReceive itself as a spending op
// (XE-17229's suggested fix), so a plain 1-of-2 receive with NO
// representative change is now also rejected. PR #7 instead kept plain
// receives 1-of-N and only required threshold for rep-changing receives
// via its RequiresThresholdMultisig helper. The rep-change guard already
// in verifyBlockCredential (changesRepresentative) is therefore no longer
// the only thing standing between a rogue member and the delegation.
func TestMultisigReceiveRequiresThreshold(t *testing.T) {
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

	// 1-of-2 signer tries a plain receive without changing representative.
	// With BlockReceive in IsSpendingOp this MUST now fail (stricter than
	// PR #7, which allowed plain 1-of-2 receives).
	recv1of2 := &core.Block{
		Type:      core.BlockReceive,
		Account:   msAddr,
		Previous:  openMS.Hash,
		Balance:   5_000,
		Source:    send1.Hash,
		Asset:     "XE",
		Timestamp: now + 4,
	}
	signMultisig(t, recv1of2, kp1)
	if err := ledger.AddBlock(recv1of2); err == nil {
		t.Fatalf("expected 1-of-2 BlockReceive (no rep change) to be rejected, but it succeeded")
	}

	// Same receive with full 2-of-2 threshold signatures succeeds.
	recv2of2 := *recv1of2
	signMultisig(t, &recv2of2, kp1, kp2)
	if err := ledger.AddBlock(&recv2of2); err != nil {
		t.Fatalf("expected 2-of-2 BlockReceive (no rep change) to succeed, got: %v", err)
	}
	if got := ledger.GetVoteWeight(honestRep.Address()).Uint64(); got != 5_000 {
		t.Fatalf("expected honestRep weight 5000, got %d", got)
	}

	// 1-of-2 rogue signer attempts to hijack representative delegation on BlockReceive -> MUST fail!
	hijackRecv := &core.Block{
		Type:           core.BlockReceive,
		Account:        msAddr,
		Previous:       recv2of2.Hash,
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

// TestMultisigLeaseAcceptRequiresThreshold is adapted from PR #7's
// TestMultisigLeaseAcceptAndCancelRequireThreshold. Two adaptations for
// HEAD (8cc209d): the RequiresThresholdMultisig assertions are dropped
// (that helper is PR #7-only and is not added by this fix), and the whole
// flow uses XCU instead of PR #7's XUSD — at HEAD only XE and XCU are
// valid assets (validAssets, core/types.go), leases are XCU-denominated
// (validateAndAddLease / validateAndAddLeaseAccept require Asset == "XCU"),
// and XUSD cannot even be seeded (SeedAssetForTesting rejects it).
// MintForTesting at HEAD is likewise XCU-only, so funding goes through
// SeedAssetForTesting.
func TestMultisigLeaseAcceptRequiresThreshold(t *testing.T) {
	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()
	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
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

	// Open multisig provider and fund with XCU for stake.
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
		Asset:     "XCU",
		Timestamp: now + 1,
	}
	signMultisig(t, mintProv, kp1, kp2)
	if err := ledger.SeedAssetForTesting(mintProv); err != nil {
		t.Fatalf("SeedAssetForTesting provider: %v", err)
	}

	// Open consumer and create lease to multisig provider.
	mintConsumer := &core.Block{
		Type:      core.BlockMint,
		Account:   kpConsumer.Address(),
		Previous:  "0",
		Balance:   100_000,
		Amount:    100_000,
		Asset:     "XCU",
		Timestamp: now + 2,
	}
	core.MustSignBlock(mintConsumer, kpConsumer)
	if err := ledger.SeedAssetForTesting(mintConsumer); err != nil {
		t.Fatalf("SeedAssetForTesting consumer: %v", err)
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
		Asset:           "XCU",
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

	// 1-of-2 rogue signer tries to lock provider's XCU stake via BlockLeaseAccept -> MUST be rejected!
	accept1of2 := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerAddr,
		Previous:        mintProv.Hash,
		Source:          leaseBlk.Hash,
		Amount:          stake,
		Balance:         100_000 - stake,
		CertificateHash: certHash,
		LockedR:         core.RFallback,
		// HEAD requires locked emission params on accept
		// (validateLockedEmissionAt); the test ledger has no epoch
		// function configured, so only the >0 check applies.
		LockedPayoutCap: 1_000_000,
		LockedTWAP:      1000,
		Attestations:    []core.TimekeeperAttestation{*att},
		Asset:           "XCU",
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
