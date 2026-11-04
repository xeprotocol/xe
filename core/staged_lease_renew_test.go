package core_test

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func newTestLedger() (*core.Ledger, *store.MemStore) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	cfg := core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
	}
	l := core.NewLedger(ms, cfg)
	return l, ms
}

func setupConsumerWithEscrow(t *testing.T, l *core.Ledger, ms *store.MemStore, consumer, provider *core.KeyPair, fundAmount, leaseAmount uint64) (*core.Block, string) {
	t.Helper()
	// 1. Mint XUSD to consumer
	mint := &core.Block{
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
	if err := core.SignBlock(mint, consumer); err != nil {
		t.Fatalf("sign mint: %v", err)
	}
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("seed mint: %v", err)
	}

	leaseHash := "1111222233334444555566667777888811112222333344445555666677778888"

	// Add live escrow pending send
	ps := &core.PendingSend{
		SendHash:    leaseHash,
		Source:      consumer.Address(),
		Destination: provider.Address(),
		Amount:      leaseAmount,
		Asset:       "XUSD",
	}
	if err := ms.PutPendingSend(ps); err != nil {
		t.Fatalf("put pending send: %v", err)
	}

	// Add lease in store
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer.Address(),
		Provider:  provider.Address(),
		VCPUs:     2,
		MemoryMB:  2048,
		DiskGB:    20,
		Duration:  3600,
	}
	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	return mint, leaseHash
}

func signRenewBlock(t *testing.T, kp *core.KeyPair, prev, leaseHash string, parentBal, cost uint64, asset string) *core.Block {
	t.Helper()
	if asset == "" {
		asset = "XUSD"
	}
	b := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         kp.Address(),
		Previous:        prev,
		Balance:         parentBal - cost,
		Amount:          cost,
		Timestamp:       core.Now().UnixNano(),
		Asset:           asset,
		Source:          leaseHash,
		Duration:        3600,
		CertificateHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		LockedR:         100,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign lease_renew: %v", err)
	}
	return b
}

func TestValidateStagedBlock_LeaseRenew(t *testing.T) {
	l, ms := newTestLedger()
	consumer, _ := core.GenerateKeyPair()
	provider, _ := core.GenerateKeyPair()
	attacker, _ := core.GenerateKeyPair()

	const fundAmount = 100_000_000
	const leaseAmount = 10_000_000
	const renewCost = 5_000_000

	mint, leaseHash := setupConsumerWithEscrow(t, l, ms, consumer, provider, fundAmount, leaseAmount)

	// 1. Valid staged BlockLeaseRenew
	validRenew := signRenewBlock(t, consumer, mint.Hash, leaseHash, fundAmount, renewCost, "XUSD")
	if err := l.ValidateStagedBlock(validRenew, fundAmount); err != nil {
		t.Fatalf("expected valid staged lease_renew to pass, got: %v", err)
	}

	// 2. Reject non-XUSD asset
	badAsset := signRenewBlock(t, consumer, mint.Hash, leaseHash, fundAmount, renewCost, "XE")
	err := l.ValidateStagedBlock(badAsset, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "must have asset=XUSD") {
		t.Fatalf("expected asset=XUSD error, got: %v", err)
	}

	// 3. Reject empty source
	badSource := signRenewBlock(t, consumer, mint.Hash, leaseHash, fundAmount, renewCost, "XUSD")
	badSource.Source = ""
	err = l.ValidateStagedBlock(badSource, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "must reference a source lease hash") {
		t.Fatalf("expected missing source error, got: %v", err)
	}

	// 4. Reject nonexistent escrow
	badEscrow := signRenewBlock(t, consumer, mint.Hash, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", fundAmount, renewCost, "XUSD")
	err = l.ValidateStagedBlock(badEscrow, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "no live escrow for lease") {
		t.Fatalf("expected no live escrow error, got: %v", err)
	}

	// 5. Reject insufficient balance (cost > parentBalance)
	tooCostly := signRenewBlock(t, consumer, mint.Hash, leaseHash, 1_000, 2_000, "XUSD")
	err = l.ValidateStagedBlock(tooCostly, 1_000)
	if err == nil || !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("expected insufficient balance error, got: %v", err)
	}

	// 6. Reject balance mismatch (balance != parentBalance - amount)
	mismatchBal := signRenewBlock(t, consumer, mint.Hash, leaseHash, fundAmount, renewCost, "XUSD")
	mismatchBal.Balance = fundAmount - renewCost + 100
	if err := core.SignBlock(mismatchBal, consumer); err != nil {
		t.Fatalf("sign mismatch block: %v", err)
	}
	err = l.ValidateStagedBlock(mismatchBal, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "balance mismatch") {
		t.Fatalf("expected balance mismatch error, got: %v", err)
	}

	// 7. Reject renewal when lease is already settled
	settledLeaseHash := "9999888877776666555544443333222299998888777766665555444433332222"
	psSettled := &core.PendingSend{
		SendHash:    settledLeaseHash,
		Source:      consumer.Address(),
		Destination: provider.Address(),
		Amount:      leaseAmount,
		Asset:       "XUSD",
	}
	_ = ms.PutPendingSend(psSettled)
	settledLease := &core.Lease{
		LeaseHash: settledLeaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer.Address(),
		Provider:  provider.Address(),
		Settled:   true,
	}
	_ = ms.PutLease(settledLease)
	settledRenew := signRenewBlock(t, consumer, mint.Hash, settledLeaseHash, fundAmount, renewCost, "XUSD")
	err = l.ValidateStagedBlock(settledRenew, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "already settled") {
		t.Fatalf("expected lease already settled error, got: %v", err)
	}

	// 8. Reject renewal from non-consumer account
	attackerRenew := signRenewBlock(t, attacker, "0", leaseHash, fundAmount, renewCost, "XUSD")
	attackerRenew.Representative = attacker.Address()
	attackerRenew.PubKey = attacker.PubKeyHex()
	if err := core.SignBlock(attackerRenew, attacker); err != nil {
		t.Fatalf("sign attacker block: %v", err)
	}
	err = l.ValidateStagedBlock(attackerRenew, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "only the consumer can renew") {
		t.Fatalf("expected only consumer can renew error, got: %v", err)
	}
}

func TestAddBlock_ConflictingLeaseRenewStaged(t *testing.T) {
	l, ms := newTestLedger()
	consumer, _ := core.GenerateKeyPair()
	provider, _ := core.GenerateKeyPair()

	const fundAmount = 100_000_000
	const leaseAmount = 10_000_000
	const renewCost = 5_000_000

	mint, leaseHash := setupConsumerWithEscrow(t, l, ms, consumer, provider, fundAmount, leaseAmount)

	// Create first on-chain block on top of mint: e.g. a send block S1
	destKey, _ := core.GenerateKeyPair()
	s1 := &core.Block{
		Type:        core.BlockSend,
		Account:     consumer.Address(),
		Previous:    mint.Hash,
		Balance:     fundAmount - 1_000_000,
		Amount:      1_000_000,
		Timestamp:   core.Now().UnixNano(),
		Asset:       "XUSD",
		Destination: destKey.Address(),
	}
	if err := core.SignBlock(s1, consumer); err != nil {
		t.Fatalf("sign s1: %v", err)
	}
	if err := l.AddBlock(s1); err != nil {
		t.Fatalf("add s1 to ledger: %v", err)
	}

	// Now create a conflicting BlockLeaseRenew with Previous = mint.Hash (sibling to s1)
	conflictingRenew := signRenewBlock(t, consumer, mint.Hash, leaseHash, fundAmount, renewCost, "XUSD")

	// Ingest conflicting lease_renew via AddBlock.
	// Previously this failed with: "conflict block: staged block: unknown type: lease_renew"
	err := l.AddBlock(conflictingRenew)
	if err != nil {
		t.Fatalf("expected conflicting lease_renew to be staged successfully, got error: %v", err)
	}

	// Verify that the conflicting block was staged in the store
	staged, err := ms.GetStagedBlock(conflictingRenew.Hash)
	if err != nil || staged == nil {
		t.Fatalf("expected staged block %s to be stored, got err=%v", conflictingRenew.Hash, err)
	}
	if staged.Hash != conflictingRenew.Hash {
		t.Fatalf("staged block hash mismatch: got %s, want %s", staged.Hash, conflictingRenew.Hash)
	}

	// Verify conflict record was created linking s1 and conflictingRenew
	conflict, err := ms.GetConflict(consumer.Address(), mint.Hash)
	if err != nil || conflict == nil {
		t.Fatalf("expected conflict record for previous %s, got: %v", mint.Hash, err)
	}
	foundS1 := false
	foundRenew := false
	for _, h := range conflict.BlockHashes {
		if h == s1.Hash {
			foundS1 = true
		}
		if h == conflictingRenew.Hash {
			foundRenew = true
		}
	}
	if !foundS1 || !foundRenew {
		t.Fatalf("conflict record does not contain both blocks: %+v", conflict.BlockHashes)
	}
}
