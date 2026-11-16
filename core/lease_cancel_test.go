package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestLeaseCancelRefundsFullPendingEscrow verifies that cancelling a renewed lease
// refunds the full pending escrow (initial lease + renewals) rather than only the
// initial lease amount, preventing renewal funds from being destroyed (#158).
func TestLeaseCancelRefundsFullPendingEscrow(t *testing.T) {
	memStore := store.NewMemStore()
	l := core.NewLedger(memStore, core.LedgerConfig{
		Difficulty: 0,
	})

	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate consumer keypair: %v", err)
	}
	consumerAddr := consumerKP.Address()

	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate provider keypair: %v", err)
	}
	providerAddr := providerKP.Address()

	now := time.Now().UnixNano()

	// 1. Initialize consumer account with open receive block
	initialFunds := uint64(10_000_000)
	genesisSend := &core.Block{
		Type:        core.BlockSend,
		Account:     "0000000000000000000000000000000000000000000000000000000000000000",
		Previous:    "0",
		Amount:      initialFunds,
		Asset:       "XUSD",
		Destination: consumerAddr,
		Timestamp:   now - int64(10*time.Minute),
	}
	genesisHash, err := core.HashBlock(genesisSend)
	if err != nil {
		t.Fatalf("failed to hash genesisSend: %v", err)
	}
	genesisSend.Hash = genesisHash
	_ = memStore.PutBlock(genesisSend)
	_ = memStore.PutPendingSend(&core.PendingSend{
		SendHash:    genesisSend.Hash,
		Source:      genesisSend.Account,
		Destination: consumerAddr,
		Amount:      initialFunds,
		Asset:       "XUSD",
	})

	consumerReceive := &core.Block{
		Type:      core.BlockReceive,
		Account:   consumerAddr,
		Previous:  "0",
		Source:    genesisSend.Hash,
		Balance:   initialFunds,
		Asset:     "XUSD",
		Timestamp: now - int64(9*time.Minute),
	}
	if err := core.SignBlock(consumerReceive, consumerKP); err != nil {
		t.Fatalf("failed to sign consumerReceive: %v", err)
	}
	if err := l.AddBlock(consumerReceive); err != nil {
		t.Fatalf("failed to add consumerReceive: %v", err)
	}

	// 2. Set up an existing renewed lease state in the ledger store:
	// Initial lease cost: 40,000 micro-XUSD.
	// Renewal cost: 40,000 micro-XUSD. Total pending escrow = 80,000 micro-XUSD.
	leaseCost := uint64(40_000)
	renewalCost := uint64(40_000)
	totalEscrow := leaseCost + renewalCost // 80,000

	leaseBlock := &core.Block{
		Type:        core.BlockLease,
		Account:     consumerAddr,
		Previous:    consumerReceive.Hash,
		Destination: providerAddr,
		Amount:      leaseCost,
		Balance:     initialFunds - leaseCost,
		Asset:       "XUSD",
		Timestamp:   now - int64(8*time.Minute),
	}
	leaseHash, err := core.HashBlock(leaseBlock)
	if err != nil {
		t.Fatalf("failed to hash leaseBlock: %v", err)
	}
	leaseBlock.Hash = leaseHash
	if err := memStore.PutBlock(leaseBlock); err != nil {
		t.Fatalf("failed to put leaseBlock: %v", err)
	}

	// Register the lease in the store so lease cancellation validation finds it
	if err := memStore.PutLease(&core.Lease{
		LeaseHash: leaseBlock.Hash,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		State:     core.LeaseCreated,
		Duration:  3600,
		Cost:      leaseCost,
	}); err != nil {
		t.Fatalf("failed to put lease: %v", err)
	}

	// Store pending send reflecting total escrow including renewals
	if err := memStore.PutPendingSend(&core.PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      totalEscrow, // 80,000
		Asset:       "XUSD",
	}); err != nil {
		t.Fatalf("failed to put pending send: %v", err)
	}

	// Update consumer chain frontier to point to leaseBlock
	chain, err := memStore.GetAccountChain(consumerAddr)
	if err != nil || chain == nil {
		t.Fatalf("failed to get consumer chain: %v", err)
	}
	chain.Blocks = append(chain.Blocks, leaseBlock)
	_ = memStore.PutAccountChain(consumerAddr, chain)
	_ = memStore.PutFrontier(consumerAddr, leaseBlock.Hash)

	// Current balance on record before cancel
	currentBal := l.GetAssetBalances(consumerAddr)["XUSD"]

	// 3. Test live cancel with OLD erroneous formula (expect failure):
	// Old formula expected refund of only leaseBlock.Amount (40,000), expecting currentBal + 40,000.
	erroneousCancel := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumerAddr,
		Previous:  leaseBlock.Hash,
		Source:    leaseBlock.Hash,
		Balance:   currentBal + leaseCost, // Missing the 40,000 renewal escrow refund!
		Asset:     "XUSD",
		Timestamp: now - int64(5*time.Minute),
	}
	if err := core.SignBlock(erroneousCancel, consumerKP); err != nil {
		t.Fatalf("failed to sign erroneousCancel: %v", err)
	}

	err = l.AddBlock(erroneousCancel)
	if err == nil {
		t.Fatalf("expected erroneousCancel with partial refund to fail balance check")
	}
	if !strings.Contains(err.Error(), "balance mismatch") {
		t.Fatalf("expected balance mismatch error, got: %v", err)
	}

	// 4. Test live cancel with FULL pending refund (80,000):
	// Expected balance: currentBal + totalEscrow (all escrow refunded)
	correctCancel := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumerAddr,
		Previous:  leaseBlock.Hash,
		Source:    leaseBlock.Hash,
		Balance:   currentBal + totalEscrow, // Full refund (initial + renewals)
		Asset:     "XUSD",
		Timestamp: now - int64(4*time.Minute),
	}
	if err := core.SignBlock(correctCancel, consumerKP); err != nil {
		t.Fatalf("failed to sign correctCancel: %v", err)
	}

	if err := l.AddBlock(correctCancel); err != nil {
		t.Fatalf("correctCancel with full pending refund failed: %v", err)
	}

	// 5. Verify final consumer balance and pending escrow deleted
	finalBal := l.GetAssetBalances(consumerAddr)["XUSD"]
	expectedFinal := currentBal + totalEscrow
	if finalBal != expectedFinal {
		t.Fatalf("expected final consumer balance %d, got %d", expectedFinal, finalBal)
	}

	pendingAfter, err := memStore.GetPendingSend(leaseBlock.Hash)
	if err != nil {
		t.Fatalf("GetPendingSend failed: %v", err)
	}
	if pendingAfter != nil {
		t.Fatalf("expected pending escrow to be fully deleted after cancel, but still exists: %+v", pendingAfter)
	}
}
