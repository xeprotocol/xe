package node_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/store"
)

// TestBuildForceSettleBlockWithRenewalsRefundsFullPendingEscrow verifies that
// BuildForceSettleBlock computes the refund from the full pending escrow (base lease cost
// plus renewal top-ups), rather than only the base lease.Cost, preventing escrow
// destruction upon lease force settlement (#155).
func TestBuildForceSettleBlockWithRenewalsRefundsFullPendingEscrow(t *testing.T) {
	memStore := store.NewMemStore()

	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate timekeeper keypair: %v", err)
	}
	tkConfig := &core.TimekeeperConfig{
		Keys:      []string{tkKP.PubKeyHex()},
		Threshold: 1,
	}

	l := core.NewLedger(memStore, core.LedgerConfig{
		Difficulty:         0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig { return tkConfig },
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

	// 1. Initialize consumer account with genesis send and receive
	initialFunds := uint64(10_000_000)
	genesisSend := &core.Block{
		Type:        core.BlockSend,
		Account:     "0000000000000000000000000000000000000000000000000000000000000000",
		Previous:    "0",
		Amount:      initialFunds,
		Asset:       "XUSD",
		Destination: consumerAddr,
		Timestamp:   now - int64(10*time.Hour),
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
		Timestamp: now - int64(9*time.Hour),
	}
	if err := core.SignBlock(consumerReceive, consumerKP); err != nil {
		t.Fatalf("failed to sign consumerReceive: %v", err)
	}
	if err := l.AddBlock(consumerReceive); err != nil {
		t.Fatalf("failed to add consumerReceive: %v", err)
	}

	// 2. Set up lease and renewals in the ledger store:
	// Base cost: 50,000 µXUSD. Renewal cost: 50,000 µXUSD. Total escrow: 100,000 µXUSD.
	baseCost := uint64(50_000)
	renewalCost := uint64(50_000)
	totalEscrow := baseCost + renewalCost

	startTime := now - int64(5*time.Hour)
	leaseBlock := &core.Block{
		Type:        core.BlockLease,
		Account:     consumerAddr,
		Previous:    consumerReceive.Hash,
		Destination: providerAddr,
		Amount:      baseCost,
		Balance:     initialFunds - baseCost,
		Asset:       "XUSD",
		Timestamp:   startTime,
	}
	leaseHash, err := core.HashBlock(leaseBlock)
	if err != nil {
		t.Fatalf("failed to hash leaseBlock: %v", err)
	}
	leaseBlock.Hash = leaseHash
	if err := memStore.PutBlock(leaseBlock); err != nil {
		t.Fatalf("failed to put leaseBlock: %v", err)
	}

	// Renewal block representing extension
	renewBlock := &core.Block{
		Type:        core.BlockLeaseRenew,
		Account:     consumerAddr,
		Previous:    leaseBlock.Hash,
		Source:      leaseBlock.Hash,
		Destination: providerAddr,
		Amount:      renewalCost,
		Balance:     initialFunds - totalEscrow,
		Asset:       "XUSD",
		Timestamp:   startTime + int64(time.Minute),
	}
	renewHash, err := core.HashBlock(renewBlock)
	if err != nil {
		t.Fatalf("failed to hash renewBlock: %v", err)
	}
	renewBlock.Hash = renewHash
	if err := memStore.PutBlock(renewBlock); err != nil {
		t.Fatalf("failed to put renewBlock: %v", err)
	}

	// Store pending send reflecting total escrow including renewals
	if err := memStore.PutPendingSend(&core.PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      totalEscrow,
		Asset:       "XUSD",
	}); err != nil {
		t.Fatalf("failed to put pending send: %v", err)
	}

	// Set lease state to Accepted with a renewal segment (expired past Grace + Gap)
	leaseDuration := uint64(3600)   // 1 hour
	renewalDuration := uint64(3600) // 1 hour
	lease := &core.Lease{
		LeaseHash: leaseBlock.Hash,
		State:     core.LeaseAccepted,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		Cost:      baseCost,
		Duration:  leaseDuration,
		StartTime: startTime,
		Renewals: []core.LeaseSegment{
			{
				RenewHash: renewBlock.Hash,
				Cost:      renewalCost,
				Duration:  renewalDuration,
				StartTime: startTime + int64(time.Minute),
			},
		},
	}
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("failed to put lease: %v", err)
	}

	// Update consumer chain to include leaseBlock and renewBlock
	chain, err := memStore.GetAccountChain(consumerAddr)
	if err != nil || chain == nil {
		t.Fatalf("failed to get consumer chain: %v", err)
	}
	chain.Blocks = append(chain.Blocks, leaseBlock, renewBlock)
	_ = memStore.PutAccountChain(consumerAddr, chain)
	_ = memStore.PutFrontier(consumerAddr, renewBlock.Hash)

	// Rebuild ledger with the updated chain state
	l = core.NewLedger(memStore, core.LedgerConfig{
		Difficulty:         0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig { return tkConfig },
	})

	// 3. Create Node with consumer keypair and storage
	n := &node.Node{
		KeyPair: consumerKP,
		Ledger:  l,
	}

	// Sign valid attestation for force settle
	att, err := core.SignAttestation(leaseBlock.Hash, now, tkKP)
	if err != nil {
		t.Fatalf("failed to sign attestation: %v", err)
	}
	attestations := []core.TimekeeperAttestation{*att}

	// 4. Test: Old formula partial refund (baseCost only) must be rejected by ledger
	currentBal := l.GetAssetBalances(consumerAddr)["XUSD"]
	erroneousBlock := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      consumerAddr,
		Previous:     renewBlock.Hash,
		Source:       leaseBlock.Hash,
		Balance:      currentBal + baseCost, // Buggy: missed renewalEscrow
		Amount:       baseCost,
		Asset:        "XUSD",
		Timestamp:    now,
		Attestations: attestations,
	}
	if err := core.SignBlock(erroneousBlock, consumerKP); err != nil {
		t.Fatalf("failed to sign erroneousBlock: %v", err)
	}
	err = l.AddBlock(erroneousBlock)
	if err == nil {
		t.Fatalf("expected erroneous partial-refund force settle block to fail ledger balance check")
	}
	if !strings.Contains(err.Error(), "balance mismatch") {
		t.Fatalf("expected balance mismatch error, got: %v", err)
	}

	// 5. Test: BuildForceSettleBlock produces block with full pending escrow refund
	b, err := n.BuildForceSettleBlock(lease, attestations)
	if err != nil {
		t.Fatalf("BuildForceSettleBlock failed: %v", err)
	}

	if b.Amount != totalEscrow {
		t.Fatalf("expected force settle block amount %d (full escrow), got %d", totalEscrow, b.Amount)
	}
	if b.Balance != initialFunds {
		t.Fatalf("expected consumer balance %d, got %d", initialFunds, b.Balance)
	}

	// 6. Test: Ledger accepts block built by BuildForceSettleBlock and clears escrow
	if err := l.AddBlock(b); err != nil {
		t.Fatalf("ledger rejected block from BuildForceSettleBlock: %v", err)
	}

	finalBal := l.GetAssetBalances(consumerAddr)["XUSD"]
	if finalBal != initialFunds {
		t.Fatalf("expected final consumer balance %d, got %d", initialFunds, finalBal)
	}

	ps, err := memStore.GetPendingSend(leaseBlock.Hash)
	if err != nil {
		t.Fatalf("GetPendingSend failed: %v", err)
	}
	if ps != nil {
		t.Fatalf("expected pending escrow to be deleted from store, but found: %+v", ps)
	}
}
