package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestLeaseMergeRules_UndoMechanisms(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{
		TimestampWindow: core.DefaultTimestampWindow,
	})

	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	consumer := "2222222222222222222222222222222222222222222222222222222222222222"
	provider := "3333333333333333333333333333333333333333333333333333333333333333"

	// 1. Test error when provider chain not found locally
	err := l.ResolveRenewWinsOverSettle(leaseHash, provider)
	if err == nil || !core.IsRetryableError(err) {
		t.Fatalf("expected retryable error for missing provider chain, got %v", err)
	}

	// 2. Test error when consumer chain not found locally
	err = l.ResolveSettleWinsOverForceSettle(leaseHash, consumer)
	if err == nil || !core.IsRetryableError(err) {
		t.Fatalf("expected retryable error for missing consumer chain, got %v", err)
	}

	// 3. Setup mock chains
	now := time.Now().UnixNano()
	settleBlock := &core.Block{
		Type:      core.BlockLeaseSettle,
		Hash:      "4444444444444444444444444444444444444444444444444444444444444444",
		Account:   provider,
		Source:    leaseHash,
		Timestamp: now,
		Asset:     "XE",
		Amount:    100,
	}
	s.CommitBlock(&core.BlockCommit{
		Block:        settleBlock,
		Account:      provider,
		Chain:        &core.AccountChain{Blocks: []*core.Block{settleBlock}},
		FrontierHash: settleBlock.Hash,
		PutLease: &core.Lease{
			LeaseHash: leaseHash,
			State:     core.LeaseSettled,
			Settled:   true,
			Consumer:  consumer,
			Provider:  provider,
			Duration:  60,
			StartTime: now - 100,
		},
		AssetCredit:  &core.AssetDelta{Account: provider, Asset: "XE", Amount: 100},
	})

	// 4. Test ResolveRenewWinsOverSettle unwinds settleBlock
	err = l.ResolveRenewWinsOverSettle(leaseHash, provider)
	if err != nil {
		t.Fatalf("ResolveRenewWinsOverSettle failed: %v", err)
	}

	// Verify provider chain frontier is no longer settleBlock
	pchain, err := s.GetAccountChain(provider)
	if err != nil {
		t.Fatalf("GetAccountChain: %v", err)
	}
	if pchain != nil && len(pchain.Blocks) > 0 {
		for _, b := range pchain.Blocks {
			if b.Hash == settleBlock.Hash {
				t.Fatalf("expected settleBlock to be unwound, but still in chain")
			}
		}
	}

	// 5. Setup mock force settle block
	forceBlock := &core.Block{
		Type:      core.BlockLeaseForceSettle,
		Hash:      "5555555555555555555555555555555555555555555555555555555555555555",
		Account:   consumer,
		Source:    leaseHash,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    50,
	}
	s.CommitBlock(&core.BlockCommit{
		Block:        forceBlock,
		Account:      consumer,
		Chain:        &core.AccountChain{Blocks: []*core.Block{forceBlock}},
		FrontierHash: forceBlock.Hash,
		PutLease: &core.Lease{
			LeaseHash: leaseHash,
			State:     core.LeaseUnfulfilled,
			Settled:   true,
			Consumer:  consumer,
			Provider:  provider,
			Duration:  60,
			StartTime: now - 100,
		},
		AssetCredit:  &core.AssetDelta{Account: consumer, Asset: "XUSD", Amount: 50},
	})

	// 6. Test ResolveSettleWinsOverForceSettle unwinds forceBlock
	err = l.ResolveSettleWinsOverForceSettle(leaseHash, consumer)
	if err != nil {
		t.Fatalf("ResolveSettleWinsOverForceSettle failed: %v", err)
	}

	// Verify consumer chain frontier is no longer forceBlock
	cchain, err := s.GetAccountChain(consumer)
	if err != nil {
		t.Fatalf("GetAccountChain: %v", err)
	}
	if cchain != nil && len(cchain.Blocks) > 0 {
		for _, b := range cchain.Blocks {
			if b.Hash == forceBlock.Hash {
				t.Fatalf("expected forceBlock to be unwound, but still in chain")
			}
		}
	}
}
