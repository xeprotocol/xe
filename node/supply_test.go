package node

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestSupplyAuditor_LeaseRenewConservation(t *testing.T) {
	ms := store.NewMemStore()
	// Initialize empty ledger to write genesis
	_ = core.NewLedger(ms, core.LedgerConfig{})

	consumer := strings.Repeat("1", 64)
	provider := strings.Repeat("2", 64)
	leaseHash := strings.Repeat("a", 64)
	renewHash := strings.Repeat("b", 64)
	settleHash := strings.Repeat("c", 64)

	// Chain blocks:
	// 1. consumer mint 10000 XUSD
	b1 := &core.Block{
		Account: consumer,
		Hash:    strings.Repeat("e", 64),
		Type:    core.BlockMint,
		Asset:   "XUSD",
		Amount:  10000,
		Balance: 10000,
	}
	// 2. consumer lease: 1000 XUSD escrowed
	b2 := &core.Block{
		Account:  consumer,
		Previous: b1.Hash,
		Hash:     leaseHash,
		Type:     core.BlockLease,
		Asset:    "XUSD",
		Amount:   1000,
		Balance:  9000,
	}
	// 3. consumer renew: 500 XUSD topup
	b3 := &core.Block{
		Account:  consumer,
		Previous: b2.Hash,
		Hash:     renewHash,
		Source:   leaseHash,
		Type:     core.BlockLeaseRenew,
		Asset:    "XUSD",
		Amount:   500,
		Balance:  8500,
	}
	// 4. provider settles lease: 10000 XE emitted
	b4 := &core.Block{
		Account: provider,
		Hash:    settleHash,
		Source:  leaseHash,
		Type:    core.BlockLeaseSettle,
		Asset:   "XE",
		Amount:  10000,
		Balance: 10000,
	}

	_ = ms.PutBlock(b1)
	_ = ms.PutBlock(b2)
	_ = ms.PutBlock(b3)
	_ = ms.PutBlock(b4)

	_ = ms.PutAccountChain(consumer, &core.AccountChain{
		Blocks: []*core.Block{b1, b2, b3},
	})
	_ = ms.PutFrontier(consumer, b3.Hash)

	_ = ms.PutAccountChain(provider, &core.AccountChain{
		Blocks: []*core.Block{b4},
	})
	_ = ms.PutFrontier(provider, b4.Hash)

	_ = ms.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer,
		Provider:  provider,
		Cost:      1000,
		State:     core.LeaseSettled,
		Settled:   true,
		Renewals: []core.LeaseSegment{
			{RenewHash: renewHash, Cost: 500},
		},
	})

	// Recreate ledger so it rebuilds asset balances from chains in store
	l := core.NewLedger(ms, core.LedgerConfig{})
	auditor := core.NewSupplyAuditor(l)
	rep := auditor.Report()

	xusd := rep.Assets["XUSD"]
	if xusd == nil {
		t.Fatalf("missing XUSD in report")
	}

	// EscrowBurned should be base (1000) + renewal (500) = 1500
	if xusd.EscrowBurned != 1500 {
		t.Fatalf("expected EscrowBurned 1500, got %d", xusd.EscrowBurned)
	}

	// Balances (8500) + EscrowBurned (1500) = 10000 Accounted == 10000 Created (Minted)
	if xusd.Discrepancy != 0 {
		t.Fatalf("expected discrepancy 0, got %d (accounted: %d, created: %d)", xusd.Discrepancy, xusd.Accounted, xusd.Created)
	}
	if !xusd.Conserved {
		t.Fatalf("expected XUSD to be conserved, notes: %v", rep.Notes)
	}
	if !rep.Conserved {
		t.Fatalf("expected report Conserved true, got false, notes: %v", rep.Notes)
	}
	if len(rep.Notes) != 0 {
		t.Fatalf("expected clean notes array on conserved network, got %v", rep.Notes)
	}
}
