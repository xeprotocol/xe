package core

import (
	"testing"
)

func TestTermsFromChain_LeaseRenew(t *testing.T) {
	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	blocks := []*Block{
		{
			Type:    BlockLease,
			Hash:    leaseHash,
			Asset:   "XUSD",
			Amount:  1000,
			Balance: 5000,
		},
		{
			Type:    BlockLeaseRenew,
			Hash:    "2222222222222222222222222222222222222222222222222222222222222222",
			Source:  leaseHash,
			Asset:   "XUSD",
			Amount:  300,
			Balance: 4700,
		},
		{
			Type:    BlockLeaseRenew,
			Hash:    "3333333333333333333333333333333333333333333333333333333333333333",
			Source:  leaseHash,
			Asset:   "XUSD",
			Amount:  200,
			Balance: 4500,
		},
		{
			Type:    BlockLeaseSettle,
			Hash:    "4444444444444444444444444444444444444444444444444444444444444444",
			Source:  leaseHash,
			Asset:   "XE",
			Amount:  50000,
			Balance: 50000,
		},
	}

	terms := termsFromChain(blocks)
	if terms.leaseCost[leaseHash] != 1000 {
		t.Fatalf("expected leaseCost 1000, got %d", terms.leaseCost[leaseHash])
	}
	if terms.leaseRenewCost[leaseHash] != 500 {
		t.Fatalf("expected leaseRenewCost 500, got %d", terms.leaseRenewCost[leaseHash])
	}
	if terms.settleEmission[leaseHash] != 50000 {
		t.Fatalf("expected settleEmission 50000, got %d", terms.settleEmission[leaseHash])
	}
}

func TestLease_TotalCost(t *testing.T) {
	l := &Lease{
		Cost: 1000,
		Renewals: []LeaseSegment{
			{Cost: 400},
			{Cost: 350},
		},
	}
	if got := l.TotalCost(); got != 1750 {
		t.Fatalf("expected TotalCost 1750, got %d", got)
	}
}
