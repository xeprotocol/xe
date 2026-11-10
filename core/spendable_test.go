package core

import (
	"testing"
)

type mockSpendableStore struct {
	Store
	QuorumStore
	LeaseStore
	chains       map[string]*AccountChain
	finalHeights map[string]uint64
	leases       map[string]*Lease
}

func (m *mockSpendableStore) GetAccountChain(acc string) (*AccountChain, error) {
	return m.chains[acc], nil
}

func (m *mockSpendableStore) GetFinalHeight(acc string) (uint64, error) {
	return m.finalHeights[acc], nil
}

func (m *mockSpendableStore) SetFinalHeight(acc string, h uint64) error {
	m.finalHeights[acc] = h
	return nil
}

func (m *mockSpendableStore) GetLease(hash string) (*Lease, error) {
	return m.leases[hash], nil
}

func TestSpendableBalances_BlockLeaseSettle_ReturnsStake(t *testing.T) {
	provider := "provider_addr_123"
	leaseHash := "lease_hash_abc"

	mockStore := &mockSpendableStore{
		chains:       make(map[string]*AccountChain),
		finalHeights: make(map[string]uint64),
		leases:       make(map[string]*Lease),
	}

	// Provider settled lease with 50,000 XUSD stake
	mockStore.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		Provider:  provider,
		Stake:     50000,
		Duration:  3600,
	}

	// Chain has 1 block: BlockLeaseSettle for XE payout (1000 XE) with Source = leaseHash
	mockStore.chains[provider] = &AccountChain{
		Blocks: []*Block{
			{
				Account: provider,
				Type:    BlockLeaseSettle,
				Asset:   "XE",
				Balance: 1000,
				Source:  leaseHash,
				Hash:    "block1",
			},
		},
	}

	// Finalized at height 1
	mockStore.finalHeights[provider] = 1

	ledger := &Ledger{
		store:      mockStore,
		finalStore: mockStore,
	}

	spendable := ledger.SpendableBalances(provider)

	// Verify XE balance is spendable
	if spendable["XE"] != 1000 {
		t.Fatalf("expected 1000 spendable XE, got %d", spendable["XE"])
	}

	// Verify returned XUSD stake is spendable
	if spendable["XUSD"] != 50000 {
		t.Fatalf("expected 50000 spendable XUSD (returned stake), got %d", spendable["XUSD"])
	}
}

func TestSpendableBalances_FinalizedFrontier(t *testing.T) {
	acc := "test_account"
	mockStore := &mockSpendableStore{
		chains:       make(map[string]*AccountChain),
		finalHeights: make(map[string]uint64),
		leases:       make(map[string]*Lease),
	}

	mockStore.chains[acc] = &AccountChain{
		Blocks: []*Block{
			{Hash: "h1", Account: acc, Balance: 100},
			{Hash: "h2", Account: acc, Balance: 200},
		},
	}
	mockStore.finalHeights[acc] = 1

	ledger := &Ledger{
		store:      mockStore,
		finalStore: mockStore,
	}

	frontier := ledger.FinalizedFrontier(acc)
	if frontier != "h1" {
		t.Fatalf("expected frontier h1, got %s", frontier)
	}

	mockStore.finalHeights[acc] = 2
	frontier = ledger.FinalizedFrontier(acc)
	if frontier != "h2" {
		t.Fatalf("expected frontier h2, got %s", frontier)
	}
}
