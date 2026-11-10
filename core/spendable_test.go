package core

import (
	"testing"
)

type mockSpendableStore struct {
	blocks   map[string]*Block
	chains   map[string]*AccountChain
	leases   map[string]*Lease
	finalH   map[string]uint64
	statuses map[string]BlockStatus
}

func newMockSpendableStore() *mockSpendableStore {
	return &mockSpendableStore{
		blocks:   make(map[string]*Block),
		chains:   make(map[string]*AccountChain),
		leases:   make(map[string]*Lease),
		finalH:   make(map[string]uint64),
		statuses: make(map[string]BlockStatus),
	}
}

func (m *mockSpendableStore) GetBlock(hash string) (*Block, error) {
	return m.blocks[hash], nil
}

func (m *mockSpendableStore) PutBlock(block *Block) error {
	m.blocks[block.Hash] = block
	return nil
}

func (m *mockSpendableStore) GetAccountChain(account string) (*AccountChain, error) {
	return m.chains[account], nil
}

func (m *mockSpendableStore) PutAccountChain(account string, chain *AccountChain) error {
	m.chains[account] = chain
	return nil
}

func (m *mockSpendableStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	return nil, nil
}

func (m *mockSpendableStore) PutPendingSend(ps *PendingSend) error {
	return nil
}

func (m *mockSpendableStore) DeletePendingSend(sendHash string) error {
	return nil
}

func (m *mockSpendableStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockSpendableStore) GetAllPending() ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockSpendableStore) PutFrontier(account string, blockHash string) error {
	return nil
}

func (m *mockSpendableStore) GetFrontier(account string) (string, error) {
	return "", nil
}

func (m *mockSpendableStore) CommitUndo(u *BlockUndo) error {
	return nil
}

func (m *mockSpendableStore) IsEmpty() (bool, error) {
	return len(m.blocks) == 0, nil
}

func (m *mockSpendableStore) Close() error {
	return nil
}

func (m *mockSpendableStore) CommitBlock(c *BlockCommit) error {
	return nil
}

func (m *mockSpendableStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}

func (m *mockSpendableStore) SetBlockStatus(hash string, status BlockStatus) error {
	m.statuses[hash] = status
	return nil
}

func (m *mockSpendableStore) GetBlockStatus(hash string) (BlockStatus, error) {
	return m.statuses[hash], nil
}

func (m *mockSpendableStore) SetFinalHeight(account string, height uint64) error {
	m.finalH[account] = height
	return nil
}

func (m *mockSpendableStore) GetFinalHeight(account string) (uint64, error) {
	return m.finalH[account], nil
}

func (m *mockSpendableStore) DeleteVotesForConflict(account, previous string) error {
	return nil
}

func (m *mockSpendableStore) PutLease(lease *Lease) error {
	m.leases[lease.LeaseHash] = lease
	return nil
}

func (m *mockSpendableStore) GetLease(leaseHash string) (*Lease, error) {
	return m.leases[leaseHash], nil
}

func (m *mockSpendableStore) GetLeasesByProvider(provider string) ([]*Lease, error) {
	var out []*Lease
	for _, l := range m.leases {
		if l.Provider == provider {
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *mockSpendableStore) GetLeasesByState(state LeaseState) ([]*Lease, error) {
	return nil, nil
}

func (m *mockSpendableStore) GetAllLeases() ([]*Lease, error) {
	return nil, nil
}

func TestSpendableBalances_FinalizedLeaseSettleIncludesReturnedStake(t *testing.T) {
	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{})

	provider := "provider_11111111111111111111111111111111"
	leaseHash := "lease_22222222222222222222222222222222"

	// Register lease with 10,000 XUSD stake
	store.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		Provider:  provider,
		Stake:     10000,
		State:     LeaseSettled,
	}

	// Chain:
	// Block 0: lease_accept (asset=XUSD, balance=0)
	// Block 1: lease_settle (asset=XE, amount=500, balance=500, source=leaseHash)
	chain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "accept_hash_1",
				Type:    BlockLeaseAccept,
				Account: provider,
				Asset:   "XUSD",
				Balance: 0,
			},
			{
				Hash:    "settle_hash_2",
				Type:    BlockLeaseSettle,
				Account: provider,
				Asset:   "XE",
				Amount:  500,
				Balance: 500,
				Source:  leaseHash,
			},
		},
	}
	store.chains[provider] = chain

	// Both blocks finalized
	_ = store.SetFinalHeight(provider, 2)

	spendable := ledger.SpendableBalances(provider)

	if spendable["XE"] != 500 {
		t.Fatalf("expected spendable XE=500, got %d", spendable["XE"])
	}
	if spendable["XUSD"] != 10000 {
		t.Fatalf("expected spendable XUSD=10000 (returned stake), got %d", spendable["XUSD"])
	}
}

func TestSpendableBalances_UnfinalizedLeaseSettleExcludesFromFinalizedSpendable(t *testing.T) {
	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{})

	provider := "provider_11111111111111111111111111111111"
	leaseHash := "lease_22222222222222222222222222222222"

	store.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		Provider:  provider,
		Stake:     10000,
		State:     LeaseSettled,
	}

	chain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "accept_hash_1",
				Type:    BlockLeaseAccept,
				Account: provider,
				Asset:   "XUSD",
				Balance: 0,
			},
			{
				Hash:    "settle_hash_2",
				Type:    BlockLeaseSettle,
				Account: provider,
				Asset:   "XE",
				Amount:  500,
				Balance: 500,
				Source:  leaseHash,
			},
		},
	}
	store.chains[provider] = chain

	// Only Block 0 (accept) is finalized, settle is unfinalized
	_ = store.SetFinalHeight(provider, 1)

	spendable := ledger.SpendableBalances(provider)

	// Finalized spendable XUSD must still be 0 since settle is unfinalized
	if spendable["XUSD"] != 0 {
		t.Fatalf("expected spendable XUSD=0 for unfinalized settle, got %d", spendable["XUSD"])
	}
	if spendable["XE"] != 0 {
		t.Fatalf("expected spendable XE=0 since settle block is unfinalized, got %d", spendable["XE"])
	}
}

func TestSpendableBalances_UnfinalizedOutflowsWithSettleStake(t *testing.T) {
	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{})

	provider := "provider_11111111111111111111111111111111"
	leaseHash := "lease_22222222222222222222222222222222"

	store.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		Provider:  provider,
		Stake:     10000,
		State:     LeaseSettled,
	}

	// Block 0 (finalized): initial 20,000 XUSD
	// Block 1 (unfinalized): lease_settle (+10,000 stake credited, balance was 20k -> 30k effective)
	// Block 2 (unfinalized): send 5,000 XUSD (balance becomes 25,000)
	chain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "block_0",
				Type:    BlockReceive,
				Account: provider,
				Asset:   "XUSD",
				Balance: 20000,
			},
			{
				Hash:    "block_1",
				Type:    BlockLeaseSettle,
				Account: provider,
				Asset:   "XE",
				Amount:  500,
				Balance: 500,
				Source:  leaseHash,
			},
			{
				Hash:    "block_2",
				Type:    BlockSend,
				Account: provider,
				Asset:   "XUSD",
				Balance: 25000,
			},
		},
	}
	store.chains[provider] = chain

	// Only Block 0 is finalized
	_ = store.SetFinalHeight(provider, 1)

	spendable := ledger.SpendableBalances(provider)

	// Initial finalized was 20,000. Outflow from 30,000 to 25,000 is 5,000.
	// Spendable finalized balance: 20,000 - 5,000 = 15,000.
	if spendable["XUSD"] != 15000 {
		t.Fatalf("expected spendable XUSD=15000 after unfinalized outflow, got %d", spendable["XUSD"])
	}
}

func TestFinalizedFrontier(t *testing.T) {
	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{})

	account := "account_11111111111111111111111111111111"

	if frontier := ledger.FinalizedFrontier(account); frontier != "" {
		t.Fatalf("expected empty frontier for non-existent chain, got %s", frontier)
	}

	chain := &AccountChain{
		Blocks: []*Block{
			{Hash: "hash_1"},
			{Hash: "hash_2"},
		},
	}
	store.chains[account] = chain

	// Height 0
	if frontier := ledger.FinalizedFrontier(account); frontier != "" {
		t.Fatalf("expected empty frontier for height 0, got %s", frontier)
	}

	// Height 1
	_ = store.SetFinalHeight(account, 1)
	if frontier := ledger.FinalizedFrontier(account); frontier != "hash_1" {
		t.Fatalf("expected hash_1, got %s", frontier)
	}

	// Height 2
	_ = store.SetFinalHeight(account, 2)
	if frontier := ledger.FinalizedFrontier(account); frontier != "hash_2" {
		t.Fatalf("expected hash_2, got %s", frontier)
	}
}
