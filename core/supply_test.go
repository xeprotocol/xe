package core

import (
	"testing"
)

type mockSupplyStore struct {
	blocks   map[string]*Block
	chains   map[string]*AccountChain
	leases   map[string]*Lease
	finalH   map[string]uint64
	statuses map[string]BlockStatus
}

func newMockSupplyStore() *mockSupplyStore {
	return &mockSupplyStore{
		blocks:   make(map[string]*Block),
		chains:   make(map[string]*AccountChain),
		leases:   make(map[string]*Lease),
		finalH:   make(map[string]uint64),
		statuses: make(map[string]BlockStatus),
	}
}

func (m *mockSupplyStore) GetBlock(hash string) (*Block, error) {
	return m.blocks[hash], nil
}

func (m *mockSupplyStore) PutBlock(block *Block) error {
	m.blocks[block.Hash] = block
	return nil
}

func (m *mockSupplyStore) GetAccountChain(account string) (*AccountChain, error) {
	return m.chains[account], nil
}

func (m *mockSupplyStore) PutAccountChain(account string, chain *AccountChain) error {
	m.chains[account] = chain
	return nil
}

func (m *mockSupplyStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	return nil, nil
}

func (m *mockSupplyStore) PutPendingSend(ps *PendingSend) error {
	return nil
}

func (m *mockSupplyStore) DeletePendingSend(sendHash string) error {
	return nil
}

func (m *mockSupplyStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockSupplyStore) GetAllPending() ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockSupplyStore) PutFrontier(account string, blockHash string) error {
	return nil
}

func (m *mockSupplyStore) GetFrontier(account string) (string, error) {
	return "", nil
}

func (m *mockSupplyStore) CommitUndo(u *BlockUndo) error {
	return nil
}

func (m *mockSupplyStore) IsEmpty() (bool, error) {
	return len(m.blocks) == 0, nil
}

func (m *mockSupplyStore) Close() error {
	return nil
}

func (m *mockSupplyStore) CommitBlock(c *BlockCommit) error {
	return nil
}

func (m *mockSupplyStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}

func (m *mockSupplyStore) SetBlockStatus(hash string, status BlockStatus) error {
	m.statuses[hash] = status
	return nil
}

func (m *mockSupplyStore) GetBlockStatus(hash string) (BlockStatus, error) {
	return m.statuses[hash], nil
}

func (m *mockSupplyStore) SetFinalHeight(account string, height uint64) error {
	m.finalH[account] = height
	return nil
}

func (m *mockSupplyStore) GetFinalHeight(account string) (uint64, error) {
	return m.finalH[account], nil
}

func (m *mockSupplyStore) DeleteVotesForConflict(account, previous string) error {
	return nil
}

func (m *mockSupplyStore) PutLease(lease *Lease) error {
	m.leases[lease.LeaseHash] = lease
	return nil
}

func (m *mockSupplyStore) GetLease(leaseHash string) (*Lease, error) {
	return m.leases[leaseHash], nil
}

func (m *mockSupplyStore) GetLeasesByProvider(provider string) ([]*Lease, error) {
	var out []*Lease
	for _, l := range m.leases {
		if l.Provider == provider {
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *mockSupplyStore) GetLeasesByState(state LeaseState) ([]*Lease, error) {
	return nil, nil
}

func (m *mockSupplyStore) GetAllLeases() ([]*Lease, error) {
	var out []*Lease
	for _, l := range m.leases {
		out = append(out, l)
	}
	return out, nil
}

func (m *mockSupplyStore) AllFrontiers() map[string]string {
	out := make(map[string]string)
	for acc, chain := range m.chains {
		if len(chain.Blocks) > 0 {
			out[acc] = chain.Blocks[len(chain.Blocks)-1].Hash
		}
	}
	return out
}

func TestLease_TotalCost(t *testing.T) {
	lease := &Lease{
		Cost: 1000,
		Renewals: []LeaseSegment{
			{Cost: 500},
			{Cost: 250},
		},
	}
	if total := lease.TotalCost(); total != 1750 {
		t.Fatalf("expected TotalCost=1750, got %d", total)
	}
}

func TestTermsFromChain_IncludesLeaseRenew(t *testing.T) {
	leaseHash := "lease_hash_11111111111111111111111111111111"
	blocks := []*Block{
		{
			Hash:    leaseHash,
			Type:    BlockLease,
			Asset:   "XUSD",
			Amount:  1000,
			Balance: 9000,
		},
		{
			Hash:    "renew_hash_22222222222222222222222222222222",
			Type:    BlockLeaseRenew,
			Asset:   "XUSD",
			Source:  leaseHash,
			Amount:  500,
			Balance: 8500,
		},
	}

	terms := termsFromChain(blocks)
	if cost, ok := terms.leaseCost[leaseHash]; !ok || cost != 1500 {
		t.Fatalf("expected leaseCost[%s]=1500, got ok=%v, cost=%d", leaseHash, ok, cost)
	}
}

func TestSupplyAuditor_LeaseRenewConservation_FullyBalanced(t *testing.T) {
	store := newMockSupplyStore()
	ledger := NewLedger(store, LedgerConfig{})

	consumer := "consumer_11111111111111111111111111111111"
	provider := "provider_22222222222222222222222222222222"
	leaseHash := "lease_33333333333333333333333333333333"

	// Lease: base cost 1000, renewal cost 500, stake 100
	lease := &Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer,
		Provider:  provider,
		Cost:      1000,
		Stake:     100,
		State:     LeaseSettled,
		Settled:   true,
		Renewals: []LeaseSegment{
			{Cost: 500},
		},
	}
	store.leases[leaseHash] = lease

	// Consumer chain:
	// 1. Mint 2000 XUSD (balance: 2000)
	// 2. BlockLease: cost 1000 (balance: 1000)
	// 3. BlockLeaseRenew: cost 500 (balance: 500)
	consumerChain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "consumer_mint",
				Type:    BlockMint,
				Account: consumer,
				Asset:   "XUSD",
				Amount:  2000,
				Balance: 2000,
			},
			{
				Hash:    leaseHash,
				Type:    BlockLease,
				Account: consumer,
				Asset:   "XUSD",
				Amount:  1000,
				Balance: 1000,
			},
			{
				Hash:    "consumer_renew",
				Type:    BlockLeaseRenew,
				Account: consumer,
				Asset:   "XUSD",
				Source:  leaseHash,
				Amount:  500,
				Balance: 500,
			},
		},
	}
	store.chains[consumer] = consumerChain
	ledger.setAssetBalance(consumer, "XUSD", 500)

	// Provider chain:
	// 1. Mint 100 XUSD (balance: 100)
	// 2. BlockLeaseAccept: stake 100 (balance: 0)
	// 3. BlockLeaseSettle: emission 50 XE, returns 100 XUSD stake
	providerChain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "provider_mint",
				Type:    BlockMint,
				Account: provider,
				Asset:   "XUSD",
				Amount:  100,
				Balance: 100,
			},
			{
				Hash:    "provider_accept",
				Type:    BlockLeaseAccept,
				Account: provider,
				Asset:   "XUSD",
				Source:  leaseHash,
				Amount:  100,
				Balance: 0,
			},
			{
				Hash:    "provider_settle",
				Type:    BlockLeaseSettle,
				Account: provider,
				Asset:   "XE",
				Source:  leaseHash,
				Amount:  50,
				Balance: 50,
			},
		},
	}
	store.chains[provider] = providerChain
	ledger.setAssetBalance(provider, "XE", 50)
	ledger.setAssetBalance(provider, "XUSD", 100)

	auditor := NewSupplyAuditor(ledger)
	rep := auditor.Report()

	xusdSupply := rep.Assets["XUSD"]
	if xusdSupply == nil {
		t.Fatalf("expected XUSD supply report")
	}

	// Total Minted = 2000 + 100 = 2100 XUSD
	// Balances = 500 (consumer) + 100 (provider) = 600 XUSD
	// EscrowBurned = 1000 (base) + 500 (renewal) = 1500 XUSD
	// Total Accounted = 600 + 1500 = 2100 XUSD
	if xusdSupply.EscrowBurned != 1500 {
		t.Fatalf("expected EscrowBurned=1500, got %d", xusdSupply.EscrowBurned)
	}
	if xusdSupply.Discrepancy != 0 {
		t.Fatalf("expected XUSD Discrepancy=0, got %d", xusdSupply.Discrepancy)
	}
	if !xusdSupply.Conserved {
		t.Fatalf("expected XUSD Conserved=true, got false (accounted=%d, created=%d)", xusdSupply.Accounted, xusdSupply.Created)
	}
}

func TestSupplyAuditor_LeaseExpired_WithRenewals(t *testing.T) {
	store := newMockSupplyStore()
	ledger := NewLedger(store, LedgerConfig{})

	consumer := "consumer_11111111111111111111111111111111"
	leaseHash := "lease_33333333333333333333333333333333"

	lease := &Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer,
		Cost:      2000,
		State:     LeaseExpired,
		Renewals: []LeaseSegment{
			{Cost: 800},
			{Cost: 400},
		},
	}
	store.leases[leaseHash] = lease

	consumerChain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "consumer_mint",
				Type:    BlockMint,
				Account: consumer,
				Asset:   "XUSD",
				Amount:  5000,
				Balance: 5000,
			},
			{
				Hash:    leaseHash,
				Type:    BlockLease,
				Account: consumer,
				Asset:   "XUSD",
				Amount:  2000,
				Balance: 3000,
			},
			{
				Hash:    "renew_1",
				Type:    BlockLeaseRenew,
				Account: consumer,
				Asset:   "XUSD",
				Source:  leaseHash,
				Amount:  800,
				Balance: 2200,
			},
			{
				Hash:    "renew_2",
				Type:    BlockLeaseRenew,
				Account: consumer,
				Asset:   "XUSD",
				Source:  leaseHash,
				Amount:  400,
				Balance: 1800,
			},
		},
	}
	store.chains[consumer] = consumerChain
	ledger.setAssetBalance(consumer, "XUSD", 1800)

	auditor := NewSupplyAuditor(ledger)
	rep := auditor.Report()

	xusdSupply := rep.Assets["XUSD"]
	if xusdSupply == nil {
		t.Fatalf("expected XUSD supply report")
	}

	// Minted = 5000
	// Balances = 1800
	// EscrowBurned = 2000 + 800 + 400 = 3200
	// Accounted = 1800 + 3200 = 5000
	if xusdSupply.EscrowBurned != 3200 {
		t.Fatalf("expected EscrowBurned=3200, got %d", xusdSupply.EscrowBurned)
	}
	if !xusdSupply.Conserved {
		t.Fatalf("expected XUSD Conserved=true, got false (accounted=%d, created=%d)", xusdSupply.Accounted, xusdSupply.Created)
	}
}
