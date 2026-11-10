package core

import (
	"math"
	"strings"
	"testing"
)

type testMockStore struct {
	blocks    map[string]*Block
	chains    map[string]*AccountChain
	pending   map[string]*PendingSend
	frontiers map[string]string
	leases    map[string]*Lease
}

func newTestMockStore() *testMockStore {
	return &testMockStore{
		blocks:    make(map[string]*Block),
		chains:    make(map[string]*AccountChain),
		pending:   make(map[string]*PendingSend),
		frontiers: make(map[string]string),
		leases:    make(map[string]*Lease),
	}
}

func (m *testMockStore) GetBlock(hash string) (*Block, error) {
	return m.blocks[hash], nil
}

func (m *testMockStore) PutBlock(b *Block) error {
	m.blocks[b.Hash] = b
	return nil
}

func (m *testMockStore) GetAccountChain(acc string) (*AccountChain, error) {
	return m.chains[acc], nil
}

func (m *testMockStore) PutAccountChain(acc string, c *AccountChain) error {
	m.chains[acc] = c
	return nil
}

func (m *testMockStore) GetPendingSend(hash string) (*PendingSend, error) {
	return m.pending[hash], nil
}

func (m *testMockStore) PutPendingSend(ps *PendingSend) error {
	m.pending[ps.SendHash] = ps
	return nil
}

func (m *testMockStore) DeletePendingSend(hash string) error {
	delete(m.pending, hash)
	return nil
}

func (m *testMockStore) GetPendingByDest(acc string) ([]*PendingSend, error) {
	return nil, nil
}

func (m *testMockStore) GetAllPending() ([]*PendingSend, error) {
	return nil, nil
}

func (m *testMockStore) PutFrontier(acc, h string) error {
	m.frontiers[acc] = h
	return nil
}

func (m *testMockStore) GetFrontier(acc string) (string, error) {
	return m.frontiers[acc], nil
}

func (m *testMockStore) CommitUndo(u *BlockUndo) error {
	return nil
}

func (m *testMockStore) IsEmpty() (bool, error) {
	return len(m.blocks) == 0, nil
}

func (m *testMockStore) Close() error {
	return nil
}

func (m *testMockStore) GetLease(hash string) (*Lease, bool, error) {
	l, ok := m.leases[hash]
	return l, ok, nil
}

func (m *testMockStore) CommitBlock(c *BlockCommit) error {
	return nil
}

func (m *testMockStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}

func TestValidateAndAddLeaseCancel_Overflow(t *testing.T) {
	ms := newTestMockStore()
	ledger := NewLedger(ms, LedgerConfig{})

	account := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	frontierHash := "2222222222222222222222222222222222222222222222222222222222222222"

	oldBalance := uint64(math.MaxUint64 - 50)
	ledger.addAssetBalance(account, "XUSD", oldBalance)
	// Existing frontier block with nearly max uint64 XUSD balance
	frontierBlock := &Block{
		Hash:      frontierHash,
		Type:      BlockSend,
		Account:   account,
		Asset:     "XUSD",
		Balance:   oldBalance,
		Timestamp: 100,
	}
	ms.blocks[frontierHash] = frontierBlock

	chain := &AccountChain{
		Blocks: []*Block{frontierBlock},
	}
	ms.chains[account] = chain
	ms.frontiers[account] = frontierHash

	// Source lease block whose amount will overflow old balance when cancelled
	leaseBlock := &Block{
		Hash:      leaseHash,
		Type:      BlockLease,
		Account:   account,
		Amount:    100,
		Asset:     "XUSD",
		Timestamp: 50,
	}
	ms.blocks[leaseHash] = leaseBlock

	ms.pending[leaseHash] = &PendingSend{
		SendHash:    leaseHash,
		Source:      leaseHash,
		Destination: account,
		Amount:      100,
		Asset:       "XUSD",
	}

	ms.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		State:     LeaseCreated,
		Consumer:  account,
	}

	cancelBlock := &Block{
		Hash:      "3333333333333333333333333333333333333333333333333333333333333333",
		Type:      BlockLeaseCancel,
		Account:   account,
		Previous:  frontierHash,
		Source:    leaseHash,
		Asset:     "XUSD",
		Balance:   oldBalance + 100, // wraps around
		Timestamp: 200,
	}

	err := ledger.validateAndAddLeaseCancel(cancelBlock)
	if err == nil {
		t.Fatalf("expected overflow error, got nil")
	}
	if !strings.Contains(err.Error(), "lease_cancel would overflow uint64 balance") {
		t.Fatalf("expected overflow error message, got: %v", err)
	}
}

func TestValidateAndAddLeaseCancel_Valid(t *testing.T) {
	ms := newTestMockStore()
	ledger := NewLedger(ms, LedgerConfig{})

	account := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	frontierHash := "2222222222222222222222222222222222222222222222222222222222222222"

	oldBalance := uint64(500)
	ledger.addAssetBalance(account, "XUSD", oldBalance)

	frontierBlock := &Block{
		Hash:      frontierHash,
		Type:      BlockSend,
		Account:   account,
		Asset:     "XUSD",
		Balance:   oldBalance,
		Timestamp: 100,
	}
	ms.blocks[frontierHash] = frontierBlock

	chain := &AccountChain{
		Blocks: []*Block{frontierBlock},
	}
	ms.chains[account] = chain
	ms.frontiers[account] = frontierHash

	leaseBlock := &Block{
		Hash:      leaseHash,
		Type:      BlockLease,
		Account:   account,
		Amount:    100,
		Asset:     "XUSD",
		Timestamp: 50,
	}
	ms.blocks[leaseHash] = leaseBlock

	ms.pending[leaseHash] = &PendingSend{
		SendHash:    leaseHash,
		Source:      leaseHash,
		Destination: account,
		Amount:      100,
		Asset:       "XUSD",
	}

	ms.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		State:     LeaseCreated,
		Consumer:  account,
	}

	cancelBlock := &Block{
		Hash:      "3333333333333333333333333333333333333333333333333333333333333333",
		Type:      BlockLeaseCancel,
		Account:   account,
		Previous:  frontierHash,
		Source:    leaseHash,
		Asset:     "XUSD",
		Balance:   oldBalance + 100,
		Timestamp: 200,
	}

	err := ledger.validateAndAddLeaseCancel(cancelBlock)
	if err != nil {
		t.Fatalf("expected valid cancellation to succeed, got: %v", err)
	}
}
