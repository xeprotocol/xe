package core

import (
	"strings"
	"testing"
	"time"
)

type mockSpendableStore struct {
	blocks   map[string]*Block
	chains   map[string]*AccountChain
	leases   map[string]*Lease
	pending  map[string]*PendingSend
	finalH   map[string]uint64
	statuses map[string]BlockStatus
}

func newMockSpendableStore() *mockSpendableStore {
	return &mockSpendableStore{
		blocks:   make(map[string]*Block),
		chains:   make(map[string]*AccountChain),
		leases:   make(map[string]*Lease),
		pending:  make(map[string]*PendingSend),
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
	return m.pending[sendHash], nil
}

func (m *mockSpendableStore) PutPendingSend(ps *PendingSend) error {
	m.pending[ps.SendHash] = ps
	return nil
}

func (m *mockSpendableStore) DeletePendingSend(sendHash string) error {
	delete(m.pending, sendHash)
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

func TestLeaseStakeCalculation(t *testing.T) {
	// Ensure default state
	ApplyGenesisLeaseTiming(nil)
	if LeaseStakeDivisor != DefaultLeaseStakeDivisor {
		t.Fatalf("expected LeaseStakeDivisor=%d, got %d", DefaultLeaseStakeDivisor, LeaseStakeDivisor)
	}
	if DefaultLeaseStakeDivisor != 10 {
		t.Fatalf("expected DefaultLeaseStakeDivisor=10, got %d", DefaultLeaseStakeDivisor)
	}

	// Cost 1,500,000 mXCU -> 150,000 stake (10% collateral, matching docs/api.md:932)
	if s := LeaseStake(1_500_000); s != 150_000 {
		t.Fatalf("expected stake 150000 for cost 1500000, got %d", s)
	}

	// Cost 259 mXCU (from issue #374 reproduction) -> 26 stake (ceilDiv(259, 10))
	if s := LeaseStake(259); s != 26 {
		t.Fatalf("expected stake 26 for cost 259, got %d", s)
	}

	// Edge cases
	if s := LeaseStake(0); s != 0 {
		t.Fatalf("expected stake 0 for cost 0, got %d", s)
	}
	if s := LeaseStake(1); s != 1 {
		t.Fatalf("expected stake 1 for cost 1, got %d", s)
	}
	if s := LeaseStake(10); s != 1 {
		t.Fatalf("expected stake 1 for cost 10, got %d", s)
	}
	if s := LeaseStake(11); s != 2 {
		t.Fatalf("expected stake 2 for cost 11, got %d", s)
	}

	// Divisor override and reset
	LeaseStakeDivisor = 0
	if s := LeaseStake(1000); s != 0 {
		t.Fatalf("expected stake 0 when LeaseStakeDivisor=0, got %d", s)
	}
	ApplyGenesisLeaseTiming(nil)
	if LeaseStakeDivisor != DefaultLeaseStakeDivisor {
		t.Fatalf("ApplyGenesisLeaseTiming did not restore LeaseStakeDivisor")
	}
}

func setupTestKeysAndTimekeepers(t *testing.T) (*KeyPair, *KeyPair, *KeyPair, []string, *TimekeeperConfig) {
	t.Helper()
	providerKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair provider: %v", err)
	}
	consumerKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair consumer: %v", err)
	}
	tkKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair tk: %v", err)
	}

	tkConfig := &TimekeeperConfig{
		Threshold: 1,
		Keys:      []string{tkKp.PubKeyHex()},
	}
	return providerKp, consumerKp, tkKp, []string{tkKp.PubKeyHex()}, tkConfig
}

func TestLeaseAccept_RequiresNonZeroStakeAndBalance(t *testing.T) {
	ApplyGenesisLeaseTiming(nil)
	providerKp, consumerKp, tkKp, _, tkConfig := setupTestKeysAndTimekeepers(t)

	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{
		TimekeeperConfigFn: func() *TimekeeperConfig { return tkConfig },
		TimekeeperErasFn: func() []TimekeeperEra {
			return []TimekeeperEra{{Since: 0, Config: tkConfig}}
		},
		CertificateLookupFn: func(hash string) *CertificateInfo {
			return &CertificateInfo{
				Provider:  providerKp.Address(),
				ExpiresAt: time.Now().UnixNano() + int64(time.Hour),
			}
		},
	})
	ledger.epochAtFn = func(ns int64) []EpochParams {
		return []EpochParams{{R: 2000, PayoutCap: 0, TWAP: 250}}
	}

	cost := uint64(1000)
	expectedStake := LeaseStake(cost) // 100
	certHash := "cert_1234567890abcdef"
	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"

	leaseBlock := &Block{
		Hash:            leaseHash,
		Type:            BlockLease,
		Account:         consumerKp.Address(),
		Destination:     providerKp.Address(),
		Amount:          cost,
		CertificateHash: certHash,
	}
	store.blocks[leaseHash] = leaseBlock
	store.leases[leaseHash] = &Lease{
		LeaseHash:       leaseHash,
		State:           LeaseCreated,
		Consumer:        consumerKp.Address(),
		Provider:        providerKp.Address(),
		Cost:            cost,
		CertificateHash: certHash,
	}

	att, err := SignAttestation(leaseHash, time.Now().UnixNano(), tkKp)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	// 1. Provider with 0 XCU balance attempting accept -> must fail insufficient balance
	store.chains[providerKp.Address()] = &AccountChain{
		Blocks: []*Block{
			{
				Hash:    "provider_open",
				Account: providerKp.Address(),
				Asset:   "XCU",
				Balance: 0,
			},
		},
	}
	acceptBlockZeroBal := &Block{
		Type:            BlockLeaseAccept,
		Account:         providerKp.Address(),
		Previous:        "provider_open",
		Balance:         0,
		Amount:          expectedStake,
		Asset:           "XCU",
		Source:          leaseHash,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    []TimekeeperAttestation{*att},
	}
	err = ledger.validateAndAddLeaseAccept(acceptBlockZeroBal, false)
	if err == nil || !strings.Contains(err.Error(), "insufficient XCU balance for stake") {
		t.Fatalf("expected insufficient XCU balance error, got: %v", err)
	}

	// 2. Provider submitting 0 stake when stake is required -> must fail mismatch
	store.chains[providerKp.Address()].Blocks[0].Balance = 500
	acceptBlockZeroStake := &Block{
		Type:            BlockLeaseAccept,
		Account:         providerKp.Address(),
		Previous:        "provider_open",
		Balance:         500,
		Amount:          0,
		Asset:           "XCU",
		Source:          leaseHash,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    []TimekeeperAttestation{*att},
	}
	err = ledger.validateAndAddLeaseAccept(acceptBlockZeroStake, false)
	if err == nil || !strings.Contains(err.Error(), "lease_accept stake mismatch") {
		t.Fatalf("expected stake mismatch error, got: %v", err)
	}

	// 3. When LeaseStakeDivisor = 0, live accept must reject zero stake
	LeaseStakeDivisor = 0
	acceptBlockDivZero := &Block{
		Type:            BlockLeaseAccept,
		Account:         providerKp.Address(),
		Previous:        "provider_open",
		Balance:         500,
		Amount:          0,
		Asset:           "XCU",
		Source:          leaseHash,
		CertificateHash: certHash,
		LockedR:         2000,
		Attestations:    []TimekeeperAttestation{*att},
	}
	err = ledger.validateAndAddLeaseAccept(acceptBlockDivZero, false)
	if err == nil || !strings.Contains(err.Error(), "provider stake cannot be zero") {
		t.Fatalf("expected provider stake cannot be zero error, got: %v", err)
	}
	ApplyGenesisLeaseTiming(nil)
}

func TestLeaseSettle_RejectsZeroStake(t *testing.T) {
	ApplyGenesisLeaseTiming(nil)
	providerKp, consumerKp, tkKp, _, tkConfig := setupTestKeysAndTimekeepers(t)

	store := newMockSpendableStore()
	ledger := NewLedger(store, LedgerConfig{
		TimekeeperConfigFn: func() *TimekeeperConfig { return tkConfig },
		TimekeeperErasFn: func() []TimekeeperEra {
			return []TimekeeperEra{{Since: 0, Config: tkConfig}}
		},
	})

	leaseHash := "2222222222222222222222222222222222222222222222222222222222222222"
	now := time.Now().UnixNano()
	expiry := now - int64(10*time.Second) // expired

	// Case 1: Lease with Stake = 0 on live path (skipSkew = false) -> MUST BE REJECTED
	store.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		State:     LeaseAccepted,
		Consumer:  consumerKp.Address(),
		Provider:  providerKp.Address(),
		Cost:      259,
		Stake:     0, // ZERO STAKE
		Duration:  60,
		StartTime: expiry - int64(60*time.Second),
		LockedR:   2000,
	}

	att, err := SignAttestation(leaseHash, now, tkKp)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	settleBlock := &Block{
		Type:         BlockLeaseSettle,
		Account:      providerKp.Address(),
		Previous:     "provider_open",
		Asset:        "XE",
		Source:       leaseHash,
		Amount:       518,
		Balance:      518,
		Attestations: []TimekeeperAttestation{*att},
	}

	err = ledger.validateAndAddLeaseSettle(settleBlock, false)
	if err == nil || !strings.Contains(err.Error(), "lease has zero stake collateral") {
		t.Fatalf("expected lease has zero stake collateral error, got: %v", err)
	}

	// On sync/replay (skipSkew = true), legacy zero-stake does not hard-fail this check
	errSync := ledger.validateAndAddLeaseSettle(settleBlock, true)
	// (it fails later at getPendingSendOverlay since mock store has no pending escrow, not zero stake)
	if errSync != nil && strings.Contains(errSync.Error(), "lease has zero stake collateral") {
		t.Fatalf("sync path should not fail on zero stake collateral check")
	}
}
