package core

import (
	"strings"
	"sync"
	"testing"
)

type mockCausalStore struct {
	mu        sync.Mutex
	blocks    map[string]*Block
	chains    map[string]*AccountChain
	pending   map[string]*PendingSend
	frontiers map[string]string
	leases    map[string]*Lease
	keys      map[string]string
	staged    map[string]*Block
	conflicts map[string]*Conflict
}

func newMockCausalStore() *mockCausalStore {
	return &mockCausalStore{
		blocks:    make(map[string]*Block),
		chains:    make(map[string]*AccountChain),
		pending:   make(map[string]*PendingSend),
		frontiers: make(map[string]string),
		leases:    make(map[string]*Lease),
		keys:      make(map[string]string),
		staged:    make(map[string]*Block),
		conflicts: make(map[string]*Conflict),
	}
}

func (m *mockCausalStore) GetBlock(hash string) (*Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocks[hash], nil
}

func (m *mockCausalStore) PutBlock(block *Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[block.Hash] = block
	return nil
}

func (m *mockCausalStore) GetAccountChain(account string) (*AccountChain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chains[account], nil
}

func (m *mockCausalStore) PutAccountChain(account string, chain *AccountChain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chains[account] = chain
	return nil
}

func (m *mockCausalStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending[sendHash], nil
}

func (m *mockCausalStore) PutPendingSend(ps *PendingSend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[ps.SendHash] = ps
	return nil
}

func (m *mockCausalStore) DeletePendingSend(sendHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, sendHash)
	return nil
}

func (m *mockCausalStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*PendingSend
	for _, p := range m.pending {
		if p.Destination == account {
			res = append(res, p)
		}
	}
	return res, nil
}

func (m *mockCausalStore) GetAllPending() ([]*PendingSend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*PendingSend
	for _, p := range m.pending {
		res = append(res, p)
	}
	return res, nil
}

func (m *mockCausalStore) PutFrontier(account string, blockHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frontiers[account] = blockHash
	return nil
}

func (m *mockCausalStore) GetFrontier(account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.frontiers[account], nil
}

func (m *mockCausalStore) CommitUndo(u *BlockUndo) error {
	return nil
}

func (m *mockCausalStore) IsEmpty() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.blocks) == 0, nil
}

func (m *mockCausalStore) Close() error {
	return nil
}

func (m *mockCausalStore) CommitBlock(c *BlockCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Block != nil {
		m.blocks[c.Block.Hash] = c.Block
	}
	if c.Chain != nil {
		m.chains[c.Account] = c.Chain
	}
	if c.FrontierHash != "" {
		m.frontiers[c.Account] = c.FrontierHash
	}
	if c.AddPending != nil {
		m.pending[c.AddPending.SendHash] = c.AddPending
	}
	if c.DeletePendingID != "" {
		delete(m.pending, c.DeletePendingID)
	}
	if c.PutLease != nil {
		m.leases[c.PutLease.LeaseHash] = c.PutLease
	}
	if c.PutAccountKey != "" {
		m.keys[c.Account] = c.PutAccountKey
	}
	return nil
}

func (m *mockCausalStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return m.CommitBlock(commit)
}

func (m *mockCausalStore) PutLease(lease *Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases[lease.LeaseHash] = lease
	return nil
}

func (m *mockCausalStore) GetLease(leaseHash string) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leases[leaseHash], nil
}

func (m *mockCausalStore) GetLeasesByProvider(provider string) ([]*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*Lease
	for _, l := range m.leases {
		if l.Provider == provider {
			res = append(res, l)
		}
	}
	return res, nil
}

func (m *mockCausalStore) GetLeasesByState(state LeaseState) ([]*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*Lease
	for _, l := range m.leases {
		if l.State == state {
			res = append(res, l)
		}
	}
	return res, nil
}

func (m *mockCausalStore) GetAllLeases() ([]*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*Lease
	for _, l := range m.leases {
		res = append(res, l)
	}
	return res, nil
}

func (m *mockCausalStore) PutAccountKey(account, pubKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[account] = pubKey
	return nil
}

func (m *mockCausalStore) GetAccountKey(account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[account], nil
}

func (m *mockCausalStore) DeleteAccountKey(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, account)
	return nil
}

func (m *mockCausalStore) AllAccountKeys() (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make(map[string]string)
	for k, v := range m.keys {
		res[k] = v
	}
	return res, nil
}

func (m *mockCausalStore) SaveConflict(c *Conflict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conflicts[c.AccountAddress+":"+c.PreviousHash] = c
	return nil
}

func (m *mockCausalStore) GetConflict(account, previousHash string) (*Conflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conflicts[account+":"+previousHash], nil
}

func (m *mockCausalStore) DeleteConflict(account, previousHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conflicts, account+":"+previousHash)
	return nil
}

func (m *mockCausalStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*Conflict
	for _, c := range m.conflicts {
		if c.AccountAddress == account {
			res = append(res, c)
		}
	}
	return res, nil
}

func (m *mockCausalStore) GetAllConflicts() ([]*Conflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*Conflict
	for _, c := range m.conflicts {
		res = append(res, c)
	}
	return res, nil
}

func (m *mockCausalStore) SaveStagedBlock(b *Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged[b.Hash] = b
	return nil
}

func (m *mockCausalStore) GetStagedBlock(hash string) (*Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.staged[hash], nil
}

func (m *mockCausalStore) DeleteStagedBlock(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.staged, hash)
	return nil
}

func newTestLedgerForCausal(t *testing.T) (*Ledger, *mockCausalStore) {
	s := newMockCausalStore()
	l := NewLedger(s, LedgerConfig{})
	return l, s
}

func signTestBlock(t *testing.T, b *Block, kp *KeyPair) *Block {
	t.Helper()
	if err := SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	return b
}

func TestCausalTimestamp_Receive(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	senderKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	senderAddr := MustDeriveAddress(senderKp.PubKeyHex())

	recipKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recipAddr := MustDeriveAddress(recipKp.PubKeyHex())

	_ = s.PutAccountKey(senderAddr, senderKp.PubKeyHex())
	_ = s.PutAccountKey(recipAddr, recipKp.PubKeyHex())

	sendTs := int64(2000)
	sendBlock := &Block{
		Type:        BlockSend,
		Account:     senderAddr,
		Destination: recipAddr,
		Amount:      50,
		Balance:     50,
		Asset:       "XE",
		Timestamp:   sendTs,
		Previous:    "0",
	}
	signTestBlock(t, sendBlock, senderKp)
	if err := s.PutBlock(sendBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPendingSend(&PendingSend{
		SendHash:    sendBlock.Hash,
		Source:      senderAddr,
		Destination: recipAddr,
		Amount:      50,
		Asset:       "XE",
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Live rejection: receive timestamp < send timestamp
	recvBad := &Block{
		Type:      BlockReceive,
		Account:   recipAddr,
		Source:    sendBlock.Hash,
		Amount:    50,
		Balance:   50,
		Asset:     "XE",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, recvBad, recipKp)
	err = l.validateAndAddReceive(recvBad)
	if err == nil {
		t.Fatal("expected live validateAndAddReceive to fail when timestamp < send timestamp")
	}
	if !strings.Contains(err.Error(), "receive timestamp 1500 is before source send timestamp 2000") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. Staged rejection: staged receive timestamp < send timestamp
	stagedBad := &Block{
		Type:      BlockReceive,
		Account:   recipAddr,
		Source:    sendBlock.Hash,
		Amount:    50,
		Balance:   50,
		Asset:     "XE",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, recipKp)
	err = l.ValidateStagedBlock(stagedBad, 0)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < send timestamp")
	}
	if !strings.Contains(err.Error(), "staged receive: timestamp 1500 is before source send timestamp 2000") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 3. Staged acceptance: staged receive timestamp >= send timestamp
	stagedGood := &Block{
		Type:      BlockReceive,
		Account:   recipAddr,
		Source:    sendBlock.Hash,
		Amount:    50,
		Balance:   50,
		Asset:     "XE",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, recipKp)
	if err := l.ValidateStagedBlock(stagedGood, 0); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}
}

func TestCausalTimestamp_LeaseAccept(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	consumerKp, _ := GenerateKeyPair()
	consumerAddr := MustDeriveAddress(consumerKp.PubKeyHex())

	providerKp, _ := GenerateKeyPair()
	providerAddr := MustDeriveAddress(providerKp.PubKeyHex())

	_ = s.PutAccountKey(consumerAddr, consumerKp.PubKeyHex())
	_ = s.PutAccountKey(providerAddr, providerKp.PubKeyHex())

	leaseTs := int64(2000)
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Balance:     900,
		Asset:       "XCU",
		Timestamp:   leaseTs,
		Previous:    "0",
	}
	signTestBlock(t, leaseBlock, consumerKp)
	if err := s.PutBlock(leaseBlock); err != nil {
		t.Fatal(err)
	}

	// 1. Live rejection: lease_accept timestamp < lease timestamp
	acceptBad := &Block{
		Type:      BlockLeaseAccept,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    LeaseStake(100),
		Asset:     "XCU",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, acceptBad, providerKp)
	err := l.validateAndAddLeaseAccept(acceptBad, true)
	if err == nil {
		t.Fatal("expected live validateAndAddLeaseAccept to fail when timestamp < lease timestamp")
	}
	if !strings.Contains(err.Error(), "lease_accept timestamp 1500 is before source lease timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Staged rejection: staged lease_accept timestamp < lease timestamp
	stagedBad := &Block{
		Type:      BlockLeaseAccept,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    LeaseStake(100),
		Balance:   1000 - LeaseStake(100),
		Asset:     "XCU",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, providerKp)
	err = l.ValidateStagedBlock(stagedBad, 1000)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < lease timestamp")
	}
	if !strings.Contains(err.Error(), "staged lease_accept: timestamp 1500 is before source lease timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Staged acceptance: staged lease_accept timestamp >= lease timestamp
	stagedGood := &Block{
		Type:      BlockLeaseAccept,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    LeaseStake(100),
		Balance:   1000 - LeaseStake(100),
		Asset:     "XCU",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, providerKp)
	if err := l.ValidateStagedBlock(stagedGood, 1000); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}
}

func TestCausalTimestamp_LeaseCancel(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	consumerKp, _ := GenerateKeyPair()
	consumerAddr := MustDeriveAddress(consumerKp.PubKeyHex())

	providerKp, _ := GenerateKeyPair()
	providerAddr := MustDeriveAddress(providerKp.PubKeyHex())

	_ = s.PutAccountKey(consumerAddr, consumerKp.PubKeyHex())
	_ = s.PutAccountKey(providerAddr, providerKp.PubKeyHex())

	leaseTs := int64(2000)
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Balance:     900,
		Asset:       "XCU",
		Timestamp:   leaseTs,
		Previous:    "0",
	}
	signTestBlock(t, leaseBlock, consumerKp)
	if err := s.PutBlock(leaseBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPendingSend(&PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XCU",
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Live rejection: lease_cancel timestamp < lease timestamp
	cancelBad := &Block{
		Type:      BlockLeaseCancel,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Asset:     "XCU",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, cancelBad, consumerKp)
	err := l.validateAndAddLeaseCancel(cancelBad)
	if err == nil {
		t.Fatal("expected live validateAndAddLeaseCancel to fail when timestamp < lease timestamp")
	}
	if !strings.Contains(err.Error(), "lease_cancel timestamp 1500 is before source lease timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Staged rejection: staged lease_cancel timestamp < lease timestamp
	stagedBad := &Block{
		Type:      BlockLeaseCancel,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Balance:   100,
		Asset:     "XCU",
		Timestamp: 1500, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, consumerKp)
	err = l.ValidateStagedBlock(stagedBad, 0)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < lease timestamp")
	}
	if !strings.Contains(err.Error(), "staged lease_cancel: timestamp 1500 is before source lease timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Staged acceptance: staged lease_cancel timestamp >= lease timestamp
	stagedGood := &Block{
		Type:      BlockLeaseCancel,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Balance:   100,
		Asset:     "XCU",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, consumerKp)
	if err := l.ValidateStagedBlock(stagedGood, 0); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}
}

func TestCausalTimestamp_LeaseRenew(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	consumerKp, _ := GenerateKeyPair()
	consumerAddr := MustDeriveAddress(consumerKp.PubKeyHex())

	providerKp, _ := GenerateKeyPair()
	providerAddr := MustDeriveAddress(providerKp.PubKeyHex())

	_ = s.PutAccountKey(consumerAddr, consumerKp.PubKeyHex())
	_ = s.PutAccountKey(providerAddr, providerKp.PubKeyHex())

	leaseTs := int64(1800)
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XCU",
		Timestamp:   leaseTs,
		Previous:    "0",
	}
	signTestBlock(t, leaseBlock, consumerKp)
	if err := s.PutBlock(leaseBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPendingSend(&PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XCU",
	}); err != nil {
		t.Fatal(err)
	}

	lease := &Lease{
		LeaseHash: leaseBlock.Hash,
		State:     LeaseAccepted,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		StartTime: 2000,
		Duration:  300,
		Cost:      100,
	}
	if err := s.PutLease(lease); err != nil {
		t.Fatal(err)
	}

	// Predecessor timestamp is max(lease.StartTime=2000, leaseBlock.Timestamp=1800) = 2000

	// 1. Live rejection: lease_renew timestamp < predecessor timestamp
	renewBad := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Asset:     "XCU",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, renewBad, consumerKp)
	err := l.validateAndAddLeaseRenew(renewBad, true)
	if err == nil {
		t.Fatal("expected live validateAndAddLeaseRenew to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "lease_renew timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Staged rejection: staged lease_renew timestamp < predecessor timestamp
	stagedBad := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Balance:   450,
		Asset:     "XCU",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, consumerKp)
	err = l.ValidateStagedBlock(stagedBad, 500)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "staged lease_renew: timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Staged acceptance: staged lease_renew timestamp >= predecessor timestamp
	stagedGood := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Balance:   450,
		Asset:     "XCU",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, consumerKp)
	if err := l.ValidateStagedBlock(stagedGood, 500); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}

	// 4. Renewal chain: existing renewal at StartTime=3000, RenewBlock.Timestamp=3200
	renew1Block := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Asset:     "XCU",
		Timestamp: 3200,
		Previous:  "0",
	}
	signTestBlock(t, renew1Block, consumerKp)
	_ = s.PutBlock(renew1Block)
	lease.Renewals = []LeaseSegment{
		{
			RenewHash: renew1Block.Hash,
			StartTime: 3000,
			Duration:  100,
			Cost:      50,
		},
	}
	_ = s.PutLease(lease)

	// Now predecessor timestamp is 3200
	renewBad2 := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Asset:     "XCU",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, renewBad2, consumerKp)
	err = l.validateAndAddLeaseRenew(renewBad2, true)
	if err == nil || !strings.Contains(err.Error(), "lease_renew timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for renewBad2, got: %v", err)
	}

	stagedBad2 := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Balance:   450,
		Asset:     "XCU",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, stagedBad2, consumerKp)
	err = l.ValidateStagedBlock(stagedBad2, 500)
	if err == nil || !strings.Contains(err.Error(), "staged lease_renew: timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for stagedBad2, got: %v", err)
	}
}

func TestCausalTimestamp_LeaseSettle(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	consumerKp, _ := GenerateKeyPair()
	consumerAddr := MustDeriveAddress(consumerKp.PubKeyHex())

	providerKp, _ := GenerateKeyPair()
	providerAddr := MustDeriveAddress(providerKp.PubKeyHex())

	_ = s.PutAccountKey(consumerAddr, consumerKp.PubKeyHex())
	_ = s.PutAccountKey(providerAddr, providerKp.PubKeyHex())

	leaseTs := int64(1800)
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XE",
		Timestamp:   leaseTs,
		Previous:    "0",
	}
	signTestBlock(t, leaseBlock, consumerKp)
	if err := s.PutBlock(leaseBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPendingSend(&PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XE",
	}); err != nil {
		t.Fatal(err)
	}

	lease := &Lease{
		LeaseHash: leaseBlock.Hash,
		State:     LeaseAccepted,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		StartTime: 2000,
		Duration:  300,
		Cost:      100,
	}
	if err := s.PutLease(lease); err != nil {
		t.Fatal(err)
	}

	// 1. Live rejection: lease_settle timestamp < predecessor timestamp
	settleBad := &Block{
		Type:      BlockLeaseSettle,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    100,
		Asset:     "XE",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, settleBad, providerKp)
	err := l.validateAndAddLeaseSettle(settleBad, true)
	if err == nil {
		t.Fatal("expected live validateAndAddLeaseSettle to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "lease_settle timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Staged rejection: staged lease_settle timestamp < predecessor timestamp
	stagedBad := &Block{
		Type:      BlockLeaseSettle,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    100,
		Balance:   100,
		Asset:     "XE",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, providerKp)
	err = l.ValidateStagedBlock(stagedBad, 0)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "staged lease_settle: timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Staged acceptance: staged lease_settle timestamp >= predecessor timestamp
	stagedGood := &Block{
		Type:      BlockLeaseSettle,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    100,
		Balance:   100,
		Asset:     "XE",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, providerKp)
	if err := l.ValidateStagedBlock(stagedGood, 0); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}

	// 4. Renewal chain: existing renewal at StartTime=3000, RenewBlock.Timestamp=3200
	renew1Block := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Asset:     "XE",
		Timestamp: 3200,
		Previous:  "0",
	}
	signTestBlock(t, renew1Block, consumerKp)
	_ = s.PutBlock(renew1Block)
	lease.Renewals = []LeaseSegment{
		{
			RenewHash: renew1Block.Hash,
			StartTime: 3000,
			Duration:  100,
			Cost:      50,
		},
	}
	_ = s.PutLease(lease)

	// Now predecessor timestamp is 3200
	settleBad2 := &Block{
		Type:      BlockLeaseSettle,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    100,
		Asset:     "XE",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, settleBad2, providerKp)
	err = l.validateAndAddLeaseSettle(settleBad2, true)
	if err == nil || !strings.Contains(err.Error(), "lease_settle timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for settleBad2, got: %v", err)
	}

	stagedBad2 := &Block{
		Type:      BlockLeaseSettle,
		Account:   providerAddr,
		Source:    leaseBlock.Hash,
		Amount:    100,
		Balance:   100,
		Asset:     "XE",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, stagedBad2, providerKp)
	err = l.ValidateStagedBlock(stagedBad2, 0)
	if err == nil || !strings.Contains(err.Error(), "staged lease_settle: timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for stagedBad2, got: %v", err)
	}
}

func TestCausalTimestamp_LeaseForceSettle(t *testing.T) {
	l, s := newTestLedgerForCausal(t)

	consumerKp, _ := GenerateKeyPair()
	consumerAddr := MustDeriveAddress(consumerKp.PubKeyHex())

	providerKp, _ := GenerateKeyPair()
	providerAddr := MustDeriveAddress(providerKp.PubKeyHex())

	_ = s.PutAccountKey(consumerAddr, consumerKp.PubKeyHex())
	_ = s.PutAccountKey(providerAddr, providerKp.PubKeyHex())

	leaseTs := int64(1800)
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XCU",
		Timestamp:   leaseTs,
		Previous:    "0",
	}
	signTestBlock(t, leaseBlock, consumerKp)
	if err := s.PutBlock(leaseBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPendingSend(&PendingSend{
		SendHash:    leaseBlock.Hash,
		Source:      consumerAddr,
		Destination: providerAddr,
		Amount:      100,
		Asset:       "XCU",
	}); err != nil {
		t.Fatal(err)
	}

	lease := &Lease{
		LeaseHash: leaseBlock.Hash,
		State:     LeaseAccepted,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		StartTime: 2000,
		Duration:  300,
		Cost:      100,
	}
	if err := s.PutLease(lease); err != nil {
		t.Fatal(err)
	}

	// 1. Live rejection: lease_force_settle timestamp < predecessor timestamp
	forceBad := &Block{
		Type:      BlockLeaseForceSettle,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Asset:     "XCU",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, forceBad, consumerKp)
	err := l.validateAndAddLeaseForceSettle(forceBad, true)
	if err == nil {
		t.Fatal("expected live validateAndAddLeaseForceSettle to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "lease_force_settle timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. Staged rejection: staged lease_force_settle timestamp < predecessor timestamp
	stagedBad := &Block{
		Type:      BlockLeaseForceSettle,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Balance:   100,
		Asset:     "XCU",
		Timestamp: 1900, // < 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedBad, consumerKp)
	err = l.ValidateStagedBlock(stagedBad, 0)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to fail when timestamp < predecessor timestamp")
	}
	if !strings.Contains(err.Error(), "staged lease_force_settle: timestamp 1900 is before predecessor timestamp 2000") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Staged acceptance: staged lease_force_settle timestamp >= predecessor timestamp
	stagedGood := &Block{
		Type:      BlockLeaseForceSettle,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Balance:   100,
		Asset:     "XCU",
		Timestamp: 2500, // >= 2000
		Previous:  "0",
	}
	signTestBlock(t, stagedGood, consumerKp)
	if err := l.ValidateStagedBlock(stagedGood, 0); err != nil {
		t.Fatalf("expected ValidateStagedBlock to pass: %v", err)
	}

	// 4. Renewal chain: existing renewal at StartTime=3000, RenewBlock.Timestamp=3200
	renew1Block := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Amount:    50,
		Asset:     "XCU",
		Timestamp: 3200,
		Previous:  "0",
	}
	signTestBlock(t, renew1Block, consumerKp)
	_ = s.PutBlock(renew1Block)
	lease.Renewals = []LeaseSegment{
		{
			RenewHash: renew1Block.Hash,
			StartTime: 3000,
			Duration:  100,
			Cost:      50,
		},
	}
	_ = s.PutLease(lease)

	// Now predecessor timestamp is 3200
	forceBad2 := &Block{
		Type:      BlockLeaseForceSettle,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Asset:     "XCU",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, forceBad2, consumerKp)
	err = l.validateAndAddLeaseForceSettle(forceBad2, true)
	if err == nil || !strings.Contains(err.Error(), "lease_force_settle timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for forceBad2, got: %v", err)
	}

	stagedBad2 := &Block{
		Type:      BlockLeaseForceSettle,
		Account:   consumerAddr,
		Source:    leaseBlock.Hash,
		Balance:   100,
		Asset:     "XCU",
		Timestamp: 3100, // < 3200
		Previous:  "0",
	}
	signTestBlock(t, stagedBad2, consumerKp)
	err = l.ValidateStagedBlock(stagedBad2, 0)
	if err == nil || !strings.Contains(err.Error(), "staged lease_force_settle: timestamp 3100 is before predecessor timestamp 3200") {
		t.Fatalf("expected error for stagedBad2, got: %v", err)
	}
}
