package core

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type minimalConflictStore struct {
	mu          sync.RWMutex
	conflicts   map[string]*Conflict
	staged      map[string]*Block
	onFirstSave func(c *Conflict)
	saveCalls   int
	savedStates []*Conflict
	rmwDelay    time.Duration
}

func newMinimalConflictStore() *minimalConflictStore {
	return &minimalConflictStore{
		conflicts: make(map[string]*Conflict),
		staged:    make(map[string]*Block),
	}
}

func (s *minimalConflictStore) key(account, prev string) string {
	return account + "|" + prev
}

func cloneConflict(c *Conflict) *Conflict {
	if c == nil {
		return nil
	}
	cp := *c
	cp.BlockHashes = append([]string(nil), c.BlockHashes...)
	if c.WeightSnapshot != nil {
		cp.WeightSnapshot = make(map[string]uint64, len(c.WeightSnapshot))
		for k, v := range c.WeightSnapshot {
			cp.WeightSnapshot[k] = v
		}
	}
	return &cp
}

func (s *minimalConflictStore) SaveConflict(c *Conflict) error {
	s.mu.Lock()
	cp := cloneConflict(c)
	s.conflicts[s.key(c.AccountAddress, c.PreviousHash)] = cp
	s.saveCalls++
	callNum := s.saveCalls
	s.savedStates = append(s.savedStates, cloneConflict(c))
	hook := s.onFirstSave
	s.mu.Unlock()

	if callNum == 1 && hook != nil {
		hook(cloneConflict(c))
	}
	return nil
}

func (s *minimalConflictStore) GetConflict(account, previousHash string) (*Conflict, error) {
	s.mu.RLock()
	c := cloneConflict(s.conflicts[s.key(account, previousHash)])
	delay := s.rmwDelay
	s.mu.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return c, nil
}

func (s *minimalConflictStore) DeleteConflict(account, previousHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conflicts, s.key(account, previousHash))
	return nil
}

func (s *minimalConflictStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Conflict
	for _, c := range s.conflicts {
		if c.AccountAddress == account {
			out = append(out, cloneConflict(c))
		}
	}
	return out, nil
}

func (s *minimalConflictStore) GetAllConflicts() ([]*Conflict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Conflict
	for _, c := range s.conflicts {
		out = append(out, cloneConflict(c))
	}
	return out, nil
}

func (s *minimalConflictStore) SaveStagedBlock(b *Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bc := *b
	s.staged[b.Hash] = &bc
	return nil
}

func (s *minimalConflictStore) DeleteStagedBlock(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.staged, hash)
	return nil
}

func (s *minimalConflictStore) GetStagedBlock(hash string) (*Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.staged[hash]
	if b == nil {
		return nil, nil
	}
	bc := *b
	return &bc, nil
}

type testFullStore struct {
	*minimalConflictStore
	mu          sync.RWMutex
	blocks      map[string]*Block
	chains      map[string]*AccountChain
	pending     map[string]*PendingSend
	frontiers   map[string]string
	delegations map[string]string
	blockStatus map[string]BlockStatus
	finalHeight map[string]uint64
	votes       map[string]*Vote
}

func newTestFullStore() *testFullStore {
	return &testFullStore{
		minimalConflictStore: newMinimalConflictStore(),
		blocks:               make(map[string]*Block),
		chains:               make(map[string]*AccountChain),
		pending:              make(map[string]*PendingSend),
		frontiers:            make(map[string]string),
		delegations:          make(map[string]string),
		blockStatus:          make(map[string]BlockStatus),
		finalHeight:          make(map[string]uint64),
		votes:                make(map[string]*Vote),
	}
}

func (s *testFullStore) GetBlock(hash string) (*Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b := s.blocks[hash]; b != nil {
		cp := *b
		return &cp, nil
	}
	return nil, nil
}

func (s *testFullStore) GetAccountChain(account string) (*AccountChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch := s.chains[account]
	if ch == nil {
		return nil, nil
	}
	out := &AccountChain{Blocks: make([]*Block, len(ch.Blocks))}
	for i, b := range ch.Blocks {
		cp := *b
		out.Blocks[i] = &cp
	}
	return out, nil
}

func (s *testFullStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p := s.pending[sendHash]; p != nil {
		cp := *p
		return &cp, nil
	}
	return nil, nil
}

func (s *testFullStore) GetPendingByDest(dest string) ([]*PendingSend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PendingSend
	for _, p := range s.pending {
		if p.Destination == dest {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *testFullStore) GetAllPending() ([]*PendingSend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PendingSend
	for _, p := range s.pending {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func (s *testFullStore) IsEmpty() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blocks) == 0, nil
}

func (s *testFullStore) PutBlock(b *Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *b
	s.blocks[b.Hash] = &cp
	return nil
}

func (s *testFullStore) PutAccountChain(account string, chain *AccountChain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &AccountChain{Blocks: make([]*Block, len(chain.Blocks))}
	for i, b := range chain.Blocks {
		cp := *b
		out.Blocks[i] = &cp
	}
	s.chains[account] = out
	return nil
}

func (s *testFullStore) PutPendingSend(ps *PendingSend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *ps
	s.pending[ps.SendHash] = &cp
	return nil
}

func (s *testFullStore) DeletePendingSend(sendHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, sendHash)
	return nil
}

func (s *testFullStore) PutFrontier(account string, blockHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frontiers[account] = blockHash
	return nil
}

func (s *testFullStore) GetFrontier(account string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frontiers[account], nil
}

func (s *testFullStore) Close() error { return nil }

func (s *testFullStore) AllFrontiers() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.frontiers))
	for k, v := range s.frontiers {
		out[k] = v
	}
	return out
}

func (s *testFullStore) CommitBlock(c *BlockCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bc := *c.Block
	s.blocks[bc.Hash] = &bc
	out := &AccountChain{Blocks: make([]*Block, len(c.Chain.Blocks))}
	for i, b := range c.Chain.Blocks {
		cp := *b
		out.Blocks[i] = &cp
	}
	s.chains[c.Account] = out
	if c.FrontierHash != "" {
		s.frontiers[c.Account] = c.FrontierHash
	}
	if c.AddPending != nil {
		cp := *c.AddPending
		s.pending[cp.SendHash] = &cp
	}
	if c.DeletePendingID != "" {
		delete(s.pending, c.DeletePendingID)
	}
	if c.DeleteDelegation {
		delete(s.delegations, c.Account)
	} else if c.DelegationRep != "" {
		s.delegations[c.Account] = c.DelegationRep
	}
	return nil
}

func (s *testFullStore) CommitUndo(u *BlockUndo) error { return nil }
func (s *testFullStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	if commit != nil {
		return s.CommitBlock(commit)
	}
	return nil
}

func (s *testFullStore) SetBlockStatus(hash string, status BlockStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockStatus[hash] = status
	return nil
}

func (s *testFullStore) GetBlockStatus(hash string) (BlockStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockStatus[hash], nil
}

func (s *testFullStore) SetFinalHeight(account string, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalHeight[account] = height
	return nil
}

func (s *testFullStore) GetFinalHeight(account string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.finalHeight[account], nil
}

func (s *testFullStore) DeleteVotesForConflict(account, previous string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := account + "|" + previous + "|"
	for k := range s.votes {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(s.votes, k)
		}
	}
	return nil
}

func (s *testFullStore) PutVote(v *Vote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *v
	s.votes[v.ConflictAccount+"|"+v.ConflictPrev+"|"+v.RepPubKey] = &cp
	return nil
}

func (s *testFullStore) GetVotesByConflict(account, previous string) ([]*Vote, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := account + "|" + previous + "|"
	var out []*Vote
	for k, v := range s.votes {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *testFullStore) HasVoted(account, previous, repPubKey string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.votes[account+"|"+previous+"|"+repPubKey]
	return ok, nil
}

func (s *testFullStore) GetVote(account, previous, repPubKey string) (*Vote, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v := s.votes[account+"|"+previous+"|"+repPubKey]; v != nil {
		cp := *v
		return &cp, nil
	}
	return nil, nil
}

func TestRecordConflictConcurrentRMWPreservesAllCandidates(t *testing.T) {
	cs := newMinimalConflictStore()
	cs.rmwDelay = 2 * time.Millisecond

	account := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	prev := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	existing := fmt.Sprintf("%064x", 1)

	if _, err := recordConflict(cs, account, prev, existing, fmt.Sprintf("%064x", 2)); err != nil {
		t.Fatalf("initial recordConflict failed: %v", err)
	}

	const workers = 6
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		h := fmt.Sprintf("%064x", i+3)
		go func(hash string) {
			defer wg.Done()
			if _, err := recordConflict(cs, account, prev, existing, hash); err != nil {
				t.Errorf("concurrent recordConflict(%s) failed: %v", hash, err)
			}
			_, _ = GetConflictForBlock(cs, hash)
		}(h)
	}
	wg.Wait()

	c, err := cs.GetConflict(account, prev)
	if err != nil || c == nil {
		t.Fatalf("expected conflict record, got c=%v err=%v", c, err)
	}
	wantCount := 2 + workers
	if len(c.BlockHashes) != wantCount {
		t.Fatalf("lost conflict candidate hashes under concurrent recordConflict: got %d (%v), want %d", len(c.BlockHashes), c.BlockHashes, wantCount)
	}
}

func TestAddBlockConflictNeverExposesUninitializedWeightSnapshot(t *testing.T) {
	st := newTestFullStore()
	l := NewLedger(st, LedgerConfig{})

	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	carol, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	now := Now().UnixNano()
	mint := &Block{
		Type:           BlockMint,
		Account:        alice.Address(),
		Previous:       "0",
		Balance:        1000,
		Amount:         1000,
		Representative: alice.Address(),
		Timestamp:      now - 3000,
		Asset:          "XE",
	}
	if err := SignBlock(mint, alice); err != nil {
		t.Fatalf("SignBlock mint: %v", err)
	}
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}
	_ = st.SetFinalHeight(alice.Address(), 1)

	b1 := &Block{
		Type:        BlockSend,
		Account:     alice.Address(),
		Previous:    mint.Hash,
		Balance:     900,
		Amount:      100,
		Destination: bob.Address(),
		Timestamp:   now - 2000,
		Asset:       "XE",
	}
	if err := SignBlock(b1, alice); err != nil {
		t.Fatalf("SignBlock b1: %v", err)
	}
	if err := l.AddBlock(b1); err != nil {
		t.Fatalf("AddBlock b1: %v", err)
	}

	b2 := &Block{
		Type:        BlockSend,
		Account:     alice.Address(),
		Previous:    mint.Hash,
		Balance:     800,
		Amount:      200,
		Destination: carol.Address(),
		Timestamp:   now - 1000,
		Asset:       "XE",
	}
	if err := SignBlock(b2, alice); err != nil {
		t.Fatalf("SignBlock b2: %v", err)
	}

	st.minimalConflictStore.saveCalls = 0
	st.minimalConflictStore.savedStates = nil

	if err := l.AddBlock(b2); err != nil {
		t.Fatalf("AddBlock conflicting b2: %v", err)
	}

	if len(st.minimalConflictStore.savedStates) == 0 {
		t.Fatalf("expected conflict record to be saved")
	}
	firstSaved := st.minimalConflictStore.savedStates[0]
	if firstSaved.WeightSnapshot == nil || firstSaved.TotalWeight == 0 {
		t.Fatalf("first SaveConflict exposed uninitialized weight snapshot: WeightSnapshot=%v TotalWeight=%d (total SaveConflict calls=%d)",
			firstSaved.WeightSnapshot, firstSaved.TotalWeight, len(st.minimalConflictStore.savedStates))
	}
}

func TestEvictPhantomsDoesNotOverwriteNewCandidatesOrResurrectResolvedConflict(t *testing.T) {
	st := newTestFullStore()
	l := NewLedger(st, LedgerConfig{})
	qm := NewQuorumManager(st, st, st, l)

	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	carol, _ := GenerateKeyPair()
	dave, _ := GenerateKeyPair()

	now := Now().UnixNano()
	mint := &Block{
		Type:           BlockMint,
		Account:        alice.Address(),
		Previous:       "0",
		Balance:        1000,
		Amount:         1000,
		Representative: alice.Address(),
		Timestamp:      now - 5000,
		Asset:          "XE",
	}
	_ = SignBlock(mint, alice)
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}
	_ = st.SetFinalHeight(alice.Address(), 1)

	b1 := &Block{
		Type:        BlockSend,
		Account:     alice.Address(),
		Previous:    mint.Hash,
		Balance:     900,
		Amount:      100,
		Destination: bob.Address(),
		Timestamp:   now - 4000,
		Asset:       "XE",
	}
	_ = SignBlock(b1, alice)
	if err := l.AddBlock(b1); err != nil {
		t.Fatalf("AddBlock b1: %v", err)
	}

	b2 := &Block{
		Type:        BlockSend,
		Account:     alice.Address(),
		Previous:    mint.Hash,
		Balance:     800,
		Amount:      200,
		Destination: carol.Address(),
		Timestamp:   now - 3000,
		Asset:       "XE",
	}
	_ = SignBlock(b2, alice)
	if err := l.AddBlock(b2); err != nil {
		t.Fatalf("AddBlock b2: %v", err)
	}

	// Inject a dead phantom into the stored conflict and take a stale snapshot
	// as sweepStaleConflicts() does via GetAllConflicts().
	deadPhantom := fmt.Sprintf("%064x", 0xdead)
	c, _ := st.GetConflict(alice.Address(), mint.Hash)
	c.BlockHashes = append(c.BlockHashes, deadPhantom)
	c.DetectedAt = Now().Add(-2 * phantomEvictionDelay)
	_ = st.SaveConflict(c)

	staleSnapshot := cloneConflict(c)

	// Concurrently, a third valid conflicting block b3 arrives via AddBlock -> recordConflict.
	b3 := &Block{
		Type:        BlockSend,
		Account:     alice.Address(),
		Previous:    mint.Hash,
		Balance:     700,
		Amount:      300,
		Destination: dave.Address(),
		Timestamp:   now - 2000,
		Asset:       "XE",
	}
	_ = SignBlock(b3, alice)
	if err := l.AddBlock(b3); err != nil {
		t.Fatalf("AddBlock b3: %v", err)
	}

	// Running evictPhantomsAndResolve with the pre-b3 snapshot from sweepStaleConflicts
	// must trim deadPhantom without wiping b3 from the stored Conflict record.
	qm.evictPhantomsAndResolve(staleSnapshot)

	afterTrim, _ := st.GetConflict(alice.Address(), mint.Hash)
	if afterTrim == nil {
		t.Fatalf("expected conflict record to exist after trimming dead phantom")
	}
	if !containsConflictHash(afterTrim.BlockHashes, b3.Hash) {
		t.Fatalf("evictPhantomsAndResolve overwrote concurrently added candidate %s; remaining hashes=%v", b3.Hash, afterTrim.BlockHashes)
	}
	if containsConflictHash(afterTrim.BlockHashes, deadPhantom) {
		t.Fatalf("expected deadPhantom to be trimmed, got %v", afterTrim.BlockHashes)
	}

	// Subcase B: if the conflict was concurrently resolved and removed before
	// evictPhantomsAndResolve saves, it must NOT resurrect the deleted conflict.
	RemoveConflict(st, alice.Address(), mint.Hash)
	qm.evictPhantomsAndResolve(staleSnapshot)
	if resurrected, _ := st.GetConflict(alice.Address(), mint.Hash); resurrected != nil {
		t.Fatalf("evictPhantomsAndResolve resurrected a resolved/deleted conflict: %+v", resurrected)
	}
}
