package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

type mockConflictStore struct {
	mu        sync.RWMutex
	conflicts map[string]*Conflict
	staged    map[string]*Block
	saveCount int64
}

func newMockConflictStore() *mockConflictStore {
	return &mockConflictStore{
		conflicts: make(map[string]*Conflict),
		staged:    make(map[string]*Block),
	}
}

func (m *mockConflictStore) SaveConflict(c *Conflict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	atomic.AddInt64(&m.saveCount, 1)
	cp := *c
	cp.BlockHashes = append([]string{}, c.BlockHashes...)
	if c.WeightSnapshot != nil {
		cp.WeightSnapshot = make(map[string]uint64, len(c.WeightSnapshot))
		for k, v := range c.WeightSnapshot {
			cp.WeightSnapshot[k] = v
		}
	}
	m.conflicts[c.AccountAddress+"|"+c.PreviousHash] = &cp
	return nil
}

func (m *mockConflictStore) GetConflict(account, previousHash string) (*Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conflicts[account+"|"+previousHash]
	if !ok || c == nil {
		return nil, nil
	}
	cp := *c
	cp.BlockHashes = append([]string{}, c.BlockHashes...)
	if c.WeightSnapshot != nil {
		cp.WeightSnapshot = make(map[string]uint64, len(c.WeightSnapshot))
		for k, v := range c.WeightSnapshot {
			cp.WeightSnapshot[k] = v
		}
	}
	return &cp, nil
}

func (m *mockConflictStore) DeleteConflict(account, previousHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conflicts, account+"|"+previousHash)
	return nil
}

func (m *mockConflictStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Conflict
	for _, c := range m.conflicts {
		if c.AccountAddress == account {
			cp := *c
			cp.BlockHashes = append([]string{}, c.BlockHashes...)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *mockConflictStore) GetAllConflicts() ([]*Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Conflict
	for _, c := range m.conflicts {
		cp := *c
		cp.BlockHashes = append([]string{}, c.BlockHashes...)
		out = append(out, &cp)
	}
	return out, nil
}

func (m *mockConflictStore) SaveStagedBlock(b *Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged[b.Hash] = b
	return nil
}

func (m *mockConflictStore) GetStagedBlock(hash string) (*Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.staged[hash], nil
}

func (m *mockConflictStore) DeleteStagedBlock(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.staged, hash)
	return nil
}

func TestRecordConflictConcurrentRMWPreservesAllCandidates(t *testing.T) {
	cs := newMockConflictStore()
	account := "acc_test_1"
	prev := "prev_test_1"

	var wg sync.WaitGroup
	startCh := make(chan struct{})

	// 8 candidates arriving concurrently
	totalCandidates := 8
	for i := 0; i < totalCandidates; i++ {
		wg.Add(1)
		candidateHash := fmt.Sprintf("%064d", i+1)
		existingHash := fmt.Sprintf("%064d", 0)
		go func(hash string) {
			defer wg.Done()
			<-startCh
			_, _, _ = recordConflict(cs, account, prev, existingHash, hash, nil)
		}(candidateHash)
	}

	close(startCh)
	wg.Wait()

	rec, err := cs.GetConflict(account, prev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec == nil {
		t.Fatalf("expected conflict record, got nil")
	}

	// Initial pair includes existingHash (hash 0) and first candidate, plus other candidates.
	// We want all candidate hashes preserved.
	if len(rec.BlockHashes) < totalCandidates {
		t.Fatalf("lost conflict candidate hashes under concurrent recordConflict: got %d (%v), want at least %d",
			len(rec.BlockHashes), rec.BlockHashes, totalCandidates)
	}
}

func TestAddBlockConflictNeverExposesUninitializedWeightSnapshot(t *testing.T) {
	cs := newMockConflictStore()
	account := "acc_test_snap"
	prev := "prev_test_snap"

	snapFn := func() map[string]uint64 {
		return map[string]uint64{
			"rep1": 5000,
			"rep2": 3000,
		}
	}

	stopReaders := int32(0)
	var observedViolations int64
	var readerWg sync.WaitGroup

	numReaders := 16
	for i := 0; i < numReaders; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for atomic.LoadInt32(&stopReaders) == 0 {
				c, _ := cs.GetConflict(account, prev)
				if c != nil {
					if c.WeightSnapshot == nil || len(c.WeightSnapshot) == 0 || c.TotalWeight == 0 {
						atomic.AddInt64(&observedViolations, 1)
					}
				}
			}
		}()
	}

	// Trigger recordConflict with snapshot
	isNew, rec, err := recordConflict(cs, account, prev, "hashA", "hashB", snapFn)
	if err != nil {
		t.Fatalf("recordConflict failed: %v", err)
	}
	if !isNew || rec == nil {
		t.Fatalf("expected isNew=true and non-nil rec")
	}

	atomic.StoreInt32(&stopReaders, 1)
	readerWg.Wait()

	if violations := atomic.LoadInt64(&observedViolations); violations > 0 {
		t.Fatalf("observed %d instances of uninitialized weight snapshot in conflict record", violations)
	}
}

func TestEvictPhantomsDoesNotOverwriteNewCandidatesOrResurrectResolvedConflict(t *testing.T) {
	cs := newMockConflictStore()
	account := "acc_test_evict"
	prev := "prev_test_evict"

	hReal := "8385c0e700000000000000000000000000000000000000000000000000000001"
	hDead := "dead000000000000000000000000000000000000000000000000000000000002"
	hNew := "6d7decb700000000000000000000000000000000000000000000000000000003"

	// 1. Initial conflict with real + dead phantom
	_, _, err := recordConflict(cs, account, prev, hReal, hDead, nil)
	if err != nil {
		t.Fatalf("initial recordConflict failed: %v", err)
	}

	var wg sync.WaitGroup
	startCh := make(chan struct{})

	// Routine A: adds hNew concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startCh
		_, _, _ = recordConflict(cs, account, prev, hReal, hNew, nil)
	}()

	// Routine B: trims hDead concurrently via trimConflictHashes
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startCh
		_ = trimConflictHashes(cs, account, prev, []string{hDead})
	}()

	close(startCh)
	wg.Wait()

	// Verify that hNew is preserved and hDead is trimmed
	c, err := cs.GetConflict(account, prev)
	if err != nil {
		t.Fatalf("GetConflict failed: %v", err)
	}
	if c == nil {
		t.Fatalf("conflict record should not be nil")
	}

	hasNew := false
	hasDead := false
	for _, h := range c.BlockHashes {
		if h == hNew {
			hasNew = true
		}
		if h == hDead {
			hasDead = true
		}
	}

	if !hasNew {
		t.Fatalf("evictPhantomsAndResolve overwrote concurrently added candidate %s; remaining hashes=%v", hNew, c.BlockHashes)
	}
	if hasDead {
		t.Fatalf("dead phantom %s was not trimmed from hashes: %v", hDead, c.BlockHashes)
	}

	// 2. Remove conflict (simulate resolution)
	RemoveConflict(cs, account, prev)
	removedCheck, _ := cs.GetConflict(account, prev)
	if removedCheck != nil {
		t.Fatalf("conflict should be removed")
	}

	// 3. Late phantom eviction should NOT resurrect the deleted conflict
	err = trimConflictHashes(cs, account, prev, []string{hDead})
	if err != nil {
		t.Fatalf("trimConflictHashes returned error: %v", err)
	}

	resurrectedCheck, _ := cs.GetConflict(account, prev)
	if resurrectedCheck != nil {
		t.Fatalf("trimConflictHashes resurrected deleted conflict into ConflictStore!")
	}
}
