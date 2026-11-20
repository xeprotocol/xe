package core

import (
	"testing"
)

type testOrphanStore struct {
	blocks       map[string]*Block
	chains       map[string]*AccountChain
	staged       map[string]*Block
	statuses     map[string]BlockStatus
	deletedStage []string
}

func newTestOrphanStore() *testOrphanStore {
	return &testOrphanStore{
		blocks:   make(map[string]*Block),
		chains:   make(map[string]*AccountChain),
		staged:   make(map[string]*Block),
		statuses: make(map[string]BlockStatus),
	}
}

func (s *testOrphanStore) GetBlock(hash string) (*Block, error)               { return s.blocks[hash], nil }
func (s *testOrphanStore) PutBlock(b *Block) error                             { s.blocks[b.Hash] = b; return nil }
func (s *testOrphanStore) GetAccountChain(account string) (*AccountChain, error) { return s.chains[account], nil }
func (s *testOrphanStore) PutAccountChain(account string, c *AccountChain) error { s.chains[account] = c; return nil }
func (s *testOrphanStore) GetPendingSend(h string) (*PendingSend, error)       { return nil, nil }
func (s *testOrphanStore) PutPendingSend(ps *PendingSend) error                { return nil }
func (s *testOrphanStore) DeletePendingSend(h string) error                    { return nil }
func (s *testOrphanStore) GetPendingByDest(acc string) ([]*PendingSend, error) { return nil, nil }
func (s *testOrphanStore) GetAllPending() ([]*PendingSend, error)              { return nil, nil }
func (s *testOrphanStore) PutFrontier(acc, h string) error                     { return nil }
func (s *testOrphanStore) GetFrontier(acc string) (string, error)              { return "0", nil }
func (s *testOrphanStore) CommitUndo(u *BlockUndo) error                       { return nil }
func (s *testOrphanStore) IsEmpty() (bool, error)                              { return len(s.blocks) == 0, nil }
func (s *testOrphanStore) Close() error                                        { return nil }
func (s *testOrphanStore) CommitBlock(c *BlockCommit) error {
	if c.Block != nil {
		s.blocks[c.Block.Hash] = c.Block
	}
	if c.Chain != nil {
		s.chains[c.Account] = c.Chain
	}
	return nil
}
func (s *testOrphanStore) CommitCascade(undos []*BlockUndo, c *BlockCommit) error { return nil }

func (s *testOrphanStore) SaveConflict(c *Conflict) error                  { return nil }
func (s *testOrphanStore) GetConflict(acc, prev string) (*Conflict, error) { return nil, nil }
func (s *testOrphanStore) DeleteConflict(acc, prev string) error           { return nil }
func (s *testOrphanStore) GetConflictsForAccount(acc string) ([]*Conflict, error) { return nil, nil }
func (s *testOrphanStore) GetAllConflicts() ([]*Conflict, error)           { return nil, nil }

func (s *testOrphanStore) SaveStagedBlock(b *Block) error {
	s.staged[b.Hash] = b
	return nil
}
func (s *testOrphanStore) GetStagedBlock(h string) (*Block, error) {
	return s.staged[h], nil
}
func (s *testOrphanStore) DeleteStagedBlock(h string) error {
	delete(s.staged, h)
	s.deletedStage = append(s.deletedStage, h)
	return nil
}

func (s *testOrphanStore) SetBlockStatus(h string, st BlockStatus) error {
	s.statuses[h] = st
	return nil
}
func (s *testOrphanStore) GetBlockStatus(h string) (BlockStatus, error) {
	return s.statuses[h], nil
}
func (s *testOrphanStore) SetFinalHeight(acc string, height uint64) error { return nil }
func (s *testOrphanStore) GetFinalHeight(acc string) (uint64, error)      { return 0, nil }
func (s *testOrphanStore) DeleteVotesForConflict(acc, prev string) error  { return nil }

func TestDropConflictIfOrphaned_DeletesStagedBlocks(t *testing.T) {
	store := newTestOrphanStore()
	ledger := NewLedger(store, LedgerConfig{})
	qm := NewQuorumManager(store, store, nil, ledger)

	account := "0101010101010101010101010101010101010101010101010101010101010101"
	prev := "0202020202020202020202020202020202020202020202020202020202020202"
	cand1 := "0303030303030303030303030303030303030303030303030303030303030303"
	cand2 := "0404040404040404040404040404040404040404040404040404040404040404"

	// Staged blocks are stored
	store.staged[cand1] = &Block{Hash: cand1, Account: account}
	store.staged[cand2] = &Block{Hash: cand2, Account: account}

	// Candidate 1 was rejected during a rollback
	store.statuses[cand1] = StatusRejected

	// Canonical chain does NOT include prev (it was rolled back)
	store.chains[account] = &AccountChain{
		Blocks: []*Block{},
	}

	conflict := &Conflict{
		AccountAddress: account,
		PreviousHash:   prev,
		BlockHashes:    []string{cand1, cand2},
	}

	// Verify the conflict is identified as orphaned by rollback
	if !qm.conflictOrphanedByRollback(conflict) {
		t.Fatalf("expected conflict to be detected as orphaned by rollback")
	}

	// Drop orphaned conflict
	dropped := qm.dropConflictIfOrphaned(conflict)
	if !dropped {
		t.Fatalf("expected dropConflictIfOrphaned to return true")
	}

	// Both staged bodies MUST have been deleted from store
	if len(store.staged) != 0 {
		t.Fatalf("expected all staged blocks to be deleted, but %d remain: %+v", len(store.staged), store.staged)
	}

	if len(store.deletedStage) != 2 {
		t.Fatalf("expected 2 DeleteStagedBlock calls, got %d: %v", len(store.deletedStage), store.deletedStage)
	}
}
