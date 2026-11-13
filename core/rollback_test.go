package core

import (
	"math/big"
	"testing"
)

type mockStoreForRollback struct {
	chain           *AccountChain
	undoCommitted   *BlockUndo
	deletedConflict struct {
		account  string
		previous string
	}
	finalVotes map[string]string
}

func newMockStoreForRollback() *mockStoreForRollback {
	return &mockStoreForRollback{
		finalVotes: make(map[string]string),
	}
}

func (m *mockStoreForRollback) GetBlock(hash string) (*Block, error)                   { return nil, nil }
func (m *mockStoreForRollback) PutBlock(block *Block) error                           { return nil }
func (m *mockStoreForRollback) GetAccountChain(account string) (*AccountChain, error) { return m.chain, nil }
func (m *mockStoreForRollback) PutAccountChain(account string, chain *AccountChain) error {
	m.chain = chain
	return nil
}
func (m *mockStoreForRollback) GetPendingSend(sendHash string) (*PendingSend, error) { return nil, nil }
func (m *mockStoreForRollback) PutPendingSend(ps *PendingSend) error                 { return nil }
func (m *mockStoreForRollback) DeletePendingSend(sendHash string) error              { return nil }
func (m *mockStoreForRollback) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}
func (m *mockStoreForRollback) GetAllPending() ([]*PendingSend, error)           { return nil, nil }
func (m *mockStoreForRollback) PutFrontier(account string, blockHash string) error { return nil }
func (m *mockStoreForRollback) GetFrontier(account string) (string, error)       { return "", nil }
func (m *mockStoreForRollback) CommitUndo(u *BlockUndo) error {
	m.undoCommitted = u
	return nil
}
func (m *mockStoreForRollback) IsEmpty() (bool, error) { return false, nil }
func (m *mockStoreForRollback) Close() error           { return nil }

func (m *mockStoreForRollback) CommitBlock(c *BlockCommit) error { return nil }
func (m *mockStoreForRollback) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}

func (m *mockStoreForRollback) SetBlockStatus(hash string, status BlockStatus) error { return nil }
func (m *mockStoreForRollback) GetBlockStatus(hash string) (BlockStatus, error) {
	return StatusFinalized, nil
}
func (m *mockStoreForRollback) SetFinalHeight(account string, height uint64) error { return nil }
func (m *mockStoreForRollback) GetFinalHeight(account string) (uint64, error)        { return 0, nil }
func (m *mockStoreForRollback) DeleteVotesForConflict(account, previous string) error {
	m.deletedConflict.account = account
	m.deletedConflict.previous = previous
	return nil
}

func (m *mockStoreForRollback) GetFinalVote(account, previous string) (string, bool, error) {
	k := account + "|" + previous
	h, ok := m.finalVotes[k]
	return h, ok, nil
}

func (m *mockStoreForRollback) PutFinalVoteIfAbsent(account, previous, hash string) (string, bool, error) {
	k := account + "|" + previous
	if existing, ok := m.finalVotes[k]; ok {
		return existing, false, nil
	}
	m.finalVotes[k] = hash
	return hash, true, nil
}

func (m *mockStoreForRollback) DeleteFinalVote(account, previous string) error {
	delete(m.finalVotes, account+"|"+previous)
	return nil
}

func TestFinalVoteStore_Interface(t *testing.T) {
	var s FinalVoteStore = newMockStoreForRollback()

	account := "rep1"
	previous := "prev1"
	hash1 := "block1"
	hash2 := "block2"

	// Setting a final vote lock with PutFinalVoteIfAbsent locks the position
	stored, written, err := s.PutFinalVoteIfAbsent(account, previous, hash1)
	if err != nil || !written || stored != hash1 {
		t.Fatalf("expected written=true, stored=%s; got written=%v, stored=%s, err=%v", hash1, written, stored, err)
	}

	// Invoking DeleteFinalVote unlocks the position so that GetFinalVote returns ok=false
	if err := s.DeleteFinalVote(account, previous); err != nil {
		t.Fatalf("DeleteFinalVote failed: %v", err)
	}

	_, ok, err := s.GetFinalVote(account, previous)
	if err != nil || ok {
		t.Fatalf("expected ok=false after DeleteFinalVote; got ok=%v, err=%v", ok, err)
	}

	// A subsequent PutFinalVoteIfAbsent with a replacement hash succeeds (written=true)
	stored, written, err = s.PutFinalVoteIfAbsent(account, previous, hash2)
	if err != nil || !written || stored != hash2 {
		t.Fatalf("expected replacement written=true, stored=%s; got written=%v, stored=%s, err=%v", hash2, written, stored, err)
	}
}

func TestUndoBlockApply_CleansUpFinalVotesAndLock(t *testing.T) {
	ms := newMockStoreForRollback()
	l := &Ledger{
		store:          ms,
		atomicStore:    ms,
		finalStore:     ms,
		finalVoteStore: ms,
		locks:          make(map[string]*accountLock),
		leaseLocks:     make(map[string]*accountLock),
		assetBalances:  make(map[string]map[string]uint64),
		delegation:     make(map[string]string),
		weights:        make(map[string]*big.Int),
	}

	account := "provider_account_1"
	prevHash := "prev_block_hash_999"
	deadAcceptHash := "dead_accept_hash_aaa"
	replacementHash := "replacement_hash_bbb"

	targetBlock := &Block{
		Account:  account,
		Hash:     deadAcceptHash,
		Previous: prevHash,
		Type:     BlockSend,
		Asset:    "XE",
		Amount:   100,
		Balance:  900,
	}

	parentBlock := &Block{
		Account: account,
		Hash:    prevHash,
		Type:    BlockSend,
		Asset:   "XE",
		Balance: 1000,
	}

	ms.chain = &AccountChain{
		Blocks: []*Block{parentBlock, targetBlock},
	}

	// Lock the position with the dead block's final vote
	stored, written, err := l.finalVoteStore.PutFinalVoteIfAbsent(account, prevHash, deadAcceptHash)
	if err != nil || !written || stored != deadAcceptHash {
		t.Fatalf("failed to lock final vote: written=%v, stored=%s, err=%v", written, stored, err)
	}

	// Unwind the target block
	if err := l.undoBlockApply(account, targetBlock); err != nil {
		t.Fatalf("undoBlockApply failed: %v", err)
	}

	// Verify DeleteVotesForConflict was called on finalStore
	if ms.deletedConflict.account != account || ms.deletedConflict.previous != prevHash {
		t.Fatalf("expected DeleteVotesForConflict called for %s|%s, got %s|%s",
			account, prevHash, ms.deletedConflict.account, ms.deletedConflict.previous)
	}

	// Verify DeleteFinalVote was called on finalVoteStore (GetFinalVote returns ok=false)
	_, ok, err := l.finalVoteStore.GetFinalVote(account, prevHash)
	if err != nil {
		t.Fatalf("GetFinalVote error: %v", err)
	}
	if ok {
		t.Fatalf("expected final vote lock to be cleared (ok=false), but lock was still present")
	}

	// Verify a subsequent PutFinalVoteIfAbsent with a replacement hash succeeds (written=true)
	stored, written, err = l.finalVoteStore.PutFinalVoteIfAbsent(account, prevHash, replacementHash)
	if err != nil {
		t.Fatalf("PutFinalVoteIfAbsent failed: %v", err)
	}
	if !written {
		t.Fatalf("expected written=true for replacement block hash, got false")
	}
	if stored != replacementHash {
		t.Fatalf("expected stored=%s, got %s", replacementHash, stored)
	}
}
