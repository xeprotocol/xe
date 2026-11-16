package core

import (
	"fmt"
	"testing"
)

type mockConflictStore struct {
	conflicts map[string]*Conflict
	staged    map[string]*Block
}

func newMockConflictStore() *mockConflictStore {
	return &mockConflictStore{
		conflicts: make(map[string]*Conflict),
		staged:    make(map[string]*Block),
	}
}

func (m *mockConflictStore) SaveConflict(c *Conflict) error {
	m.conflicts[c.AccountAddress+":"+c.PreviousHash] = c
	return nil
}

func (m *mockConflictStore) GetConflict(account, previousHash string) (*Conflict, error) {
	return m.conflicts[account+":"+previousHash], nil
}

func (m *mockConflictStore) DeleteConflict(account, previousHash string) error {
	delete(m.conflicts, account+":"+previousHash)
	return nil
}

func (m *mockConflictStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	var res []*Conflict
	for _, c := range m.conflicts {
		if c.AccountAddress == account {
			res = append(res, c)
		}
	}
	return res, nil
}

func (m *mockConflictStore) GetAllConflicts() ([]*Conflict, error) {
	var res []*Conflict
	for _, c := range m.conflicts {
		res = append(res, c)
	}
	return res, nil
}

func (m *mockConflictStore) SaveStagedBlock(b *Block) error {
	m.staged[b.Hash] = b
	return nil
}

func (m *mockConflictStore) GetStagedBlock(hash string) (*Block, error) {
	return m.staged[hash], nil
}

func (m *mockConflictStore) DeleteStagedBlock(hash string) error {
	delete(m.staged, hash)
	return nil
}

func TestRecordConflictCapEnforced(t *testing.T) {
	ms := newMockConflictStore()
	account := "0x1111111111111111111111111111111111111111"
	previous := "prev000000000000000000000000000000000000"

	sibs := make([]string, 12)
	for i := 0; i < 12; i++ {
		sibs[i] = fmt.Sprintf("blockhash%02d0000000000000000000000000000", i)
	}

	// 1. Initial 2 siblings created
	isNew, err := recordConflict(ms, account, previous, sibs[0], sibs[1])
	if err != nil || !isNew {
		t.Fatalf("initial conflict creation failed: isNew=%v, err=%v", isNew, err)
	}

	// 2. Add siblings up to 10
	for i := 2; i < 10; i++ {
		isNew, err := recordConflict(ms, account, previous, sibs[0], sibs[i])
		if err != nil {
			t.Fatalf("failed to add sibling %d: %v", i, err)
		}
		if isNew {
			t.Fatalf("expected isNew=false for existing conflict sibling %d", i)
		}
	}

	// Verify conflict record contains exactly 10 hashes
	rec, err := ms.GetConflict(account, previous)
	if err != nil || rec == nil {
		t.Fatalf("failed to get conflict: %v", err)
	}
	if len(rec.BlockHashes) != 10 {
		t.Fatalf("expected 10 hashes in conflict, got %d", len(rec.BlockHashes))
	}

	// 3. Adding an 11th distinct sibling MUST fail with an error rather than silently dropping
	_, err = recordConflict(ms, account, previous, sibs[0], sibs[10])
	if err == nil {
		t.Fatalf("expected 11th sibling to fail with conflict record full error, but got nil")
	}

	// 4. Existing recorded sibling should return nil error (idempotent)
	_, err = recordConflict(ms, account, previous, sibs[0], sibs[5])
	if err != nil {
		t.Fatalf("re-recording existing sibling 5 failed: %v", err)
	}
}

func TestContainsConflictHash(t *testing.T) {
	hashes := []string{"hash1", "hash2", "hash3"}
	if !containsConflictHash(hashes, "hash2") {
		t.Fatal("expected containsConflictHash to return true for hash2")
	}
	if containsConflictHash(hashes, "hash4") {
		t.Fatal("expected containsConflictHash to return false for hash4")
	}
}
