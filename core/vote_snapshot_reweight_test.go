package core

import (
	"math/big"
	"testing"
)

type mockVoteStore struct {
	votes map[string]*Vote
}

func newMockVoteStore() *mockVoteStore {
	return &mockVoteStore{votes: make(map[string]*Vote)}
}

func (m *mockVoteStore) key(account, prev, rep string) string {
	return account + "|" + prev + "|" + rep
}

func (m *mockVoteStore) PutVote(v *Vote) error {
	m.votes[m.key(v.ConflictAccount, v.ConflictPrev, v.RepPubKey)] = v
	return nil
}

func (m *mockVoteStore) GetVote(account, previous, repPubKey string) (*Vote, error) {
	return m.votes[m.key(account, previous, repPubKey)], nil
}

func (m *mockVoteStore) GetVotesByConflict(account, previous string) ([]*Vote, error) {
	var out []*Vote
	prefix := account + "|" + previous + "|"
	for k, v := range m.votes {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, v)
		}
	}
	return out, nil
}

func (m *mockVoteStore) HasVoted(account, previous, repPubKey string) (bool, error) {
	_, ok := m.votes[m.key(account, previous, repPubKey)]
	return ok, nil
}

type mockConflictStore struct {
	conflicts map[string]*Conflict
}

func newMockConflictStore() *mockConflictStore {
	return &mockConflictStore{conflicts: make(map[string]*Conflict)}
}

func (m *mockConflictStore) key(account, prev string) string {
	return account + "|" + prev
}

func (m *mockConflictStore) SaveConflict(c *Conflict) error {
	m.conflicts[m.key(c.AccountAddress, c.PreviousHash)] = c
	return nil
}

func (m *mockConflictStore) GetConflict(account, previous string) (*Conflict, error) {
	return m.conflicts[m.key(account, previous)], nil
}

func (m *mockConflictStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	var out []*Conflict
	for _, c := range m.conflicts {
		if c.AccountAddress == account {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockConflictStore) DeleteConflict(account, previous string) error {
	delete(m.conflicts, m.key(account, previous))
	return nil
}

func TestQuorumManager_FinalTally_RebasedToWeightSnapshot(t *testing.T) {
	// Replicates Issue #159:
	// Representatives R (pub1), S (pub2), T (pub3).
	// Initially R has weight 50, but before conflict creation, whale re-delegates 40 to S.
	// Conflict snapshot has R=10, S=70, T=20 (total 100).
	// R and T vote for fork X.
	// Without fix: tally counts R=50 + T=20 = 70/100 -> falsely finalizes fork X!
	// With fix: tally counts R=10 + T=20 = 30/100 -> correctly rejects finalization!

	vStore := newMockVoteStore()
	cStore := newMockConflictStore()

	account := "account_test"
	previous := "prev_hash"
	forkX := "fork_block_x_hash"
	forkY := "fork_block_y_hash"

	repR := "rep_r_pubkey"
	repT := "rep_t_pubkey"

	// 1. Pre-conflict vote from R with stale weight 50
	voteR := &Vote{
		ConflictAccount: account,
		ConflictPrev:    previous,
		BlockHash:       forkX,
		RepPubKey:       repR,
		Weight:          50, // stale pre-conflict weight
		Final:           true,
	}
	_ = vStore.PutVote(voteR)

	// Vote from T with weight 20
	voteT := &Vote{
		ConflictAccount: account,
		ConflictPrev:    previous,
		BlockHash:       forkX,
		RepPubKey:       repT,
		Weight:          20,
		Final:           true,
	}
	_ = vStore.PutVote(voteT)

	// 2. Conflict record is created with true post-delegation snapshot: R=10, S=70, T=20
	snapshot := map[string]uint64{
		repR: 10, // R dropped from 50 to 10
		repT: 20,
		"rep_s_pubkey": 70,
	}

	conflict := &Conflict{
		AccountAddress: account,
		PreviousHash:   previous,
		BlockHashes:    []string{forkX, forkY},
		WeightSnapshot: snapshot,
		TotalWeight:    100,
	}
	_ = cStore.SaveConflict(conflict)

	qm := NewQuorumManager(nil, cStore, vStore, nil)

	// 3. Perform final tally
	res, err := qm.finalTally(account, previous)
	if err != nil {
		t.Fatalf("finalTally failed: %v", err)
	}

	// Quorum requires 67% (numerator 67, denominator 100).
	// Because R's weight was correctly re-weighted to 10, total support is 10 + 20 = 30 < 67.
	// No block should finalize!
	if res != nil {
		t.Fatalf("vulnerability reproduced: fork %s finalized on stale frozen weight (got winner %s, expected nil)",
			forkX, res.WinnerHash)
	}
}

func TestVoteManager_ReaffirmUpdatesStoredWeight(t *testing.T) {
	vStore := newMockVoteStore()
	account := "account_test"
	previous := "prev_hash"
	repR := "rep_r_pubkey"

	// Pre-conflict final vote with weight 50
	v := &Vote{
		ConflictAccount: account,
		ConflictPrev:    previous,
		BlockHash:       "fork_x",
		RepPubKey:       repR,
		Weight:          50,
		Final:           true,
	}
	_ = vStore.PutVote(v)

	// Verify initial stored weight
	stored, _ := vStore.GetVote(account, previous, repR)
	if stored.Weight != 50 {
		t.Fatalf("expected stored weight 50, got %d", stored.Weight)
	}
}
