package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

type MemStore struct {
	mu            sync.RWMutex
	blocks        map[string]*core.Block
	chains        map[string]*core.AccountChain
	pending       map[string]*core.PendingSend
	pendingByDest map[string]map[string]*core.PendingSend
	frontiers     map[string]string

	conflicts map[string]*core.Conflict
	staged    map[string]*core.Block

	votes map[string]*core.Vote

	blockStatus map[string]core.BlockStatus
	finalHeight map[string]uint64

	finalVotes map[string]string

	delegations map[string]string

	leases map[string]*core.Lease

	certificates map[string][]byte

	reputation map[string]*core.ReputationAggregate

	keysets map[string]*core.Keyset

	accountKeys map[string]string

	stateBlocks map[uint64]*statechain.Block
}

func NewMemStore() *MemStore {
	return &MemStore{
		blocks:        make(map[string]*core.Block),
		chains:        make(map[string]*core.AccountChain),
		pending:       make(map[string]*core.PendingSend),
		pendingByDest: make(map[string]map[string]*core.PendingSend),
		frontiers:     make(map[string]string),
		conflicts:     make(map[string]*core.Conflict),
		staged:        make(map[string]*core.Block),
		votes:         make(map[string]*core.Vote),
		blockStatus:   make(map[string]core.BlockStatus),
		finalHeight:   make(map[string]uint64),
		finalVotes:    make(map[string]string),
		delegations:   make(map[string]string),
		leases:        make(map[string]*core.Lease),
		certificates:  make(map[string][]byte),
		reputation:    make(map[string]*core.ReputationAggregate),
		keysets:       make(map[string]*core.Keyset),
		accountKeys:   make(map[string]string),
		stateBlocks:   make(map[uint64]*statechain.Block),
	}
}

func (m *MemStore) GetBlock(hash string) (*core.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blocks[hash]
	if !ok {
		return nil, nil
	}
	return copyBlock(b), nil
}

func (m *MemStore) PutBlock(block *core.Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[block.Hash] = copyBlock(block)
	return nil
}

func (m *MemStore) GetAccountChain(account string) (*core.AccountChain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	chain, ok := m.chains[account]
	if !ok {
		return nil, nil
	}
	return copyChain(chain), nil
}

func (m *MemStore) PutAccountChain(account string, chain *core.AccountChain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chains[account] = copyChain(chain)
	return nil
}

func (m *MemStore) GetPendingSend(sendHash string) (*core.PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ps, ok := m.pending[sendHash]
	if !ok {
		return nil, nil
	}
	cp := *ps
	return &cp, nil
}

func (m *MemStore) PutPendingSend(ps *core.PendingSend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ps
	m.pending[ps.SendHash] = &cp
	if m.pendingByDest[ps.Destination] == nil {
		m.pendingByDest[ps.Destination] = make(map[string]*core.PendingSend)
	}
	m.pendingByDest[ps.Destination][ps.SendHash] = &cp
	return nil
}

func (m *MemStore) DeletePendingSend(sendHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.pending[sendHash]
	if !ok {
		return nil
	}
	dest := ps.Destination
	delete(m.pending, sendHash)
	if destMap := m.pendingByDest[dest]; destMap != nil {
		delete(destMap, sendHash)
		if len(destMap) == 0 {
			delete(m.pendingByDest, dest)
		}
	}
	return nil
}

func (m *MemStore) GetPendingByDest(account string) ([]*core.PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	destMap := m.pendingByDest[account]
	if len(destMap) == 0 {
		return nil, nil
	}
	out := make([]*core.PendingSend, 0, len(destMap))
	for _, ps := range destMap {
		cp := *ps
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemStore) GetAllPending() ([]*core.PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.PendingSend, 0, len(m.pending))
	for _, ps := range m.pending {
		cp := *ps
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemStore) PutFrontier(account string, blockHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frontiers[account] = blockHash
	return nil
}

func (m *MemStore) GetFrontier(account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.frontiers[account], nil
}

func (m *MemStore) IsEmpty() (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blocks) == 0, nil
}

func (m *MemStore) Close() error {
	return nil
}

func (m *MemStore) CommitUndo(u *core.BlockUndo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyUndoLocked(u)
}

func (m *MemStore) applyUndoLocked(u *core.BlockUndo) error {
	if u.DeleteAccount {

		delete(m.chains, u.Account)
		delete(m.frontiers, u.Account)
	} else {
		m.chains[u.Account] = copyChain(u.Chain)
		m.frontiers[u.Account] = u.FrontierHash
	}

	if u.DeletePendingID != "" {
		if ps, ok := m.pending[u.DeletePendingID]; ok {
			dest := ps.Destination
			delete(m.pending, u.DeletePendingID)
			if dm := m.pendingByDest[dest]; dm != nil {
				delete(dm, u.DeletePendingID)
				if len(dm) == 0 {
					delete(m.pendingByDest, dest)
				}
			}
		}
	}
	if u.AddPending != nil {
		cp := *u.AddPending
		m.pending[cp.SendHash] = &cp
		if m.pendingByDest[cp.Destination] == nil {
			m.pendingByDest[cp.Destination] = make(map[string]*core.PendingSend)
		}
		cp2 := cp
		m.pendingByDest[cp.Destination][cp.SendHash] = &cp2
	}
	if u.RejectHash != "" {
		m.blockStatus[u.RejectHash] = core.StatusRejected
	}

	if u.RestoreDelegation {
		if u.PrevRep == "" {
			delete(m.delegations, u.Account)
		} else {
			m.delegations[u.Account] = u.PrevRep
		}
	}

	if u.RestoreLease != nil {
		cp := *u.RestoreLease
		m.leases[cp.LeaseHash] = &cp
	}
	if u.DeleteLeaseHash != "" {
		delete(m.leases, u.DeleteLeaseHash)
	}
	if u.DeleteKeysetAccount != "" {
		delete(m.keysets, u.DeleteKeysetAccount)
	}
	if u.DeleteAccountKeyAccount != "" {
		delete(m.accountKeys, u.DeleteAccountKeyAccount)
	}
	return nil
}

func (m *MemStore) Sync() error {
	return nil
}

func (m *MemStore) AllFrontiers() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.frontiers))
	for k, v := range m.frontiers {
		out[k] = v
	}
	return out
}

func (m *MemStore) CommitBlock(c *core.BlockCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyCommitLocked(c)
}

func (m *MemStore) applyCommitLocked(c *core.BlockCommit) error {

	if c.ExpectLeaseHash != "" {
		lease, ok := m.leases[c.ExpectLeaseHash]
		if !ok {
			return fmt.Errorf("CommitBlock: %w: lease %s not found", core.ErrLeaseStateConflict, c.ExpectLeaseHash[:12])
		}
		if lease.State != c.ExpectLeaseState {
			return fmt.Errorf("CommitBlock: %w: lease %s is %s, want %s",
				core.ErrLeaseStateConflict, c.ExpectLeaseHash[:12], lease.State, c.ExpectLeaseState)
		}
	}

	m.blocks[c.Block.Hash] = copyBlock(c.Block)

	m.chains[c.Account] = copyChain(c.Chain)

	if c.FrontierHash != "" {
		m.frontiers[c.Account] = c.FrontierHash
	}

	if c.AddPending != nil {
		cp := *c.AddPending
		m.pending[cp.SendHash] = &cp
		if m.pendingByDest[cp.Destination] == nil {
			m.pendingByDest[cp.Destination] = make(map[string]*core.PendingSend)
		}
		cp2 := cp
		m.pendingByDest[cp.Destination][cp.SendHash] = &cp2
	}

	if c.DeletePendingID != "" {
		ps, ok := m.pending[c.DeletePendingID]
		if ok {
			dest := ps.Destination
			delete(m.pending, c.DeletePendingID)
			if destMap := m.pendingByDest[dest]; destMap != nil {
				delete(destMap, c.DeletePendingID)
				if len(destMap) == 0 {
					delete(m.pendingByDest, dest)
				}
			}
		}
	}

	if c.PutLease != nil {
		cp := *c.PutLease
		m.leases[cp.LeaseHash] = &cp
	}

	if c.SettleLeaseHash != "" {
		if l, ok := m.leases[c.SettleLeaseHash]; ok {
			l.Settled = true
			l.State = core.LeaseSettled
		}
	}

	if c.CancelLeaseHash != "" {
		if l, ok := m.leases[c.CancelLeaseHash]; ok {
			l.State = core.LeaseCancelled
		}
	}

	if c.UnfulfillLeaseHash != "" {
		if l, ok := m.leases[c.UnfulfillLeaseHash]; ok {
			l.Settled = true
			l.State = core.LeaseUnfulfilled
		}
	}

	if c.DeleteDelegation {
		delete(m.delegations, c.Account)
	} else if c.DelegationRep != "" {
		m.delegations[c.Account] = c.DelegationRep
	}

	if c.PutKeyset != nil {
		ks := *c.PutKeyset
		keys := make([]string, len(ks.Keys))
		copy(keys, ks.Keys)
		ks.Keys = keys
		m.keysets[c.Account] = &ks
	}

	if c.PutAccountKey != "" {
		m.accountKeys[c.Account] = c.PutAccountKey
	}

	return nil
}

func (m *MemStore) CommitCascade(undos []*core.BlockUndo, commit *core.BlockCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if commit != nil && commit.ExpectLeaseHash != "" {
		lease, ok := m.leases[commit.ExpectLeaseHash]
		for _, u := range undos {
			if u.RestoreLease != nil && u.RestoreLease.LeaseHash == commit.ExpectLeaseHash {
				lease, ok = u.RestoreLease, true
			}
			if u.DeleteLeaseHash == commit.ExpectLeaseHash {
				lease, ok = nil, false
			}
		}
		if !ok || lease == nil {
			return fmt.Errorf("CommitCascade: %d undo(s) + winner: %w: lease %s not found",
				len(undos), core.ErrLeaseStateConflict, commit.ExpectLeaseHash[:12])
		}
		if lease.State != commit.ExpectLeaseState {
			return fmt.Errorf("CommitCascade: %d undo(s) + winner: %w: lease %s is %s, want %s",
				len(undos), core.ErrLeaseStateConflict, commit.ExpectLeaseHash[:12], lease.State, commit.ExpectLeaseState)
		}
	}

	for i, u := range undos {
		if err := m.applyUndoLocked(u); err != nil {
			return fmt.Errorf("CommitCascade: undo %d/%d: %w", i+1, len(undos), err)
		}
	}
	if commit != nil {
		if err := m.applyCommitLocked(commit); err != nil {
			return fmt.Errorf("CommitCascade: winner commit: %w", err)
		}
	}
	return nil
}

func memConflictKey(account, prev string) string {
	return account + "|" + prev
}

func copyWeightSnapshot(ws map[string]uint64) map[string]uint64 {
	if ws == nil {
		return nil
	}
	cp := make(map[string]uint64, len(ws))
	for k, v := range ws {
		cp[k] = v
	}
	return cp
}

func (m *MemStore) SaveConflict(c *core.Conflict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	cp.BlockHashes = make([]string, len(c.BlockHashes))
	copy(cp.BlockHashes, c.BlockHashes)
	cp.WeightSnapshot = copyWeightSnapshot(c.WeightSnapshot)
	m.conflicts[memConflictKey(c.AccountAddress, c.PreviousHash)] = &cp
	return nil
}

func (m *MemStore) GetConflict(account, previousHash string) (*core.Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conflicts[memConflictKey(account, previousHash)]
	if !ok {
		return nil, nil
	}
	cp := *c
	cp.BlockHashes = make([]string, len(c.BlockHashes))
	copy(cp.BlockHashes, c.BlockHashes)
	cp.WeightSnapshot = copyWeightSnapshot(c.WeightSnapshot)
	return &cp, nil
}

func (m *MemStore) DeleteConflict(account, previousHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conflicts, memConflictKey(account, previousHash))
	return nil
}

func (m *MemStore) GetConflictsForAccount(account string) ([]*core.Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := account + "|"
	var out []*core.Conflict
	for k, c := range m.conflicts {
		if strings.HasPrefix(k, prefix) {
			cp := *c
			cp.BlockHashes = make([]string, len(c.BlockHashes))
			copy(cp.BlockHashes, c.BlockHashes)
			cp.WeightSnapshot = copyWeightSnapshot(c.WeightSnapshot)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemStore) GetAllConflicts() ([]*core.Conflict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Conflict, 0, len(m.conflicts))
	for _, c := range m.conflicts {
		cp := *c
		cp.BlockHashes = make([]string, len(c.BlockHashes))
		copy(cp.BlockHashes, c.BlockHashes)
		cp.WeightSnapshot = copyWeightSnapshot(c.WeightSnapshot)
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemStore) SaveStagedBlock(b *core.Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged[b.Hash] = copyBlock(b)
	return nil
}

func (m *MemStore) GetStagedBlock(hash string) (*core.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.staged[hash]
	if !ok {
		return nil, nil
	}
	return copyBlock(b), nil
}

func (m *MemStore) DeleteStagedBlock(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.staged, hash)
	return nil
}

func memVoteKey(account, prev, rep string) string {
	return account + "|" + prev + "|" + rep
}

func copyVote(v *core.Vote) *core.Vote {
	cp := *v
	if v.Signature != nil {
		cp.Signature = make([]byte, len(v.Signature))
		copy(cp.Signature, v.Signature)
	}
	return &cp
}

func (m *MemStore) PutVote(vote *core.Vote) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.votes[memVoteKey(vote.ConflictAccount, vote.ConflictPrev, vote.RepPubKey)] = copyVote(vote)
	return nil
}

func (m *MemStore) GetVotesByConflict(account, previous string) ([]*core.Vote, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := account + "|" + previous + "|"
	var out []*core.Vote
	for k, v := range m.votes {
		if strings.HasPrefix(k, prefix) {
			out = append(out, copyVote(v))
		}
	}
	return out, nil
}

func (m *MemStore) HasVoted(account, previous, repPubKey string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.votes[memVoteKey(account, previous, repPubKey)]
	return ok, nil
}

func (m *MemStore) GetVote(account, previous, repPubKey string) (*core.Vote, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.votes[memVoteKey(account, previous, repPubKey)]
	if !ok {
		return nil, nil
	}
	return copyVote(v), nil
}

func (m *MemStore) SetBlockStatus(hash string, status core.BlockStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockStatus[hash] = status
	return nil
}

func (m *MemStore) GetBlockStatus(hash string) (core.BlockStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.blockStatus[hash]
	if !ok {
		return core.StatusPending, nil
	}
	return s, nil
}

func (m *MemStore) SetFinalHeight(account string, height uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finalHeight[account] = height
	return nil
}

func (m *MemStore) GetFinalHeight(account string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.finalHeight[account], nil
}

func (m *MemStore) GetFinalVote(account, previous string) (string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.finalVotes[account+"|"+previous]
	return h, ok, nil
}

func (m *MemStore) PutFinalVoteIfAbsent(account, previous, hash string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := account + "|" + previous
	if existing, ok := m.finalVotes[k]; ok {
		return existing, false, nil
	}
	m.finalVotes[k] = hash
	return hash, true, nil
}

func (m *MemStore) DeleteVotesForConflict(account, previous string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := account + "|" + previous + "|"
	for k := range m.votes {
		if strings.HasPrefix(k, prefix) {
			delete(m.votes, k)
		}
	}
	return nil
}

func (m *MemStore) PutCertificate(hash string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificates[hash] = append([]byte(nil), data...)
	return nil
}

func (m *MemStore) CertificateByHash(hash string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.certificates[hash]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), data...), nil
}

func (m *MemStore) DeleteCertificate(hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificates, hash)
	return nil
}

func (m *MemStore) AllCertificates() (map[string][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]byte, len(m.certificates))
	for k, v := range m.certificates {
		out[k] = append([]byte(nil), v...)
	}
	return out, nil
}

func (m *MemStore) PutDelegation(account, representative string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delegations[account] = representative
	return nil
}

func (m *MemStore) DeleteDelegation(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.delegations, account)
	return nil
}

func (m *MemStore) PutLease(lease *core.Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *lease
	m.leases[lease.LeaseHash] = &cp
	return nil
}

func (m *MemStore) DropLeaseForTesting(leaseHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.leases, leaseHash)
}

func (m *MemStore) GetLease(leaseHash string) (*core.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.leases[leaseHash]
	if !ok {
		return nil, nil
	}
	cp := *l
	return &cp, nil
}

func (m *MemStore) GetLeasesByProvider(provider string) ([]*core.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*core.Lease
	for _, l := range m.leases {
		if l.Provider == provider {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemStore) GetLeasesByState(state core.LeaseState) ([]*core.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*core.Lease
	for _, l := range m.leases {
		if l.State == state {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemStore) GetAllLeases() ([]*core.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Lease, 0, len(m.leases))
	for _, l := range m.leases {
		cp := *l
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemStore) PutReputation(account string, agg *core.ReputationAggregate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *agg
	m.reputation[account] = &cp
	return nil
}

func (m *MemStore) GetReputation(account string) (*core.ReputationAggregate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agg, ok := m.reputation[account]
	if !ok {
		return nil, nil
	}
	cp := *agg
	return &cp, nil
}

func (m *MemStore) GetAllReputations() (map[string]*core.ReputationAggregate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*core.ReputationAggregate, len(m.reputation))
	for k, v := range m.reputation {
		cp := *v
		out[k] = &cp
	}
	return out, nil
}

func (m *MemStore) DeleteReputation(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.reputation, account)
	return nil
}

func (m *MemStore) PutKeyset(account string, keyset *core.Keyset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks := *keyset
	keys := make([]string, len(ks.Keys))
	copy(keys, ks.Keys)
	ks.Keys = keys
	m.keysets[account] = &ks
	return nil
}

func (m *MemStore) GetKeyset(account string) (*core.Keyset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ks, ok := m.keysets[account]
	if !ok {
		return nil, nil
	}
	cp := *ks
	keys := make([]string, len(cp.Keys))
	copy(keys, cp.Keys)
	cp.Keys = keys
	return &cp, nil
}

func (m *MemStore) PutAccountKey(account, pubKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accountKeys[account] = pubKey
	return nil
}

func (m *MemStore) GetAccountKey(account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accountKeys[account], nil
}

func (m *MemStore) DeleteAccountKey(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.accountKeys, account)
	return nil
}

func (m *MemStore) AllAccountKeys() (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.accountKeys))
	for k, v := range m.accountKeys {
		out[k] = v
	}
	return out, nil
}

func (m *MemStore) IterateDelegations(fn func(account, representative string) error) error {
	m.mu.RLock()
	pairs := make([][2]string, 0, len(m.delegations))
	for acc, rep := range m.delegations {
		pairs = append(pairs, [2]string{acc, rep})
	}
	m.mu.RUnlock()
	for _, p := range pairs {
		if err := fn(p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

func copyStateBlock(b *statechain.Block) *statechain.Block {
	data, _ := json.Marshal(b)
	var cp statechain.Block
	_ = json.Unmarshal(data, &cp)
	return &cp
}

func (m *MemStore) PutStateBlock(block *statechain.Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateBlocks[block.Index] = copyStateBlock(block)
	return nil
}

func (m *MemStore) GetStateBlock(index uint64) (*statechain.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b := m.stateBlocks[index]
	if b == nil {
		return nil, nil
	}
	return copyStateBlock(b), nil
}

func (m *MemStore) GetStateTip() (*statechain.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var tip *statechain.Block
	var maxIdx uint64
	for idx, b := range m.stateBlocks {
		if b != nil && (tip == nil || idx > maxIdx) {
			tip, maxIdx = b, idx
		}
	}
	if tip == nil {
		return nil, nil
	}
	return copyStateBlock(tip), nil
}

func (m *MemStore) GetStateBlockRange(start, count uint64) ([]*statechain.Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var blocks []*statechain.Block
	for i := start; i < start+count; i++ {
		if b := m.stateBlocks[i]; b != nil {
			blocks = append(blocks, copyStateBlock(b))
		}
	}
	return blocks, nil
}

func (m *MemStore) StateBlockCount() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return uint64(len(m.stateBlocks)), nil
}

func copyBlock(b *core.Block) *core.Block {
	cp := *b
	if len(cp.Attestations) > 0 {
		cp.Attestations = append([]core.TimekeeperAttestation(nil), cp.Attestations...)
	}
	return &cp
}

func copyChain(chain *core.AccountChain) *core.AccountChain {
	out := &core.AccountChain{
		Blocks: make([]*core.Block, len(chain.Blocks)),
	}
	for i, b := range chain.Blocks {
		cp := *b
		if len(cp.Attestations) > 0 {
			cp.Attestations = append([]core.TimekeeperAttestation(nil), cp.Attestations...)
		}
		out.Blocks[i] = &cp
	}
	return out
}
