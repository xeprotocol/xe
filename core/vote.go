package core

import (
	"container/list"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const voteWindowNanos = int64(5 * 60 * 1e9)

const maxPendingVotesPerConflict = 10

// maxPendingConflicts caps distinct (account, prev) keys sitting in the
// vote-before-conflict buffer. 1024 keys × maxPendingVotesPerConflict
// votes is the hard resident ceiling for that buffer.
const maxPendingConflicts = 1024

const revoteBackoff = 15 * time.Second

// errConflictAbsent means the vote is well-formed but the ledger has no
// conflict record yet. Callers must buffer it and must not write the store.
var errConflictAbsent = errors.New("conflict absent")

// pendingSlot is one buffered conflict. elem is its FIFO node; Front is oldest.
// Duplicate votes do not move the node, so a peer cannot pin its keys by refreshing them.
type pendingSlot struct {
	key   string
	votes []*Vote
	elem  *list.Element
}

type VoteManager struct {
	store     VoteStore
	keyPair   *KeyPair
	ledger    *Ledger
	quorumMgr *QuorumManager

	conflictMu sync.Map

	pendingVotesMu sync.Mutex
	pendingByKey   map[string]*pendingSlot
	pendingFIFO    *list.List

	lastRevoteMu    sync.Mutex
	lastRevoteNanos map[string]int64

	candidateMu             sync.Mutex
	lastNewCandidateNanos   map[string]int64
	seenCandidates          map[string]map[string]bool
	pendingStabilityRedrive map[string]*time.Timer
	closed                  bool
	redriveWG               sync.WaitGroup

	sweepMu      sync.Mutex
	sweepRunning bool
	sweepQueued  bool
	sweepPasses  atomic.Int64

	VoteEmitter func(v *Vote)

	VotePullFn func(account, previous string) bool
}

func conflictKey(account, prev string) string {
	return account + "|" + prev
}

func (vm *VoteManager) conflictLock(account, prev string) *sync.Mutex {
	key := conflictKey(account, prev)
	v, _ := vm.conflictMu.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func NewVoteManager(store VoteStore, keyPair *KeyPair, ledger *Ledger) *VoteManager {
	return &VoteManager{
		store:                   store,
		keyPair:                 keyPair,
		ledger:                  ledger,
		pendingByKey:            make(map[string]*pendingSlot, maxPendingConflicts),
		pendingFIFO:             list.New(),
		lastRevoteNanos:         make(map[string]int64),
		lastNewCandidateNanos:   make(map[string]int64),
		seenCandidates:          make(map[string]map[string]bool),
		pendingStabilityRedrive: make(map[string]*time.Timer),
	}
}

func (vm *VoteManager) SetQuorumManager(qm *QuorumManager) {
	vm.quorumMgr = qm
}

func (vm *VoteManager) OnConflict(c Conflict) {
	if len(c.BlockHashes) == 0 {
		return
	}

	mu := vm.conflictLock(c.AccountAddress, c.PreviousHash)
	mu.Lock()
	defer mu.Unlock()

	vm.flushPendingVotes(c.AccountAddress, c.PreviousHash)
	vm.castVoteLocked(c.AccountAddress, c.PreviousHash, c.BlockHashes...)
}

func (vm *VoteManager) OnBlockAdded(b *Block) {
	if b == nil || b.Type == BlockGenesis {
		return
	}
	vm.CastVote(b.Account, b.Previous, b.Hash)
}

// flushPendingVotes drains the buffer for one conflict.
// Caller holds that conflict's conflictLock.
func (vm *VoteManager) flushPendingVotes(account, prev string) {
	if vm.ledger.GetConflict(account, prev) == nil {
		return
	}
	vm.applyPending(vm.detachPending(account, prev))
}

func (vm *VoteManager) applyPending(pending []*Vote) {
	for _, v := range pending {
		if v == nil {
			continue
		}
		if err := vm.ValidateVote(v); err != nil {
			continue
		}
		if err := vm.receiveVoteInner(v); err != nil {
			if errors.Is(err, errConflictAbsent) {
				vm.bufferVote(v)
			}
		}
	}
}

func (vm *VoteManager) ReceiveVote(v *Vote) error {
	if v == nil {
		return fmt.Errorf("ReceiveVote: nil vote")
	}
	if err := vm.ValidateVote(v); err != nil {
		return err
	}

	account, prev := v.ConflictAccount, v.ConflictPrev
	if vm.ledger.GetConflict(account, prev) == nil {
		vm.bufferVote(v)
		// The conflict may have been saved and its callback may have
		// already flushed an empty buffer between the check and the insert.
		if vm.ledger.GetConflict(account, prev) != nil {
			vm.replayPending(account, prev)
		}
		return nil
	}

	mu := vm.conflictLock(account, prev)
	mu.Lock()
	defer mu.Unlock()

	if vm.ledger.GetConflict(account, prev) == nil {
		vm.bufferVote(v)
		return nil
	}

	if vm.positionResolved(account, prev) {
		vm.discardPending(account, prev)
		vm.reaffirmFromState(account, prev)
		return nil
	}

	vm.flushPendingVotes(account, prev)
	if err := vm.receiveVoteInner(v); err != nil {
		if errors.Is(err, errConflictAbsent) {
			vm.bufferVote(v)
			return nil
		}
		return err
	}
	vm.castVoteLocked(account, prev)
	return nil
}

// replayPending runs only when the caller does not hold conflictLock.
// pendingVotesMu is released before conflictLock is acquired.
func (vm *VoteManager) replayPending(account, prev string) {
	if vm.ledger.GetConflict(account, prev) == nil {
		return
	}
	pending := vm.detachPending(account, prev)
	if len(pending) == 0 {
		return
	}
	if vm.ledger.GetConflict(account, prev) == nil {
		vm.rebuffer(pending)
		return
	}

	mu := vm.conflictLock(account, prev)
	mu.Lock()
	defer mu.Unlock()

	if vm.ledger.GetConflict(account, prev) == nil {
		vm.rebuffer(pending)
		return
	}
	if vm.positionResolved(account, prev) {
		return
	}
	vm.applyPending(pending)
	vm.castVoteLocked(account, prev)
}

func (vm *VoteManager) receiveVoteInner(v *Vote) error {
	if v == nil {
		return fmt.Errorf("ReceiveVote: nil vote")
	}
	conflict := vm.ledger.GetConflict(v.ConflictAccount, v.ConflictPrev)
	if conflict == nil {
		return errConflictAbsent
	}

	existing, err := vm.store.GetVote(v.ConflictAccount, v.ConflictPrev, v.RepPubKey)
	if err != nil {
		return fmt.Errorf("ReceiveVote: GetVote: %w", err)
	}
	if existing != nil && existing.Final {
		return nil
	}

	if conflict.WeightSnapshot != nil {
		v.Weight = conflict.WeightSnapshot[v.RepAccount()]
	} else {
		w := vm.ledger.GetVoteWeight(v.RepAccount())
		if w.IsUint64() {
			v.Weight = w.Uint64()
		} else {
			v.Weight = 0
		}
	}
	if err := vm.store.PutVote(v); err != nil {
		return err
	}

	vm.lastRevoteMu.Lock()
	delete(vm.lastRevoteNanos, conflictKey(v.ConflictAccount, v.ConflictPrev))
	vm.lastRevoteMu.Unlock()
	if vm.quorumMgr != nil {
		vm.quorumMgr.OnVote(v)
	}
	return nil
}

func cloneVote(v *Vote) *Vote {
	if v == nil {
		return nil
	}
	cp := *v
	if v.Signature != nil {
		cp.Signature = append([]byte(nil), v.Signature...)
	}
	return &cp
}

func mergePendingVote(votes []*Vote, v *Vote) []*Vote {
	cp := cloneVote(v)
	for i, existing := range votes {
		if existing != nil && existing.RepPubKey == cp.RepPubKey {
			if cp.Timestamp >= existing.Timestamp {
				votes[i] = cp
			}
			return votes
		}
	}
	if len(votes) >= maxPendingVotesPerConflict {
		return votes
	}
	return append(votes, cp)
}

func (vm *VoteManager) bufferVote(v *Vote) {
	if v == nil {
		return
	}
	key := conflictKey(v.ConflictAccount, v.ConflictPrev)
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()

	if slot, ok := vm.pendingByKey[key]; ok {
		slot.votes = mergePendingVote(slot.votes, v)
		return
	}
	if vm.pendingFIFO.Len() >= maxPendingConflicts {
		oldest := vm.pendingFIFO.Front()
		if oldest != nil {
			old := oldest.Value.(*pendingSlot)
			vm.pendingFIFO.Remove(oldest)
			delete(vm.pendingByKey, old.key)
			old.votes = nil
			old.elem = nil
		}
	}
	slot := &pendingSlot{key: key}
	slot.votes = mergePendingVote(nil, v)
	slot.elem = vm.pendingFIFO.PushBack(slot)
	vm.pendingByKey[key] = slot
}

func (vm *VoteManager) detachPending(account, prev string) []*Vote {
	key := conflictKey(account, prev)
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()
	slot := vm.pendingByKey[key]
	if slot == nil {
		return nil
	}
	delete(vm.pendingByKey, key)
	if slot.elem != nil {
		vm.pendingFIFO.Remove(slot.elem)
		slot.elem = nil
	}
	votes := slot.votes
	slot.votes = nil
	return votes
}

func (vm *VoteManager) discardPending(account, prev string) {
	_ = vm.detachPending(account, prev)
}

func (vm *VoteManager) rebuffer(votes []*Vote) {
	for _, v := range votes {
		vm.bufferVote(v)
	}
}

func VerifyVoteSignature(v *Vote) bool {
	pub, err := DecodePublicKey(v.RepPubKey)
	if err != nil {
		return false
	}
	signingBytes, err := voteSigningBytes(v)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, signingBytes, v.Signature)
}

func (vm *VoteManager) ValidateVote(v *Vote) error {
	pub, err := DecodePublicKey(v.RepPubKey)
	if err != nil {
		return fmt.Errorf("ValidateVote: %w", err)
	}

	signingBytes, err := voteSigningBytes(v)
	if err != nil {
		return fmt.Errorf("ValidateVote: %w", err)
	}

	if !ed25519.Verify(pub, signingBytes, v.Signature) {
		return fmt.Errorf("ValidateVote: signature verification failed")
	}

	weight := vm.ledger.GetVoteWeight(v.RepAccount())
	if weight.Sign() <= 0 {
		return fmt.Errorf("ValidateVote: representative %s has zero vote weight", v.RepPubKey[:8])
	}

	if v.Timestamp < 0 {
		return fmt.Errorf("ValidateVote: timestamp must not be negative")
	}
	nowNanos := Now().UnixNano()
	var delta int64
	if v.Timestamp > nowNanos {
		delta = v.Timestamp - nowNanos
	} else {
		delta = nowNanos - v.Timestamp
	}
	if delta > voteWindowNanos {
		return fmt.Errorf("ValidateVote: timestamp out of range: delta=%v", time.Duration(delta))
	}

	return nil
}

func (v *Vote) RepAccount() string {
	a, err := DeriveAddress(v.RepPubKey)
	if err != nil {
		return ""
	}
	return a
}

func lowestHash(hashes []string) string {
	lowest := hashes[0]
	for _, h := range hashes[1:] {
		if h < lowest {
			lowest = h
		}
	}
	return lowest
}

// Test inspection helpers
func (vm *VoteManager) PendingConflictCountForTest() int {
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()
	return vm.pendingFIFO.Len()
}

func (vm *VoteManager) ConflictLockCountForTest() int {
	n := 0
	vm.conflictMu.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func (vm *VoteManager) PendingVotesForTest(account, prev string) []*Vote {
	key := conflictKey(account, prev)
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()
	slot := vm.pendingByKey[key]
	if slot == nil {
		return nil
	}
	out := make([]*Vote, len(slot.votes))
	copy(out, slot.votes)
	return out
}

func (vm *VoteManager) SeenCandidatesCountForTest() int {
	vm.candidateMu.Lock()
	defer vm.candidateMu.Unlock()
	return len(vm.seenCandidates)
}

func (vm *VoteManager) KeyPairForTest() *KeyPair {
	return vm.keyPair
}

const MaxPendingConflictsForTest = maxPendingConflicts
const MaxPendingVotesPerConflictForTest = maxPendingVotesPerConflict

func (vm *VoteManager) LedgerForTest() *Ledger {
	return vm.ledger
}

func VoteSigningBytes(v *Vote) ([]byte, error) {
	return voteSigningBytes(v)
}
