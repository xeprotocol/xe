package core

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const voteWindowNanos = int64(5 * 60 * 1e9)

const maxPendingVotesPerConflict = 10

const revoteBackoff = 15 * time.Second

type VoteManager struct {
	store     VoteStore
	keyPair   *KeyPair
	ledger    *Ledger
	quorumMgr *QuorumManager

	conflictMu sync.Map

	pendingVotesMu sync.Mutex
	pendingVotes   map[string][]*Vote

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

func (vm *VoteManager) conflictLock(account, prev string) *sync.Mutex {
	key := account + "|" + prev
	v, _ := vm.conflictMu.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func NewVoteManager(store VoteStore, keyPair *KeyPair, ledger *Ledger) *VoteManager {
	return &VoteManager{
		store:                   store,
		keyPair:                 keyPair,
		ledger:                  ledger,
		pendingVotes:            make(map[string][]*Vote),
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

func (vm *VoteManager) flushPendingVotes(account, prev string) {
	key := account + "|" + prev
	vm.pendingVotesMu.Lock()
	pending := vm.pendingVotes[key]
	delete(vm.pendingVotes, key)
	vm.pendingVotesMu.Unlock()

	for _, v := range pending {
		if err := vm.ValidateVote(v); err != nil {
			continue
		}
		_ = vm.receiveVoteInner(v)
	}
}

func (vm *VoteManager) ReceiveVote(v *Vote) error {
	if err := vm.ValidateVote(v); err != nil {

		if vm.isConflictNotFound(v) {
			vm.bufferVote(v)
			return nil
		}
		return err
	}

	mu := vm.conflictLock(v.ConflictAccount, v.ConflictPrev)
	mu.Lock()
	defer mu.Unlock()

	if vm.positionResolved(v.ConflictAccount, v.ConflictPrev) {
		vm.reaffirmFromState(v.ConflictAccount, v.ConflictPrev)
		return nil
	}

	if err := vm.receiveVoteInner(v); err != nil {
		return err
	}

	vm.castVoteLocked(v.ConflictAccount, v.ConflictPrev)
	return nil
}

func (vm *VoteManager) receiveVoteInner(v *Vote) error {
	existing, err := vm.store.GetVote(v.ConflictAccount, v.ConflictPrev, v.RepPubKey)
	if err != nil {
		return fmt.Errorf("ReceiveVote: GetVote: %w", err)
	}
	if existing != nil && existing.Final {
		return nil
	}

	conflict := vm.ledger.GetConflict(v.ConflictAccount, v.ConflictPrev)
	if conflict != nil && conflict.WeightSnapshot != nil {
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
	delete(vm.lastRevoteNanos, v.ConflictAccount+"|"+v.ConflictPrev)
	vm.lastRevoteMu.Unlock()
	if vm.quorumMgr != nil {
		vm.quorumMgr.OnVote(v)
	}
	return nil
}

func (vm *VoteManager) isConflictNotFound(v *Vote) bool {

	pub, err := DecodePublicKey(v.RepPubKey)
	if err != nil {
		return false
	}
	signingBytes, err := voteSigningBytes(v)
	if err != nil {
		return false
	}
	if !ed25519.Verify(pub, signingBytes, v.Signature) {
		return false
	}

	if vm.ledger.GetVoteWeight(v.RepAccount()).Sign() <= 0 {
		return false
	}

	if v.Timestamp < 0 {
		return false
	}
	nowNanos := Now().UnixNano()
	var delta int64
	if v.Timestamp > nowNanos {
		delta = v.Timestamp - nowNanos
	} else {
		delta = nowNanos - v.Timestamp
	}
	if delta > voteWindowNanos {
		return false
	}

	conflict := vm.ledger.GetConflict(v.ConflictAccount, v.ConflictPrev)
	return conflict == nil
}

func (vm *VoteManager) bufferVote(v *Vote) {
	key := v.ConflictAccount + "|" + v.ConflictPrev
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()
	if len(vm.pendingVotes[key]) >= maxPendingVotesPerConflict {
		return
	}
	vm.pendingVotes[key] = append(vm.pendingVotes[key], v)
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
