package core

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// voteWindowNanos is the allowed clock skew for vote timestamps (±5 minutes).
const voteWindowNanos = int64(5 * 60 * 1e9)

// maxPendingVotesPerConflict caps buffered votes for a single not-yet-known
// conflict to prevent memory exhaustion from DoS.
const maxPendingVotesPerConflict = 10

// revoteBackoff is the minimum interval between two sweep-driven re-emits of the
// SAME converge preference for a position. It throttles (not suppresses) the
// re-drive: exactly one re-emit per window still fires, so a converge vote
// dropped at a peer is re-delivered next window (the self-heal). Matches the 15s
// sweep cadence. Cleared on any inbound vote (re-arm) so new information is never
// delayed. (#565)
const revoteBackoff = 15 * time.Second

// VoteManager handles voting on conflicts. It casts a vote the first time a
// conflict is detected, validates incoming votes, and stores them via VoteStore.
type VoteManager struct {
	store     VoteStore
	keyPair   *KeyPair
	ledger    *Ledger
	quorumMgr *QuorumManager

	// Per-conflict mutex to serialize HasVoted+PutVote and prevent
	// double-counting of vote weight via TOCTOU.
	conflictMu sync.Map // key: "account|prev" → *sync.Mutex

	// pendingVotes buffers votes that arrive before the local node has
	// detected the referenced conflict. Flushed in OnConflict.
	pendingVotesMu sync.Mutex
	pendingVotes   map[string][]*Vote // key: "account|prev"

	// lastRevoteNanos throttles sweep-driven converge re-emits to one per
	// revoteBackoff window per position: key "account|prev" → Unix nanos of the
	// last re-emit. Cleared by receiveVoteInner on any inbound vote (re-arm). A
	// missing/zero entry means "emit now", so any bug degrades to always-emit. (#565)
	lastRevoteMu    sync.Mutex
	lastRevoteNanos map[string]int64

	// Candidate-stability window state (#600 part 2 / #616 / #568), guarded by
	// candidateMu (key "account|prev"):
	//   - lastNewCandidateNanos: Unix nanos when the LAST genuinely-new HELD
	//     candidate was first observed at the position. The 67% quorum-path
	//     commit-lock is withheld until lockStabilityWindow has elapsed since this
	//     stamp, so a lower-hash sibling in flight reliably arrives and shifts the
	//     rep's preference before any irrevocable lock forms.
	//   - seenCandidates: the set of held candidate hashes already observed per
	//     position, so only a NEW held hash bumps the stamp. "Held" = a body this
	//     node holds (GetBlockOrStaged != nil); votes for unheld/fabricated hashes
	//     never start or reset the window (ValidateVote does not check candidate
	//     membership, so otherwise one funded rep could reset it forever and
	//     suppress all locking — a liveness wedge; mirrors the #600-part-1 unheld
	//     filter in finalTally).
	//   - pendingStabilityRedrive: dedups (and tracks, so Close can cancel) the
	//     one-shot AfterFunc re-drive scheduled when the quorum branch defers ONLY
	//     because the window has not elapsed, so a quiet position finalizes one
	//     window later instead of waiting for the 15s sweep. Cleared when the
	//     timer fires or Close stops it.
	//   - closed + redriveWG: lifecycle for the re-drive timers — their callbacks
	//     run on their own goroutines and read the replaceable clock (Now), so
	//     Close cancels pending timers and waits out in-flight callbacks rather
	//     than leaking them past the VoteManager's life (a stopped node; a test
	//     about to swap the clock mock back).
	candidateMu             sync.Mutex
	lastNewCandidateNanos   map[string]int64
	seenCandidates          map[string]map[string]bool
	pendingStabilityRedrive map[string]*time.Timer
	closed                  bool
	redriveWG               sync.WaitGroup

	// SweepFrontiers singleflight (#640): one sweep at a time, at most one
	// queued re-run; sweepPasses counts completed passes (observable in tests).
	sweepMu      sync.Mutex
	sweepRunning bool
	sweepQueued  bool
	sweepPasses  atomic.Int64

	// VoteEmitter is an optional callback invoked after a vote is cast locally,
	// for broadcasting to the network. May be nil.
	VoteEmitter func(v *Vote)
}

func (vm *VoteManager) conflictLock(account, prev string) *sync.Mutex {
	key := account + "|" + prev
	v, _ := vm.conflictMu.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// NewVoteManager creates a VoteManager backed by the given store, using keyPair
// to sign local votes, and ledger to query vote weights and conflicts.
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

// SetQuorumManager registers a QuorumManager to be notified after each
// successfully stored vote.
func (vm *VoteManager) SetQuorumManager(qm *QuorumManager) {
	vm.quorumMgr = qm
}

// OnConflict is a ConflictCallback (func(Conflict)) implementation, called by the
// Ledger once when a fork first reaches size 2. It drives two-phase finalization
// voting for the contested position: a converge vote for the deterministic
// preference (lowestHash), escalating to a commit-locked final vote once a
// candidate has a visible supermajority. (#526)
func (vm *VoteManager) OnConflict(c Conflict) {
	if len(c.BlockHashes) == 0 {
		return
	}

	mu := vm.conflictLock(c.AccountAddress, c.PreviousHash)
	mu.Lock()
	defer mu.Unlock()

	// Replay any votes buffered before this conflict was known locally.
	vm.flushPendingVotes(c.AccountAddress, c.PreviousHash)

	// Drive two-phase voting for this position (converge → final).
	vm.castVoteLocked(c.AccountAddress, c.PreviousHash, c.BlockHashes...)
}

// OnBlockAdded drives finalization voting for an uncontested block as soon as it
// is accepted (the per-block trigger). Skips genesis (never contestable). Fired
// by the Ledger outside the account lock so it may freely read store state. (#526)
func (vm *VoteManager) OnBlockAdded(b *Block) {
	if b == nil || b.Type == BlockGenesis {
		return
	}
	vm.CastVote(b.Account, b.Previous, b.Hash)
}

// flushPendingVotes replays buffered votes for a conflict that is now known.
// Called with the conflict lock already held by OnConflict.
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

// ReceiveVote validates and stores an incoming vote from the network.
// After successfully storing the vote, it notifies the QuorumManager if one is set.
// A representative who has already voted on a conflict is rejected (no vote flipping).
func (vm *VoteManager) ReceiveVote(v *Vote) error {
	if err := vm.ValidateVote(v); err != nil {
		// If the only failure is "conflict not found", buffer the vote
		// so it can be replayed when the conflict is eventually detected.
		if vm.isConflictNotFound(v) {
			vm.bufferVote(v)
			return nil
		}
		return err
	}

	mu := vm.conflictLock(v.ConflictAccount, v.ConflictPrev)
	mu.Lock()
	defer mu.Unlock()

	// #654: a vote for a position WE already resolved means the sender is a
	// laggard that missed final-vote quorum before the post-finalization
	// cleanup deleted everyone's votes — the stored-vote re-affirm
	// (#566/#569) has no source anywhere on the network, so without an
	// answer the laggard re-votes forever with only its own weight and its
	// conflict record never clears (account frozen on that node only).
	// Answer with a fresh final vote derived from finalized chain state and
	// drop the inbound vote: storing votes for a settled position is pure
	// pollution, and receiveVoteInner's throttle-stamp reset would let a
	// re-voting laggard bypass the re-affirm backoff.
	if vm.positionResolved(v.ConflictAccount, v.ConflictPrev) {
		vm.reaffirmFromState(v.ConflictAccount, v.ConflictPrev)
		return nil
	}

	if err := vm.receiveVoteInner(v); err != nil {
		return err
	}
	// Re-drive local two-phase voting: a peer's vote may shift the converge
	// leader or satisfy this rep's lock condition.
	vm.castVoteLocked(v.ConflictAccount, v.ConflictPrev)
	return nil
}

// receiveVoteInner stores a validated peer vote. Caller must hold the per-position
// lock for (v.ConflictAccount, v.ConflictPrev). A converge vote (mutable) may
// replace the peer's prior converge vote; a final vote, once recorded, is
// irrevocable — any later or conflicting vote from that rep is ignored. (#526)
func (vm *VoteManager) receiveVoteInner(v *Vote) error {
	existing, err := vm.store.GetVote(v.ConflictAccount, v.ConflictPrev, v.RepPubKey)
	if err != nil {
		return fmt.Errorf("ReceiveVote: GetVote: %w", err)
	}
	if existing != nil && existing.Final {
		return nil // final votes are irrevocable — ignore further votes from this rep
	}
	// Use weight snapshot from conflict detection time if available,
	// otherwise fall back to current weight. This prevents a timing attack
	// where an attacker inflates weight between conflict detection and voting.
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
	// Re-arm the re-emit throttle (#565): a fresh inbound vote may shift the
	// converge leader or satisfy this rep's lock condition, so clear the stamp and
	// let the next sweep-driven castVoteLocked re-emit immediately instead of
	// waiting out the window — back-off never delays a vote that follows new
	// network information.
	vm.lastRevoteMu.Lock()
	delete(vm.lastRevoteNanos, v.ConflictAccount+"|"+v.ConflictPrev)
	vm.lastRevoteMu.Unlock()
	if vm.quorumMgr != nil {
		vm.quorumMgr.OnVote(v)
	}
	return nil
}

// isConflictNotFound returns true if the vote passes all validation checks
// except conflict existence. Used to decide whether to buffer the vote.
func (vm *VoteManager) isConflictNotFound(v *Vote) bool {
	// Signature check
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
	// Weight check
	if vm.ledger.GetVoteWeight(v.RepAccount()).Sign() <= 0 {
		return false
	}
	// Timestamp check
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
	// All checks pass except conflict existence
	conflict := vm.ledger.GetConflict(v.ConflictAccount, v.ConflictPrev)
	return conflict == nil
}

// bufferVote stores a vote for a not-yet-known conflict, capped per conflict.
func (vm *VoteManager) bufferVote(v *Vote) {
	key := v.ConflictAccount + "|" + v.ConflictPrev
	vm.pendingVotesMu.Lock()
	defer vm.pendingVotesMu.Unlock()
	if len(vm.pendingVotes[key]) >= maxPendingVotesPerConflict {
		return
	}
	vm.pendingVotes[key] = append(vm.pendingVotes[key], v)
}

// VerifyVoteSignature reports whether v carries a valid ed25519 signature by
// v.RepPubKey over its canonical signing bytes. It checks ONLY the signature
// (not weight or timestamp), so the gossip layer can reject forged votes BEFORE
// they reach dedup state — a forged vote must not be able to pollute the dedup
// map and suppress a genuine, finality-critical vote (#570/H9).
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

// ValidateVote checks that a vote is well-formed and legitimate:
//  1. Signature is valid (ed25519 over voteSigningBytes).
//  2. The representative has delegated weight > 0.
//  3. The vote timestamp is within ±5 minutes of Now().
//
// A vote does NOT require a conflict record to exist: under two-phase
// finalization every position (contested or not) is voted on, and uncontested
// positions carry no conflict record. (#526)
func (vm *VoteManager) ValidateVote(v *Vote) error {
	// 1. Verify signature.
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

	// 2. Check representative has delegated weight > 0.
	weight := vm.ledger.GetVoteWeight(v.RepAccount())
	if weight.Sign() <= 0 {
		return fmt.Errorf("ValidateVote: representative %s has zero vote weight", v.RepPubKey[:8])
	}

	// 3. Check timestamp within ±5 minutes.
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

// RepAccount returns the representative's ACCOUNT ADDRESS, derived from the
// public key the vote is signed with (#829).
//
// A vote carries the rep's PUBLIC KEY, not its address, deliberately: the gossip
// layer verifies a vote's signature before it can touch dedup state (#570/H9),
// and that check must stay stateless — a ledger lookup on the pre-dedup path
// would let an unknown-rep vote cost a store read, which is exactly the
// amplification H9 closed. Vote WEIGHT, though, is delegated to an ADDRESS (the
// Representative field on blocks), so every weight lookup and weight-snapshot
// read goes through this derivation. Returns "" for a malformed key, which
// yields zero weight — the safe direction.
func (v *Vote) RepAccount() string {
	a, err := DeriveAddress(v.RepPubKey)
	if err != nil {
		return ""
	}
	return a
}

// lowestHash returns the lexicographically smallest hash from the slice.
// Used for deterministic tie-breaking in conflict voting.
func lowestHash(hashes []string) string {
	lowest := hashes[0]
	for _, h := range hashes[1:] {
		if h < lowest {
			lowest = h
		}
	}
	return lowest
}
