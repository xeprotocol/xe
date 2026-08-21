package core

// finalization.go — two-phase finalization voting (#526), epic #529.
//
// Every block reaches a finalized state via representative voting, not just
// blocks that fork. A position (root = account + previous) runs an election:
//   - Phase 1 (converge): reps cast a MUTABLE converge vote for their preferred
//     candidate (lowestHash among candidates seen — deterministic, monotonic).
//   - Phase 2 (final): once a candidate has a visible ≥67% converge supermajority
//     (or, after fallbackDelay on a fork, the converge plurality), a rep writes
//     the write-once commit-lock and casts an IRREVOCABLE final vote for the
//     locked hash.
// A block finalizes when ≥67% of delegated weight has FINAL-voted it. The durable
// commit-lock makes a rep structurally unable to final-vote two hashes at a root,
// so adversarial timing/restart can only delay finalization, never double it.
//
// One evolving vote slot per (account, previous, rep): a converge vote (mutable)
// may be replaced as preference shifts, then promoted in place to a final vote
// (immutable). Only final votes finalize; converge votes only establish leaders.

import (
	"crypto/ed25519"
	"log"
	"math/big"
	"time"
)

// ---- dependency model (emission gate) ----

// blockDep is a (account, hash) dependency: the block `hash` on chain `account`
// must be finalized before the dependent block can be finalized.
type blockDep struct {
	account string
	hash    string
}

// blockDependencies returns the finalization dependencies of b — the blocks that
// must be finalized before b may be finalized (and before a representative emits
// a finalization vote for b).
//
// `previous` is always a dependency (same account); because previous is always
// present, finalizing a block transitively requires finalizing all of its
// same-account ancestors — so e.g. a lease_settle's lease_accept (an ancestor on
// the provider's own chain) is covered without an explicit entry. The only deps
// that `previous` does NOT cover are CROSS-account: a block that consumes another
// account's block via Source (a receive consuming a send; a lease lifecycle block
// referencing the consumer's lease-create block). Those are added explicitly and
// resolved to their owning account via GetBlock.
//
// The switch is exhaustive and fails CLOSED: an unknown block type yields an
// unresolvable dependency, so the emission gate withholds votes rather than
// silently finalizing a block whose dependencies were never checked. (#526)
func (l *Ledger) blockDependencies(b *Block) []blockDep {
	var deps []blockDep
	if b.Previous != "" && b.Previous != "0" {
		deps = append(deps, blockDep{account: b.Account, hash: b.Previous})
	}
	switch b.Type {
	case BlockReceive, BlockLeaseAccept, BlockLeaseSettle, BlockLeaseCancel, BlockLeaseForceSettle:
		// Cross-account: Source references a block on another account's chain
		// (receive → the send; lease_accept/settle/cancel/force_settle → the
		// consumer's lease-create block). Resolve its owner via GetBlock.
		if b.Source != "" && b.Source != "0" {
			deps = append(deps, blockDep{account: l.accountOfBlock(b.Source), hash: b.Source})
		}
	case BlockSend, BlockBurn, BlockMint, BlockLease, BlockMultisigOpen, BlockMultisigUpdate, BlockGenesis:
		// previous only (no cross-account dependency).
	default:
		// Fail closed: never let a new/unknown block type bypass the gate.
		deps = append(deps, blockDep{account: "", hash: "unknown-type:" + string(b.Type)})
	}
	return deps
}

// accountOfBlock resolves a block hash to its owning account, or "" if the block
// is not known locally (which the gate treats as not-finalized → withhold vote).
func (l *Ledger) accountOfBlock(hash string) string {
	blk := l.GetBlock(hash)
	if blk == nil {
		return ""
	}
	return blk.Account
}

// depsFinalized reports whether every dependency of b is finalized in this node's
// local ledger. It gates finalization-vote EMISSION only — a node withholds its
// own votes for a block whose dependencies it has not finalized, but still tallies
// incoming votes and keeps the election alive (so a lagging node never deadlocks).
// An unresolvable dependency (account "") is treated as not finalized. (#526)
func (l *Ledger) depsFinalized(b *Block) bool {
	for _, d := range l.blockDependencies(b) {
		if d.account == "" {
			// Unresolvable dependency (missing/corrupt Source block, or an unknown
			// block type): withhold and surface it — a permanently-stuck position
			// should be observable, not silent. Distinct from a not-yet-arrived dep.
			log.Printf("finalization: withholding vote for %s %s — unresolvable dependency %s",
				b.Type, shortHash(b.Hash), shortHash(d.hash))
			return false
		}
		if !l.IsFinalized(d.account, d.hash) {
			return false
		}
	}
	return true
}

// ---- two-phase election engine (VoteManager) ----

// thresholdMet reports whether weight ≥ quorum (67%) of total.
func thresholdMet(weight, total *big.Int) bool {
	if total == nil || weight == nil || total.Sign() == 0 {
		return false
	}
	lhs := new(big.Int).Mul(weight, big.NewInt(quorumDenominator))
	rhs := new(big.Int).Mul(total, big.NewInt(quorumNumerator))
	return lhs.Cmp(rhs) >= 0
}

// leaderHash returns the max-weight candidate, breaking ties by lowest hash.
func leaderHash(cw map[string]*big.Int) string {
	best := ""
	var bestW *big.Int
	for h, w := range cw {
		if best == "" || w.Cmp(bestW) > 0 || (w.Cmp(bestW) == 0 && h < best) {
			best, bestW = h, w
		}
	}
	return best
}

// CastVote runs the local representative's two-phase voting for a position. seed
// lists candidate hashes the caller already knows (e.g. a just-added block). It
// acquires the per-position lock; safe to call repeatedly (idempotent).
func (vm *VoteManager) CastVote(account, prev string, seed ...string) {
	mu := vm.conflictLock(account, prev)
	mu.Lock()
	defer mu.Unlock()
	vm.castVoteLocked(account, prev, seed...)
}

// castVoteLocked is CastVote assuming the per-position lock is already held (e.g.
// called from receiveVoteInner). It re-emits a converge vote only when the
// preferred candidate changed and escalates to a final vote once the lock
// condition is met. No-op for zero-weight reps.
func (vm *VoteManager) castVoteLocked(account, prev string, seed ...string) {
	if vm.keyPair == nil {
		return
	}
	// #829: vote WEIGHT is delegated to an account ADDRESS (the Representative
	// field on blocks), while a vote is SIGNED by — and keyed in the vote store
	// by — that account's public key. The two are no longer the same string, so
	// weight lookups derive the address while store lookups keep the key.
	rep := vm.keyPair.PubKeyHex()
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return // not a weighted representative
	}

	// Re-drive gate (#565): once THIS position's election is already resolved there
	// is no live vote here, so skip the work. All three 15s re-drive timers
	// (RevoteFn, OnFinalized→SweepFrontiers, the SweepFrontiers ticker) and the
	// ReceiveVote re-drive funnel through here; this single guard stops them
	// re-emitting (and re-scanning votes) for a settled position. It gates on the
	// POSITION's children, not on IsFinalized(prev): the parent at height(prev)
	// finalizes BEFORE its children fork, so IsFinalized(prev) is true for the
	// entire live election and would wrongly suppress all voting (see
	// positionResolved).
	if vm.positionResolved(account, prev) {
		return
	}

	// If we have already final-voted at this root, RE-AFFIRM it and stop — final
	// votes are irrevocable, but a peer that dropped our final vote must still
	// receive it. Final votes are not mutated and were never re-broadcast, so a node
	// that missed one can never reach the >50%/67% it needs to finalize the agreed
	// winner — its conflict record then never clears and the account stays frozen on
	// that node, even though every node agrees on the chain tip (a lagging-node
	// liveness wedge under load). Re-broadcasting our existing final vote is
	// idempotent (the receiver dedups it; the vote is immutable) and lets the laggard
	// converge. Throttled to once per revoteBackoff window per position — sharing the
	// converge re-emit stamp, so a position still emits at most one vote per window
	// (no #565 vote-storm) — and re-armed on any inbound vote. (#566)
	if existing, _ := vm.store.GetVote(account, prev, rep); existing != nil && existing.Final {
		key := account + "|" + prev
		vm.lastRevoteMu.Lock()
		last := vm.lastRevoteNanos[key]
		reEmit := last == 0 || Now().UnixNano()-last >= int64(revoteBackoff)
		vm.lastRevoteMu.Unlock()
		if reEmit && vm.VoteEmitter != nil {
			// #604: the stored final vote may not be durable yet — emitFinalLocked
			// defers emission when its durability Sync fails (#570/H1), but the vote
			// row is already written, so this branch would otherwise gossip it
			// non-durably on the next sweep, defeating the deferral. Run the same
			// sync-or-defer gate, and consume the backoff stamp only on success so
			// a deferred re-affirm retries on the next sweep.
			if s, ok := vm.store.(Syncer); ok {
				if err := s.Sync(); err != nil {
					log.Printf("re-affirm: durability sync failed, deferring final vote for %s/%s: %v", shortAddr(account), shortHash(prev), err)
					return
				}
			}
			vm.lastRevoteMu.Lock()
			vm.lastRevoteNanos[key] = Now().UnixNano()
			vm.lastRevoteMu.Unlock()
			// Re-broadcast with a FRESH timestamp + signature, NOT the stored vote
			// verbatim. The stored final vote is immutable but keeps its original
			// timestamp; once that is older than voteWindowNanos (±5 min) every peer
			// rejects it via ValidateVote, so the laggard this re-affirmation exists to
			// heal never receives it (its conflict never clears → account frozen on that
			// node) — defeating #566 for any position open longer than 5 minutes. A
			// freshly-signed vote for the SAME locked hash is semantically identical
			// (same rep, root, hash, Final) and the receiver recomputes weight, so it is
			// safe and idempotent: a peer that already holds the final vote dedups it,
			// one that dropped it stores+tallies it. The local stored vote is untouched
			// (still immutable). (#569)
			if fresh := vm.buildVote(account, prev, existing.BlockHash, true); fresh != nil {
				vm.VoteEmitter(fresh)
			}
		}
		return
	}

	// If this node already holds a commit-lock for the root, it must final-vote the
	// LOCKED hash (never a different one), regardless of current preference.
	if vm.ledger.finalVoteStore != nil {
		if locked, ok, _ := vm.ledger.finalVoteStore.GetFinalVote(account, prev); ok {
			vm.emitFinalLocked(account, prev, locked)
			return
		}
	}

	candidates := vm.gatherCandidates(account, prev, seed...)
	if len(candidates) == 0 {
		return
	}
	// #600 part 2 / #616: stamp the candidate-stability window. Record Now() the
	// first time each genuinely-NEW HELD candidate is observed at this position, so
	// maybeLockLocked can withhold the 67% quorum lock until lockStabilityWindow has
	// elapsed since the last new held sibling appeared — giving a lower-hash sibling
	// in flight time to arrive and shift our preference before any irrevocable lock
	// forms. We already hold the per-position lock here. Only HELD hashes count
	// (GetBlockOrStaged != nil): a vote for an unheld/fabricated hash must not start
	// or reset the window, else one funded rep could reset it forever and suppress
	// all locking (a liveness wedge; mirrors the #600-part-1 unheld filter).
	vm.noteHeldCandidatesLocked(account, prev, candidates)
	// #600: a candidate is PREF-ELIGIBLE only if this node holds its body (live or
	// staged) or its hash is in the conflict record — i.e. a validated body was
	// really seen at this position (recordConflict only ever records validated
	// blocks). This is the emission-layer twin of the part-1 tally filter:
	// ValidateVote never checks a vote's BlockHash is a real candidate, so a
	// validly-signed converge vote for a fabricated all-zero hash (lower than any
	// real hash) would otherwise become pref on every rep and the unheld-body
	// early-return below would silence ALL converge voting at the position — no
	// votes emitted, nothing to tally (the part-1 filter never gets a chance), no
	// finalization, network-wide, from one funded rep key. Excluding vote-only
	// unheld hashes defers nothing real: if the body exists it arrives via
	// gossip/sync, joins the held set (or the conflict record), and preference
	// shifts to it normally.
	//
	// A conflict-record sibling whose body is missing HERE stays eligible on
	// purpose: it is a live phantom the #540/#566 pull machinery is fetching, and
	// abstaining until it lands is what lets the deterministic lowest-hash winner
	// be rehydrated and elected instead of the fallback racing to finalize the
	// sibling the majority happens to hold.
	//
	// A staged sibling counts as held and votable: a fork's second block lives only
	// in staging until it resolves, but it is a real validated body. Refusing to
	// converge-vote for it would wedge an equivocated account — no node would ever
	// vote for the sibling it holds only in staging, so no candidate could reach a
	// quorum (#540).
	conflict := vm.ledger.GetConflict(account, prev)
	eligible := candidates[:0]
	for _, h := range candidates {
		if vm.ledger.GetBlockOrStaged(h) != nil ||
			(conflict != nil && containsConflictHash(conflict.BlockHashes, h)) {
			eligible = append(eligible, h)
		}
	}
	if len(eligible) == 0 {
		return // only vote-only fabricated hashes here: nothing real to vote for
	}
	pref := lowestHash(eligible)
	prefBlock := vm.ledger.GetBlockOrStaged(pref)
	if prefBlock == nil {
		return // a conflict-record sibling not held here — await the phantom pull (#540/#566)
	}
	if !vm.ledger.depsFinalized(prefBlock) {
		return // dependency gate: withhold emission (still tally incoming votes)
	}

	// Emit / replace the converge vote. A preference change (or no prior vote)
	// always emits immediately. A redundant re-emit of the SAME preference is
	// throttled to once per revoteBackoff window: this still re-broadcasts our
	// current converge vote every window — so a vote dropped at a peer is
	// re-delivered (the self-heal) — while cutting the per-tick re-drive storm
	// that saturates the vote channel. It is a throttle, never a suppressor: there
	// is no "already-converged" precondition, so a converged-but-quiet rep keeps
	// re-emitting, and a peer can never be left permanently stale. (#565)
	existing, _ := vm.store.GetVote(account, prev, rep)
	prefChanged := existing == nil || existing.BlockHash != pref || existing.Final
	emit := prefChanged
	if !emit {
		key := account + "|" + prev
		vm.lastRevoteMu.Lock()
		last := vm.lastRevoteNanos[key]
		vm.lastRevoteMu.Unlock()
		if last == 0 || Now().UnixNano()-last >= int64(revoteBackoff) {
			emit = true
		}
	}
	if emit {
		if v := vm.buildVote(account, prev, pref, false); v != nil {
			_ = vm.store.PutVote(v)
			if vm.quorumMgr != nil {
				vm.quorumMgr.OnVote(v)
			}
			if vm.VoteEmitter != nil {
				vm.VoteEmitter(v)
			}
			key := account + "|" + prev
			vm.lastRevoteMu.Lock()
			vm.lastRevoteNanos[key] = Now().UnixNano()
			vm.lastRevoteMu.Unlock()
		}
	}

	vm.maybeLockLocked(account, prev, pref)
}

// maybeLockLocked escalates to a final vote when the lock condition holds:
// a visible ≥67% converge supermajority for our preferred candidate, or — only on
// a fork older than fallbackDelay — the converge plurality leader. Caller holds
// the per-position lock.
//
// SAFETY (#538): the fallback path may only commit the durable write-once lock for
// a candidate carrying a STRICT MAJORITY (>50%) of total delegated weight in
// converge votes. A node's local plurality among the votes it happens to have seen
// is NOT evidence the network agrees: two nodes that each ingested a different
// equivocating sibling before gossip propagated would each see their own sibling
// as the sole/plurality candidate and lock divergently. Because each rep is
// commit-locked to at most one hash per root, two siblings can never both gather a
// strict majority of converge weight, so this bar lets at most one sibling be
// locked network-wide. Below the bar the position stays unlocked (recoverable
// liveness stall) instead of committing behind the unhealable rollback wall.
func (vm *VoteManager) maybeLockLocked(account, prev, pref string) {
	cw, total := vm.convergeWeights(account, prev)

	lockTarget := ""
	if thresholdMet(cw[pref], total) {
		// #600 part 2 / #616: gate ONLY the 67% quorum path behind the candidate-
		// stability window. A higher-hash sibling H can reach a transient 67%
		// converge quorum before the deterministic lower-hash winner L propagates;
		// locking immediately mirrors a commit-lock split across the network. Defer
		// the lock until lockStabilityWindow has elapsed since the last new held
		// candidate — long enough for L to arrive and flip pref to L — then lock our
		// CURRENT preference. The fallback branch below is untouched: its 10s delay
		// already exceeds the window, and it carries its own strict-majority +
		// leader==pref guards.
		if remaining, ok := vm.stabilityWindowRemaining(account, prev); ok && remaining <= 0 {
			lockTarget = pref
		} else {
			// Window not elapsed (or not yet started): withhold and arm a one-shot
			// re-drive so a quiet position finalizes one window later, not one 15s
			// sweep later.
			if remaining < 0 {
				remaining = 0
			}
			vm.scheduleStabilityRedrive(account, prev, remaining)
		}
	}
	if lockTarget == "" && vm.fallbackElapsed(account, prev) {
		leader := leaderHash(cw)
		// SAFETY (#565): the converge-fallback may only commit-lock the node's OWN
		// deterministic preference (pref = lowestHash over held candidates = the
		// global winner). Converge votes are not commit-locked, so a node that
		// dropped flip-to-winner converge votes can hold a STALE local converge
		// majority for the loser; locking leaderHash != pref would turn that stale
		// tally into a divergent, irrevocable commit-lock. Requiring leader == pref
		// means a node only ever fallback-locks the hash it would itself elect, so
		// at most one sibling is ever locked network-wide. Below this bar the
		// position stays a recoverable stall until the winner's votes propagate.
		if leader != "" && leader == pref && strictMajority(cw[leader], total) {
			lockTarget = leader
		}
	}
	if lockTarget == "" {
		return
	}
	vm.emitFinalLocked(account, prev, lockTarget)
}

// noteHeldCandidatesLocked records, for each candidate hash this node actually
// holds (live or staged), the time it was FIRST seen at the position — bumping the
// stability-window stamp only on a genuinely-new held hash. Unheld/fabricated
// hashes are ignored so they can neither start nor reset the window (#600/#616).
// Caller holds the per-position lock; this takes the independent candidateMu only
// to guard the maps.
func (vm *VoteManager) noteHeldCandidatesLocked(account, prev string, candidates []string) {
	key := account + "|" + prev
	vm.candidateMu.Lock()
	defer vm.candidateMu.Unlock()
	seen := vm.seenCandidates[key]
	if seen == nil {
		seen = make(map[string]bool)
		vm.seenCandidates[key] = seen
	}
	for _, h := range candidates {
		if seen[h] {
			continue
		}
		if vm.ledger.GetBlockOrStaged(h) == nil {
			continue // unheld: must not start or reset the window
		}
		seen[h] = true
		vm.lastNewCandidateNanos[key] = Now().UnixNano()
	}
}

// stabilityWindowRemaining reports how long is left before the 67% quorum lock path
// may fire at this position. ok is false when no held candidate has been observed
// yet (no stamp — the window has not even started, so the quorum path must wait).
// remaining <= 0 means the window has elapsed and the quorum path may lock (#600).
func (vm *VoteManager) stabilityWindowRemaining(account, prev string) (remaining time.Duration, ok bool) {
	key := account + "|" + prev
	vm.candidateMu.Lock()
	stamp := vm.lastNewCandidateNanos[key]
	vm.candidateMu.Unlock()
	if stamp == 0 {
		return lockStabilityWindow, false
	}
	elapsed := Now().UnixNano() - stamp
	return time.Duration(int64(lockStabilityWindow) - elapsed), true
}

// scheduleStabilityRedrive arms a single one-shot re-drive of this position after
// the stability window's remaining time (+ a small margin), deduped per position.
// Without it a quiet position whose quorum lock is deferred only by the window
// would wait for the 15s sweep, turning a 3s window into up-to-15s finalization
// latency. positionResolved short-circuits a settled position on re-entry, so the
// re-drive is a no-op once finalized. (#600/#616)
//
// The timers are tracked and the callbacks WaitGroup-counted so Close can cancel
// pending re-drives and wait out in-flight ones: the callback runs on its own
// goroutine and reads the replaceable clock (Now) inside CastVote, so a timer
// that outlives its VoteManager — a stopped node, or a finished test about to
// swap the clock mock — must be stoppable, not leaked.
func (vm *VoteManager) scheduleStabilityRedrive(account, prev string, remaining time.Duration) {
	key := account + "|" + prev
	vm.candidateMu.Lock()
	defer vm.candidateMu.Unlock()
	if vm.closed || vm.pendingStabilityRedrive[key] != nil {
		return
	}
	vm.redriveWG.Add(1)
	vm.pendingStabilityRedrive[key] = time.AfterFunc(remaining+100*time.Millisecond, func() {
		defer vm.redriveWG.Done()
		vm.candidateMu.Lock()
		delete(vm.pendingStabilityRedrive, key)
		closed := vm.closed
		vm.candidateMu.Unlock()
		if closed {
			return
		}
		vm.CastVote(account, prev)
	})
}

// Close cancels all pending stability re-drives and waits for any in-flight
// re-drive callback to finish, then marks the VoteManager closed (no further
// re-drives are scheduled). Idempotent. Callers stop the VoteManager when its
// node shuts down; tests close it before swapping the Now clock back.
func (vm *VoteManager) Close() {
	vm.candidateMu.Lock()
	vm.closed = true
	for key, t := range vm.pendingStabilityRedrive {
		if t.Stop() {
			// Stopped before firing: its callback (and Done) will never run.
			vm.redriveWG.Done()
		}
		delete(vm.pendingStabilityRedrive, key)
	}
	vm.candidateMu.Unlock()
	vm.redriveWG.Wait()
}

// emitFinalLocked writes the write-once commit-lock for the root and emits an
// irrevocable final vote for the LOCKED hash (which may differ from lockTarget if
// a record already existed). Withholds the final vote if the locked block's
// dependencies aren't finalized locally (retried on the next trigger/sweep).
// Caller holds the per-position lock.
func (vm *VoteManager) emitFinalLocked(account, prev, lockTarget string) {
	rep := vm.keyPair.PubKeyHex()
	locked := lockTarget
	if vm.ledger.finalVoteStore != nil {
		stored, _, err := vm.ledger.finalVoteStore.PutFinalVoteIfAbsent(account, prev, lockTarget)
		if err != nil {
			return
		}
		locked = stored
	}
	// A staged sibling is a real body the rep may final-vote (see castVoteLocked).
	lockedBlock := vm.ledger.GetBlockOrStaged(locked)
	if lockedBlock == nil {
		return
	}
	if !vm.ledger.depsFinalized(lockedBlock) {
		return // deps not finalized yet — retry later; the lock persists
	}
	if existing, _ := vm.store.GetVote(account, prev, rep); existing != nil && existing.Final && existing.BlockHash == locked {
		return // already final-voted the locked hash
	}
	v := vm.buildVote(account, prev, locked, true)
	if v == nil {
		return
	}
	if err := vm.store.PutVote(v); err != nil {
		return
	}
	// #570/H1: make the commit-lock + final vote durable BEFORE the irrevocable
	// final vote is tallied/gossiped. A crash after gossip but before the OS
	// flushes these writes (BadgerDB SyncWrites=false) would lose them; on
	// restart the rep no longer has its local final vote (the #566 re-affirm
	// needs it) and could final-vote the OTHER sibling → two conflicting
	// irrevocable final votes → #538-class divergence. On Sync failure, defer:
	// the lock persists and the next trigger/sweep retries idempotently.
	if s, ok := vm.store.(Syncer); ok {
		if err := s.Sync(); err != nil {
			log.Printf("emitFinalLocked: durability sync failed, deferring final vote for %s/%s: %v", shortAddr(account), shortHash(prev), err)
			return
		}
	}
	if vm.quorumMgr != nil {
		vm.quorumMgr.OnVote(v)
	}
	if vm.VoteEmitter != nil {
		vm.VoteEmitter(v)
	}
}

// buildVote constructs and signs a vote (converge or final) for this rep. Weight
// is the conflict's snapshot when one exists (manipulation-resistant), else the
// current delegated weight.
func (vm *VoteManager) buildVote(account, prev, blockHash string, final bool) *Vote {
	// #829: the vote is SIGNED by (and identified by) the rep's public key, but
	// the weight it carries is delegated to the rep's ACCOUNT ADDRESS. Look weight
	// up by address; the two strings are no longer interchangeable.
	rep := vm.keyPair.PubKeyHex()
	repAccount := vm.keyPair.Address()
	var w uint64
	if c := vm.ledger.GetConflict(account, prev); c != nil && c.WeightSnapshot != nil {
		w = c.WeightSnapshot[repAccount]
	} else if weight := vm.ledger.GetVoteWeight(repAccount); weight.IsUint64() {
		w = weight.Uint64()
	}
	v := &Vote{
		RepPubKey:       rep,
		BlockHash:       blockHash,
		ConflictAccount: account,
		ConflictPrev:    prev,
		Timestamp:       Now().UnixNano(),
		Final:           final,
		Weight:          w,
	}
	sb, err := voteSigningBytes(v)
	if err != nil {
		return nil
	}
	v.Signature = ed25519.Sign(vm.keyPair.Private, sb)
	return v
}

// convergeWeights tallies each representative's CURRENT vote (converge or final —
// both express a commitment to that hash) by candidate, returning the per-hash
// weight map and the election's total delegated weight.
func (vm *VoteManager) convergeWeights(account, prev string) (map[string]*big.Int, *big.Int) {
	votes, _ := vm.store.GetVotesByConflict(account, prev)
	cw := make(map[string]*big.Int)
	for _, v := range votes {
		if cw[v.BlockHash] == nil {
			cw[v.BlockHash] = new(big.Int)
		}
		cw[v.BlockHash].Add(cw[v.BlockHash], new(big.Int).SetUint64(v.Weight))
	}
	return cw, vm.electionTotalWeight(account, prev)
}

// electionTotalWeight is the conflict's snapshot total when one exists, else the
// current total delegated weight (uncontested positions).
func (vm *VoteManager) electionTotalWeight(account, prev string) *big.Int {
	if c := vm.ledger.GetConflict(account, prev); c != nil && c.TotalWeight > 0 {
		return new(big.Int).SetUint64(c.TotalWeight)
	}
	return vm.ledger.GetTotalDelegatedWeight()
}

// gatherCandidates returns the distinct candidate block hashes at a root: the
// seed(s), any block hashes that have votes, and any in a conflict record.
func (vm *VoteManager) gatherCandidates(account, prev string, seed ...string) []string {
	set := make(map[string]bool)
	for _, h := range seed {
		if h != "" {
			set[h] = true
		}
	}
	if votes, _ := vm.store.GetVotesByConflict(account, prev); votes != nil {
		for _, v := range votes {
			set[v.BlockHash] = true
		}
	}
	if c := vm.ledger.GetConflict(account, prev); c != nil {
		for _, h := range c.BlockHashes {
			set[h] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

// fallbackElapsed reports whether the election at this position has been open
// longer than fallbackDelay. Forks carry a conflict record with a detection time;
// uncontested positions don't, so fall back to the oldest vote's age — this gives
// uncontested positions the same non-voter fallback as forks, so a single
// candidate can finalize on the online weight when >1/3 of total weight is
// offline (otherwise normal finality would halt while forks still resolve). (#526)
func (vm *VoteManager) fallbackElapsed(account, prev string) bool {
	if c := vm.ledger.GetConflict(account, prev); c != nil && !c.DetectedAt.IsZero() {
		if Now().Sub(c.DetectedAt) >= fallbackDelay {
			return true
		}
	}
	return vm.positionAgeElapsed(account, prev)
}

// positionResolved reports whether the sibling election at (account, prev) is
// already finalized. The election elects the children at height(prev)+1, so it
// is resolved iff FinalHeight(account) > height(prev) — the children are at or
// below the final-height watermark. It deliberately does NOT use
// IsFinalized(account, prev): that is FinalHeight >= height(prev), which is true
// the instant the PARENT finalizes (parents finalize before their children
// fork), so it would report "resolved" for the entire live children election and
// suppress all voting on a contested account — wedging it permanently. A missing
// or not-yet-on-chain prev returns false (votable, fail-safe). (#565)
func (vm *VoteManager) positionResolved(account, prev string) bool {
	if prev == "" || prev == "0" {
		// Open position (#640): it elects the account's height-1 block, so it is
		// resolved iff that block is finalized — the same FinalHeight > height(prev)
		// rule with height("0") = 0. GetBlockHeight can never resolve "0" (it is not
		// a block), so without this branch an open position was NEVER resolved:
		// every account's open position kept re-affirming its final vote forever,
		// each inbound re-affirm re-tallied and re-cleaned the position (deleting
		// its votes, which re-arms every peer's re-emit throttle) and spawned a
		// full OnFinalized sweep. One such loop per account, growing with every
		// account ever opened — the storm that collapses finalization under load
		// once the #600 stability window lengthens the unfinalized set.
		return vm.ledger.FinalHeight(account) > 0
	}
	h, err := vm.ledger.GetBlockHeight(account, prev)
	if err != nil || h == 0 {
		return false
	}
	return vm.ledger.FinalHeight(account) > h
}

// positionAgeElapsed reports whether the earliest vote at a position is older than
// fallbackDelay. Used as the non-voter fallback timer for uncontested positions,
// which carry no conflict record / detection time. (#526)
func (vm *VoteManager) positionAgeElapsed(account, prev string) bool {
	votes, _ := vm.store.GetVotesByConflict(account, prev)
	var oldest int64
	for _, v := range votes {
		if oldest == 0 || v.Timestamp < oldest {
			oldest = v.Timestamp
		}
	}
	if oldest == 0 {
		return false
	}
	return Now().UnixNano()-oldest >= int64(fallbackDelay)
}

// SweepFrontiers re-drives finalization voting for EVERY unfinalized position on
// every account chain — not just the frontier. This is the liveness backstop: a
// vote withheld because a dependency wasn't finalized is retried once that
// dependency finalizes, including non-frontier positions an already-extended
// chain would otherwise leave unreachable, and a node that missed a block's
// add-trigger still votes. Drives lowest-unfinalized first so dependencies
// finalize before the blocks that depend on them. (#526)
//
// Singleflight (#640): concurrent calls coalesce — one sweep runs at a time,
// with at most one queued re-run (a request arriving mid-sweep may have missed
// that sweep's pass over its account, so it must not be dropped). OnFinalized
// fires `go SweepFrontiers` after every finalization/cleanup; without
// coalescing, sweep goroutines pile up under load — each walking every
// unfinalized position — and saturate the scheduler until vote ingestion
// starves and finalization collapses.
func (vm *VoteManager) SweepFrontiers() {
	vm.sweepMu.Lock()
	if vm.sweepRunning {
		vm.sweepQueued = true
		vm.sweepMu.Unlock()
		return
	}
	vm.sweepRunning = true
	vm.sweepMu.Unlock()
	for {
		vm.sweepPasses.Add(1)
		vm.sweepFrontiersOnce()
		vm.sweepMu.Lock()
		if !vm.sweepQueued {
			vm.sweepRunning = false
			vm.sweepMu.Unlock()
			return
		}
		vm.sweepQueued = false
		vm.sweepMu.Unlock()
	}
}

func (vm *VoteManager) sweepFrontiersOnce() {
	for account := range vm.ledger.Frontiers() {
		fh := vm.ledger.FinalHeight(account)
		chain := vm.ledger.GetChain(account)
		for i := int(fh); i < len(chain); i++ { // index fh (0-based) == first unfinalized
			b := chain[i]
			if b == nil || b.Type == BlockGenesis {
				continue
			}
			vm.CastVote(account, b.Previous, b.Hash)
		}
	}
}

// reaffirmFromState answers a laggard that is still voting on a position this
// node has already resolved. After finalization the cleanup deletes every
// rep's stored vote, so the #566/#569 stored-vote re-affirm has no source —
// network-wide — and a rep that missed final-vote quorum can never gather it
// again (#654: permanent one-node wedge, accounts frozen behind the
// unresolved-conflict guard on that node only). The finalized child at the
// position is behind the rollback wall, so a fresh final vote for it is a
// commitment this rep can always soundly make, whether or not it ever voted
// here before. Demand-driven only — called from the ReceiveVote conflict-not-
// found path, never from sweeps (#640 storm) — and throttled to one emission
// per revoteBackoff window per position.
func (vm *VoteManager) reaffirmFromState(account, prev string) {
	if vm.keyPair == nil || vm.VoteEmitter == nil {
		return
	}
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return // not a weighted representative
	}
	key := account + "|" + prev
	vm.lastRevoteMu.Lock()
	last := vm.lastRevoteNanos[key]
	emit := last == 0 || Now().UnixNano()-last >= int64(revoteBackoff)
	if emit {
		vm.lastRevoteNanos[key] = Now().UnixNano()
	}
	vm.lastRevoteMu.Unlock()
	if !emit {
		return
	}
	winner := vm.finalizedChildAt(account, prev)
	if winner == "" {
		return
	}
	if fresh := vm.buildVote(account, prev, winner, true); fresh != nil {
		vm.VoteEmitter(fresh)
	}
}

// VotesForPosition returns the votes this node can offer a peer that is trying to
// resolve the conflict at (account, prev): its stored votes for the position,
// plus — when this node is a weighted representative that has already finalized
// the child there — a freshly-derived, signed final vote for that finalized
// child. After finalization the cleanup deletes stored votes network-wide, so a
// lagging node pulling votes (net.PullVotes, #703) would otherwise get nothing; a
// final vote for the finalized child is a sound commitment behind the rollback
// wall, exactly like the #654 re-affirm, and lets the laggard's weight-gated
// tally reach quorum and reorg off its losing fork. This is the point-to-point
// pull answer (returned to one requesting peer), so unlike reaffirmFromState it
// does NOT gossip and is not subject to the broadcast throttle.
func (vm *VoteManager) VotesForPosition(account, prev string) []*Vote {
	out, _ := vm.store.GetVotesByConflict(account, prev)
	if vm.keyPair == nil {
		return out
	}
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return out // not a weighted representative — nothing to add
	}
	winner := vm.finalizedChildAt(account, prev)
	if winner == "" {
		return out
	}
	// Don't duplicate our own already-stored final vote for this position.
	for _, v := range out {
		if v != nil && v.RepPubKey == vm.keyPair.PubKeyHex() && v.Final {
			return out
		}
	}
	if fresh := vm.buildVote(account, prev, winner, true); fresh != nil {
		out = append(out, fresh)
	}
	return out
}

// finalizedChildAt returns the hash of the on-chain child at (account, prev)
// when that child is at or below the final-height watermark, "" otherwise.
func (vm *VoteManager) finalizedChildAt(account, prev string) string {
	open := prev == "" || prev == "0"
	chain := vm.ledger.GetChain(account)
	for i, b := range chain {
		match := b.Previous == prev || (open && i == 0)
		if !match {
			continue
		}
		if vm.ledger.FinalHeight(account) >= uint64(i+1) {
			return b.Hash
		}
		return ""
	}
	return ""
}
