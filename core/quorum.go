package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

// BlockStatus represents the finalization state of a block.
type BlockStatus uint8

const (
	StatusPending   BlockStatus = 0
	StatusFinalized BlockStatus = 1
	StatusRejected  BlockStatus = 2
)

// quorumNumerator and quorumDenominator define the 67% threshold:
// a block needs blockWeight * 100 >= totalWeight * 67 to reach quorum.
const (
	quorumNumerator   = 67
	quorumDenominator = 100
)

// fallbackDelay is how long after conflict detection before the fallback
// resolution kicks in. After this delay, if all voted weight is on a single
// block, the conflict resolves even without reaching the global 67% quorum.
// This handles cases where non-voting representatives inflate the total weight.
const fallbackDelay = 10 * time.Second

// lockStabilityWindow gates the 67% converge-quorum commit-lock path (#600 part 2
// / #616 / #568): a rep may only escalate to the irrevocable write-once commit-lock
// via the quorum path once this long has elapsed since the LAST new HELD candidate
// was first observed at the position. It must be ≫ gossip propagation (so a
// lower-hash sibling that is genuinely in flight reliably arrives and shifts the
// rep's preference before any lock forms) yet ≪ fallbackDelay (so it never delays
// the >50% fallback path, which already waits fallbackDelay and carries its own
// strict-majority + leader==pref guards). It closes the mirrored commit-lock split
// where a higher-hash sibling H reaches a transient 67% converge quorum and a
// majority of reps lock it before the deterministic lower-hash winner L propagates.
const lockStabilityWindow = 3 * time.Second

// phantomEvictionDelay is how long after conflict detection before evicting
// block hashes whose bodies cannot be loaded by this node. A "phantom" block
// is one whose hash entered a conflict record (e.g. via gossip) but whose
// body never arrived or was never persisted. Without eviction, the conflict
// is permanently stuck — the quorum can't vote on a block it can't load.
const phantomEvictionDelay = 30 * time.Second

// phantomUnretrievableTimeout bounds how long a LIVE phantom (one carrying
// converge-vote weight) may stay in a conflict record while its body remains
// unretrievable. The #566 fix retains a live phantom and re-requests its body
// forever, on the premise that a candidate the network still backs is merely a
// pull in flight and will eventually land. But a phantom whose body exists on NO
// node anywhere (the #686 shape — a hash that entered the record via gossip but
// whose body never persisted on any holder) can NEVER be served: every pull is
// futile, the live phantom is never trimmed, and because it can be the
// lowest-hash preferred candidate every rep withholds its vote awaiting the pull
// (castVoteLocked returns when prefBlock == nil) — so a real, valid sibling that
// IS present everywhere never finalizes and the account is frozen forever.
//
// After this timeout — far longer than phantomEvictionDelay, so a genuinely
// in-flight body has many sweeps and ample propagation time to arrive (the #566
// protection) — a live phantom that STILL cannot be retrieved is treated as
// droppable, but ONLY when at least one real, valid candidate remains. Dropping
// it lets resolution proceed to the deterministic winner among AVAILABLE blocks
// through the weight-gated finalTally (never a local auto-finalize — the #538
// protection). It must be ≫ phantomEvictionDelay and the 15s sweep so a slow pull
// is never mistaken for an unretrievable one.
const phantomUnretrievableTimeout = 10 * time.Minute

// failedPromotionTTL bounds how long a winner that failed full promotion stays
// quarantined (#673). ~2× the 15s sweep so a permanent reject (e.g. cert expiry)
// stays out for at least one full sweep cycle, while the quarantine never
// becomes a permanent blocklist: on expiry the entry is dropped and the
// candidate is re-evaluated, so a failure that was somehow transient is retried.
const failedPromotionTTL = 30 * time.Second

// quorumResult holds the outcome of a successful quorum tally.
type quorumResult struct {
	ConflictAccount string
	ConflictPrev    string
	WinnerHash      string
	LoserHashes     []string
	WinningWeight   uint64
	TotalWeight     uint64
}

// QuorumManager tallies votes for conflicts and confirms/rejects blocks once
// a representative quorum (67%) is reached.
type QuorumManager struct {
	conflictMgr ConflictStore
	voteMgr     VoteStore
	ledger      *Ledger
	store       QuorumStore
	mu          sync.Mutex

	// RevoteFn, if set, re-drives two-phase voting for a position during the
	// stale sweep (typically VoteManager.CastVote). Called OUTSIDE qm.mu to keep
	// the lock order (per-position lock → qm.mu) and avoid deadlock. (#526)
	RevoteFn func(account, previous string)

	// OnFinalized, if set, is invoked (asynchronously) after a block is finalized,
	// to immediately re-drive voting for positions that depend on it (typically
	// VoteManager.SweepFrontiers) instead of waiting for the next periodic sweep.
	// Fired via `go` so it never runs under qm.mu / the account lock. (#526)
	OnFinalized func()

	// PhantomPullFn, if set, is invoked during the stale sweep with the phantom
	// hashes of an open conflict — sibling blocks named in the conflict record
	// whose bodies this node never received (sync's anti-amplification guard
	// refuses to backfill a frontier it can't recognise, and the block is not
	// re-gossiped). Without both bodies a node can neither converge-vote for the
	// missing sibling nor run weighted 2-block voting, so an equivocated account
	// stalls. The node wires this to a targeted block-by-hash pull from peers; the
	// pulled body is ingested into staging and the next sweep resolves the fork
	// through the existing weight-gated finalize. MUST return promptly (the pull
	// itself runs asynchronously) — it is called under qm.mu. (#540)
	PhantomPullFn func(account, previous string, hashes []string)

	// VotePullFn, if set, is invoked during the stale sweep for a conflict the
	// node holds both/all bodies for but still cannot resolve from its LOCAL votes
	// — the #703 minority sync-reorg wedge. A lagging node that holds its own
	// non-final losing fork at (account, previous) stages the network winner as a
	// conflict, but the network already finalized that winner and (after the
	// post-finalization cleanup deleted everyone's votes) will not re-gossip the
	// final votes that would let the laggard's weight-gated tally resolve and
	// reorg off its losing fork. The node wires this to a targeted vote-by-position
	// pull from peers (net.PullVotes); the pulled final votes are ingested via
	// VoteManager.ReceiveVote, which re-drives the tally and — once quorum lands —
	// promotes the winner through the normal confirmConflict/swapBlockLocked reorg
	// (whose finality wall never reorgs a locally-finalized block). MUST return
	// promptly (the pull runs asynchronously) — called OUTSIDE qm.mu. (#703)
	VotePullFn func(account, previous string)

	// failedPromotions quarantines winners that PASSED the staged precheck
	// (promotable / the confirmConflict guard) but then FAILED full validation
	// in swapBlockLocked (#673). Keyed account|previous|hash → the time the
	// failure was recorded. promotable consults it so the sweep stops
	// re-selecting a winner confirmConflict can never promote — the no-attacker
	// trigger is a contested lease whose certificate expires between staging and
	// promotion. ONLY DETERMINISTIC rejects are recorded (gated on
	// !IsRetryableError at the call site): a transient/node-local failure must
	// never be quarantined, or two nodes could substitute different winners and
	// fork finality — the substitution is fork-safe only while promotable stays
	// a deterministic function of the finalized parent. TTL'd
	// (failedPromotionTTL) so it is a liveness aid, not a permanent blocklist.
	// Guarded by mu — every reader (promotable, via finalTally) and writer
	// (confirmConflict) holds it.
	failedPromotions map[string]time.Time
}

// NewQuorumManager creates a QuorumManager. store must implement QuorumStore;
// ledger is used to look up vote weights and block heights.
func NewQuorumManager(store QuorumStore, conflictStore ConflictStore, voteStore VoteStore, ledger *Ledger) *QuorumManager {
	return &QuorumManager{
		conflictMgr:      conflictStore,
		voteMgr:          voteStore,
		ledger:           ledger,
		store:            store,
		failedPromotions: make(map[string]time.Time),
	}
}

// failedPromotionKey identifies a winner that failed full promotion at a
// specific position (#673). The position (account|previous) is part of the key
// so the quarantine is scoped to the contested frontier, not the whole account.
func failedPromotionKey(account, previous, hash string) string {
	return account + "|" + previous + "|" + hash
}

// OnVote is called after a vote is stored (locally cast or received). It tallies
// FINAL votes at the vote's position and finalizes the winner once a block has
// ≥67% of delegated weight in final votes. Works for both contested positions (a
// conflict record + staged winner) and uncontested ones (no conflict). (#526)
func (qm *QuorumManager) OnVote(vote *Vote) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	result, err := qm.finalTally(vote.ConflictAccount, vote.ConflictPrev)
	if err != nil || result == nil {
		return
	}
	if err := qm.confirmConflict(result); err != nil {
		log.Printf("quorum: finalize for %s|%s: %v",
			shortHash(result.ConflictAccount), shortHash(result.ConflictPrev), err)
	}
}

// finalTally counts FINAL votes (Final==true) at a position, returning a
// quorumResult once a block reaches ≥67% of delegated weight — or, only for an
// aged fork, when all final votes are unanimous (non-voter fallback). Converge
// votes never finalize. Works without a conflict record (uncontested positions
// have none), using current total delegated weight as the denominator. (#526)
func (qm *QuorumManager) finalTally(account, previous string) (*quorumResult, error) {
	votes, err := qm.voteMgr.GetVotesByConflict(account, previous)
	if err != nil {
		return nil, fmt.Errorf("finalTally: GetVotesByConflict: %w", err)
	}

	weightByBlock := make(map[string]*big.Int)
	candidateSet := make(map[string]bool)
	for _, v := range votes {
		candidateSet[v.BlockHash] = true
		if !v.Final {
			continue // only final votes finalize
		}
		// #600: only hashes whose block this node holds (live or staged) may
		// gate or win the tally. ValidateVote never checks BlockHash is a real
		// candidate, so a validly-signed final vote for a fabricated hash
		// (e.g. 000…0 — lower than any real hash) would otherwise become
		// lowestFinal with ~zero weight and permanently block BOTH finalize
		// paths (final votes are irrevocable — one minimal-weight rep wedges
		// the position forever). An unheld hash can never finalize here anyway
		// (finalization needs the body), and honest reps final-vote only
		// bodies they hold (emitFinalLocked requires GetBlockOrStaged), so
		// skipping defers nothing except until the body arrives via
		// gossip/sync — at which point the vote tallies normally.
		//
		// #672: body presence is necessary but NOT sufficient. ValidateVote never
		// checks that BlockHash is a real sibling at this root, so a validly-signed
		// final vote for a held block at the WRONG position (e.g. an already-
		// finalized ancestor of the same account) would otherwise enter the tally,
		// become the lowest-hash candidate, and hijack the election via the wedge-
		// breaker / pickWinner — dropping the conflict without finalizing a real
		// child. Require the loaded body to be an actual sibling at this root:
		// Account==account && Previous==previous (the election at (account,previous)
		// elects children of previous, so every honest candidate has Previous==
		// previous by construction; this also holds for open blocks, previous=="0").
		if qm.ledger == nil {
			continue
		}
		b := qm.ledger.GetBlockOrStaged(v.BlockHash)
		if b == nil || b.Account != account || b.Previous != previous {
			continue
		}
		if weightByBlock[v.BlockHash] == nil {
			weightByBlock[v.BlockHash] = new(big.Int)
		}
		weightByBlock[v.BlockHash].Add(weightByBlock[v.BlockHash], new(big.Int).SetUint64(v.Weight))
	}

	conflict, _ := qm.conflictMgr.GetConflict(account, previous)
	var bigTotal *big.Int
	if conflict != nil {
		// All competing blocks are candidates (so losers get rejected).
		for _, h := range conflict.BlockHashes {
			candidateSet[h] = true
		}
		if conflict.TotalWeight > 0 {
			// Snapshot total from fork-detection time (manipulation-resistant).
			bigTotal = new(big.Int).SetUint64(conflict.TotalWeight)
		}
	}
	if bigTotal == nil {
		bigTotal = qm.ledger.GetTotalDelegatedWeight()
	}
	if bigTotal.Sign() == 0 {
		return nil, nil
	}

	bigThreshold := new(big.Int).Mul(bigTotal, big.NewInt(quorumNumerator))
	// #538/#570-H2: DETERMINISM on the 67% path. The tallied per-candidate weight
	// (summed from a node's local WeightSnapshot) and bigTotal (a node-local
	// detection-time snapshot) can drift between nodes, so iterating the map and
	// returning the FIRST candidate over threshold could let two honest nodes
	// finalize DIFFERENT siblings under that drift (each crossing 67% against its
	// own local weights). Only the LOWEST-HASH final-voted candidate — identical
	// on every node — may finalize here; a node that sees it below 67% withholds
	// rather than finalizing a higher-hash sibling. Each rep is commit-locked to
	// one hash per position, so the legitimate winner the majority locks is the
	// lowest hash; a higher-hash sibling never reaches a real 67% supermajority.
	// #642: winner selection is by hash, but promotion re-runs full validation —
	// a rep final-votes the lowest-hash candidate as its deterministic converge
	// target without re-checking that the block can still be promoted, so a
	// MAJORITY can final-vote a lowest-hash sibling that fails full validation
	// against the (now finalized) parent. confirmConflict then refuses it forever
	// and nothing demotes it → permanent freeze (the minter wedge). pickWinner
	// keeps the deterministic lowest-hash choice when it is promotable, but when
	// the chosen winner cannot be promoted it substitutes the lowest-hash
	// PROMOTABLE candidate. An unpromotable block can never be a valid frontier on
	// any honest node, and the substitution is a pure function of the finalized
	// parent + total hash order, so every node picks the same winner — no
	// divergence. Only trusted once the parent is finalized (validation context
	// frozen); before that, behave as before and let resolution defer.
	prevFinalized := previous == "0" || qm.ledger.IsFinalized(account, previous)
	pickWinner := func(lowest string) string {
		if lowest == "" || !prevFinalized || qm.promotable(account, previous, lowest) {
			return lowest
		}
		best := ""
		for h := range candidateSet {
			if qm.promotable(account, previous, h) && (best == "" || h < best) {
				best = h
			}
		}
		if best != "" && best != lowest {
			log.Printf("quorum: winner %s for %s|%s is unpromotable (fails full validation) — substituting lowest-hash promotable candidate %s (#642)",
				shortHash(lowest), shortHash(account), shortHash(previous), shortHash(best))
		}
		return best
	}

	lowestFinal := ""
	for h := range weightByBlock {
		if lowestFinal == "" || h < lowestFinal {
			lowestFinal = h
		}
	}
	if lowestFinal != "" {
		if new(big.Int).Mul(weightByBlock[lowestFinal], big.NewInt(quorumDenominator)).Cmp(bigThreshold) >= 0 {
			if w := pickWinner(lowestFinal); w != "" {
				return buildResultFrom(account, previous, w, candidateSet), nil
			}
		}
	}

	// Strict-majority fallback: once the election has been open longer than
	// fallbackDelay, finalize the candidate holding a STRICT MAJORITY (>50%) of
	// total delegated weight in FINAL votes, even below the 67% quorum. Covers
	// >1/3 of weight offline, for BOTH contested positions (conflict DetectedAt)
	// and uncontested ones (oldest final-vote age) — so normal finality doesn't
	// halt while forks still resolve. (#526)
	//
	// SAFETY (#538): finalize the LOWEST-HASH candidate that carries final votes,
	// and only when it holds a STRICT MAJORITY (>50%) of total weight in FINAL votes.
	// Two independent guards, each sufficient to forbid divergent finalization, and
	// together robust even under per-node weight-snapshot drift:
	//
	//  - DETERMINISM: the lowest hash is identical on every node, so the fallback
	//    winner is deterministic. Two honest nodes can never finalize DIFFERENT
	//    siblings of a position — each either finalizes this same lowest-hash
	//    candidate or withholds. (The candidate's weight, summed from a node's local
	//    WeightSnapshot, and bigTotal, a node-local detection-time snapshot, can
	//    drift between nodes; picking max-weight could then let two nodes finalize
	//    different siblings. Picking lowest-hash removes that: a node that sees the
	//    lowest-hash candidate below 50% simply withholds — it never finalizes a
	//    higher-hash sibling instead.)
	//  - STRICT MAJORITY: because each rep is commit-locked to at most one hash per
	//    root, two candidates can never each gather >50% of final weight — so at most
	//    one block clears the bar, and a position backed by ≤50% stays a recoverable
	//    liveness stall rather than finalizing behind the unhealable rollback wall.
	//
	// This deliberately does NOT require a single candidate with final votes (the old
	// len==1 gate). A COMMIT-LOCK SPLIT — an earlier-propagating sibling gathers a
	// transient converge quorum and a minority of reps lock it via the 67% path, then
	// the lower-hash winner arrives and the majority lock IT — leaves two candidates
	// with final votes (e.g. a 60% lower-hash winner / 40% loser), neither at 67%,
	// and the len==1 gate would stall it forever. The lowest-hash >50% winner is safe
	// to finalize and the same on every node; the higher-hash sibling never
	// finalizes anywhere. (#538/#566)
	if len(weightByBlock) > 0 {
		aged := false
		if conflict != nil && !conflict.DetectedAt.IsZero() {
			aged = Now().Sub(conflict.DetectedAt) >= fallbackDelay
		}
		if !aged {
			var oldest int64
			for _, v := range votes {
				if v.Final && (oldest == 0 || v.Timestamp < oldest) {
					oldest = v.Timestamp
				}
			}
			aged = oldest != 0 && Now().UnixNano()-oldest >= int64(fallbackDelay)
		}
		if aged {
			lowest := ""
			for h := range weightByBlock {
				if lowest == "" || h < lowest {
					lowest = h
				}
			}
			lowestWeight := weightByBlock[lowest]
			if strictMajority(lowestWeight, bigTotal) {
				if w := pickWinner(lowest); w != "" {
					log.Printf("quorum: fallback finalize for %s|%s on %s (lowest-hash candidate, strict-majority final weight %s of %s, %d candidate(s) with final votes)",
						shortHash(account), shortHash(previous), shortHash(w), lowestWeight, bigTotal, len(weightByBlock))
					return buildResultFrom(account, previous, w, candidateSet), nil
				}
			}
			// #570 C1-tiebreak / #600 part 2 / #568: the deterministic WEDGE-BREAKER.
			// The fallback withholds because the lowest-hash candidate is ≤50% — but
			// in the mirrored commit-lock split a MAJORITY irrevocably commit-locked a
			// HIGHER-hash sibling first, so the lowest can NEVER reach >50% and the
			// higher is never a fallback target → permanent stall. When a strict
			// majority of total weight is already irrevocably final-voted onto
			// NON-lowest candidates, the lowest provably cannot win, so resolve the
			// position by finalizing the lowest-hash final-voted candidate.
			//
			// Safe under per-node weight drift: the winner is the lowest hash —
			// identical on every node regardless of local snapshots — so two nodes can
			// never finalize different siblings. The trigger is monotonic in the
			// irrevocable, gossiped final-vote set (non-lowest weight only grows), so
			// every node eventually fires it. This trades the "weight-majority wins"
			// outcome for liveness+determinism in the provably-wedged case; the higher-
			// hash sibling the majority locked is never finalized anywhere.
			nonLowest := new(big.Int)
			for h, w := range weightByBlock {
				if h != lowest {
					nonLowest.Add(nonLowest, w)
				}
			}
			if strictMajority(nonLowest, bigTotal) {
				if w := pickWinner(lowest); w != "" {
					log.Printf("quorum: WEDGE-BREAKER finalize for %s|%s on %s (lowest-hash candidate; %s of %s total weight irrevocably final-voted onto %d higher-hash sibling(s), so the lowest can never reach a majority — resolving the split deterministically)",
						shortHash(account), shortHash(previous), shortHash(w), nonLowest, bigTotal, len(weightByBlock)-1)
					return buildResultFrom(account, previous, w, candidateSet), nil
				}
			}
			log.Printf("quorum: WITHHOLDING fallback finalize for %s|%s — lowest-hash candidate %s holds only %s of %s "+
				"final-vote weight (≤50%%) across %d candidate(s); no strict majority, finalizing now could fork finality (#538)",
				shortHash(account), shortHash(previous), shortHash(lowest), lowestWeight, bigTotal, len(weightByBlock))
		}
	}

	return nil, nil
}

// strictMajority reports whether weight is strictly greater than half of total
// (weight*2 > total). Used to gate the non-voter fallback finalize: because each
// representative is commit-locked to a single hash per root, at most one block can
// hold a strict majority of total delegated weight in final votes — so requiring
// it makes divergent fallback-finalization of two equivocating siblings
// impossible while preserving liveness whenever a majority of weight is online. (#538)
func strictMajority(weight, total *big.Int) bool {
	if total == nil || weight == nil || total.Sign() == 0 {
		return false
	}
	return new(big.Int).Mul(weight, big.NewInt(2)).Cmp(total) > 0
}

// buildResultFrom builds a quorumResult: the winner plus every other candidate as
// a loser (to be rejected).
func buildResultFrom(account, previous, winner string, candidateSet map[string]bool) *quorumResult {
	var losers []string
	for h := range candidateSet {
		if h != winner {
			losers = append(losers, h)
		}
	}
	return &quorumResult{
		ConflictAccount: account,
		ConflictPrev:    previous,
		WinnerHash:      winner,
		LoserHashes:     losers,
	}
}

// promotable reports whether the candidate hash can become the account's
// frontier at this position: a block already on the main chain was validated
// when added, and a staged block must pass the same full validation
// confirmConflict applies (ValidateStagedBlock against the parent balance). A
// candidate whose body is absent cannot be promoted. Used by finalTally to
// avoid selecting a winner that confirmConflict will refuse forever (#642).
// Deterministic across nodes once the parent is finalized — the validation
// context (parent balance) is then frozen by the rollback wall.
func (qm *QuorumManager) promotable(account, previous, hash string) bool {
	if h, err := qm.ledger.GetBlockHeight(account, hash); err == nil {
		// #672: on-chain is necessary but not sufficient to be promotable AT THIS
		// root. A real sibling sits exactly one above the contested root, so require
		// height(hash)==height(previous)+1 (or height 1 for an open position,
		// previous=="0"). Without this, an already-finalized ANCESTOR — on-chain but
		// at the wrong height — counts as promotable, letting pickWinner substitute
		// it as the winner when the deterministic lowest-hash choice cannot promote.
		if previous == "0" {
			return h == 1
		}
		ph, perr := qm.ledger.GetBlockHeight(account, previous)
		return perr == nil && h == ph+1
	}
	// #673: a staged candidate that passed THIS precheck but then failed full
	// validation during promotion (swapBlockLocked) is quarantined so the sweep
	// stops re-selecting it forever. Expire stale entries lazily so the
	// quarantine is a TTL'd liveness aid, never a permanent blocklist. (Caller
	// holds qm.mu.)
	key := failedPromotionKey(account, previous, hash)
	if recordedAt, ok := qm.failedPromotions[key]; ok {
		if Now().Sub(recordedAt) < failedPromotionTTL {
			return false
		}
		delete(qm.failedPromotions, key)
	}
	staged, err := qm.conflictMgr.GetStagedBlock(hash)
	if err != nil || staged == nil {
		return false // no body to promote
	}
	asset := staged.Asset
	if asset == "" {
		asset = "XE"
	}
	var parentBalance uint64
	if previous != "0" {
		parentBalance = qm.ledger.GetAssetBalanceAtBlock(account, asset, previous)
	}
	return qm.ledger.ValidateStagedBlock(staged, parentBalance) == nil
}

// confirmConflict finalises a conflict resolution: promotes the winning block
// to the main chain (if it was in staging), rejects losers, cleans up votes,
// and removes the conflict record.
func (qm *QuorumManager) confirmConflict(result *quorumResult) error {
	// Idempotency guard is HEIGHT-based, not status-based (#526): a winner whose
	// final height has been advanced is truly done. A status byte alone is not
	// enough — if final votes arrived for a block not yet on this node's chain we
	// may have set its status without advancing the watermark; re-running once the
	// block is present must still advance it.
	if qm.ledger.IsFinalized(result.ConflictAccount, result.WinnerHash) {
		// The winner is already finalized — by a prior confirmConflict run, or by
		// the per-block #526 finality that finalized it before this conflict
		// election resolved. The swap + finalize is done, but the conflict record
		// and loser blocks may still be present, which leaves the account wedged
		// behind the unresolved-conflict guard (the original early `return nil`
		// skipped the cleanup below). Run the idempotent cleanup so it clears (#555).
		entry := qm.ledger.acquireAccountLock(result.ConflictAccount)
		defer qm.ledger.releaseAccountLock(result.ConflictAccount, entry)
		qm.cleanupResolvedConflict(result)
		return nil
	}

	// Hold the per-account lock for the entire conflict resolution to prevent
	// AddBlock from processing children of the loser block during the swap.
	entry := qm.ledger.acquireAccountLock(result.ConflictAccount)
	defer qm.ledger.releaseAccountLock(result.ConflictAccount, entry)

	// Check if the winner is in staging (it was the second block seen).
	// If so, promote it to the main chain by swapping out the loser.
	winnerBlock, err := qm.conflictMgr.GetStagedBlock(result.WinnerHash)
	if err != nil {
		return fmt.Errorf("confirmConflict: GetStagedBlock: %w", err)
	}
	// Promote a staged winner — but only if it isn't already on the main chain
	// (a prior run may have swapped it, then failed a later step). #526
	if winnerBlock != nil {
		if _, onChain := qm.ledger.GetBlockHeight(result.ConflictAccount, result.WinnerHash); onChain != nil {
			if err := VerifyBlock(winnerBlock); err != nil {
				return fmt.Errorf("confirmConflict: verify winner: %w", err)
			}
			if qm.ledger.difficulty > 0 {
				hashBytes, derr := hex.DecodeString(winnerBlock.Hash)
				if derr != nil {
					return fmt.Errorf("confirmConflict: decode winner hash: %w", derr)
				}
				if !ValidatePoW(hashBytes, winnerBlock.PoWNonce, qm.ledger.difficulty) {
					return fmt.Errorf("confirmConflict: winner block %s failed PoW validation", shortHash(result.WinnerHash))
				}
			}

			asset := winnerBlock.Asset
			if asset == "" {
				asset = "XE"
			}
			var parentBalance uint64
			if result.ConflictPrev != "0" {
				parentBalance = qm.ledger.GetAssetBalanceAtBlock(result.ConflictAccount, asset, result.ConflictPrev)
			}
			if err := qm.ledger.ValidateStagedBlock(winnerBlock, parentBalance); err != nil {
				log.Printf("confirmConflict: staged winner %s failed validation: %v — refusing promotion",
					shortHash(result.WinnerHash), err)
				return fmt.Errorf("confirmConflict: invalid staged winner: %w", err)
			}

			// Find which loser is ON the main chain and swap the winner in. Use
			// GetBlockHeight (on-chain membership), NOT GetBlock (mere existence):
			// a losing sibling already rolled back off-chain by a cross-account
			// cascade still exists in the store, and attempting to swap it fails
			// forever with "block not found in chain" (#709).
			swapped := false
			for _, loserHash := range result.LoserHashes {
				if _, lerr := qm.ledger.GetBlockHeight(result.ConflictAccount, loserHash); lerr != nil {
					continue // not on the main chain — nothing to swap out
				}
				mainBlock := qm.ledger.GetBlock(loserHash)
				if mainBlock != nil {
					// Save demoted block to staging BEFORE swapping, so it's
					// preserved even if SwapBlock succeeds but a later step fails.
					if err := qm.conflictMgr.SaveStagedBlock(mainBlock); err != nil {
						return fmt.Errorf("confirmConflict: SaveStagedBlock (demoted): %w", err)
					}
					if err := qm.ledger.swapBlockLocked(result.ConflictAccount, loserHash, result.WinnerHash, winnerBlock); err != nil {
						// #673: the winner passed the staged precheck but failed FULL
						// validation here. Quarantine it ONLY when the reject is
						// deterministic (a non-retryable ErrWinnerFullValidation, e.g. a
						// cert that expired between staging and promotion) so the next
						// sweep substitutes a promotable candidate instead of
						// re-selecting this one forever. A retryable failure (epoch
						// behind, badger txn conflict) or a non-validation swap error
						// (build-undo / activate-cascade) is left un-quarantined:
						// quarantining a transient/node-local failure could make two
						// nodes substitute different winners and fork finality. All
						// confirmConflict callers hold qm.mu, so this map write is safe.
						if errors.Is(err, ErrWinnerFullValidation) && !IsRetryableError(err) {
							qm.failedPromotions[failedPromotionKey(result.ConflictAccount, result.ConflictPrev, result.WinnerHash)] = Now()
							log.Printf("confirmConflict: winner %s for %s|%s failed full validation deterministically — quarantining for %s so the sweep substitutes a promotable candidate (#673): %v",
								shortHash(result.WinnerHash), shortHash(result.ConflictAccount), shortHash(result.ConflictPrev), failedPromotionTTL, err)
						}
						return fmt.Errorf("confirmConflict: SwapBlock: %w", err)
					}
					swapped = true
					break
				}
			}
			if !swapped {
				// No candidate is on the main chain. If the winner simply extends the
				// current frontier (the losing sibling was already rolled back off-chain),
				// it just needs to be APPENDED, not swapped — append it through the normal
				// validate+add path, then finalize below. If it can't be appended yet (a
				// dependency such as its source send is still pending on a not-yet-healed
				// account), leave it staged and retry on the next sweep. (#709)
				appended, aerr := qm.appendStagedWinner(result, winnerBlock)
				if aerr != nil {
					return fmt.Errorf("confirmConflict: append winner: %w", aerr)
				}
				if !appended {
					// Cannot promote yet (winner doesn't extend the frontier, or a
					// dependency isn't ready). Leave staging intact and retry later;
					// don't mark anything finalized. #526
					return nil
				}
			}
		}
	}

	// Advance the final-height watermark FIRST — right after the swap, before the
	// fallible cleanup — so a later-step failure can't leave a promoted winner with
	// an unadvanced watermark (which would wedge the position on retry). Only when
	// the winner is on this node's main chain; if final votes arrived for a block we
	// don't yet hold, set status only and let a later re-tally advance the height
	// once it is present (the height-based idempotency guard re-enters). Monotonic:
	// never lower the watermark. #525/#526
	if height, herr := qm.ledger.GetBlockHeight(result.ConflictAccount, result.WinnerHash); herr == nil {
		if cur, _ := qm.store.GetFinalHeight(result.ConflictAccount); height > cur {
			if err := qm.store.SetFinalHeight(result.ConflictAccount, height); err != nil {
				return fmt.Errorf("confirmConflict: SetFinalHeight: %w", err)
			}
			// #833: the one place a watermark advances post-bootstrap. Counting it
			// gives /node a positive liveness signal, so "nothing has finalized
			// since startup" can be alarmed on instead of read as healthy.
			qm.ledger.recordFinalityAdvance()
			// Observation only — no control flow depends on it. #833's counter
			// above answers "did anything finalize"; this answers "how much,
			// and how long did it take", which #833 does not track. Counting
			// the watermark delta rather than one per call keeps it exact
			// under re-tally (#841).
			observeFinalityAdvance(height-cur, qm.ledger.GetBlockOrStaged(result.WinnerHash))
		}
	}

	if err := qm.finalizeBlock(result.WinnerHash); err != nil {
		return err
	}

	// Reject the losers and remove the conflict record so the account is not left
	// wedged behind the unresolved-conflict guard. Runs to completion even on a
	// transient per-step error (#555). Idempotent.
	qm.cleanupResolvedConflict(result)
	return nil
}

// appendStagedWinner promotes a staged winner that EXTENDS the current frontier —
// the case where the losing sibling was already rolled back off-chain so there is
// nothing to swap. It validates and appends the winner through the normal add path
// (dispatchValidateAndAdd) under the held account lock. Returns (true,nil) on a
// successful append; (false,nil) when the winner can't be promoted yet — it does
// not extend the frontier, or a dependency such as its source send is still
// pending on a not-yet-healed account (retry next sweep); (false,err) on a hard
// failure. Caller holds the account lock. (#709)
func (qm *QuorumManager) appendStagedWinner(result *quorumResult, winnerBlock *Block) (bool, error) {
	chain, err := qm.ledger.store.GetAccountChain(result.ConflictAccount)
	if err != nil {
		return false, err
	}
	frontier := "0"
	if chain != nil && len(chain.Blocks) > 0 {
		frontier = chain.Blocks[len(chain.Blocks)-1].Hash
	}
	if winnerBlock.Previous != frontier {
		// The winner doesn't extend the frontier (a deeper reorg or a gap, not a
		// plain append). Leave it for the swap path / a later sweep.
		return false, nil
	}
	if err := qm.ledger.dispatchValidateAndAdd(winnerBlock, true); err != nil {
		if IsRetryableError(err) {
			return false, nil // dependency not ready (e.g. source send not pending) — retry
		}
		return false, err
	}
	return true, nil
}

// cleanupResolvedConflict performs the post-resolution cleanup for a conflict
// whose winner is finalized: it rejects the loser blocks, clears their staging
// entries and votes, and — critically — removes the conflict record so the
// account can advance again. It must run even when the winner was finalized by
// the per-block #526 path or by a prior confirmConflict run that finalized but
// failed before this cleanup, so it is idempotent and the caller invokes it from
// the already-finalized guard too (#555). None of the steps abort the cleanup:
// leaving the conflict record behind is a permanent account wedge, which is far
// worse than a loser block carrying a stale status byte — so every step logs on
// error and continues, and RemoveConflict always runs. Caller holds the account
// lock.
func (qm *QuorumManager) cleanupResolvedConflict(result *quorumResult) {
	if err := qm.conflictMgr.DeleteStagedBlock(result.WinnerHash); err != nil {
		log.Printf("confirmConflict: DeleteStagedBlock(winner %s): %v", shortHash(result.WinnerHash), err)
	}
	if err := qm.rejectBlocks(result.LoserHashes); err != nil {
		log.Printf("confirmConflict: rejectBlocks: %v — continuing cleanup", err)
	}
	for _, loserHash := range result.LoserHashes {
		if err := qm.conflictMgr.DeleteStagedBlock(loserHash); err != nil {
			log.Printf("confirmConflict: DeleteStagedBlock(loser %s): %v", shortHash(loserHash), err)
		}
	}
	if err := qm.store.DeleteVotesForConflict(result.ConflictAccount, result.ConflictPrev); err != nil {
		log.Printf("confirmConflict: DeleteVotesForConflict: %v", err)
	}
	RemoveConflict(qm.conflictMgr, result.ConflictAccount, result.ConflictPrev)

	// Immediately re-drive dependent positions (a receive whose source just
	// finalized, etc.) instead of waiting up to one sweep interval. Async — never
	// under qm.mu / the account lock. (#526)
	if qm.OnFinalized != nil {
		go qm.OnFinalized()
	}
}

// StartStaleConflictSweep launches a background goroutine that periodically
// re-tallies unresolved conflicts. This ensures the fallback resolution
// triggers even when no new votes arrive after the delay period.
func (qm *QuorumManager) StartStaleConflictSweep(stop <-chan struct{}) {
	go func() {
		// #702: drop orphaned conflicts left by a cross-account cascade rollback
		// immediately at boot — they survive cold-sync (the conflict store is
		// rebuilt state) and would otherwise persist until the first tick.
		qm.pruneOrphanedConflicts()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				qm.sweepStaleConflicts()
			}
		}
	}()
}

// pruneOrphanedConflicts drops every conflict record whose candidates have all
// left the account's canonical chain — see dropConflictIfOrphaned. Called once at
// startup (cold-sync / restart) so an orphaned record from a pre-restart cascade
// is cleared even before the first sweep tick. (#702)
func (qm *QuorumManager) pruneOrphanedConflicts() {
	conflicts, err := qm.conflictMgr.GetAllConflicts()
	if err != nil {
		return
	}
	dropped := 0
	for _, c := range conflicts {
		if qm.dropConflictIfOrphaned(c) {
			dropped++
		}
	}
	if dropped > 0 {
		log.Printf("quorum: pruned %d orphaned conflict record(s) at startup (#702)", dropped)
	}
}

// dropConflictIfOrphaned removes the conflict record for c if it is orphaned by a
// cross-account cascade rollback: the chain position it sat on was unwound, so it
// can never resolve (confirmConflict finds no loser on-chain to swap, and the
// phantom sweep re-drives votes forever). Such a record permanently breaks any
// "conflicts == 0 at rest" gate and survives cold-sync. The check + delete run
// under the account lock so an in-flight swap/confirm cannot race. Returns true
// iff the record was dropped. (#702, #686/#279 class)
func (qm *QuorumManager) dropConflictIfOrphaned(c *Conflict) bool {
	entry := qm.ledger.acquireAccountLock(c.AccountAddress)
	defer qm.ledger.releaseAccountLock(c.AccountAddress, entry)
	if !qm.conflictOrphanedByRollback(c) {
		return false
	}
	log.Printf("quorum: dropping orphaned conflict %s|%s — its chain position was rolled back (a candidate is rejected and the parent is no longer on the canonical chain) (#702)",
		shortHash(c.AccountAddress), shortHash(c.PreviousHash))
	if err := qm.store.DeleteVotesForConflict(c.AccountAddress, c.PreviousHash); err != nil {
		log.Printf("quorum: DeleteVotesForConflict (orphan drop) for %s|%s: %v",
			shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
	}
	RemoveConflict(qm.conflictMgr, c.AccountAddress, c.PreviousHash)
	return true
}

// dropConflictIfResolved removes the conflict record for c when its position has
// already been finalized locally but the record lingered — the #707 cleanup gap.
// cleanupResolvedConflict normally fires from confirmConflict, which needs
// finalTally to still see a quorum of votes; once the network finalizes the
// winner and the post-finalization cleanup deletes everyone's votes, a node that
// finalized the winner but failed to clean its own record can never re-confirm
// (finalTally finds no votes → no confirmConflict), and ReceiveVote drops any
// inbound/pulled vote because the position is resolved. The account then stays
// wedged behind the unresolved-conflict guard forever. A finalized child is
// irrevocable, so running the idempotent cleanup directly is always correct.
// Takes qm.mu + the account lock to match confirmConflict's cleanup context.
// Returns true iff the record was dropped. (#707)
func (qm *QuorumManager) dropConflictIfResolved(c *Conflict) bool {
	winner := qm.ledger.FinalizedChildHash(c.AccountAddress, c.PreviousHash)
	if winner == "" {
		return false
	}
	losers := make([]string, 0, len(c.BlockHashes))
	for _, h := range c.BlockHashes {
		if h != winner {
			losers = append(losers, h)
		}
	}
	log.Printf("quorum: cleaning resolved-but-lingering conflict %s|%s — child %s is finalized but the record persisted (votes cleaned up network-wide) (#707)",
		shortHash(c.AccountAddress), shortHash(c.PreviousHash), shortHash(winner))
	qm.mu.Lock()
	entry := qm.ledger.acquireAccountLock(c.AccountAddress)
	qm.cleanupResolvedConflict(&quorumResult{
		ConflictAccount: c.AccountAddress,
		ConflictPrev:    c.PreviousHash,
		WinnerHash:      winner,
		LoserHashes:     losers,
	})
	qm.ledger.releaseAccountLock(c.AccountAddress, entry)
	qm.mu.Unlock()
	return true
}

// conflictOrphanedByRollback reports whether c is a #702 rollback orphan: the
// chain position it sat on was unwound by a cross-account cascade so it can never
// resolve. Caller holds the account lock. The predicate is deliberately narrow to
// avoid touching #540/#566 phantom conflicts (live conflicts whose bodies are
// merely missing locally, which the phantom machinery handles):
//
//   - the PARENT position is dead — the `previous` both siblings extend is no
//     longer on the account's canonical chain (for an open conflict, previous "0",
//     that means the account is now chainless). A live conflict's parent is still
//     on-chain (its on-chain sibling extends it), so this is false for one;
//   - NO candidate is on the canonical chain (a resolved/winning conflict keeps
//     its winner there);
//   - at least one candidate is StatusRejected — a block THIS node definitively
//     rolled back. This is what distinguishes a real rollback orphan from a
//     phantom (bodies never applied here, so never rejected) or a never-synced
//     position; force-dropping either of those would re-open #540/#566.
func (qm *QuorumManager) conflictOrphanedByRollback(c *Conflict) bool {
	chain, err := qm.ledger.store.GetAccountChain(c.AccountAddress)
	if err != nil {
		return false // transient read error — don't drop on uncertainty
	}
	onChain := make(map[string]bool)
	if chain != nil {
		for _, b := range chain.Blocks {
			onChain[b.Hash] = true
		}
	}
	chainless := chain == nil || len(chain.Blocks) == 0

	positionDead := false
	if c.PreviousHash == "0" {
		positionDead = chainless
	} else {
		positionDead = !onChain[c.PreviousHash]
	}
	if !positionDead {
		return false
	}
	for _, h := range c.BlockHashes {
		if onChain[h] {
			return false
		}
	}
	for _, h := range c.BlockHashes {
		if st, _ := qm.store.GetBlockStatus(h); st == StatusRejected {
			return true
		}
	}
	return false
}

func (qm *QuorumManager) sweepStaleConflicts() {
	conflicts, err := qm.conflictMgr.GetAllConflicts()
	if err != nil {
		return
	}
	for _, c := range conflicts {
		// #707: the position is already finalized locally but the conflict record
		// lingered (votes cleaned up network-wide, so finalTally can no longer
		// re-confirm and ReceiveVote drops pulled votes as already-resolved). Run
		// the idempotent cleanup directly before any other machinery.
		if qm.dropConflictIfResolved(c) {
			continue
		}
		// #702: a conflict whose candidates have all left the account's canonical
		// chain (a cross-account cascade rolled back the chain segment it sat on)
		// can never resolve. Drop it before the phantom/revote machinery, which
		// would otherwise re-drive votes for it forever.
		if qm.dropConflictIfOrphaned(c) {
			continue
		}

		age := Now().Sub(c.DetectedAt)

		// Phantom block eviction: if any block hash in the conflict can't be
		// loaded after phantomEvictionDelay, request the missing bodies and trim
		// what's unrecoverable. If eviction leaves the conflict open with every
		// body now present (a phantom pull landed both siblings), fall through to
		// drive convergence; otherwise the conflict was resolved, dropped, or is a
		// recoverable single-real stall — `continue` and let a later sweep retry
		// once the pull delivers the missing body. (#540)
		if age >= phantomEvictionDelay {
			qm.mu.Lock()
			fullyLoaded := qm.evictPhantomsAndResolve(c)
			qm.mu.Unlock()
			if !fullyLoaded {
				continue
			}
		} else if age < fallbackDelay {
			continue
		}
		// Re-drive two-phase voting (converge → final, incl. plurality fallback on
		// aged forks). Called outside qm.mu — RevoteFn takes the per-position lock
		// and itself triggers finalize via OnVote. Lock order: position → qm.mu.
		if qm.RevoteFn != nil {
			qm.RevoteFn(c.AccountAddress, c.PreviousHash)
		}
		qm.mu.Lock()
		result, err := qm.finalTally(c.AccountAddress, c.PreviousHash)
		if err == nil && result != nil {
			if err := qm.confirmConflict(result); err != nil {
				log.Printf("quorum: confirmConflict (sweep) for %s|%s: %v",
					shortHash(result.ConflictAccount), shortHash(result.ConflictPrev), err)
			}
		}
		unresolved := result == nil
		qm.mu.Unlock()

		// #703: the conflict aged out without resolving from LOCAL votes. If this
		// node holds its own non-final losing fork at the position while the network
		// finalized the sibling, the resolving final votes were cleaned up network-
		// wide and are never re-gossiped — so re-driving local voting (RevoteFn) can
		// never reach quorum. Pull the votes from peers (their finalized state yields
		// a fresh final vote); ReceiveVote then re-drives the tally and the next
		// sweep promotes the winner via the normal reorg. Called outside qm.mu (the
		// pull runs asynchronously). Bounded to genuinely-stalled aged conflicts.
		if unresolved && qm.VotePullFn != nil {
			qm.VotePullFn(c.AccountAddress, c.PreviousHash)
		}
	}
}

// evictPhantomsAndResolve handles a conflict that has aged past
// phantomEvictionDelay. It classifies the conflict's hashes into real bodies
// (loadable from the chain or staging) and phantoms (bodies never received),
// requests the phantom bodies from peers (PhantomPullFn), and trims or drops
// what cannot be resolved locally. It returns true only when the conflict is
// still open with EVERY body present (no phantoms) — the caller then re-drives
// weighted voting to converge the fork. Otherwise it returns false: the conflict
// was resolved, dropped, or is a recoverable single-real stall awaiting a pulled
// body. Caller must hold qm.mu. (#538/#540)
func (qm *QuorumManager) evictPhantomsAndResolve(c *Conflict) bool {
	var realBlocks []string
	var phantoms []string
	for _, h := range c.BlockHashes {
		// A sibling whose body is only in staging (the second block of a fork, or
		// one pulled to resolve a phantom conflict) is a real, validated body — not
		// a phantom. Counting it as real lets weighted 2-block voting run and the
		// fork converge instead of stalling (#540).
		if qm.ledger.GetBlockOrStaged(h) != nil {
			realBlocks = append(realBlocks, h)
		} else {
			phantoms = append(phantoms, h)
		}
	}

	if len(phantoms) == 0 {
		return true // both bodies present — the sweep re-drives voting to converge
	}

	// One or more sibling bodies are still missing. Ask peers for them by hash so a
	// later sweep holds both real blocks and the existing weight-gated voting can
	// resolve the fork. The pull is best-effort and asynchronous; meanwhile the
	// branches below keep the conflict in a safe, recoverable state. (#540)
	if qm.PhantomPullFn != nil {
		qm.PhantomPullFn(c.AccountAddress, c.PreviousHash, phantoms)
	}

	// Split the phantoms by whether they still carry converge-vote weight. A LIVE
	// phantom is a candidate a weighted representative prefers (its hash is carried
	// network-wide by votes) whose body is merely missing HERE — a pull in flight,
	// a holder briefly unreachable, the body lost to a restart. A DEAD phantom has
	// no vote weight: a hash that entered the record but that no rep is backing.
	//
	// A live phantom MUST stay in the conflict record and under the pull. The
	// periodic sweep only re-requests hashes still in the record (this function
	// derives `phantoms` from c.BlockHashes), so trimming a live phantom strands
	// it: a single missed pull becomes permanent, because the sweep never asks for
	// the body again, while the persisted votes keep that candidate the preferred
	// winner — so it can never be rehydrated, never finalizes, and the account
	// stays frozen behind the unresolved-conflict guard forever. That is the #566
	// block-availability deadlock. Only dead phantoms are safe to trim. (#566)
	livePhantoms, deadPhantoms := qm.splitPhantomsByVoteWeight(c.AccountAddress, c.PreviousHash, phantoms)

	// #686: a LIVE phantom that has stayed unretrievable far past
	// phantomUnretrievableTimeout — re-requested every sweep but never served by any
	// peer because its body exists on NO node — must not strand a real, valid sibling
	// forever. When at least one real candidate remains, reclassify such a stale live
	// phantom as droppable so the dead-phantom trim below removes it and the survivor
	// is routed through the weight-gated finalTally (no local auto-finalize — #538).
	// Gated on a real block existing: with none present (only the live phantom backed
	// network-wide), dropping would un-freeze the account behind a still-unresolved
	// preferred sibling (the spend-before-final hole the #566 retain-and-pull guards),
	// so the live phantom is kept there as before. The long timeout is the #566
	// protection: a body merely in flight has many sweeps to arrive before it is ever
	// reclassified, so a slow pull is never mistaken for an unretrievable one.
	if len(realBlocks) > 0 && len(livePhantoms) > 0 && Now().Sub(c.DetectedAt) >= phantomUnretrievableTimeout {
		log.Printf("quorum: dropping %d unretrievable live phantom(s) from conflict %s|%s after %v "+
			"(body served by no peer; %d real candidate(s) remain) — resolving via the weight-gated tally (#686)",
			len(livePhantoms), shortHash(c.AccountAddress), shortHash(c.PreviousHash),
			Now().Sub(c.DetectedAt).Round(time.Second), len(realBlocks))
		deadPhantoms = append(deadPhantoms, livePhantoms...)
		livePhantoms = nil
	}

	if len(realBlocks) == 0 {
		if len(livePhantoms) > 0 {
			// This node holds neither sibling, but a live candidate exists
			// network-wide. Keep the conflict open and keep pulling rather than
			// dropping it — dropping would un-freeze the account while a preferred
			// sibling is still unresolved (a spend-before-final hole). Trim only the
			// dead phantoms so the record converges on the live set. (#566)
			if len(deadPhantoms) > 0 {
				c.BlockHashes = livePhantoms
				if err := qm.conflictMgr.SaveConflict(c); err != nil {
					log.Printf("quorum: SaveConflict (dead-phantom trim, no real) for %s|%s: %v",
						shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
				}
			}
			return false
		}
		// All phantoms dead — nothing we can resolve and nothing the network is
		// backing. Drop the entire conflict so the account isn't permanently wedged.
		log.Printf("quorum: all-phantom conflict for %s|%s — dropping after %v",
			shortHash(c.AccountAddress), shortHash(c.PreviousHash),
			Now().Sub(c.DetectedAt).Round(time.Second))
		_ = qm.conflictMgr.DeleteConflict(c.AccountAddress, c.PreviousHash)
		return false
	}

	if len(realBlocks) == 1 {
		// If the sole real block is ALREADY finalized, confirmConflict short-circuits
		// on its height-based idempotency guard and leaves the conflict record in
		// place — so the 15s sweep re-runs this eviction forever (the symptom seen in
		// #538: "phantom eviction ... after Xm" repeating with a growing age). The
		// phantom is a sibling at an already-finalized position: either it lost the
		// election (benign — just clean up) or another node finalized it instead
		// (an un-healable finality fork that no longer self-heals; it must be
		// surfaced, not silently spun on). Either way, drop the record so the loop
		// stops; the durable final-height watermark already records the outcome.
		if qm.ledger.IsFinalized(c.AccountAddress, realBlocks[0]) {
			for _, ph := range phantoms {
				if st, _ := qm.store.GetBlockStatus(ph); st != StatusRejected {
					log.Printf("quorum: UN-HEALABLE FORK for %s|%s — local finalized %s but "+
						"sibling %s arrived behind the rollback wall (another node may have "+
						"finalized it); cannot reconcile, dropping conflict after %v (#538)",
						shortHash(c.AccountAddress), shortHash(c.PreviousHash),
						shortHash(realBlocks[0]), shortHash(ph),
						Now().Sub(c.DetectedAt).Round(time.Second))
				}
			}
			_ = qm.store.DeleteVotesForConflict(c.AccountAddress, c.PreviousHash)
			RemoveConflict(qm.conflictMgr, c.AccountAddress, c.PreviousHash)
			return false
		}

		// Only one real block, NOT yet finalized. The block being the only one whose
		// body this node can load is NOT evidence the network agrees on it — under the
		// #538 equivocation race the "phantom" is the OTHER node's real sibling, which
		// that node may have finalized. Auto-finalizing the local block here (the old
		// behaviour) is the conflict-resolution twin of the fallback-finalize hole: it
		// finalizes on local view, with no weight floor, so two nodes each finalize
		// their own sibling and fork finality behind the rollback wall. (#538)
		//
		// So phantom eviction must NOT finalize on its own authority. Trim the phantom
		// hashes from the conflict record (un-diluting the vote tally), then route the
		// survivor through the WEIGHT-GATED finalTally: it finalizes only on a real
		// ≥67% quorum or the strict-majority (>50%) non-voter fallback — both of which
		// at most one of two siblings can ever clear. If neither is met, the (now
		// trimmed) conflict stays open: a recoverable liveness stall, not a fork. The
		// trim makes the loop self-terminating — next sweep sees no phantoms.
		// Retain any LIVE phantom (a candidate the network still backs) so the next
		// sweep keeps re-requesting its body; trim only DEAD phantoms (no vote
		// weight). Trimming a live phantom is the #566 deadlock. The survivor's
		// finalize is still deferred to the weight-gated finalTally — never an
		// auto-finalize. (#538/#566)
		if len(deadPhantoms) > 0 {
			c.BlockHashes = append(append([]string{}, realBlocks...), livePhantoms...)
			if err := qm.conflictMgr.SaveConflict(c); err != nil {
				log.Printf("quorum: SaveConflict (dead-phantom trim, single real) for %s|%s: %v",
					shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
			}
			log.Printf("quorum: trimmed %d dead phantom(s) from conflict %s|%s (kept %d live) — "+
				"deferring finalize of survivor %s to weighted quorum (no local auto-finalize) (#538)",
				len(deadPhantoms), shortHash(c.AccountAddress), shortHash(c.PreviousHash),
				len(livePhantoms), shortHash(realBlocks[0]))
		}
		result, err := qm.finalTally(c.AccountAddress, c.PreviousHash)
		if err != nil {
			log.Printf("quorum: finalTally (phantom eviction) for %s|%s: %v",
				shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
			return false
		}
		if result != nil {
			if err := qm.confirmConflict(result); err != nil {
				log.Printf("quorum: confirmConflict (phantom eviction) for %s|%s: %v",
					shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
			}
		}
		return false
	}

	// Multiple real blocks remain. Trim only DEAD phantoms; retain LIVE phantoms so
	// the pull keeps re-requesting their bodies — trimming a live phantom is the
	// #566 deadlock. (#540/#566)
	if len(deadPhantoms) > 0 {
		c.BlockHashes = append(append([]string{}, realBlocks...), livePhantoms...)
		if err := qm.conflictMgr.SaveConflict(c); err != nil {
			log.Printf("quorum: SaveConflict (dead-phantom trim) for %s|%s: %v",
				shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
		}
		log.Printf("quorum: trimmed %d dead phantom(s) from conflict %s|%s (kept %d live)",
			len(deadPhantoms), shortHash(c.AccountAddress), shortHash(c.PreviousHash), len(livePhantoms))
	}
	// Fully loaded (re-drive to converge) only when no live phantom remains. If a
	// live candidate is still missing its body here, keep the conflict open so the
	// next sweep re-requests it rather than reporting premature full-load. (#566)
	return len(livePhantoms) == 0
}

// splitPhantomsByVoteWeight partitions phantom hashes into those that still carry
// converge-vote weight at the position (live candidates a weighted representative
// prefers — must be retained and kept under the pull) and those with none (dead —
// safe to trim). A hash backed by any positive-weight vote is live. (#566)
//
// GetVotesByConflict returns ALL stored votes for the position, including votes
// received from peers — so this classification reflects the network's preference
// as seen here, not just this node's own vote. Its liveness therefore depends on
// converge-vote gossip having reached this node, which the existing two-phase
// propagation already guarantees (the same votes that make the phantom the
// preferred winner are what mark it live).
func (qm *QuorumManager) splitPhantomsByVoteWeight(account, previous string, phantoms []string) (live, dead []string) {
	votes, _ := qm.voteMgr.GetVotesByConflict(account, previous)
	weighted := make(map[string]bool, len(votes))
	for _, v := range votes {
		if v.Weight > 0 {
			weighted[v.BlockHash] = true
		}
	}
	for _, h := range phantoms {
		if weighted[h] {
			live = append(live, h)
		} else {
			dead = append(dead, h)
		}
	}
	return live, dead
}

// finalizeBlock sets a block's status to StatusFinalized.
func (qm *QuorumManager) finalizeBlock(hash string) error {
	return qm.store.SetBlockStatus(hash, StatusFinalized)
}

// rejectBlocks sets each block's status to StatusRejected.
func (qm *QuorumManager) rejectBlocks(hashes []string) error {
	for _, h := range hashes {
		if err := qm.store.SetBlockStatus(h, StatusRejected); err != nil {
			return fmt.Errorf("rejectBlocks: SetBlockStatus(%s): %w", h, err)
		}
	}
	return nil
}

// FinalityObserver is called after a per-account final-height watermark
// advances, with the number of positions the watermark moved and the block that
// just finalized (which may be nil if this node does not hold it).
type FinalityObserver func(blocks uint64, winner *Block)

var finalityObserver atomic.Pointer[FinalityObserver]

// SetFinalityObserver installs an observation hook on the finality path, or
// clears it when fn is nil. Safe to call at any time; safe to call from several
// nodes in one process (#717).
//
// It is a hook rather than a direct metrics call because the dependency
// direction is the strongest available statement that observation cannot
// influence consensus: package core does not import the observability package
// at all, so there is no route by which a gauge, a registry or a scrape could
// reach a decision here. node.StartObservability installs it.
func SetFinalityObserver(fn FinalityObserver) {
	if fn == nil {
		finalityObserver.Store(nil)
		return
	}
	finalityObserver.Store(&fn)
}

// observeFinalityAdvance reports finality progress to the installed observer,
// if any. It is a pure observation hook: it never returns an error and never
// affects consensus. Kept in one function so the consensus path carries a
// single call site (#841).
//
// Distinct from (*Ledger).recordFinalityAdvance, which counts advance EVENTS
// for /node (#833). This one carries the block delta and the block that just
// finalized, so the observer can measure how much finalized and how long it
// took — neither of which that counter tracks. Deliberately not the same name,
// so neither is mistaken for the other at the call site.
func observeFinalityAdvance(blocks uint64, winner *Block) {
	if blocks == 0 {
		return
	}
	if fn := finalityObserver.Load(); fn != nil {
		(*fn)(blocks, winner)
	}
}
