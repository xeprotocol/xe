package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type BlockStatus uint8

const (
	StatusPending   BlockStatus = 0
	StatusFinalized BlockStatus = 1
	StatusRejected  BlockStatus = 2
)

const (
	quorumNumerator   = 67
	quorumDenominator = 100
)

const staleConflictAge = 10 * time.Second

const withholdLogInterval = 5 * time.Minute

const lockStabilityWindow = 3 * time.Second

const phantomEvictionDelay = 30 * time.Second

const phantomUnretrievableTimeout = 10 * time.Minute

const failedPromotionTTL = 30 * time.Second

type quorumResult struct {
	ConflictAccount string
	ConflictPrev    string
	WinnerHash      string
	LoserHashes     []string
	WinningWeight   uint64
	TotalWeight     uint64
}

type QuorumManager struct {
	conflictMgr ConflictStore
	voteMgr     VoteStore
	ledger      *Ledger
	store       QuorumStore
	mu          sync.Mutex

	RevoteFn func(account, previous string)

	OnFinalized func()

	PhantomPullFn func(account, previous string, hashes []string)

	VotePullFn func(account, previous string)

	failedPromotions map[string]time.Time

	withheldLogNanos map[string]int64
}

func NewQuorumManager(store QuorumStore, conflictStore ConflictStore, voteStore VoteStore, ledger *Ledger) *QuorumManager {
	return &QuorumManager{
		conflictMgr:      conflictStore,
		voteMgr:          voteStore,
		ledger:           ledger,
		store:            store,
		failedPromotions: make(map[string]time.Time),
		withheldLogNanos: make(map[string]int64),
	}
}

func failedPromotionKey(account, previous, hash string) string {
	return account + "|" + previous + "|" + hash
}

func (qm *QuorumManager) OnVote(vote *Vote) {
	qm.Retally(vote.ConflictAccount, vote.ConflictPrev)
}

func (qm *QuorumManager) Retally(account, previous string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	result, err := qm.finalTally(account, previous)
	if err != nil || result == nil {
		return
	}
	if err := qm.confirmConflict(result); err != nil {
		log.Printf("quorum: finalize for %s|%s: %v",
			shortHash(result.ConflictAccount), shortHash(result.ConflictPrev), err)
	}
}

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
			continue
		}

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

		for _, h := range conflict.BlockHashes {
			candidateSet[h] = true
		}
		if conflict.TotalWeight > 0 {

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

	prevFinalized := previous == "0" || qm.ledger.IsFinalized(account, previous)
	pickWinner := func(winner string) string {
		if winner == "" || !prevFinalized || qm.promotable(account, previous, winner) {
			return winner
		}
		best := ""
		for h := range candidateSet {
			if qm.promotable(account, previous, h) && (best == "" || h < best) {
				best = h
			}
		}
		if best != "" && best != winner {
			log.Printf("quorum: winner %s for %s|%s is unpromotable (fails full validation) — substituting lowest-hash promotable candidate %s",
				shortHash(winner), shortHash(account), shortHash(previous), shortHash(best))
		}
		return best
	}

	hashes := make([]string, 0, len(weightByBlock))
	for h := range weightByBlock {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	for _, h := range hashes {
		if new(big.Int).Mul(weightByBlock[h], big.NewInt(quorumDenominator)).Cmp(bigThreshold) >= 0 {
			if w := pickWinner(h); w != "" {
				return buildResultFrom(account, previous, w, candidateSet), nil
			}
		}
	}

	if len(weightByBlock) > 0 {
		stale := false
		if conflict != nil && !conflict.DetectedAt.IsZero() {
			stale = Now().Sub(conflict.DetectedAt) >= staleConflictAge
		}
		if !stale {
			var oldest int64
			for _, v := range votes {
				if v.Final && (oldest == 0 || v.Timestamp < oldest) {
					oldest = v.Timestamp
				}
			}
			stale = oldest != 0 && Now().UnixNano()-oldest >= int64(staleConflictAge)
		}
		if stale && qm.shouldLogWithhold(account, previous) {
			parts := make([]string, 0, len(hashes))
			for _, h := range hashes {
				parts = append(parts, shortHash(h)+"="+weightByBlock[h].String())
			}
			log.Printf("quorum: WITHHOLDING finalize for %s|%s — no candidate holds ≥67%% of %s total "+
				"final-vote weight across %d candidate(s) [%s]; there is no lower bar",
				shortHash(account), shortHash(previous), bigTotal, len(weightByBlock), strings.Join(parts, ", "))
		}
	}

	return nil, nil
}

func (qm *QuorumManager) shouldLogWithhold(account, previous string) bool {
	key := account + "|" + previous
	now := Now().UnixNano()
	if last, ok := qm.withheldLogNanos[key]; ok && now-last < int64(withholdLogInterval) {
		return false
	}
	qm.withheldLogNanos[key] = now
	return true
}

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

func (qm *QuorumManager) promotable(account, previous, hash string) bool {
	if h, err := qm.ledger.GetBlockHeight(account, hash); err == nil {

		if previous == "0" {
			return h == 1
		}
		ph, perr := qm.ledger.GetBlockHeight(account, previous)
		return perr == nil && h == ph+1
	}

	key := failedPromotionKey(account, previous, hash)
	if recordedAt, ok := qm.failedPromotions[key]; ok {
		if Now().Sub(recordedAt) < failedPromotionTTL {
			return false
		}
		delete(qm.failedPromotions, key)
	}
	staged, err := qm.conflictMgr.GetStagedBlock(hash)
	if err != nil || staged == nil {
		return false
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

func (qm *QuorumManager) confirmConflict(result *quorumResult) error {

	if qm.ledger.IsFinalized(result.ConflictAccount, result.WinnerHash) {

		entry := qm.ledger.acquireAccountLock(result.ConflictAccount)
		defer qm.ledger.releaseAccountLock(result.ConflictAccount, entry)
		qm.cleanupResolvedConflict(result)
		return nil
	}

	entry := qm.ledger.acquireAccountLock(result.ConflictAccount)
	defer qm.ledger.releaseAccountLock(result.ConflictAccount, entry)

	winnerBlock, err := qm.conflictMgr.GetStagedBlock(result.WinnerHash)
	if err != nil {
		return fmt.Errorf("confirmConflict: GetStagedBlock: %w", err)
	}

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

			swapped := false
			for _, loserHash := range result.LoserHashes {
				if _, lerr := qm.ledger.GetBlockHeight(result.ConflictAccount, loserHash); lerr != nil {
					continue
				}
				mainBlock := qm.ledger.GetBlock(loserHash)
				if mainBlock != nil {

					if err := qm.conflictMgr.SaveStagedBlock(mainBlock); err != nil {
						return fmt.Errorf("confirmConflict: SaveStagedBlock (demoted): %w", err)
					}
					if err := qm.ledger.swapBlockLocked(result.ConflictAccount, loserHash, result.WinnerHash, winnerBlock); err != nil {

						if errors.Is(err, ErrWinnerFullValidation) && !IsRetryableError(err) {
							qm.failedPromotions[failedPromotionKey(result.ConflictAccount, result.ConflictPrev, result.WinnerHash)] = Now()
							log.Printf("confirmConflict: winner %s for %s|%s failed full validation deterministically — quarantining for %s so the sweep substitutes a promotable candidate: %v",
								shortHash(result.WinnerHash), shortHash(result.ConflictAccount), shortHash(result.ConflictPrev), failedPromotionTTL, err)
						}
						return fmt.Errorf("confirmConflict: SwapBlock: %w", err)
					}
					swapped = true
					break
				}
			}
			if !swapped {

				appended, aerr := qm.appendStagedWinner(result, winnerBlock)
				if aerr != nil {
					return fmt.Errorf("confirmConflict: append winner: %w", aerr)
				}
				if !appended {

					return nil
				}
			}
		}
	}

	if height, herr := qm.ledger.GetBlockHeight(result.ConflictAccount, result.WinnerHash); herr == nil {
		if cur, _ := qm.store.GetFinalHeight(result.ConflictAccount); height > cur {
			if err := qm.store.SetFinalHeight(result.ConflictAccount, height); err != nil {
				return fmt.Errorf("confirmConflict: SetFinalHeight: %w", err)
			}

			qm.ledger.recordFinalityAdvance()

			observeFinalityAdvance(height-cur, qm.ledger.GetBlockOrStaged(result.WinnerHash))
		}
	}

	if err := qm.finalizeBlock(result.WinnerHash); err != nil {
		return err
	}

	qm.cleanupResolvedConflict(result)
	return nil
}

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

		return false, nil
	}
	if err := qm.ledger.dispatchValidateAndAdd(winnerBlock, true); err != nil {
		if IsRetryableError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

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
	delete(qm.withheldLogNanos, result.ConflictAccount+"|"+result.ConflictPrev)

	if qm.OnFinalized != nil {
		go qm.OnFinalized()
	}
}

func (qm *QuorumManager) StartStaleConflictSweep(stop <-chan struct{}) {
	go func() {

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
		log.Printf("quorum: pruned %d orphaned conflict record(s) at startup", dropped)
	}
}

func (qm *QuorumManager) dropConflictIfOrphaned(c *Conflict) bool {
	entry := qm.ledger.acquireAccountLock(c.AccountAddress)
	defer qm.ledger.releaseAccountLock(c.AccountAddress, entry)
	if !qm.conflictOrphanedByRollback(c) {
		return false
	}
	log.Printf("quorum: dropping orphaned conflict %s|%s — its chain position was rolled back (a candidate is rejected and the parent is no longer on the canonical chain)",
		shortHash(c.AccountAddress), shortHash(c.PreviousHash))
	if err := qm.store.DeleteVotesForConflict(c.AccountAddress, c.PreviousHash); err != nil {
		log.Printf("quorum: DeleteVotesForConflict (orphan drop) for %s|%s: %v",
			shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
	}
	RemoveConflict(qm.conflictMgr, c.AccountAddress, c.PreviousHash)
	return true
}

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
	log.Printf("quorum: cleaning resolved-but-lingering conflict %s|%s — child %s is finalized but the record persisted (votes cleaned up network-wide)",
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

func (qm *QuorumManager) conflictOrphanedByRollback(c *Conflict) bool {
	chain, err := qm.ledger.store.GetAccountChain(c.AccountAddress)
	if err != nil {
		return false
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

		if qm.dropConflictIfResolved(c) {
			continue
		}

		if qm.dropConflictIfOrphaned(c) {
			continue
		}

		age := Now().Sub(c.DetectedAt)

		if age >= phantomEvictionDelay {
			qm.mu.Lock()
			fullyLoaded := qm.evictPhantomsAndResolve(c)
			qm.mu.Unlock()
			if !fullyLoaded {
				continue
			}
		} else if age < staleConflictAge {
			continue
		}

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

		if unresolved && qm.VotePullFn != nil {
			qm.VotePullFn(c.AccountAddress, c.PreviousHash)
		}
	}
}

func (qm *QuorumManager) evictPhantomsAndResolve(c *Conflict) bool {
	var realBlocks []string
	var phantoms []string
	for _, h := range c.BlockHashes {

		if qm.ledger.GetBlockOrStaged(h) != nil {
			realBlocks = append(realBlocks, h)
		} else {
			phantoms = append(phantoms, h)
		}
	}

	if len(phantoms) == 0 {
		return true
	}

	if qm.PhantomPullFn != nil {
		qm.PhantomPullFn(c.AccountAddress, c.PreviousHash, phantoms)
	}

	livePhantoms, deadPhantoms := qm.splitPhantomsByVoteWeight(c.AccountAddress, c.PreviousHash, phantoms)

	if len(realBlocks) > 0 && len(livePhantoms) > 0 && Now().Sub(c.DetectedAt) >= phantomUnretrievableTimeout {
		log.Printf("quorum: dropping %d unretrievable live phantom(s) from conflict %s|%s after %v "+
			"(body served by no peer; %d real candidate(s) remain) — resolving via the weight-gated tally",
			len(livePhantoms), shortHash(c.AccountAddress), shortHash(c.PreviousHash),
			Now().Sub(c.DetectedAt).Round(time.Second), len(realBlocks))
		deadPhantoms = append(deadPhantoms, livePhantoms...)
		livePhantoms = nil
	}

	if len(realBlocks) == 0 {
		if len(livePhantoms) > 0 {

			if len(deadPhantoms) > 0 {
				c.BlockHashes = livePhantoms
				if err := qm.conflictMgr.SaveConflict(c); err != nil {
					log.Printf("quorum: SaveConflict (dead-phantom trim, no real) for %s|%s: %v",
						shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
				}
			}
			return false
		}

		log.Printf("quorum: all-phantom conflict for %s|%s — dropping after %v",
			shortHash(c.AccountAddress), shortHash(c.PreviousHash),
			Now().Sub(c.DetectedAt).Round(time.Second))
		_ = qm.conflictMgr.DeleteConflict(c.AccountAddress, c.PreviousHash)
		return false
	}

	if len(realBlocks) == 1 {

		if qm.ledger.IsFinalized(c.AccountAddress, realBlocks[0]) {
			for _, ph := range phantoms {
				if st, _ := qm.store.GetBlockStatus(ph); st != StatusRejected {
					log.Printf("quorum: UN-HEALABLE FORK for %s|%s — local finalized %s but "+
						"sibling %s arrived behind the rollback wall (another node may have "+
						"finalized it); cannot reconcile, dropping conflict after %v",
						shortHash(c.AccountAddress), shortHash(c.PreviousHash),
						shortHash(realBlocks[0]), shortHash(ph),
						Now().Sub(c.DetectedAt).Round(time.Second))
				}
			}
			_ = qm.store.DeleteVotesForConflict(c.AccountAddress, c.PreviousHash)
			RemoveConflict(qm.conflictMgr, c.AccountAddress, c.PreviousHash)
			return false
		}

		if len(deadPhantoms) > 0 {
			c.BlockHashes = append(append([]string{}, realBlocks...), livePhantoms...)
			if err := qm.conflictMgr.SaveConflict(c); err != nil {
				log.Printf("quorum: SaveConflict (dead-phantom trim, single real) for %s|%s: %v",
					shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
			}
			log.Printf("quorum: trimmed %d dead phantom(s) from conflict %s|%s (kept %d live) — "+
				"deferring finalize of survivor %s to weighted quorum (no local auto-finalize)",
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

	if len(deadPhantoms) > 0 {
		c.BlockHashes = append(append([]string{}, realBlocks...), livePhantoms...)
		if err := qm.conflictMgr.SaveConflict(c); err != nil {
			log.Printf("quorum: SaveConflict (dead-phantom trim) for %s|%s: %v",
				shortHash(c.AccountAddress), shortHash(c.PreviousHash), err)
		}
		log.Printf("quorum: trimmed %d dead phantom(s) from conflict %s|%s (kept %d live)",
			len(deadPhantoms), shortHash(c.AccountAddress), shortHash(c.PreviousHash), len(livePhantoms))
	}

	return len(livePhantoms) == 0
}

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

func (qm *QuorumManager) finalizeBlock(hash string) error {
	return qm.store.SetBlockStatus(hash, StatusFinalized)
}

func (qm *QuorumManager) rejectBlocks(hashes []string) error {
	for _, h := range hashes {
		if err := qm.store.SetBlockStatus(h, StatusRejected); err != nil {
			return fmt.Errorf("rejectBlocks: SetBlockStatus(%s): %w", h, err)
		}
	}
	return nil
}

type FinalityObserver func(blocks uint64, winner *Block)

var finalityObserver atomic.Pointer[FinalityObserver]

func SetFinalityObserver(fn FinalityObserver) {
	if fn == nil {
		finalityObserver.Store(nil)
		return
	}
	finalityObserver.Store(&fn)
}

func observeFinalityAdvance(blocks uint64, winner *Block) {
	if blocks == 0 {
		return
	}
	if fn := finalityObserver.Load(); fn != nil {
		(*fn)(blocks, winner)
	}
}
