package core

import (
	"crypto/ed25519"
	"log"
	"math/big"
	"strings"
	"time"
)

type blockDep struct {
	account string
	hash    string
}

func (l *Ledger) blockDependencies(b *Block) []blockDep {
	var deps []blockDep
	if b.Previous != "" && b.Previous != "0" {
		deps = append(deps, blockDep{account: b.Account, hash: b.Previous})
	}
	switch b.Type {
	case BlockReceive, BlockLeaseAccept, BlockLeaseSettle, BlockLeaseCancel, BlockLeaseForceSettle:

		if b.Source != "" && b.Source != "0" {
			deps = append(deps, blockDep{account: l.accountOfBlock(b.Source), hash: b.Source})
		}
	case BlockSend, BlockBurn, BlockMint, BlockLease, BlockMultisigOpen, BlockMultisigUpdate, BlockGenesis:

	default:

		deps = append(deps, blockDep{account: "", hash: "unknown-type:" + string(b.Type)})
	}
	return deps
}

func (l *Ledger) accountOfBlock(hash string) string {
	blk := l.GetBlock(hash)
	if blk == nil {
		return ""
	}
	return blk.Account
}

func (l *Ledger) depsFinalized(b *Block) bool {
	for _, d := range l.blockDependencies(b) {
		if d.account == "" {

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

func thresholdMet(weight, total *big.Int) bool {
	if total == nil || weight == nil || total.Sign() == 0 {
		return false
	}
	lhs := new(big.Int).Mul(weight, big.NewInt(quorumDenominator))
	rhs := new(big.Int).Mul(total, big.NewInt(quorumNumerator))
	return lhs.Cmp(rhs) >= 0
}

func (vm *VoteManager) CastVote(account, prev string, seed ...string) {
	mu := vm.conflictLock(account, prev)
	mu.Lock()
	defer mu.Unlock()
	vm.castVoteLocked(account, prev, seed...)
}

func (vm *VoteManager) castVoteLocked(account, prev string, seed ...string) {
	if vm.keyPair == nil {
		return
	}

	rep := vm.keyPair.PubKeyHex()
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return
	}

	if vm.positionResolved(account, prev) {
		return
	}

	if existing, _ := vm.store.GetVote(account, prev, rep); existing != nil && existing.Final {
		key := account + "|" + prev
		vm.lastRevoteMu.Lock()
		last := vm.lastRevoteNanos[key]
		reEmit := last == 0 || Now().UnixNano()-last >= int64(revoteBackoff)
		vm.lastRevoteMu.Unlock()
		if reEmit && vm.VoteEmitter != nil {

			if s, ok := vm.store.(Syncer); ok {
				if err := s.Sync(); err != nil {
					log.Printf("re-affirm: durability sync failed, deferring final vote for %s/%s: %v", shortAddr(account), shortHash(prev), err)
					return
				}
			}
			vm.lastRevoteMu.Lock()
			vm.lastRevoteNanos[key] = Now().UnixNano()
			vm.lastRevoteMu.Unlock()

			if fresh := vm.buildVote(account, prev, existing.BlockHash, true); fresh != nil {
				vm.VoteEmitter(fresh)
			}
		}
		return
	}

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

	vm.noteHeldCandidatesLocked(account, prev, candidates)

	conflict := vm.ledger.GetConflict(account, prev)
	eligible := candidates[:0]
	for _, h := range candidates {
		if vm.ledger.GetBlockOrStaged(h) != nil ||
			(conflict != nil && containsConflictHash(conflict.BlockHashes, h)) {
			eligible = append(eligible, h)
		}
	}
	if len(eligible) == 0 {
		return
	}
	pref := lowestHash(eligible)
	prefBlock := vm.ledger.GetBlockOrStaged(pref)
	if prefBlock == nil {
		return
	}
	if !vm.ledger.depsFinalized(prefBlock) {
		return
	}

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

func (vm *VoteManager) maybeLockLocked(account, prev, pref string) {
	cw, total := vm.convergeWeights(account, prev)
	if !thresholdMet(cw[pref], total) {
		return
	}

	remaining, ok := vm.stabilityWindowRemaining(account, prev)
	if !ok || remaining > 0 {

		if remaining < 0 {
			remaining = 0
		}
		vm.scheduleStabilityRedrive(account, prev, remaining)
		return
	}
	vm.emitFinalLocked(account, prev, pref)
}

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
			continue
		}
		seen[h] = true
		vm.lastNewCandidateNanos[key] = Now().UnixNano()
	}
}

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

func (vm *VoteManager) Close() {
	vm.candidateMu.Lock()
	vm.closed = true
	for key, t := range vm.pendingStabilityRedrive {
		if t.Stop() {

			vm.redriveWG.Done()
		}
		delete(vm.pendingStabilityRedrive, key)
	}
	vm.candidateMu.Unlock()
	vm.redriveWG.Wait()
}

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

	lockedBlock := vm.ledger.GetBlockOrStaged(locked)
	if lockedBlock == nil {
		return
	}
	if !vm.ledger.depsFinalized(lockedBlock) {
		return
	}
	if existing, _ := vm.store.GetVote(account, prev, rep); existing != nil && existing.Final && existing.BlockHash == locked {
		return
	}
	v := vm.buildVote(account, prev, locked, true)
	if v == nil {
		return
	}
	if err := vm.store.PutVote(v); err != nil {
		return
	}

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

func (vm *VoteManager) buildVote(account, prev, blockHash string, final bool) *Vote {

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

func (vm *VoteManager) electionTotalWeight(account, prev string) *big.Int {
	if c := vm.ledger.GetConflict(account, prev); c != nil && c.TotalWeight > 0 {
		return new(big.Int).SetUint64(c.TotalWeight)
	}
	return vm.ledger.GetTotalDelegatedWeight()
}

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

func (vm *VoteManager) positionResolved(account, prev string) bool {
	if prev == "" || prev == "0" {

		return vm.ledger.FinalHeight(account) > 0
	}
	h, err := vm.ledger.GetBlockHeight(account, prev)
	if err != nil || h == 0 {
		return false
	}
	return vm.ledger.FinalHeight(account) > h
}

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

	pullOnly := !vm.hasVoteWeight()
	vm.evictStalePullStamps()
	for account := range vm.ledger.Frontiers() {
		fh := vm.ledger.FinalHeight(account)
		chain := vm.ledger.GetChain(account)
		if pullOnly {
			vm.pullChainVotes(account, chain, int(fh))
			continue
		}
		for i := int(fh); i < len(chain); i++ {
			b := chain[i]
			if b == nil || b.Type == BlockGenesis {
				continue
			}
			vm.CastVote(account, b.Previous, b.Hash)
		}
	}
}

func (vm *VoteManager) pullChainVotes(account string, chain []*Block, fh int) {
	floor := -1
	for i := fh; i < len(chain); i++ {
		if b := chain[i]; b != nil && b.Type != BlockGenesis {
			floor = i
			break
		}
	}
	if floor < 0 {
		return
	}
	lo, hi := chain[floor], chain[len(chain)-1]
	if hi != nil && hi != lo {
		vm.pullVotesFor(account, hi.Previous)
	}
	vm.pullVotesFor(account, lo.Previous)
}

const pullStampTTL = 10 * revoteBackoff

func (vm *VoteManager) evictStalePullStamps() {
	cutoff := Now().UnixNano() - int64(pullStampTTL)
	vm.lastRevoteMu.Lock()
	defer vm.lastRevoteMu.Unlock()
	for key, stamp := range vm.lastRevoteNanos {
		if strings.HasPrefix(key, "pull|") && stamp < cutoff {
			delete(vm.lastRevoteNanos, key)
		}
	}
}

func (vm *VoteManager) hasVoteWeight() bool {
	if vm.keyPair == nil {
		return false
	}
	return vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() > 0
}

func (vm *VoteManager) pullVotesFor(account, prev string) {
	if vm.VotePullFn == nil {
		return
	}
	key := "pull|" + account + "|" + prev
	now := Now().UnixNano()
	vm.lastRevoteMu.Lock()
	last := vm.lastRevoteNanos[key]
	vm.lastRevoteMu.Unlock()
	if last != 0 && now-last < int64(revoteBackoff) {
		return
	}
	if !vm.VotePullFn(account, prev) {
		return
	}
	vm.lastRevoteMu.Lock()
	vm.lastRevoteNanos[key] = now
	vm.lastRevoteMu.Unlock()
}

func (vm *VoteManager) reaffirmFromState(account, prev string) {
	if vm.keyPair == nil || vm.VoteEmitter == nil {
		return
	}
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return
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

func (vm *VoteManager) VotesForPosition(account, prev string) []*Vote {
	out, _ := vm.store.GetVotesByConflict(account, prev)
	if vm.keyPair == nil {
		return out
	}
	if vm.ledger.GetVoteWeight(vm.keyPair.Address()).Sign() <= 0 {
		return out
	}
	winner := vm.finalizedChildAt(account, prev)
	if winner == "" {
		return out
	}

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
