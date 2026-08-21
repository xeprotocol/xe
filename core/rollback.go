package core

// rollback.go — cascading cross-account rollback (#527), epic #529.
//
// When a fork resolves against a send that another account has already received,
// removing the loser send must also roll back that receive (and anything built on
// it) — otherwise the recipient keeps a credit for funds that were never sent
// (the #518 double-spend). The consuming receive is located with NO reverse
// index: a pending-send record keyed by the send hash means "unreceived"; its
// ABSENCE means "consumed", so we unwind the recipient's chain from its head down
// to and including the consuming receive. Undoing a receive re-creates the source
// send's pending; the caller (swapBlockLocked) then deletes that pending as it
// removes the loser send.
//
// planCascade is READ-ONLY: it walks the whole rollback tree and validates it is
// safe BEFORE any mutation — no finalized block (finality wall) and only
// reversible block types. A cross-account cycle (an unwind that reaches a send
// back into an account already being unwound) is NOT refused (#691): the rollback
// set is the loser send's whole forward cone, and because every block that closes
// a loop is causally a descendant of the loser send, the cone forms a contiguous
// top segment on each account. The walk dedups by block hash (the `planned` set)
// so it terminates on a cycle and emits each block once, in strictly descending
// index order per account — i.e. reverse causal order, exactly the order
// swapBlockLocked's build loop requires. Validating before mutating means an
// unsafe cascade is refused cleanly with no partial state.
//
// The plan is then consumed by swapBlockLocked, which (#622) builds every undo
// via buildBlockUndo against running per-account snapshots and commits them with
// the winner in ONE CommitCascade store transaction — so a crash mid-promotion
// can never strand an account half-promoted. (The old applyCascade, which rolled
// each planned block back in its own CommitUndo txn, was that crash window and
// has been removed.)

import (
	"fmt"
	"log"
	"math/big"
)

// cascadeStep is one block to roll back, in apply order (consumers before the
// sends they consumed; head-first within an account).
type cascadeStep struct {
	account string
	b       *Block
}

// planCascade returns the ordered rollback plan needed so that removing the
// (loser) send `sendHash` leaves no surviving credit on its recipient, or an
// error if the cascade is unsafe. `planned` is the set of block hashes already in
// the plan (seed it with the swapped account's descendants); it dedups the
// cross-account walk so a cycle terminates and each block is emitted once.
// Read-only — acquires no locks, mutates nothing. (#527, #691)
func (l *Ledger) planCascade(sendHash string, planned map[string]bool) ([]cascadeStep, error) {
	if ps, _ := l.store.GetPendingSend(sendHash); ps != nil {
		return nil, nil // still pending → nobody received it; no cascade needed
	}
	var plan []cascadeStep
	if err := l.planRollbackOfSend(sendHash, planned, &plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// planRollbackOfSend plans the rollback of the consumer of a consumed send.
func (l *Ledger) planRollbackOfSend(sendHash string, planned map[string]bool, plan *[]cascadeStep) error {
	if ps, _ := l.store.GetPendingSend(sendHash); ps != nil {
		return nil // not consumed
	}
	send := l.GetBlock(sendHash)
	if send == nil || send.Destination == "" {
		// Can't identify a recipient → there is no receiver to roll back. Removing
		// the send leaves no surviving credit, so the swap is safe to proceed.
		return nil
	}
	return l.planRollbackFrom(send.Destination, sendHash, planned, plan)
}

// planRollbackFrom plans unwinding `account` from its head down to and including
// the receive that consumed `consumedSend`, recursing into onward-spent sends.
//
// #691: a cross-account cycle (the recursion reaches a send back into an account
// already being unwound) is NOT an error. `planned` dedups by block hash: a block
// already in the plan is skipped, so a re-entry into an account whose top segment
// is already slated is a no-op (or extends the unwind deeper), the walk
// terminates, and each block is emitted once in strictly descending index order
// per account. A block is marked planned BEFORE recursing into its consumer (so a
// cyclic re-entry can never re-process it) and appended AFTER the recursion (so
// its consumer is rolled back first — reverse causal order). Finality and
// unsupported block types remain hard refusals.
func (l *Ledger) planRollbackFrom(account, consumedSend string, planned map[string]bool, plan *[]cascadeStep) error {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return err
	}
	if chain == nil || len(chain.Blocks) == 0 {
		// No chain on the destination → nothing was received here, so there is no
		// credit to roll back. Safe to proceed with the swap.
		return nil
	}
	recvIdx := -1
	for i, b := range chain.Blocks {
		if b.Type == BlockReceive && b.Source == consumedSend {
			recvIdx = i
			break
		}
	}
	if recvIdx == -1 {
		// The send's pending is absent but no receive of it exists on the
		// destination (the only place a receive can live). There is therefore no
		// surviving credit to roll back — proceeding is safe. Log it: an absent
		// pending with no matching receive is anomalous (store inconsistency) and
		// worth surfacing rather than failing closed (which would wedge the swap).
		log.Printf("cascade: send %s has no pending and no receiver on %s — no rollback needed (anomalous)",
			shortHash(consumedSend), shortAddr(account))
		return nil
	}
	if fh := l.FinalHeight(account); uint64(recvIdx+1) <= fh {
		return fmt.Errorf("cascade: refusing to roll back finalized block at height %d (final height %d) on %s", recvIdx+1, fh, shortAddr(account))
	}

	// Head-first: frontier down to the consuming receive. Skip blocks already in
	// the plan — a cycle or a multi-path re-entry; the planned set is a contiguous
	// top segment per account, so skipping the visited prefix and processing only
	// the deeper remainder keeps strictly-descending order. Recurse into any
	// onward-spent send BEFORE appending it (marking it planned first, so a cyclic
	// re-entry cannot re-process it), so its consumer is rolled back first.
	for i := len(chain.Blocks) - 1; i >= recvIdx; i-- {
		b := chain.Blocks[i]
		if planned[b.Hash] {
			continue
		}
		switch b.Type {
		case BlockSend, BlockReceive, BlockBurn, BlockMint:
			// reversible — undoBlockApply reverts the balance to the parent
			// generically; mint (like burn) has no pending or recipient to fix up.
		default:
			return fmt.Errorf("cascade: unsupported block type %q (%s) on %s — reversing its lease/keyset/reputation side-effects is not yet implemented", b.Type, shortHash(b.Hash), shortAddr(account))
		}
		planned[b.Hash] = true
		if b.Type == BlockSend {
			if ps, _ := l.store.GetPendingSend(b.Hash); ps == nil {
				if err := l.planRollbackOfSend(b.Hash, planned, plan); err != nil {
					return err
				}
			}
		}
		*plan = append(*plan, cascadeStep{account: account, b: b})
	}
	return nil
}

// priorLease reconstructs the lease record as it was before a lease-state
// transition that is being unwound: the current record with State reset to
// target and the accept-time fields cleared when reverting all the way to
// created. Returns nil if the lease record is missing. (#570/C1)
func (l *Ledger) priorLease(leaseHash string, target LeaseState) *Lease {
	ls, ok := l.store.(LeaseStore)
	if !ok {
		return nil
	}
	cur, err := ls.GetLease(leaseHash)
	if err != nil || cur == nil {
		return nil
	}
	restored := *cur
	restored.State = target
	restored.Settled = false
	if target == LeaseCreated {
		restored.Stake = 0
		restored.StartTime = 0
		restored.LockedR = 0
		restored.LockedPayoutCap = 0
		restored.LockedTWAP = 0
	}
	return &restored
}

// escrowPendingOf reconstructs the consumer's escrow pending for a lease from
// the original lease block — the pending a settle/cancel/force-settle burned,
// to be re-created when that transition is unwound. (#570/C1)
func (l *Ledger) escrowPendingOf(leaseHash string) *PendingSend {
	lb := l.GetBlock(leaseHash)
	if lb == nil || lb.Type != BlockLease {
		return nil
	}
	return &PendingSend{
		SendHash:    lb.Hash,
		Source:      lb.Account,
		Destination: lb.Destination,
		Amount:      lb.Amount,
		Asset:       "XUSD",
	}
}

// assetBalanceOnChain walks a chain snapshot and returns the most recent balance
// for the given asset (0 if no block of that asset appears). The #622 build half
// derives all balance inputs from explicit chain snapshots rather than the live
// in-memory map, so an undo can be built against a truncated snapshot that has
// not been (and may never be) written to the store — required for batching
// several undos on one account inside the spanning cascade transaction.
func assetBalanceOnChain(chain *AccountChain, asset string) uint64 {
	if chain == nil {
		return 0
	}
	var bal uint64
	for _, b := range chain.Blocks {
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if a == asset {
			bal = b.Balance
		}
	}
	return bal
}

// xusdBalanceOnChain walks a chain snapshot and returns the XUSD balance the
// same way rebuildAssetBalances does: each XUSD block sets the running balance to
// its own Balance, and each lease_settle adds back the provider's stake (which
// rides on an XE block and so is invisible to a plain balance walk). This is the
// single source of truth for "XUSD as a rebuild-from-store would compute it" and
// is used by the undo path so unwinding a chain agrees with a cold sync (#674).
func (l *Ledger) xusdBalanceOnChain(chain *AccountChain) uint64 {
	if chain == nil {
		return 0
	}
	ls, hasLeases := l.store.(LeaseStore)
	var bal uint64
	for _, b := range chain.Blocks {
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if a == "XUSD" {
			bal = b.Balance
		}
		if b.Type == BlockLeaseSettle && hasLeases {
			if lease, err := ls.GetLease(b.Source); err == nil && lease != nil {
				bal += lease.Stake
			}
		}
	}
	return bal
}

// buildBlockUndo is the PURE build half of undoBlockApply (#622): it computes the
// *BlockUndo for rolling back frontier block b and a closure that applies the
// in-memory deltas — but performs NO store write and mutates NO ledger state.
//
// `chain` is the explicit current chain snapshot the undo is built against; b
// must be its tail. All balance inputs are computed by walking that snapshot
// (and its truncation) rather than the live in-memory balance map, so several
// undos can be built in sequence against running per-account snapshots — each
// seeing the previous build's truncation — before any of them is committed.
// These chain-walk values equal the live in-memory reads by the balance
// invariant, so single-block callers are unchanged.
//
// The returned closure applies exactly the in-memory deltas the old post-
// CommitUndo block did: keyset cache delete, setAssetBalance(account, asset,
// parentBal), and the full delegation/weight reversal using xeBefore/xeAfter/
// prevRep with live reads of l.delegation under the mutex. The caller runs it
// only after the store write (CommitUndo or CommitCascade) succeeds.
func (l *Ledger) buildBlockUndo(account string, b *Block, chain *AccountChain) (*BlockUndo, func(), error) {
	if chain == nil || len(chain.Blocks) == 0 || chain.Blocks[len(chain.Blocks)-1].Hash != b.Hash {
		return nil, nil, fmt.Errorf("cascade apply: %s is not the frontier of %s (chain changed under the cascade)", shortHash(b.Hash), shortAddr(account))
	}

	asset := b.Asset
	if asset == "" {
		asset = "XE"
	}

	// Determine the side-effects to reverse. Send/receive touch only pending;
	// lease and multisig blocks also carry lease-record / keyset writes that
	// the same undo transaction must reverse (#570/C1), reconstructing the
	// prior state from the lease/lease-block (the forward transition target
	// state is fixed by the block type, mirroring the C3a commit-time CAS).
	var deletePendingID, deleteLeaseHash, deleteKeysetAccount string
	var addPending *PendingSend
	var restoreLease *Lease
	var assetDebit *AssetDelta
	switch b.Type {
	case BlockSend:
		deletePendingID = b.Hash // remove the pending this send created
	case BlockReceive:
		// Re-create the pending this receive consumed, from the source send.
		if src := l.GetBlock(b.Source); src != nil && src.Type == BlockSend {
			srcAsset := src.Asset
			if srcAsset == "" {
				srcAsset = "XE"
			}
			addPending = &PendingSend{
				SendHash:    src.Hash,
				Source:      src.Account,
				Destination: src.Destination,
				Amount:      src.Amount,
				Asset:       srcAsset,
			}
		}
	case BlockLease:
		// Reverse lease creation: delete the lease record and its escrow pending.
		deletePendingID = b.Hash
		deleteLeaseHash = b.Hash
	case BlockLeaseAccept:
		// Reverse accept: lease returns to created, clearing the accept-time
		// fields. (The stake was only a balance debit — reverted generically.)
		restoreLease = l.priorLease(b.Source, LeaseCreated)
	case BlockLeaseSettle, BlockLeaseForceSettle:
		// Reverse settle/force-settle: lease returns to accepted and the
		// consumer escrow (burned by the transition) is re-created.
		restoreLease = l.priorLease(b.Source, LeaseAccepted)
		addPending = l.escrowPendingOf(b.Source)
		// #674: lease_settle returned the provider's XUSD stake via the commit's
		// AssetCredit. Reverse it symmetrically. force_settle deliberately never
		// returns the stake, so it is excluded. priorLease(LeaseAccepted)
		// preserves Stake (only the LeaseCreated target zeroes it).
		if b.Type == BlockLeaseSettle && restoreLease != nil {
			assetDebit = &AssetDelta{Account: b.Account, Asset: "XUSD", Amount: restoreLease.Stake}
		}
	case BlockLeaseCancel:
		// Reverse cancel: lease returns to created and the refunded escrow is
		// re-created.
		restoreLease = l.priorLease(b.Source, LeaseCreated)
		addPending = l.escrowPendingOf(b.Source)
	case BlockMultisigOpen:
		deleteKeysetAccount = b.Account
	case BlockMultisigUpdate:
		// The prior keyset is not recoverable from the block alone; refuse
		// rather than corrupt. Multisig equivocation is exotic; refusing leaves
		// the position safely unresolved (same discipline as the cascade's
		// unsupported-type refusal).
		return nil, nil, fmt.Errorf("undo: reversing a multisig_update is not supported (prior keyset unrecoverable): %s", shortHash(b.Hash))
	case BlockBurn, BlockMint:
		// no pending/lease/keyset side effects; balance reverts generically
	}
	if (b.Type == BlockLeaseAccept || b.Type == BlockLeaseSettle || b.Type == BlockLeaseForceSettle || b.Type == BlockLeaseCancel) && restoreLease == nil {
		return nil, nil, fmt.Errorf("undo: lease %s not found while reversing %s", shortHash(b.Source), b.Type)
	}

	// #681: the forward apply of these lease transitions emitted a reputation
	// event (see validateAndAddLease{Accept,Settle,ForceSettle,Cancel}). Reverse
	// the matching counter when the block is reorged out, mirroring the asset and
	// delegation reversals below, so a node that applied a losing equivocated
	// sibling does not over-count and stays in step with a cold-sync rebuild. The
	// parties (and settle duration) come from restoreLease, which carries them
	// regardless of the state it is being rolled back to.
	var repRevert *ReputationEvent
	if restoreLease != nil {
		switch b.Type {
		case BlockLeaseAccept:
			repRevert = &ReputationEvent{Kind: EventLeaseAccepted, Provider: restoreLease.Provider, Consumer: restoreLease.Consumer}
		case BlockLeaseSettle:
			repRevert = &ReputationEvent{Kind: EventLeaseSettled, Provider: restoreLease.Provider, Consumer: restoreLease.Consumer, DurationSecs: restoreLease.Duration}
		case BlockLeaseForceSettle:
			repRevert = &ReputationEvent{Kind: EventLeaseUnfulfilled, Provider: restoreLease.Provider, Consumer: restoreLease.Consumer}
		case BlockLeaseCancel:
			repRevert = &ReputationEvent{Kind: EventLeaseCancelled, Provider: restoreLease.Provider, Consumer: restoreLease.Consumer}
		}
	}

	newChain := &AccountChain{Blocks: chain.Blocks[:len(chain.Blocks)-1]}
	newFrontier := "0"
	if len(newChain.Blocks) > 0 {
		newFrontier = newChain.Blocks[len(newChain.Blocks)-1].Hash
	}

	// #622: all balance inputs from the snapshot walks, not the in-memory map.
	// xeBefore = XE balance at b on the full snapshot (b is the tail, so this is
	// the XE balance with b in place); parentBal = b.Asset balance on the
	// truncated snapshot; xeAfter = XE balance on the truncated snapshot.
	xeBefore := assetBalanceOnChain(chain, "XE")
	var parentBal uint64
	if b.Previous != "0" {
		parentBal = assetBalanceOnChain(newChain, asset)
		// #674: when restoring an XUSD balance from the truncated chain, account
		// for the lease_settle stake return the same way rebuildAssetBalances
		// does — the stake rides on an XE settle block, so a plain balance walk
		// misses it. Without this, undoing an XUSD block stacked above a settle
		// rewinds XUSD to the pre-settle value, and the settle's own AssetDebit
		// then subtracts the stake a second time → divergence from a cold rebuild.
		if asset == "XUSD" {
			parentBal = l.xusdBalanceOnChain(newChain)
		}
	}
	xeAfter := assetBalanceOnChain(newChain, "XE")

	// #570/M5: the representative in effect before b, recovered from the
	// truncated chain — both the persistent restore (inside CommitUndo) and
	// the in-memory weight reversal need it.
	prevRep := ""
	for i := len(newChain.Blocks) - 1; i >= 0; i-- {
		if r := newChain.Blocks[i].Representative; r != "" {
			prevRep = r
			break
		}
	}

	// #570/H5: apply the chain truncation, frontier, pending add/delete,
	// reject-status, AND the delegation restore in ONE transaction. As
	// separate writes, a crash between them (e.g. after PutPendingSend
	// re-created the source pending but before the consuming receive left the
	// chain) lets the same send be received twice; a delegation restore left
	// outside the transaction (#597) leaves a crash window where the chain is
	// rolled back but rebuildDelegation still reads the rolled-back rep —
	// diverging consensus weights from a clean replay.
	// #701: this undo emptied the account's chain — delete the now-chainless
	// account record so the live state matches a fresh rebuild-from-chain.
	deleteAccount := len(newChain.Blocks) == 0

	// #829: unwinding the block that DECLARED the account's public key must also
	// retire the credential — otherwise a reorged-out open block leaves a key
	// registered for an account with no chain, and a rebuild-from-store (which
	// derives the registry from the chains) would disagree with the live map.
	// Type-agnostic on purpose: any block type can be the one that opens a chain.
	deleteAccountKeyAccount := ""
	if b.PubKey != "" {
		deleteAccountKeyAccount = b.Account
	}

	undo := &BlockUndo{
		Account:                 account,
		Chain:                   newChain,
		FrontierHash:            newFrontier,
		AddPending:              addPending,
		DeletePendingID:         deletePendingID,
		RejectHash:              b.Hash,
		DeleteAccount:           deleteAccount,
		RestoreDelegation:       true,
		PrevRep:                 prevRep,
		RestoreLease:            restoreLease,
		DeleteLeaseHash:         deleteLeaseHash,
		DeleteKeysetAccount:     deleteKeysetAccount,
		DeleteAccountKeyAccount: deleteAccountKeyAccount,
		AssetDebit:              assetDebit,
	}

	apply := func() {
		// In-memory keyset cache mirrors the store reversal (#570/C1). Reputation
		// is reversed below via repRevert (#681) so live counters stay in step
		// with a cold-sync rebuild after a reorg.
		if deleteKeysetAccount != "" {
			l.keysetMu.Lock()
			delete(l.keysets, deleteKeysetAccount)
			l.keysetMu.Unlock()
		}
		// #829: same for the single-key credential registry.
		if deleteAccountKeyAccount != "" {
			l.accountKeyMu.Lock()
			delete(l.accountKeys, deleteAccountKeyAccount)
			l.accountKeyMu.Unlock()
		}

		// In-memory derived state — rebuilt from the (now-consistent) store on
		// restart, so it is intentionally outside the durability-critical write.
		// #701: when the chain is now empty, drop the account's balance map
		// entirely (rather than leaving a {asset:0} shell) so it matches a fresh
		// rebuild-from-chain. If the same cascade re-adds a block to this account
		// (an open-conflict winner), commitBlockWrite re-creates the balance after
		// these memApplies run, so the winner's balance is not lost.
		if deleteAccount {
			l.deleteAccountBalances(account)
		} else {
			l.setAssetBalance(account, asset, parentBal)
		}
		// #674: reverse the lease_settle XUSD stake return (the commit's
		// AssetCredit). The settle block's own asset is XE, so the setAssetBalance
		// above does not touch XUSD — this is the only carrier that removes the
		// orphaned stake credit when a settle is unwound.
		if assetDebit != nil {
			l.subAssetBalance(assetDebit.Account, assetDebit.Asset, assetDebit.Amount)
		}

		// #570/M5: reverse the full delegation/weight effect of b, not just a
		// balance delta on the current delegate. The forward path moved the
		// account's XE weight from prevRep to the rep b installed (curRep =
		// b.Representative, or the inherited prevRep), using the pre-b XE balance
		// (xeAfter) and post-b XE balance (xeBefore). Undo by moving it back and
		// restoring the delegation pointer. When b didn't change the rep, prevRep
		// == curRep and this collapses to the old balance-delta adjustment.
		l.delegationMu.Lock()
		curRep := l.delegation[account]
		if curRep != "" && l.weights[curRep] != nil {
			l.weights[curRep].Sub(l.weights[curRep], new(big.Int).SetUint64(xeBefore))
			if l.weights[curRep].Sign() < 0 {
				l.weights[curRep].SetInt64(0)
			}
		}
		if prevRep != "" {
			if l.weights[prevRep] == nil {
				l.weights[prevRep] = new(big.Int)
			}
			l.weights[prevRep].Add(l.weights[prevRep], new(big.Int).SetUint64(xeAfter))
		}
		if prevRep == "" {
			delete(l.delegation, account)
		} else {
			l.delegation[account] = prevRep
		}
		l.delegationMu.Unlock()

		// #681: reverse the reputation counter the forward apply of b emitted.
		// The engine has its own lock; this runs after the store commit, like the
		// asset/delegation reversals above. An account left counter-less is
		// dropped so the live map matches a cold-sync rebuild.
		if repRevert != nil {
			l.reputation.Revert(*repRevert)
		}
	}

	return undo, apply, nil
}

// undoBlockApply reverts a single frontier block's side-effects (balance, pending,
// delegation weight, frontier, chain membership) and marks it rejected, each in
// its OWN CommitUndo store transaction. The block MUST be the account's current
// frontier (the plan order guarantees this); it re-checks and aborts safely if
// the chain changed. Mutations only — type support and finality were validated
// during planning. (#527)
//
// This per-block-atomic path remains the right behavior for single-block callers
// (the cancel-wins accept-unwind at validateAndAddLeaseCancel, #570/C3b). The
// #622 multi-block conflict-promotion cascade instead builds every undo via
// buildBlockUndo and commits them with the winner in ONE CommitCascade.
func (l *Ledger) undoBlockApply(account string, b *Block) error {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return err
	}
	undo, apply, err := l.buildBlockUndo(account, b, chain)
	if err != nil {
		return err
	}
	if err := l.store.CommitUndo(undo); err != nil {
		return err
	}
	apply()
	return nil
}
