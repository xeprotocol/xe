package core

// cascade_commit.go — the #622 conflict-promotion overlay.
//
// Conflict promotion (swapBlockLocked) used to mutate the store incrementally:
// it unwound the loser and its cross-account cascade through applyCascade (each
// undo its own CommitUndo store txn), then re-applied the winner through the
// live dispatchValidateAndAdd path ending in its own CommitBlock. Correct on
// values and side effects (#614), but NOT crash-atomic (#622): a crash between
// those transactions stranded the account half-promoted — the loser/cascade
// unwound on disk, no winner.
//
// The fix lands the whole promotion in ONE store transaction (CommitCascade).
// To do that, the loser + cascade undos are BUILT but NOT written; the winner is
// then re-validated and committed through the same live path — but that path
// must read the POST-undo state (truncated chains, re-created pendings, reversed
// lease/keyset side effects) that has not been written to the store yet. The
// cascadeBuild overlay holds exactly that post-undo state; read helpers consult
// it first and commitBlockWrite, on the winner block only, swaps its CommitBlock
// for CommitCascade(undos, winner).
//
// Concurrency: the overlay only ever covers accounts whose per-account locks the
// promotion holds for its full duration. A concurrent AddBlock/commit on any
// OTHER account never matches an overlay entry, so it reads straight through —
// the overlay is invisible to it. The single in-flight promotion is serialized
// by the quorum lock, so at most one cascadeBuild is ever active.

import (
	"fmt"
)

// cascadeBuild is the staged, not-yet-committed state of an in-progress conflict
// promotion: the ordered undos to apply, their in-memory apply closures, and the
// derived post-undo overlay every winner-revalidation read must see.
type cascadeBuild struct {
	winnerHash string

	undos      []*BlockUndo // ordered: cross-account cascade + descendants, loser last
	memApplies []func()     // in-memory delta closures, same order as undos

	// Post-undo per-account chain snapshots. For an overlaid account this is the
	// authoritative chain the winner revalidation must see (the store still holds
	// the pre-promotion chain). The map is keyed by account; the value is the
	// final truncated chain after all of that account's undos.
	chains map[string]*AccountChain

	// Pending-send overlay, derived from the undos' AddPending/DeletePendingID.
	// addPending: re-created source pendings (keyed by send hash).
	// delPending: pendings deleted by an undone send (keyed by send hash).
	addPending map[string]*PendingSend
	delPending map[string]bool

	// Lease overlay, derived from the undos' RestoreLease/DeleteLeaseHash.
	restoreLease map[string]*Lease // keyed by lease hash
	deleteLease  map[string]bool   // keyed by lease hash

	// Keyset overlay, derived from the undos' DeleteKeysetAccount.
	deleteKeyset map[string]bool // keyed by account

	// Post-undo delegation pointer per overlaid account (from PrevRep). Used by
	// commitBlockWrite to compute the winner's delegation oldRep from the overlay
	// rather than the live (still-pre-undo) l.delegation map.
	delegation map[string]string // account → post-undo rep ("" = deleted)
	// delegated records which accounts have an overlay delegation entry (so a ""
	// value means "deleted", distinguishable from "no overlay entry").
	delegated map[string]bool
}

// newCascadeBuild constructs an overlay for the given winner hash.
func newCascadeBuild(winnerHash string) *cascadeBuild {
	return &cascadeBuild{
		winnerHash:   winnerHash,
		chains:       make(map[string]*AccountChain),
		addPending:   make(map[string]*PendingSend),
		delPending:   make(map[string]bool),
		restoreLease: make(map[string]*Lease),
		deleteLease:  make(map[string]bool),
		deleteKeyset: make(map[string]bool),
		delegation:   make(map[string]string),
		delegated:    make(map[string]bool),
	}
}

// addUndo records one undo (and its apply closure) into the overlay, folding its
// derived effects into the read-overlay maps. The undos are folded in the order
// they will be applied, so later undos on the same account override earlier ones
// (the chain snapshot is replaced with the most-truncated one).
func (cb *cascadeBuild) addUndo(undo *BlockUndo, apply func()) {
	cb.undos = append(cb.undos, undo)
	cb.memApplies = append(cb.memApplies, apply)

	cb.chains[undo.Account] = undo.Chain

	if undo.AddPending != nil {
		cp := *undo.AddPending
		cb.addPending[cp.SendHash] = &cp
		delete(cb.delPending, cp.SendHash) // re-created: no longer deleted
	}
	if undo.DeletePendingID != "" {
		cb.delPending[undo.DeletePendingID] = true
		delete(cb.addPending, undo.DeletePendingID) // deleted: drop any re-create
	}
	if undo.RestoreLease != nil {
		cp := *undo.RestoreLease
		cb.restoreLease[cp.LeaseHash] = &cp
		delete(cb.deleteLease, cp.LeaseHash)
	}
	if undo.DeleteLeaseHash != "" {
		cb.deleteLease[undo.DeleteLeaseHash] = true
		delete(cb.restoreLease, undo.DeleteLeaseHash)
	}
	if undo.DeleteKeysetAccount != "" {
		cb.deleteKeyset[undo.DeleteKeysetAccount] = true
	}
	if undo.RestoreDelegation {
		cb.delegation[undo.Account] = undo.PrevRep
		cb.delegated[undo.Account] = true
	}
}

// --- overlay read helpers ---
//
// Each consults the active cascade under cascadeMu (nil fast path), then falls
// back to the store / in-memory map. Wiring the winner-revalidation read sites
// through these keeps them correct against the un-written post-undo state while
// leaving every concurrent thread (which never touches an overlaid account)
// reading straight through.

// activeCascadeFor returns the active cascade if one is live, else nil. Held
// only long enough to copy the pointer; the cascade's maps are never mutated
// after activation (built fully before activate, applied/cleared after commit).
func (l *Ledger) activeCascadeFor() *cascadeBuild {
	l.cascadeMu.RLock()
	cb := l.activeCascade
	l.cascadeMu.RUnlock()
	return cb
}

// overlayChain returns the post-undo chain snapshot for account if the overlay
// covers it, ok=false otherwise (caller falls back to the store). The returned
// chain is a fresh copy — matching the store's copy-on-read semantics — so a
// caller that appends or mutates it (prepareBlockWrite appends the new block)
// cannot corrupt the shared overlay snapshot.
func (l *Ledger) overlayChain(account string) (*AccountChain, bool) {
	cb := l.activeCascadeFor()
	if cb == nil {
		return nil, false
	}
	ch, ok := cb.chains[account]
	if !ok {
		return nil, false
	}
	return copyAccountChainShallow(ch), true
}

// copyAccountChainShallow returns a chain with a fresh block slice (block
// pointers shared — callers append/replace slice entries but never mutate block
// fields in place).
func copyAccountChainShallow(ch *AccountChain) *AccountChain {
	if ch == nil {
		return nil
	}
	out := &AccountChain{Blocks: make([]*Block, len(ch.Blocks))}
	copy(out.Blocks, ch.Blocks)
	return out
}

// getAccountChainOverlay reads an account chain, consulting the cascade overlay
// first. Used by the winner-revalidation path (dispatchValidateAndAdd reads).
func (l *Ledger) getAccountChainOverlay(account string) (*AccountChain, error) {
	if ch, ok := l.overlayChain(account); ok {
		return ch, nil
	}
	return l.store.GetAccountChain(account)
}

// getPendingSendOverlay reads a pending send, consulting the cascade overlay
// first: a re-created source pending (addPending) is visible, a deleted one
// (delPending) is absent.
func (l *Ledger) getPendingSendOverlay(sendHash string) (*PendingSend, error) {
	cb := l.activeCascadeFor()
	if cb != nil {
		if ps, ok := cb.addPending[sendHash]; ok {
			cp := *ps
			return &cp, nil
		}
		if cb.delPending[sendHash] {
			return nil, nil
		}
	}
	return l.store.GetPendingSend(sendHash)
}

// getLeaseOverlay reads a lease record, consulting the cascade overlay first.
// ok reports whether a LeaseStore is available (mirrors the raw store assertion).
// Records are returned raw, WITHOUT BackfillState (that runs only on the node
// read path), so ledger-side callers can observe legacy State=="" — which is
// why isLiveLeaseEscrow must never be rewritten as !State.Terminal() (#763).
func (l *Ledger) getLeaseOverlay(leaseHash string) (lease *Lease, ok bool, err error) {
	cb := l.activeCascadeFor()
	if cb != nil {
		if rl, has := cb.restoreLease[leaseHash]; has {
			cp := *rl
			return &cp, true, nil
		}
		if cb.deleteLease[leaseHash] {
			return nil, true, nil
		}
	}
	ls, has := l.store.(LeaseStore)
	if !has {
		return nil, false, nil
	}
	lease, err = ls.GetLease(leaseHash)
	return lease, true, err
}

// getKeysetOverlay reads a keyset, consulting the cascade overlay first (a
// deleted keyset is absent). Falls back to the in-memory keyset cache (which the
// live path reads via GetKeyset).
func (l *Ledger) getKeysetOverlay(account string) *Keyset {
	cb := l.activeCascadeFor()
	if cb != nil && cb.deleteKeyset[account] {
		return nil
	}
	return l.GetKeyset(account)
}

// getAssetBalanceOverlay returns the asset balance for an account, computed by
// walking the overlaid post-undo chain when the overlay covers the account, else
// reading the live in-memory balance map. For an overlaid account the in-memory
// map still holds the pre-undo balance (memApplies run only after commit), so
// the chain walk is the correct post-undo value.
func (l *Ledger) getAssetBalanceOverlay(account, asset string) uint64 {
	if ch, ok := l.overlayChain(account); ok {
		if asset == "" {
			asset = "XE"
		}
		// #674: XUSD reconstruction from a chain must add back lease_settle stake
		// returns (which ride on XE blocks), the same way rebuildAssetBalances
		// does — otherwise a winner XUSD block stacked above a surviving settle is
		// validated against a stake-short balance and wrongly rejected.
		if asset == "XUSD" {
			return l.xusdBalanceOnChain(ch)
		}
		return assetBalanceOnChain(ch, asset)
	}
	return l.getAssetBalance(account, asset)
}

// overlayDelegationRep returns the post-undo delegation pointer for account if
// the overlay covers it, ok=false otherwise (caller falls back to l.delegation).
func (l *Ledger) overlayDelegationRep(account string) (rep string, ok bool) {
	cb := l.activeCascadeFor()
	if cb == nil {
		return "", false
	}
	if cb.delegated[account] {
		return cb.delegation[account], true
	}
	return "", false
}

// activateCascade installs cb as the active promotion overlay. It fails loudly
// if one is already active — the quorum lock serializes promotions, so a second
// active cascade indicates a structural invariant violation, not a recoverable
// condition. (#622)
func (l *Ledger) activateCascade(cb *cascadeBuild) error {
	l.cascadeMu.Lock()
	defer l.cascadeMu.Unlock()
	if l.activeCascade != nil {
		return fmt.Errorf("activateCascade: a conflict promotion is already in progress (winner %s) — promotions must be serialized", shortHash(l.activeCascade.winnerHash))
	}
	l.activeCascade = cb
	return nil
}

// deactivateCascade clears the active overlay. Idempotent: safe to call on the
// success path (defensively) and on the failure path.
func (l *Ledger) deactivateCascade() {
	l.cascadeMu.Lock()
	l.activeCascade = nil
	l.cascadeMu.Unlock()
}
