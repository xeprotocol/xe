package core

import (
	"fmt"
)

type cascadeBuild struct {
	winnerHash string

	undos      []*BlockUndo
	memApplies []func()

	chains map[string]*AccountChain

	addPending map[string]*PendingSend
	delPending map[string]bool

	restoreLease map[string]*Lease
	deleteLease  map[string]bool

	deleteKeyset map[string]bool

	delegation map[string]string

	delegated map[string]bool
}

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

func (cb *cascadeBuild) addUndo(undo *BlockUndo, apply func()) {
	cb.undos = append(cb.undos, undo)
	cb.memApplies = append(cb.memApplies, apply)

	cb.chains[undo.Account] = undo.Chain

	if undo.AddPending != nil {
		cp := *undo.AddPending
		cb.addPending[cp.SendHash] = &cp
		delete(cb.delPending, cp.SendHash)
	}
	if undo.DeletePendingID != "" {
		cb.delPending[undo.DeletePendingID] = true
		delete(cb.addPending, undo.DeletePendingID)
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

func (l *Ledger) activeCascadeFor() *cascadeBuild {
	l.cascadeMu.RLock()
	cb := l.activeCascade
	l.cascadeMu.RUnlock()
	return cb
}

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

func copyAccountChainShallow(ch *AccountChain) *AccountChain {
	if ch == nil {
		return nil
	}
	out := &AccountChain{Blocks: make([]*Block, len(ch.Blocks))}
	copy(out.Blocks, ch.Blocks)
	return out
}

func (l *Ledger) getAccountChainOverlay(account string) (*AccountChain, error) {
	if ch, ok := l.overlayChain(account); ok {
		return ch, nil
	}
	return l.store.GetAccountChain(account)
}

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

func (l *Ledger) getKeysetOverlay(account string) *Keyset {
	cb := l.activeCascadeFor()
	if cb != nil && cb.deleteKeyset[account] {
		return nil
	}
	return l.GetKeyset(account)
}

func (l *Ledger) getAssetBalanceOverlay(account, asset string) uint64 {
	if ch, ok := l.overlayChain(account); ok {
		if asset == "" {
			asset = "XE"
		}

		if asset == "XUSD" {
			return l.xusdBalanceOnChain(ch)
		}
		return assetBalanceOnChain(ch, asset)
	}
	return l.getAssetBalance(account, asset)
}

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

func (l *Ledger) activateCascade(cb *cascadeBuild) error {
	l.cascadeMu.Lock()
	defer l.cascadeMu.Unlock()
	if l.activeCascade != nil {
		return fmt.Errorf("activateCascade: a conflict promotion is already in progress (winner %s) — promotions must be serialized", shortHash(l.activeCascade.winnerHash))
	}
	l.activeCascade = cb
	return nil
}

func (l *Ledger) deactivateCascade() {
	l.cascadeMu.Lock()
	l.activeCascade = nil
	l.cascadeMu.Unlock()
}
