package core

import (
	"fmt"
	"log"
	"math/big"
)

type cascadeStep struct {
	account string
	b       *Block
}

func (l *Ledger) planCascade(sendHash string, planned map[string]bool) ([]cascadeStep, error) {
	if ps, _ := l.store.GetPendingSend(sendHash); ps != nil {
		return nil, nil
	}
	var plan []cascadeStep
	if err := l.planRollbackOfSend(sendHash, planned, &plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (l *Ledger) planRollbackOfSend(sendHash string, planned map[string]bool, plan *[]cascadeStep) error {
	if ps, _ := l.store.GetPendingSend(sendHash); ps != nil {
		return nil
	}
	send := l.GetBlock(sendHash)
	if send == nil || send.Destination == "" {

		return nil
	}
	return l.planRollbackFrom(send.Destination, sendHash, planned, plan)
}

func (l *Ledger) planRollbackFrom(account, consumedSend string, planned map[string]bool, plan *[]cascadeStep) error {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return err
	}
	if chain == nil || len(chain.Blocks) == 0 {

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

		log.Printf("cascade: send %s has no pending and no receiver on %s — no rollback needed (anomalous)",
			shortHash(consumedSend), shortAddr(account))
		return nil
	}
	if fh := l.FinalHeight(account); uint64(recvIdx+1) <= fh {
		return fmt.Errorf("cascade: refusing to roll back finalized block at height %d (final height %d) on %s", recvIdx+1, fh, shortAddr(account))
	}

	for i := len(chain.Blocks) - 1; i >= recvIdx; i-- {
		b := chain.Blocks[i]
		if planned[b.Hash] {
			continue
		}
		switch b.Type {
		case BlockSend, BlockReceive, BlockBurn, BlockMint:

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

func (l *Ledger) buildBlockUndo(account string, b *Block, chain *AccountChain) (*BlockUndo, func(), error) {
	if chain == nil || len(chain.Blocks) == 0 || chain.Blocks[len(chain.Blocks)-1].Hash != b.Hash {
		return nil, nil, fmt.Errorf("cascade apply: %s is not the frontier of %s (chain changed under the cascade)", shortHash(b.Hash), shortAddr(account))
	}

	asset := b.Asset
	if asset == "" {
		asset = "XE"
	}

	var deletePendingID, deleteLeaseHash, deleteKeysetAccount string
	var addPending *PendingSend
	var restoreLease *Lease
	var assetDebit *AssetDelta
	switch b.Type {
	case BlockSend:
		deletePendingID = b.Hash
	case BlockReceive:

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

		deletePendingID = b.Hash
		deleteLeaseHash = b.Hash
	case BlockLeaseAccept:

		restoreLease = l.priorLease(b.Source, LeaseCreated)
	case BlockLeaseSettle, BlockLeaseForceSettle:

		restoreLease = l.priorLease(b.Source, LeaseAccepted)
		addPending = l.escrowPendingOf(b.Source)

		if b.Type == BlockLeaseSettle && restoreLease != nil {
			assetDebit = &AssetDelta{Account: b.Account, Asset: "XUSD", Amount: restoreLease.Stake}
		}
	case BlockLeaseCancel:

		restoreLease = l.priorLease(b.Source, LeaseCreated)
		addPending = l.escrowPendingOf(b.Source)
	case BlockMultisigOpen:
		deleteKeysetAccount = b.Account
	case BlockMultisigUpdate:

		return nil, nil, fmt.Errorf("undo: reversing a multisig_update is not supported (prior keyset unrecoverable): %s", shortHash(b.Hash))
	case BlockBurn, BlockMint:

	}
	if (b.Type == BlockLeaseAccept || b.Type == BlockLeaseSettle || b.Type == BlockLeaseForceSettle || b.Type == BlockLeaseCancel) && restoreLease == nil {
		return nil, nil, fmt.Errorf("undo: lease %s not found while reversing %s", shortHash(b.Source), b.Type)
	}

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

	xeBefore := assetBalanceOnChain(chain, "XE")
	var parentBal uint64
	if b.Previous != "0" {
		parentBal = assetBalanceOnChain(newChain, asset)

		if asset == "XUSD" {
			parentBal = l.xusdBalanceOnChain(newChain)
		}
	}
	xeAfter := assetBalanceOnChain(newChain, "XE")

	prevRep := ""
	for i := len(newChain.Blocks) - 1; i >= 0; i-- {
		if r := newChain.Blocks[i].Representative; r != "" {
			prevRep = r
			break
		}
	}

	deleteAccount := len(newChain.Blocks) == 0

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

		if deleteKeysetAccount != "" {
			l.keysetMu.Lock()
			delete(l.keysets, deleteKeysetAccount)
			l.keysetMu.Unlock()
		}

		if deleteAccountKeyAccount != "" {
			l.accountKeyMu.Lock()
			delete(l.accountKeys, deleteAccountKeyAccount)
			l.accountKeyMu.Unlock()
		}

		if deleteAccount {
			l.deleteAccountBalances(account)
		} else {
			l.setAssetBalance(account, asset, parentBal)
		}

		if assetDebit != nil {
			l.subAssetBalance(assetDebit.Account, assetDebit.Asset, assetDebit.Amount)
		}

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

		if repRevert != nil {
			l.reputation.Revert(*repRevert)
		}
	}

	return undo, apply, nil
}

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
