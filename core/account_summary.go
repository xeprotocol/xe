package core

import (
	"cmp"
	"log"
	"maps"
	"slices"
	"strings"
)

type AccountSummary struct {
	Account    string
	Frontier   string
	BlockCount int

	LastBalance   uint64
	LastTimestamp int64

	FrontierType      BlockType
	FrontierTimestamp int64
	FrontierRep       string

	Balances map[string]uint64
	xe       uint64
}

func (l *Ledger) buildAccountSummaries() {
	frontiers := l.Frontiers()
	l.assetBalMu.Lock()
	for account := range frontiers {
		l.summaryDirty[account] = struct{}{}
	}
	l.assetBalMu.Unlock()
	l.summaryMu.Lock()
	l.refreshSummariesLocked()
	l.summaryMu.Unlock()
}

func (l *Ledger) refreshSummariesLocked() {
	l.assetBalMu.Lock()
	if len(l.summaryDirty) == 0 {
		l.assetBalMu.Unlock()
		return
	}
	dirty := l.summaryDirty
	l.summaryDirty = make(map[string]struct{})
	balances := make(map[string]map[string]uint64, len(dirty))
	for account := range dirty {
		m := maps.Clone(l.assetBalances[account])
		if m == nil {
			m = map[string]uint64{}
		}
		balances[account] = m
	}
	l.assetBalMu.Unlock()

	for account := range dirty {
		s, err := l.readAccountSummary(account)
		if err != nil {

			storeReadErrors.Add(1)
			log.Printf("ERROR: account summary: store read for %s failed: %v", shortAddr(account), err)
			l.assetBalMu.Lock()
			l.summaryDirty[account] = struct{}{}
			l.assetBalMu.Unlock()
			continue
		}
		if s == nil {
			delete(l.summaries, account)
			continue
		}
		s.Balances = balances[account]
		s.xe = s.Balances["XE"]
		l.summaries[account] = s
	}
	l.summaryByXE, l.summaryByID = nil, nil
}

func (l *Ledger) readAccountSummary(account string) (*AccountSummary, error) {
	frontier, err := l.store.GetFrontier(account)
	if err != nil || frontier == "" {
		return nil, err
	}
	hashes, err := l.chainHashes(account)
	if err != nil {
		return nil, err
	}
	s := &AccountSummary{Account: account, Frontier: frontier, BlockCount: len(hashes)}
	var last *Block
	if len(hashes) > 0 {
		if last, err = l.store.GetBlock(hashes[len(hashes)-1]); err != nil {
			return nil, err
		}
		if last != nil {
			s.LastBalance, s.LastTimestamp = last.Balance, last.Timestamp
		}
	}
	fb := last
	if fb == nil || fb.Hash != frontier {
		if fb, err = l.store.GetBlock(frontier); err != nil {
			return nil, err
		}
	}
	if fb != nil {
		s.FrontierType, s.FrontierTimestamp, s.FrontierRep = fb.Type, fb.Timestamp, fb.Representative
	}
	return s, nil
}

func (l *Ledger) AccountsByXEBalance() []*AccountSummary {
	l.summaryMu.Lock()
	defer l.summaryMu.Unlock()
	l.refreshSummariesLocked()
	if l.summaryByXE == nil {
		l.summaryByXE = slices.SortedFunc(maps.Values(l.summaries), func(a, b *AccountSummary) int {
			if c := cmp.Compare(b.xe, a.xe); c != 0 {
				return c
			}
			return strings.Compare(a.Account, b.Account)
		})
	}
	return l.summaryByXE
}

func (l *Ledger) AccountsByAddress() []*AccountSummary {
	l.summaryMu.Lock()
	defer l.summaryMu.Unlock()
	l.refreshSummariesLocked()
	if l.summaryByID == nil {
		l.summaryByID = slices.SortedFunc(maps.Values(l.summaries), func(a, b *AccountSummary) int {
			return strings.Compare(a.Account, b.Account)
		})
	}
	return l.summaryByID
}
