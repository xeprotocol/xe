package core

import (
	"maps"
	"math"
)

type finalSnapshot struct {
	height   int
	hash     string
	balances map[string]uint64
}

func (l *Ledger) FinalizedFrontier(account string) string {
	fh := l.FinalHeight(account)
	if fh == 0 {
		return ""
	}
	blocks, _ := l.GetChainRange(account, int(fh)-1, int(fh))
	if len(blocks) == 0 {
		return ""
	}
	return blocks[0].Hash
}

func (l *Ledger) SpendableBalances(account string) map[string]uint64 {
	fh := l.FinalHeight(account)
	if fh == 0 {
		return make(map[string]uint64)
	}
	return l.spendableUpTo(account, fh, math.MaxInt)
}

func (l *Ledger) advanceFinalSnapshot(account string, fh uint64) {
	l.spendableUpTo(account, fh, int(fh))
}

func (l *Ledger) spendableUpTo(account string, fh uint64, to int) map[string]uint64 {
	out := make(map[string]uint64)
	prev := make(map[string]uint64)
	blocks, n, snap := l.chainFromSnapshot(account, fh, to)
	pos := 0
	if snap != nil {
		pos = snap.height
		for a, v := range snap.balances {
			out[a], prev[a] = v, v
		}
	}
	limit := int(fh)
	if limit > n {
		limit = n
	}

	for _, b := range blocks {
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if pos < limit {
			out[a] = b.Balance
		} else if b.Balance < prev[a] {

			outflow := prev[a] - b.Balance
			if out[a] >= outflow {
				out[a] -= outflow
			} else {
				out[a] = 0
			}
		}
		prev[a] = b.Balance
		pos++
		if pos == limit && (snap == nil || pos > snap.height) {
			l.finalSnapMu.Lock()
			l.finalSnaps[account] = &finalSnapshot{height: pos, hash: b.Hash, balances: maps.Clone(out)}
			l.finalSnapMu.Unlock()
		}
	}
	return out
}

func (l *Ledger) chainFromSnapshot(account string, fh uint64, to int) ([]*Block, int, *finalSnapshot) {
	l.finalSnapMu.Lock()
	snap := l.finalSnaps[account]
	l.finalSnapMu.Unlock()
	if snap != nil && uint64(snap.height) <= fh {
		blocks, n := l.GetChainRange(account, snap.height-1, to)
		if len(blocks) > 0 && blocks[0].Hash == snap.hash {
			return blocks[1:], n, snap
		}
	}
	blocks, n := l.GetChainRange(account, 0, to)
	return blocks, n, nil
}
