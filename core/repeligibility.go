package core

import (
	"log"
	"math/big"
	"sync"
	"sync/atomic"
)

const (
	RepModeOpen = "open"

	RepModeAllowlist = "allowlist"
)

const MaxEligibleRepresentatives = 1000

type RepresentativeConfig struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses,omitempty"`
}

func (c *RepresentativeConfig) allowlist() map[string]bool {
	if c == nil || c.Mode != RepModeAllowlist || len(c.Addresses) == 0 {
		return nil
	}
	set := make(map[string]bool, len(c.Addresses))
	for _, a := range c.Addresses {
		if a != "" {
			set[a] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

type repEligibility struct {
	mu     sync.Mutex
	fn     func() *RepresentativeConfig
	cfg    *RepresentativeConfig
	set    map[string]bool
	parsed bool

	failedOpen atomic.Bool
}

func (l *Ledger) SetRepresentativeConfigFn(fn func() *RepresentativeConfig) {
	l.repElig.mu.Lock()
	l.repElig.fn = fn
	l.repElig.cfg, l.repElig.set, l.repElig.parsed = nil, nil, false
	l.repElig.mu.Unlock()
}

func (l *Ledger) RepEligibilityFailedOpen() bool { return l.repElig.failedOpen.Load() }

func (l *Ledger) configuredAllowlist() map[string]bool {
	l.repElig.mu.Lock()
	defer l.repElig.mu.Unlock()
	if l.repElig.fn == nil {
		return nil
	}
	cfg := l.repElig.fn()
	if l.repElig.parsed && cfg == l.repElig.cfg {
		return l.repElig.set
	}
	l.repElig.cfg, l.repElig.set, l.repElig.parsed = cfg, cfg.allowlist(), true
	return l.repElig.set
}

func (l *Ledger) eligibleAllowlistLocked() map[string]bool {
	set := l.configuredAllowlist()
	if set == nil {
		l.noteFailedOpen(false)
		return nil
	}

	for rep := range set {
		if w := l.weights[rep]; w != nil && w.Sign() > 0 {
			l.noteFailedOpen(false)
			return set
		}
	}

	for _, w := range l.weights {
		if w != nil && w.Sign() > 0 {
			l.noteFailedOpen(true)
			return nil
		}
	}
	l.noteFailedOpen(false)
	return nil
}

func (l *Ledger) noteFailedOpen(v bool) {
	if l.repElig.failedOpen.Swap(v) == v {
		return
	}
	if v {
		log.Printf("ERROR: sys.representatives allowlist matches ZERO delegated weight — ignoring it and counting every representative. " +
			"Finality would otherwise be impossible; fix the published allowlist")
	} else {
		log.Printf("sys.representatives is no longer being ignored — the published policy now resolves cleanly (either it matches delegated weight, or it no longer restricts)")
	}
}

func repEligibleLocked(set map[string]bool, rep string) bool {
	return set == nil || set[rep]
}

func (l *Ledger) sumEligibleLocked(set map[string]bool) *big.Int {
	total := new(big.Int)
	if set != nil {
		for rep := range set {
			if w := l.weights[rep]; w != nil && w.Sign() > 0 {
				total.Add(total, w)
			}
		}
		return total
	}
	for _, w := range l.weights {
		if w != nil && w.Sign() > 0 {
			total.Add(total, w)
		}
	}
	return total
}

func (l *Ledger) GetAllVoteWeights() map[string]uint64 {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	out := make(map[string]uint64, len(l.weights))
	for rep, w := range l.weights {
		if w == nil || w.Sign() <= 0 {
			continue
		}
		if w.IsUint64() {
			out[rep] = w.Uint64()
		} else {
			out[rep] = ^uint64(0)
		}
	}
	return out
}

func (l *Ledger) RepEligibilityRestricted() bool {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.eligibleAllowlistLocked() != nil
}

func (l *Ledger) GetIneligibleWeight() *big.Int {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	set := l.eligibleAllowlistLocked()
	if set == nil {
		return new(big.Int)
	}
	total := new(big.Int)
	for rep, w := range l.weights {
		if w == nil || w.Sign() <= 0 || set[rep] {
			continue
		}
		total.Add(total, w)
	}
	return total
}
