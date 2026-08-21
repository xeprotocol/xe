package core

// repeligibility.go — representative eligibility for the quorum denominator (#832).
//
// THE PROBLEM
//
// Representative-hood is emergent. Any account may name any 32-byte address in
// its block's Representative field, and updateDelegation moves that account's XE
// into weights[address] — whether or not anybody runs a node for that address.
// GetTotalDelegatedWeight sums every entry, so weight delegated to an address
// that never votes still raises the bar for every finalization on the network:
//
//	dead ≥ 33%  the 67% path is unreachable; every position waits out
//	            fallbackDelay (10s) and finalizes on the >50% fallback
//	dead ≥ 50%  neither bar can be met: finality halts network-wide, FinalHeight
//	            freezes, spendable balances freeze (C5), and there is no
//	            in-protocol recovery — the coins must physically move
//
// A claim-based distribution makes this reachable by accident: a claimant who
// self-delegates and runs no node contributes pure dead weight. The wallet
// sends Representative: "" today, which is weight-neutral, but that default is
// a convention, not a rule.
//
// WHY NOT "EXCLUDE REPRESENTATIVES WE HAVE NOT HEARD VOTE"
//
// The obvious fix — track the last vote seen per representative and drop the
// quiet ones from the denominator — is unsafe, and provably so.
//
// Finality safety rests on one arithmetic fact: the 67% path and the >50%
// fallback cannot both be satisfied at one position, because commit-locks (C2)
// make each representative's final vote exclusive and 0.67 + 0.5 > 1. Let D_A be
// the denominator node A uses and D_B node B's. Node A finalizes sibling H when
// it sees 0.67·D_A of final weight on H; node B finalizes sibling L when it sees
// 0.5·D_B on L. Those vote sets are disjoint, so both can happen whenever
//
//	0.67·D_A + 0.5·D_B ≤ T        (T = true total delegated weight)
//
// With D_A = D_B = T that is 1.17·T ≤ T — impossible, which is why the protocol
// is safe today. Shrinking the denominator to β·T makes it possible as soon as
// β ≤ 1/1.17 ≈ 0.855. So ANY denominator rule that can drop more than ~14% of
// the weight admits two conflicting finalizations — and a liveness-derived rule
// can drop everything, because "has not voted" and "has not been heard from" are
// the same observation. An adversary who delays vote delivery to one node (or
// eclipses it) shrinks that node's denominator at will and then finalizes
// whatever it likes there, behind the unhealable rollback wall (C3). Excluding
// non-responders is the textbook way to turn a partition stall into a partition
// fork, and it is not fixable by tuning the window: any window long enough to be
// safe is longer than the partitions it is meant to survive.
//
// THE RULE ACTUALLY IMPLEMENTED
//
// Eligibility is therefore derived from CHAIN DATA, not from observed liveness,
// so every synced node computes the same denominator: the state chain carries an
// optional sys.representatives policy, set by DAO threshold like every other
// sys.* key (K1).
//
//	absent (or {"mode":"open"})                    every representative counts —
//	                                               byte-for-byte today's behaviour
//	{"mode":"allowlist","addresses":[...]}         only the listed addresses count
//
// The gate is applied at ONE place: the weight lookup. An ineligible
// representative's weight is removed from the denominator (GetTotalDelegatedWeight),
// from the conflict weight snapshot (snapshotWeights → Conflict.WeightSnapshot /
// TotalWeight), and from its own vote (GetVoteWeight ⇒ 0, which stops it emitting
// via castVoteLocked and makes peers reject its votes via ValidateVote). Removing
// it from the denominator ONLY would be far worse than the bug it fixes: an
// ineligible whale could then finalize against a denominator it is not part of.
//
// Because both sides move together, the safety arithmetic above is preserved
// exactly: within the eligible set, 0.67 + 0.5 > 1 still holds, and every node
// with the same statechain state computes the same set. Statechain lag makes a
// node briefly use the previous policy — the same class of drift the denominator
// already has from ledger lag, and it is bounded by a governance action nobody
// takes during an incident.
//
// TRANSITIONAL EXPOSURE, stated plainly. Conflict.WeightSnapshot / TotalWeight
// freeze at detection time (C6), so a conflict recorded before the policy lands
// keeps tallying against the old denominator — correct, and what keeps a single
// conflict's arithmetic self-consistent. But two nodes that record the SAME
// conflict either side of the publication would snapshot different totals, and
// the inequality above can then be satisfied. This hazard is not new: the
// snapshot total already differs between nodes that detect a conflict either
// side of any large send, because weight follows balance. What IS new is the
// magnitude — a publication can halve the denominator in one step. So publish
// the policy on a quiesced network, as part of a coordinated restart, never
// during a rolling deploy or under load.
//
// FAIL-OPEN. A policy that would leave zero eligible weight is IGNORED and the
// full denominator is used. Zero total weight is silent finality death (#833);
// a fat-fingered allowlist must not be able to cause it. Widening the
// denominator is always the safe direction — it makes finalization harder, never
// easier — so failing open cannot create the divergence described above.
//
// WHAT THIS DOES NOT DO. It does not evict a representative that was eligible
// and then died; that stays a governance action, observable through the
// active-representative metrics on /ready and /metrics (#841/#861). It does not
// change custody of the delegation accounts (#827/#831). It is inert until the
// DAO publishes a policy, so shipping it costs nothing and omitting it from the
// Genesis(1) binary forecloses it forever.

import (
	"log"
	"math/big"
	"sync"
	"sync/atomic"
)

// Representative eligibility modes, published as sys.representatives.mode.
const (
	// RepModeOpen counts every representative — the default, and identical to
	// having no policy at all. It exists because sys.* keys can never be
	// deleted (statechain/kvstore.go), so "open" is the only way to lift an
	// allowlist once one has been published.
	RepModeOpen = "open"
	// RepModeAllowlist counts only the representatives named in Addresses.
	RepModeAllowlist = "allowlist"
)

// MaxEligibleRepresentatives bounds the published allowlist. It is a
// denial-of-service bound on the per-lookup work, not a policy statement.
const MaxEligibleRepresentatives = 1000

// RepresentativeConfig is the network's representative-eligibility policy, read
// from sys.representatives on the state chain.
type RepresentativeConfig struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses,omitempty"`
}

// allowlist returns the eligible-address set, or nil when the policy does not
// restrict anything. An unknown mode, or an allowlist with no addresses, is
// treated as unrestricted: an unusable policy must never be read as "nobody is
// eligible", which would halt the chain.
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

// repEligibility holds the policy source plus a one-entry cache of the parsed
// allowlist, keyed on the config pointer the source returns. The wiring returns
// a stable pointer while sys.representatives is unchanged, so the common case is
// a pointer comparison; a source that reallocates only costs a re-parse.
type repEligibility struct {
	mu     sync.Mutex
	fn     func() *RepresentativeConfig
	cfg    *RepresentativeConfig
	set    map[string]bool
	parsed bool

	// failedOpen latches whether the configured policy is currently being
	// ignored for leaving zero eligible weight. Observable, and logged on
	// transition rather than on every lookup.
	failedOpen atomic.Bool
}

// SetRepresentativeConfigFn installs the source of the representative-eligibility
// policy (typically a closure reading sys.representatives from the state chain).
// A nil fn, or one returning nil, leaves the denominator unrestricted.
func (l *Ledger) SetRepresentativeConfigFn(fn func() *RepresentativeConfig) {
	l.repElig.mu.Lock()
	l.repElig.fn = fn
	l.repElig.cfg, l.repElig.set, l.repElig.parsed = nil, nil, false
	l.repElig.mu.Unlock()
}

// RepEligibilityFailedOpen reports whether a representative-eligibility policy is
// configured but being ignored because it would leave the network with zero
// eligible vote weight. Surfaced on /delegation so a misconfigured allowlist is
// visible rather than silently inert.
func (l *Ledger) RepEligibilityFailedOpen() bool { return l.repElig.failedOpen.Load() }

// configuredAllowlist returns the parsed allowlist from the current policy, or
// nil when unrestricted. Cached on the config pointer.
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

// eligibleAllowlistLocked returns the allowlist actually in force, or nil when
// every representative counts. Caller holds delegationMu (read or write).
//
// Applies the fail-open rule: a policy that leaves zero eligible weight, while
// weight exists elsewhere, is ignored.
func (l *Ledger) eligibleAllowlistLocked() map[string]bool {
	set := l.configuredAllowlist()
	if set == nil {
		l.noteFailedOpen(false)
		return nil
	}
	// O(|allowlist|), independent of how many ineligible representatives exist —
	// which matters precisely because dead delegation can create unboundedly
	// many of them.
	for rep := range set {
		if w := l.weights[rep]; w != nil && w.Sign() > 0 {
			l.noteFailedOpen(false)
			return set
		}
	}
	// Zero eligible weight. Fail open unless there is no weight at all, in which
	// case the policy is not what is wrong (#833 covers a weightless genesis).
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
			"Finality would otherwise be impossible; fix the published allowlist (#832)")
	} else {
		log.Printf("sys.representatives is no longer being ignored — the published policy now resolves cleanly (either it matches delegated weight, or it no longer restricts) (#832)")
	}
}

// repEligibleLocked reports whether rep's weight counts, given the allowlist in
// force (nil ⇒ everything counts). Caller holds delegationMu.
func repEligibleLocked(set map[string]bool, rep string) bool {
	return set == nil || set[rep]
}

// sumEligibleLocked totals the weight that counts toward quorum. Caller holds
// delegationMu.
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

// GetAllVoteWeights returns EVERY representative's delegated weight in micro-XE,
// including representatives excluded from the quorum denominator by the
// eligibility policy. This is the observability view: GetVoteWeights is the
// consensus view, and the difference between the two is exactly the dead weight
// the gate is holding out of quorum. Representatives with zero weight are
// omitted.
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

// RepEligibilityRestricted reports whether a representative-eligibility
// allowlist is actually in force right now (published, parseable, and matching
// some delegated weight). False means the quorum denominator counts every
// representative — today's behaviour, and the default.
func (l *Ledger) RepEligibilityRestricted() bool {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.eligibleAllowlistLocked() != nil
}

// GetIneligibleWeight returns the total delegated weight that the eligibility
// policy is currently holding OUT of the quorum denominator. Zero when
// unrestricted. This is the number that used to deadlock finality.
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
