package core

import (
	"log"
	"sync"
)

// Deterministic per-account reputation derived from on-chain lease activity.
// See #380 (design) and #402 (phased implementation).
//
// Phase 1 stores raw counters only — no normalised vector, no scoring math.
// The two extensibility levers are:
//   - EventKind enum: new signals (heartbeat, challenge, …) are added by
//     introducing a new constant and a new case in ApplyReputationDelta.
//   - ReputationAggregate.Version: new fields are appended; old serialised
//     records decode with zero values for unknown fields.
//
// Reputation is node-local derived state, not consensus state. It is rebuilt
// from the lease record set on startup (see Ledger.rebuildReputation).

// ReputationVersion is the schema version of ReputationAggregate. Bump when
// adding fields and document the migration story in #402.
const ReputationVersion uint32 = 2

// EventKind identifies a reputation-affecting protocol event.
type EventKind string

const (
	EventLeaseAccepted    EventKind = "lease_accepted"
	EventLeaseSettled     EventKind = "lease_settled"
	EventLeaseCancelled   EventKind = "lease_cancelled"
	EventLeaseUnfulfilled EventKind = "lease_unfulfilled" // provider accepted but never settled (#490)
)

// ReputationEvent describes one observable protocol event that influences
// reputation. The same event mutates both parties' aggregates: callers invoke
// ApplyReputationDelta once per affected account.
type ReputationEvent struct {
	Kind         EventKind
	Provider     string // provider account; empty for events without a provider party
	Consumer     string // consumer account; empty for events without a consumer party
	Timestamp    int64  // unix nanos at which the event occurred (block timestamp)
	DurationSecs uint64 // lease duration in seconds; only meaningful for EventLeaseSettled
}

// ReputationAggregate is the per-account counter set persisted to ReputationStore.
// All counters are monotonic — they only increase. Composition into a score
// vector happens at read time in a separate function (phase 2).
type ReputationAggregate struct {
	Version uint32 `json:"version"`

	// Provider-side counters: this account acted as the provider.
	LeasesAcceptedAsProvider    uint64 `json:"leases_accepted_as_provider"`
	LeasesSettledAsProvider     uint64 `json:"leases_settled_as_provider"`
	LeaseHoursSettledAsProvider uint64 `json:"lease_hours_settled_as_provider"` // sum of settled lease durations in seconds
	LeasesUnfulfilledAsProvider uint64 `json:"leases_unfulfilled_as_provider"`  // accepted but never settled — negative signal (#490)

	// Consumer-side counters: this account acted as the consumer.
	LeasesAcceptedAsConsumer    uint64 `json:"leases_accepted_as_consumer"`
	LeasesSettledAsConsumer     uint64 `json:"leases_settled_as_consumer"`
	LeasesCancelledAsConsumer   uint64 `json:"leases_cancelled_as_consumer"`
	LeaseHoursSettledAsConsumer uint64 `json:"lease_hours_settled_as_consumer"`
	LeasesUnfulfilledAsConsumer uint64 `json:"leases_unfulfilled_as_consumer"` // had a lease the provider abandoned (#490)

	// Activity timestamps in unix nanos. FirstActivityAt is set on the first
	// event for this account and never changes; LastActivityAt updates on
	// every event.
	FirstActivityAt int64 `json:"first_activity_at"`
	LastActivityAt  int64 `json:"last_activity_at"`
}

// NewReputationAggregate returns an empty aggregate at the current schema version.
func NewReputationAggregate() *ReputationAggregate {
	return &ReputationAggregate{Version: ReputationVersion}
}

// ApplyReputationDelta mutates agg in place by applying ev's effect on the
// named account. account must be either ev.Provider or ev.Consumer; events
// that do not name the account are silently ignored so callers can blindly
// dispatch to both parties.
//
// The function is pure aside from mutating agg — no I/O, no global state.
// This makes it safe to call from the rebuild path (replay) as well as from
// the live block-validation hooks.
func ApplyReputationDelta(agg *ReputationAggregate, account string, ev ReputationEvent) {
	if agg == nil || account == "" {
		return
	}
	isProvider := account == ev.Provider
	isConsumer := account == ev.Consumer
	if !isProvider && !isConsumer {
		return
	}

	switch ev.Kind {
	case EventLeaseAccepted:
		if isProvider {
			agg.LeasesAcceptedAsProvider++
		}
		if isConsumer {
			agg.LeasesAcceptedAsConsumer++
		}
	case EventLeaseSettled:
		if isProvider {
			agg.LeasesSettledAsProvider++
			agg.LeaseHoursSettledAsProvider += ev.DurationSecs
		}
		if isConsumer {
			agg.LeasesSettledAsConsumer++
			agg.LeaseHoursSettledAsConsumer += ev.DurationSecs
		}
	case EventLeaseCancelled:
		if isConsumer {
			agg.LeasesCancelledAsConsumer++
		}
	case EventLeaseUnfulfilled:
		// Force-settled lease: the provider accepted but never settled. The
		// provider counter is the deterrent; the consumer counter is a neutral
		// record (the consumer was made whole, not rewarded — see #488 burn).
		if isProvider {
			agg.LeasesUnfulfilledAsProvider++
		}
		if isConsumer {
			agg.LeasesUnfulfilledAsConsumer++
		}
	}

	if agg.FirstActivityAt == 0 || ev.Timestamp < agg.FirstActivityAt {
		agg.FirstActivityAt = ev.Timestamp
	}
	if ev.Timestamp > agg.LastActivityAt {
		agg.LastActivityAt = ev.Timestamp
	}
}

// RevertReputationDelta is the inverse of ApplyReputationDelta for the monotonic
// counters: it decrements exactly what an Apply of the same event incremented.
// It is the reorg-undo half of the lease hooks — when a block that emitted a
// reputation event is later reorged out (buildBlockUndo), its counter effect
// must be reversed, otherwise a node that applied a losing equivocated sibling
// over-counts forever and diverges from peers and from a cold-sync rebuild (#681).
//
// Activity timestamps are intentionally NOT restored: FirstActivityAt /
// LastActivityAt are min/max reductions that cannot be inverted from a single
// event, and they are node-local, eventually-consistent metadata excluded from
// the cross-node counter parity. The surviving canonical events drive them.
func RevertReputationDelta(agg *ReputationAggregate, account string, ev ReputationEvent) {
	if agg == nil || account == "" {
		return
	}
	isProvider := account == ev.Provider
	isConsumer := account == ev.Consumer
	if !isProvider && !isConsumer {
		return
	}

	dec := func(c *uint64, by uint64) {
		if *c < by {
			// Reverting more than was applied means a forward/undo accounting
			// mismatch — clamp at zero rather than wrap the uint64, and surface it.
			log.Printf("reputation: revert underflow for %s (have %d, revert %d)", shortAddr(account), *c, by)
			*c = 0
			return
		}
		*c -= by
	}

	switch ev.Kind {
	case EventLeaseAccepted:
		if isProvider {
			dec(&agg.LeasesAcceptedAsProvider, 1)
		}
		if isConsumer {
			dec(&agg.LeasesAcceptedAsConsumer, 1)
		}
	case EventLeaseSettled:
		if isProvider {
			dec(&agg.LeasesSettledAsProvider, 1)
			dec(&agg.LeaseHoursSettledAsProvider, ev.DurationSecs)
		}
		if isConsumer {
			dec(&agg.LeasesSettledAsConsumer, 1)
			dec(&agg.LeaseHoursSettledAsConsumer, ev.DurationSecs)
		}
	case EventLeaseCancelled:
		if isConsumer {
			dec(&agg.LeasesCancelledAsConsumer, 1)
		}
	case EventLeaseUnfulfilled:
		if isProvider {
			dec(&agg.LeasesUnfulfilledAsProvider, 1)
		}
		if isConsumer {
			dec(&agg.LeasesUnfulfilledAsConsumer, 1)
		}
	}
}

// hasNoCounters reports whether every activity counter is zero — an aggregate
// that carries no reputation, only (possibly) residual activity timestamps. The
// engine drops such records on revert so the live map matches a cold-sync
// rebuild, which never materialises a counter-less account (#681).
func (a *ReputationAggregate) hasNoCounters() bool {
	return a.LeasesAcceptedAsProvider == 0 &&
		a.LeasesSettledAsProvider == 0 &&
		a.LeaseHoursSettledAsProvider == 0 &&
		a.LeasesUnfulfilledAsProvider == 0 &&
		a.LeasesAcceptedAsConsumer == 0 &&
		a.LeasesSettledAsConsumer == 0 &&
		a.LeasesCancelledAsConsumer == 0 &&
		a.LeaseHoursSettledAsConsumer == 0 &&
		a.LeasesUnfulfilledAsConsumer == 0
}

// AffectedAccounts returns the accounts whose aggregates ev mutates.
// Used by the engine to iterate exactly the right party set.
func (ev ReputationEvent) AffectedAccounts() []string {
	out := make([]string, 0, 2)
	if ev.Provider != "" {
		out = append(out, ev.Provider)
	}
	if ev.Consumer != "" && ev.Consumer != ev.Provider {
		out = append(out, ev.Consumer)
	}
	return out
}

// ReputationEngine owns the in-memory reputation map and (optionally) writes
// through to a ReputationStore for fast cold-start. The store is a perf
// optimisation only — the authoritative source is the lease record set, and
// the engine is rebuilt from leases on every non-empty ledger startup
// (mirroring how delegation and asset balances are handled).
type ReputationEngine struct {
	mu    sync.RWMutex
	agg   map[string]*ReputationAggregate
	store ReputationStore
}

// NewReputationEngine returns an engine backed by the given store. Pass nil
// for an in-memory-only engine (useful in tests).
func NewReputationEngine(store ReputationStore) *ReputationEngine {
	return &ReputationEngine{
		agg:   make(map[string]*ReputationAggregate),
		store: store,
	}
}

// Apply mutates the aggregates of every account affected by ev. Persistence
// failures are logged and swallowed: the in-memory state stays correct, and
// the rebuild path will reconstruct the store on next startup.
func (e *ReputationEngine) Apply(ev ReputationEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, acc := range ev.AffectedAccounts() {
		a := e.agg[acc]
		if a == nil {
			a = NewReputationAggregate()
		}
		ApplyReputationDelta(a, acc, ev)
		e.agg[acc] = a
		if e.store != nil {
			if err := e.store.PutReputation(acc, a); err != nil {
				log.Printf("reputation: PutReputation(%s): %v", shortAddr(acc), err)
			}
		}
	}
}

// Revert reverses the aggregate effect of ev on every affected account — the
// reorg-undo counterpart of Apply, called from buildBlockUndo when a lease block
// that emitted ev is unwound. An account left with no counters is dropped from
// both the in-memory map and the store so the live map converges with a
// cold-sync rebuild (which never creates a counter-less account). Persistence
// failures are logged and swallowed, matching Apply. (#681)
func (e *ReputationEngine) Revert(ev ReputationEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, acc := range ev.AffectedAccounts() {
		a := e.agg[acc]
		if a == nil {
			continue
		}
		RevertReputationDelta(a, acc, ev)
		if a.hasNoCounters() {
			delete(e.agg, acc)
			if e.store != nil {
				if err := e.store.DeleteReputation(acc); err != nil {
					log.Printf("reputation: DeleteReputation(%s): %v", shortAddr(acc), err)
				}
			}
			continue
		}
		e.agg[acc] = a
		if e.store != nil {
			if err := e.store.PutReputation(acc, a); err != nil {
				log.Printf("reputation: PutReputation(%s): %v", shortAddr(acc), err)
			}
		}
	}
}

// Get returns a copy of the aggregate for account, or nil if no events have
// touched the account yet.
func (e *ReputationEngine) Get(account string) *ReputationAggregate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	a := e.agg[account]
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

// All returns a copy of every account's aggregate.
func (e *ReputationEngine) All() map[string]*ReputationAggregate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]*ReputationAggregate, len(e.agg))
	for k, v := range e.agg {
		cp := *v
		out[k] = &cp
	}
	return out
}

// Reset clears the in-memory map. Used at the start of the rebuild path so
// stale entries from a prior run cannot leak through.
func (e *ReputationEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.agg = make(map[string]*ReputationAggregate)
}
