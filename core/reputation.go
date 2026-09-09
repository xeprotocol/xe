package core

import (
	"log"
	"sync"
)

const ReputationVersion uint32 = 2

type EventKind string

const (
	EventLeaseAccepted    EventKind = "lease_accepted"
	EventLeaseSettled     EventKind = "lease_settled"
	EventLeaseCancelled   EventKind = "lease_cancelled"
	EventLeaseUnfulfilled EventKind = "lease_unfulfilled"
)

type ReputationEvent struct {
	Kind         EventKind
	Provider     string
	Consumer     string
	Timestamp    int64
	DurationSecs uint64
}

type ReputationAggregate struct {
	Version uint32 `json:"version"`

	LeasesAcceptedAsProvider    uint64 `json:"leases_accepted_as_provider"`
	LeasesSettledAsProvider     uint64 `json:"leases_settled_as_provider"`
	LeaseHoursSettledAsProvider uint64 `json:"lease_hours_settled_as_provider"`
	LeasesUnfulfilledAsProvider uint64 `json:"leases_unfulfilled_as_provider"`

	LeasesAcceptedAsConsumer    uint64 `json:"leases_accepted_as_consumer"`
	LeasesSettledAsConsumer     uint64 `json:"leases_settled_as_consumer"`
	LeasesCancelledAsConsumer   uint64 `json:"leases_cancelled_as_consumer"`
	LeaseHoursSettledAsConsumer uint64 `json:"lease_hours_settled_as_consumer"`
	LeasesUnfulfilledAsConsumer uint64 `json:"leases_unfulfilled_as_consumer"`

	FirstActivityAt int64 `json:"first_activity_at"`
	LastActivityAt  int64 `json:"last_activity_at"`
}

func NewReputationAggregate() *ReputationAggregate {
	return &ReputationAggregate{Version: ReputationVersion}
}

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

type ReputationEngine struct {
	mu    sync.RWMutex
	agg   map[string]*ReputationAggregate
	store ReputationStore
}

func NewReputationEngine(store ReputationStore) *ReputationEngine {
	return &ReputationEngine{
		agg:   make(map[string]*ReputationAggregate),
		store: store,
	}
}

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

func (e *ReputationEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.agg = make(map[string]*ReputationAggregate)
}
