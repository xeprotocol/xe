package core

import (
	"testing"
)

func TestReputation_LeaseHoursSettledConversion(t *testing.T) {
	agg := NewReputationAggregate()
	provider := "provider_account_11111111111111111111111111111111"
	consumer := "consumer_account_22222222222222222222222222222222"

	// 2-hour lease = 7200 seconds
	ev := ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     provider,
		Consumer:     consumer,
		Timestamp:    1700000000,
		DurationSecs: 7200,
	}

	ApplyReputationDelta(agg, provider, ev)

	if agg.LeasesSettledAsProvider != 1 {
		t.Fatalf("expected LeasesSettledAsProvider=1, got %d", agg.LeasesSettledAsProvider)
	}
	// Must be 2 hours, NOT 7200 seconds
	if agg.LeaseHoursSettledAsProvider != 2 {
		t.Fatalf("expected LeaseHoursSettledAsProvider=2 hours, got %d", agg.LeaseHoursSettledAsProvider)
	}

	// Verify consumer side
	aggConsumer := NewReputationAggregate()
	ApplyReputationDelta(aggConsumer, consumer, ev)
	if aggConsumer.LeasesSettledAsConsumer != 1 {
		t.Fatalf("expected LeasesSettledAsConsumer=1, got %d", aggConsumer.LeasesSettledAsConsumer)
	}
	if aggConsumer.LeaseHoursSettledAsConsumer != 2 {
		t.Fatalf("expected LeaseHoursSettledAsConsumer=2 hours, got %d", aggConsumer.LeaseHoursSettledAsConsumer)
	}

	// Test Revert
	RevertReputationDelta(agg, provider, ev)
	if agg.LeasesSettledAsProvider != 0 {
		t.Fatalf("expected LeasesSettledAsProvider=0 after revert, got %d", agg.LeasesSettledAsProvider)
	}
	if agg.LeaseHoursSettledAsProvider != 0 {
		t.Fatalf("expected LeaseHoursSettledAsProvider=0 after revert, got %d", agg.LeaseHoursSettledAsProvider)
	}
}

func TestReputation_LeaseRenewalsIncluded(t *testing.T) {
	lease := &Lease{
		LeaseHash: "lease_test_hash_33333333333333333333333333333333",
		Provider:  "provider_account_11111111111111111111111111111111",
		Consumer:  "consumer_account_22222222222222222222222222222222",
		Duration:  3600, // 1 hour base
		Renewals: []LeaseSegment{
			{Duration: 7200},  // 2 hours renewal
			{Duration: 14400}, // 4 hours renewal
		},
	}

	effectiveSecs := lease.EffectiveDurationSecs()
	if effectiveSecs != 25200 {
		t.Fatalf("expected EffectiveDurationSecs=25200 (7 hours), got %d", effectiveSecs)
	}

	engine := NewReputationEngine(nil)
	ev := ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     lease.Provider,
		Consumer:     lease.Consumer,
		Timestamp:    1700000000,
		DurationSecs: effectiveSecs,
	}

	engine.Apply(ev)

	provAgg := engine.Get(lease.Provider)
	if provAgg == nil {
		t.Fatalf("expected provider aggregate to exist")
	}
	if provAgg.LeasesSettledAsProvider != 1 {
		t.Fatalf("expected LeasesSettledAsProvider=1, got %d", provAgg.LeasesSettledAsProvider)
	}
	// 25200s / 3600s = 7 hours
	if provAgg.LeaseHoursSettledAsProvider != 7 {
		t.Fatalf("expected LeaseHoursSettledAsProvider=7 hours, got %d", provAgg.LeaseHoursSettledAsProvider)
	}

	consAgg := engine.Get(lease.Consumer)
	if consAgg == nil {
		t.Fatalf("expected consumer aggregate to exist")
	}
	if consAgg.LeasesSettledAsConsumer != 1 {
		t.Fatalf("expected LeasesSettledAsConsumer=1, got %d", consAgg.LeasesSettledAsConsumer)
	}
	if consAgg.LeaseHoursSettledAsConsumer != 7 {
		t.Fatalf("expected LeaseHoursSettledAsConsumer=7 hours, got %d", consAgg.LeaseHoursSettledAsConsumer)
	}

	// Verify Revert
	engine.Revert(ev)
	provAfter := engine.Get(lease.Provider)
	if provAfter != nil && !provAfter.hasNoCounters() {
		t.Fatalf("expected provider aggregate cleared or counters zero, got %+v", provAfter)
	}
}
