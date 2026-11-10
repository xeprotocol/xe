package core

import (
	"testing"
)

func TestReputation_LeaseHoursSettled_UnitConversion(t *testing.T) {
	agg := NewReputationAggregate()

	// 24 hours = 86,400 seconds
	ev := ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     "provider1",
		Consumer:     "consumer1",
		Timestamp:    1700000000,
		DurationSecs: 86400,
	}

	// Apply to provider
	ApplyReputationDelta(agg, "provider1", ev)
	if agg.LeasesSettledAsProvider != 1 {
		t.Fatalf("expected 1 lease settled as provider, got %d", agg.LeasesSettledAsProvider)
	}
	if agg.LeaseHoursSettledAsProvider != 24 {
		t.Fatalf("expected 24 hours settled as provider, got %d", agg.LeaseHoursSettledAsProvider)
	}

	// Apply to consumer
	ApplyReputationDelta(agg, "consumer1", ev)
	if agg.LeasesSettledAsConsumer != 1 {
		t.Fatalf("expected 1 lease settled as consumer, got %d", agg.LeasesSettledAsConsumer)
	}
	if agg.LeaseHoursSettledAsConsumer != 24 {
		t.Fatalf("expected 24 hours settled as consumer, got %d", agg.LeaseHoursSettledAsConsumer)
	}

	// Revert provider
	RevertReputationDelta(agg, "provider1", ev)
	if agg.LeasesSettledAsProvider != 0 {
		t.Fatalf("expected 0 leases settled after revert, got %d", agg.LeasesSettledAsProvider)
	}
	if agg.LeaseHoursSettledAsProvider != 0 {
		t.Fatalf("expected 0 hours settled after revert, got %d", agg.LeaseHoursSettledAsProvider)
	}

	// Revert consumer
	RevertReputationDelta(agg, "consumer1", ev)
	if agg.LeasesSettledAsConsumer != 0 {
		t.Fatalf("expected 0 leases settled after revert, got %d", agg.LeasesSettledAsConsumer)
	}
	if agg.LeaseHoursSettledAsConsumer != 0 {
		t.Fatalf("expected 0 hours settled after revert, got %d", agg.LeaseHoursSettledAsConsumer)
	}
}

func TestReputation_LeaseHoursSettled_AccumulationAndTruncation(t *testing.T) {
	agg := NewReputationAggregate()

	// 5,400 seconds = 1.5 hours -> integer division yields 1 hour
	ev1 := ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     "providerX",
		Timestamp:    1700001000,
		DurationSecs: 5400,
	}
	ApplyReputationDelta(agg, "providerX", ev1)
	if agg.LeaseHoursSettledAsProvider != 1 {
		t.Fatalf("expected 1 hour, got %d", agg.LeaseHoursSettledAsProvider)
	}

	// Another 7,200 seconds = 2 hours -> cumulative 3 hours
	ev2 := ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     "providerX",
		Timestamp:    1700002000,
		DurationSecs: 7200,
	}
	ApplyReputationDelta(agg, "providerX", ev2)
	if agg.LeaseHoursSettledAsProvider != 3 {
		t.Fatalf("expected 3 hours, got %d", agg.LeaseHoursSettledAsProvider)
	}
}

func TestLease_EffectiveDurationSecs_WithRenewals(t *testing.T) {
	lease := &Lease{
		Duration: 3600,
		Renewals: []LeaseSegment{
			{Duration: 7200},
			{Duration: 10800},
		},
	}

	effective := lease.EffectiveDurationSecs()
	expected := uint64(3600 + 7200 + 10800) // 21,600s = 6 hours
	if effective != expected {
		t.Fatalf("expected effective duration %d, got %d", expected, effective)
	}
	if effective/3600 != 6 {
		t.Fatalf("expected 6 effective hours, got %d", effective/3600)
	}
}
