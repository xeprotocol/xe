package core_test

import (
	"errors"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestLease_TotalCost(t *testing.T) {
	l := &core.Lease{
		Cost: 1000,
	}
	if got := l.TotalCost(); got != 1000 {
		t.Fatalf("TotalCost without renewals: got %d, want 1000", got)
	}

	l.Renewals = []core.LeaseSegment{
		{Cost: 500, Duration: 3600},
		{Cost: 300, Duration: 1800},
	}
	if got := l.TotalCost(); got != 1800 {
		t.Fatalf("TotalCost with renewals: got %d, want 1800", got)
	}
}

func TestArchiveExpiredLease_Success(t *testing.T) {
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{})

	consumer, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key: %v", err)
	}
	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}

	leaseHash := "testlease_success_hash"
	startTime := time.Now().Add(-2 * time.Hour).UnixNano()
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer.Address(),
		Provider:  provider.Address(),
		Duration:  3600,
		Cost:      1000,
		Stake:     100,
		StartTime: startTime,
		Settled:   false,
	}

	if err := mem.PutLease(lease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}
	if err := mem.PutPendingSend(&core.PendingSend{
		SendHash:    leaseHash,
		Destination: provider.Address(),
		Amount:      1000,
	}); err != nil {
		t.Fatalf("PutPendingSend: %v", err)
	}

	if err := ledger.ArchiveExpiredLease(lease); err != nil {
		t.Fatalf("ArchiveExpiredLease failed: %v", err)
	}

	archived, err := mem.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease failed: %v", err)
	}
	if archived.State != core.LeaseExpired {
		t.Fatalf("state: got %s, want %s", archived.State, core.LeaseExpired)
	}
	if !archived.Settled {
		t.Fatalf("settled: got false, want true")
	}

	ps, err := mem.GetPendingSend(leaseHash)
	if err != nil {
		t.Fatalf("GetPendingSend: %v", err)
	}
	if ps != nil {
		t.Fatalf("expected pending send to be deleted, got %+v", ps)
	}
}

func TestArchiveExpiredLease_RejectsSettledOrCancelled(t *testing.T) {
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{})

	consumer, _ := core.GenerateKeyPair()
	provider, _ := core.GenerateKeyPair()

	cases := []struct {
		name    string
		state   core.LeaseState
		settled bool
	}{
		{"settled_flag_true", core.LeaseAccepted, true},
		{"state_settled", core.LeaseSettled, true},
		{"state_cancelled", core.LeaseCancelled, false},
		{"state_expired", core.LeaseExpired, true},
		{"state_unfulfilled", core.LeaseUnfulfilled, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaseHash := "lease_" + tc.name
			leaseInStore := &core.Lease{
				LeaseHash: leaseHash,
				State:     tc.state,
				Consumer:  consumer.Address(),
				Provider:  provider.Address(),
				Duration:  3600,
				Cost:      1000,
				StartTime: time.Now().Add(-2 * time.Hour).UnixNano(),
				Settled:   tc.settled,
			}
			if err := mem.PutLease(leaseInStore); err != nil {
				t.Fatalf("PutLease: %v", err)
			}

			// Stale snapshot that thinks it's still Accepted
			snapshot := *leaseInStore
			snapshot.State = core.LeaseAccepted
			snapshot.Settled = false

			err := ledger.ArchiveExpiredLease(&snapshot)
			if err == nil {
				t.Fatalf("expected ErrLeaseStateConflict, got nil")
			}
			if !errors.Is(err, core.ErrLeaseStateConflict) {
				t.Fatalf("expected ErrLeaseStateConflict, got %v", err)
			}
		})
	}
}

func TestArchiveExpiredLease_RejectsRenewedExpiryMismatch(t *testing.T) {
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{})

	consumer, _ := core.GenerateKeyPair()
	provider, _ := core.GenerateKeyPair()

	startTime := time.Now().Add(-2 * time.Hour).UnixNano()
	leaseHash := "lease_renewed_race"

	// Live lease in store was renewed with an additional 3600s segment
	renewedLease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer.Address(),
		Provider:  provider.Address(),
		Duration:  3600,
		Cost:      1000,
		StartTime: startTime,
		Settled:   false,
		Renewals: []core.LeaseSegment{
			{
				Duration:  3600,
				Cost:      1000,
				StartTime: startTime + int64(3600*time.Second),
			},
		},
	}
	if err := mem.PutLease(renewedLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Stale snapshot taken before the renewal committed (has no renewals, older expiry)
	staleSnapshot := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumer.Address(),
		Provider:  provider.Address(),
		Duration:  3600,
		Cost:      1000,
		StartTime: startTime,
		Settled:   false,
	}

	err := ledger.ArchiveExpiredLease(staleSnapshot)
	if err == nil {
		t.Fatalf("expected ErrLeaseStateConflict on expiry mismatch, got nil")
	}
	if !errors.Is(err, core.ErrLeaseStateConflict) {
		t.Fatalf("expected ErrLeaseStateConflict, got %v", err)
	}

	// Verify store was not mutated
	stored, err := mem.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if stored.State != core.LeaseAccepted {
		t.Fatalf("stored lease state overwritten: got %s, want %s", stored.State, core.LeaseAccepted)
	}
	if stored.Settled {
		t.Fatalf("stored lease marked settled")
	}
	if len(stored.Renewals) != 1 {
		t.Fatalf("stored lease renewals lost: got %d, want 1", len(stored.Renewals))
	}
}
