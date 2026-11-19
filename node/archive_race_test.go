package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func setupArchiveTestNode(t *testing.T) (*Node, *store.MemStore, *core.KeyPair) {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	memStore := store.NewMemStore()
	ledger := core.NewLedger(memStore, core.LedgerConfig{})

	n := &Node{
		KeyPair:        kp,
		store:          memStore,
		Ledger:         ledger,
		acceptInFlight: make(map[string]struct{}),
	}
	return n, memStore, kp
}

func TestNode_ArchiveExpiredLease_SkipsSettled(t *testing.T) {
	n, mem, kp := setupArchiveTestNode(t)
	consumer, _ := core.GenerateKeyPair()

	leaseHash := "lease_settled_test"
	now := time.Now().UnixNano()
	settledLease := &core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer.Address(),
		Provider:  kp.Address(),
		Duration:  3600,
		Cost:      1000,
		Stake:     100,
		StartTime: now - int64(100*time.Hour),
		State:     core.LeaseSettled,
		Settled:   true,
	}
	if err := mem.PutLease(settledLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Stale snapshot that thinks it's still Accepted and not Settled
	staleSnapshot := *settledLease
	staleSnapshot.State = core.LeaseAccepted
	staleSnapshot.Settled = false

	n.archiveExpiredLease(&staleSnapshot)

	// Lease in store must still be LeaseSettled
	stored, err := mem.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if stored.State != core.LeaseSettled {
		t.Fatalf("expected state to remain %s, got %s", core.LeaseSettled, stored.State)
	}
	if !stored.Settled {
		t.Fatalf("expected settled=true")
	}
}

func TestNode_ArchiveExpiredLease_SkipsRenewedNotExpired(t *testing.T) {
	n, mem, kp := setupArchiveTestNode(t)
	consumer, _ := core.GenerateKeyPair()

	leaseHash := "lease_renewed_not_expired"
	// Lease started 2 hours ago.
	startTime := time.Now().Add(-2 * time.Hour).UnixNano()

	// Renewed lease has 500 hours duration (so effective expiry is far in the future)
	renewedLease := &core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer.Address(),
		Provider:  kp.Address(),
		Duration:  3600,
		Cost:      1000,
		Stake:     100,
		StartTime: startTime,
		State:     core.LeaseAccepted,
		Settled:   false,
		Renewals: []core.LeaseSegment{
			{
				Duration:  uint64(500 * 3600),
				Cost:      50000,
				StartTime: startTime + int64(3600*time.Second),
			},
		},
	}
	if err := mem.PutLease(renewedLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Stale snapshot that only has the base 3600s
	staleSnapshot := &core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer.Address(),
		Provider:  kp.Address(),
		Duration:  3600,
		Cost:      1000,
		Stake:     100,
		StartTime: startTime,
		State:     core.LeaseAccepted,
		Settled:   false,
	}

	n.archiveExpiredLease(staleSnapshot)

	// Lease in store must still be LeaseAccepted with renewal intact
	stored, err := mem.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if stored.State != core.LeaseAccepted {
		t.Fatalf("expected state %s, got %s", core.LeaseAccepted, stored.State)
	}
	if stored.Settled {
		t.Fatalf("expected settled=false")
	}
	if len(stored.Renewals) != 1 {
		t.Fatalf("expected 1 renewal, got %d", len(stored.Renewals))
	}
}

func TestNode_ArchiveExpiredLease_ArchivesWhenExpired(t *testing.T) {
	n, mem, kp := setupArchiveTestNode(t)
	consumer, _ := core.GenerateKeyPair()

	leaseHash := "lease_truly_expired"
	// Very old start time so expiry + escrow expiry + archive gap is in the past
	oldStartTime := time.Now().Add(-500 * 24 * time.Hour).UnixNano()

	expiredLease := &core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer.Address(),
		Provider:  kp.Address(),
		Duration:  3600,
		Cost:      1000,
		Stake:     100,
		StartTime: oldStartTime,
		State:     core.LeaseAccepted,
		Settled:   false,
	}
	if err := mem.PutLease(expiredLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}
	if err := mem.PutPendingSend(&core.PendingSend{
		SendHash:    leaseHash,
		Destination: kp.Address(),
		Amount:      1000,
	}); err != nil {
		t.Fatalf("PutPendingSend: %v", err)
	}

	n.archiveExpiredLease(expiredLease)

	stored, err := mem.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if stored.State != core.LeaseExpired {
		t.Fatalf("expected state %s, got %s", core.LeaseExpired, stored.State)
	}
	if !stored.Settled {
		t.Fatalf("expected settled=true")
	}
	ps, err := mem.GetPendingSend(leaseHash)
	if err != nil {
		t.Fatalf("GetPendingSend: %v", err)
	}
	if ps != nil {
		t.Fatalf("expected pending send to be removed, got %+v", ps)
	}
}
