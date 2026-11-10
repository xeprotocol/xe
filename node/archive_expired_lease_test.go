package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/store"
)

func TestShouldArchiveExpiredLease(t *testing.T) {
	// Nil lease
	if shouldArchiveExpiredLease(nil, 1000) {
		t.Fatal("expected nil lease to return false")
	}

	startTime := int64(1_000_000_000_000) // 1000s in ns
	duration := uint64(100)               // 100s

	l := &core.Lease{
		LeaseHash: strings.Repeat("a", 64),
		State:     core.LeaseAccepted,
		StartTime: startTime,
		Duration:  duration,
		Settled:   false,
	}

	expiry := l.EffectiveExpiry()
	eligibleAt := expiry + core.LeaseEscrowExpiry + core.LeaseArchiveGap

	// Before expiry + escrow + gap
	if shouldArchiveExpiredLease(l, eligibleAt-1) {
		t.Fatal("expected false before eligibleAt")
	}

	// At eligibleAt
	if !shouldArchiveExpiredLease(l, eligibleAt) {
		t.Fatal("expected true at eligibleAt")
	}

	// After eligibleAt
	if !shouldArchiveExpiredLease(l, eligibleAt+1000) {
		t.Fatal("expected true after eligibleAt")
	}

	// Settled lease should return false
	l.Settled = true
	if shouldArchiveExpiredLease(l, eligibleAt+1000) {
		t.Fatal("expected false for settled lease")
	}
	l.Settled = false

	// Non-accepted states should return false
	for _, state := range []core.LeaseState{core.LeaseCreated, core.LeaseSettled, core.LeaseCancelled, core.LeaseUnfulfilled, core.LeaseExpired} {
		l.State = state
		if shouldArchiveExpiredLease(l, eligibleAt+1000) {
			t.Fatalf("expected false for lease state %s", state)
		}
	}
	l.State = core.LeaseAccepted

	// With renewals
	l.Renewals = []core.LeaseSegment{
		{Duration: 50},
	}
	newEligibleAt := l.EffectiveExpiry() + core.LeaseEscrowExpiry + core.LeaseArchiveGap
	if shouldArchiveExpiredLease(l, eligibleAt) {
		t.Fatal("expected false at old eligibleAt after renewal extended duration")
	}
	if !shouldArchiveExpiredLease(l, newEligibleAt) {
		t.Fatal("expected true at new eligibleAt with renewal")
	}
}

func TestNode_ArchiveExpiredLease(t *testing.T) {
	ms := store.NewMemStore()
	n := &Node{
		store: ms,
	}

	leaseHash := strings.Repeat("a", 64)
	consumer := strings.Repeat("1", 64)
	provider := strings.Repeat("2", 64)

	lease := &core.Lease{
		LeaseHash: leaseHash,
		Consumer:  consumer,
		Provider:  provider,
		Cost:      1000,
		StartTime: 1000,
		Duration:  60,
		State:     core.LeaseAccepted,
		Settled:   false,
		Renewals: []core.LeaseSegment{
			{Cost: 400},
			{Cost: 200},
		},
	}

	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	ps := &core.PendingSend{
		SendHash:    leaseHash,
		Source:      consumer,
		Destination: provider,
		Amount:      1600,
		Asset:       "XUSD",
	}
	if err := ms.PutPendingSend(ps); err != nil {
		t.Fatalf("PutPendingSend: %v", err)
	}

	// Archive the expired lease
	n.archiveExpiredLease(lease)

	// PendingSend should be deleted
	gotPS, err := ms.GetPendingSend(leaseHash)
	if err != nil {
		t.Fatalf("GetPendingSend: %v", err)
	}
	if gotPS != nil {
		t.Fatalf("expected pending send to be deleted, got %+v", gotPS)
	}

	// Lease should be expired and settled
	archivedLease, err := ms.GetLease(leaseHash)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if archivedLease == nil {
		t.Fatal("expected lease to exist")
	}
	if archivedLease.State != core.LeaseExpired {
		t.Fatalf("expected state LeaseExpired, got %s", archivedLease.State)
	}
	if !archivedLease.Settled {
		t.Fatal("expected Settled to be true")
	}

	// Archive again (idempotent no-op)
	n.archiveExpiredLease(archivedLease)
	archivedLease2, _ := ms.GetLease(leaseHash)
	if archivedLease2.State != core.LeaseExpired {
		t.Fatalf("expected state LeaseExpired, got %s", archivedLease2.State)
	}
}

func TestNode_TryArchiveExpiredLeases_AttestationGated(t *testing.T) {
	ms := store.NewMemStore()

	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()

	daoJSON := []byte(`{"keys":["` + kp1.PubKeyHex() + `","` + kp2.PubKeyHex() + `"],"threshold":2}`)
	tkJSON := []byte(`{"keys":["` + kp1.PubKeyHex() + `","` + kp2.PubKeyHex() + `"],"threshold":2}`)

	gen := &statechain.Block{
		Index:    0,
		PrevHash: strings.Repeat("0", 64),
		Ops: []statechain.Op{
			{Action: "set", Key: "sys.dao_keyset", Value: json.RawMessage(daoJSON)},
			{Action: "set", Key: "sys.timekeepers", Value: json.RawMessage(tkJSON)},
		},
	}
	var err error
	gen.Hash, err = statechain.HashBlock(gen)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}

	scChain, err := statechain.NewChain(ms, gen)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	n := &Node{
		store:      ms,
		StateChain: scChain,
	}

	now := core.Now().UnixNano()

	// Case 1: Lease is recent (eligibleAt is in the future)
	// Timekeepers sign current timestamp, which is BEFORE eligibleAt
	recentLeaseHash := strings.Repeat("c", 64)
	recentLease := &core.Lease{
		LeaseHash: recentLeaseHash,
		Consumer:  strings.Repeat("1", 64),
		Provider:  strings.Repeat("2", 64),
		Cost:      2000,
		StartTime: now,
		Duration:  60,
		State:     core.LeaseAccepted,
		Settled:   false,
	}
	_ = ms.PutLease(recentLease)
	_ = ms.PutPendingSend(&core.PendingSend{
		SendHash:    recentLeaseHash,
		Source:      recentLease.Consumer,
		Destination: recentLease.Provider,
		Amount:      2000,
		Asset:       "XUSD",
	})

	n.archiveAttestHook = func(h string, cfg *core.TimekeeperConfig) ([]core.TimekeeperAttestation, error) {
		att1, _ := core.SignAttestation(h, now, kp1)
		att2, _ := core.SignAttestation(h, now, kp2)
		return []core.TimekeeperAttestation{*att1, *att2}, nil
	}

	n.tryArchiveExpiredLeases()

	// Should NOT be archived because it's not expired
	l1, _ := ms.GetLease(recentLeaseHash)
	if l1.State != core.LeaseAccepted || l1.Settled {
		t.Fatalf("expected recent lease to remain LeaseAccepted, got state=%s settled=%v", l1.State, l1.Settled)
	}
	ps1, _ := ms.GetPendingSend(recentLeaseHash)
	if ps1 == nil {
		t.Fatal("expected pending send to remain for recent lease")
	}

	// Case 2: Expired lease but insufficient timekeeper attestations (threshold is 2, got 1)
	insuffLeaseHash := strings.Repeat("e", 64)
	insuffLease := &core.Lease{
		LeaseHash: insuffLeaseHash,
		Consumer:  strings.Repeat("1", 64),
		Provider:  strings.Repeat("2", 64),
		Cost:      2000,
		StartTime: now - int64(400*24*time.Hour),
		Duration:  60,
		State:     core.LeaseAccepted,
		Settled:   false,
	}
	_ = ms.PutLease(insuffLease)
	_ = ms.PutPendingSend(&core.PendingSend{
		SendHash:    insuffLeaseHash,
		Source:      insuffLease.Consumer,
		Destination: insuffLease.Provider,
		Amount:      2000,
		Asset:       "XUSD",
	})

	n.archiveAttestHook = func(h string, cfg *core.TimekeeperConfig) ([]core.TimekeeperAttestation, error) {
		att1, _ := core.SignAttestation(h, now, kp1)
		return []core.TimekeeperAttestation{*att1}, nil
	}

	n.tryArchiveExpiredLeases()

	// Should NOT be archived
	lInsuff, _ := ms.GetLease(insuffLeaseHash)
	if lInsuff.State != core.LeaseAccepted || lInsuff.Settled {
		t.Fatalf("expected lease to remain LeaseAccepted when threshold not met, got state=%s", lInsuff.State)
	}
	psInsuff, _ := ms.GetPendingSend(insuffLeaseHash)
	if psInsuff == nil {
		t.Fatal("expected pending send to remain when threshold not met")
	}

	// Case 3: Attestation timestamp is before eligibleAt (within skew window)
	// Make lease start time so eligibleAt is 10 seconds in future from now
	leaseNearExpiryHash := strings.Repeat("d", 64)
	nearStartTime := now - (core.LeaseEscrowExpiry + core.LeaseArchiveGap) + int64(10*time.Second)
	nearLease := &core.Lease{
		LeaseHash: leaseNearExpiryHash,
		Consumer:  strings.Repeat("1", 64),
		Provider:  strings.Repeat("2", 64),
		Cost:      500,
		StartTime: nearStartTime,
		Duration:  0,
		State:     core.LeaseAccepted,
		Settled:   false,
	}
	_ = ms.PutLease(nearLease)
	_ = ms.PutPendingSend(&core.PendingSend{
		SendHash:    leaseNearExpiryHash,
		Source:      nearLease.Consumer,
		Destination: nearLease.Provider,
		Amount:      500,
		Asset:       "XUSD",
	})

	n.archiveAttestHook = func(h string, cfg *core.TimekeeperConfig) ([]core.TimekeeperAttestation, error) {
		att1, _ := core.SignAttestation(h, now, kp1)
		att2, _ := core.SignAttestation(h, now, kp2)
		return []core.TimekeeperAttestation{*att1, *att2}, nil
	}

	n.tryArchiveExpiredLeases()

	// nearLease should NOT be archived because archiveTime (now) < eligibleAt (now + 10s)
	lNear, _ := ms.GetLease(leaseNearExpiryHash)
	if lNear.State != core.LeaseAccepted || lNear.Settled {
		t.Fatalf("expected nearLease to remain LeaseAccepted when archiveTime < eligibleAt, got state=%s", lNear.State)
	}
	psNear, _ := ms.GetPendingSend(leaseNearExpiryHash)
	if psNear == nil {
		t.Fatal("expected pending send to remain when archiveTime < eligibleAt")
	}

	// Case 4: Lease expired 400 days ago (eligibleAt is in the past)
	// Timekeepers sign current timestamp (now), which is >= eligibleAt
	matureLeaseHash := strings.Repeat("b", 64)
	matureLease := &core.Lease{
		LeaseHash: matureLeaseHash,
		Consumer:  strings.Repeat("1", 64),
		Provider:  strings.Repeat("2", 64),
		Cost:      2000,
		StartTime: now - int64(400*24*time.Hour),
		Duration:  60,
		State:     core.LeaseAccepted,
		Settled:   false,
	}
	_ = ms.PutLease(matureLease)
	_ = ms.PutPendingSend(&core.PendingSend{
		SendHash:    matureLeaseHash,
		Source:      matureLease.Consumer,
		Destination: matureLease.Provider,
		Amount:      2000,
		Asset:       "XUSD",
	})

	n.archiveAttestHook = func(h string, cfg *core.TimekeeperConfig) ([]core.TimekeeperAttestation, error) {
		att1, _ := core.SignAttestation(h, now, kp1)
		att2, _ := core.SignAttestation(h, now, kp2)
		return []core.TimekeeperAttestation{*att1, *att2}, nil
	}

	n.tryArchiveExpiredLeases()

	// Should NOW be archived
	l2, _ := ms.GetLease(matureLeaseHash)
	if l2.State != core.LeaseExpired || !l2.Settled {
		t.Fatalf("expected expired lease to be archived when attestations are mature, got state=%s settled=%v", l2.State, l2.Settled)
	}
	ps2, _ := ms.GetPendingSend(matureLeaseHash)
	if ps2 != nil {
		t.Fatal("expected pending send to be deleted after archive")
	}
}
