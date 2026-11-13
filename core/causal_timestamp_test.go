package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func signBlock(t *testing.T, b *core.Block, kp *core.KeyPair) {
	t.Helper()
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock(%s): %v", b.Type, err)
	}
}

func setupLeaseTestLedger(
	t *testing.T,
	s core.Store,
	consumerKP, providerKP, tkKP *core.KeyPair,
	certHash string,
	now int64,
) *core.Ledger {
	t.Helper()
	return core.NewLedger(s, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: core.DefaultTimestampWindow,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{
				Threshold: 1,
				Keys:      []string{tkKP.PubKeyHex()},
			}
		},
		MinterConfigFn: func() *core.MinterConfig {
			return &core.MinterConfig{
				Keys: []string{consumerKP.Address(), providerKP.Address()},
			}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			if hash == certHash {
				return &core.CertificateInfo{
					Provider:             providerKP.Address(),
					ExpiresAt:            now + int64(365*24*time.Hour),
					PriceMultiplierMilli: 1000,
				}
			}
			return nil
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 1000}}
		},
		FeatureActiveFn: func(feature string) bool { return true },
	})
}

func TestReceiveRejectsTimestampBeforeSourceSend(t *testing.T) {
	s := store.NewMemStore()
	senderKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	relayKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	l := core.NewLedger(s, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: core.DefaultTimestampWindow,
	})

	openBlk := &core.Block{
		Type:      core.BlockMint,
		Account:   senderKP.Address(),
		Previous:  "0",
		PubKey:    senderKP.PubKeyHex(),
		Balance:   1_000_000_000,
		Timestamp: now - int64(10*time.Minute),
		Asset:     "XE",
		Amount:    1_000_000_000,
	}
	signBlock(t, openBlk, senderKP)
	if err := l.SeedAssetForTesting(openBlk); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	sendTs := now + int64(5*time.Minute)
	sendBlk := &core.Block{
		Type:        core.BlockSend,
		Account:     senderKP.Address(),
		Previous:    openBlk.Hash,
		Balance:     0,
		Timestamp:   sendTs,
		Asset:       "XE",
		Destination: relayKP.Address(),
		Amount:      1_000_000_000,
	}
	signBlock(t, sendBlk, senderKP)
	if err := l.AddBlock(sendBlk); err != nil {
		t.Fatalf("AddBlock(send): %v", err)
	}

	backdatedRecv := &core.Block{
		Type:      core.BlockReceive,
		Account:   relayKP.Address(),
		Previous:  "0",
		PubKey:    relayKP.PubKeyHex(),
		Balance:   1_000_000_000,
		Timestamp: sendTs - 1,
		Asset:     "XE",
		Source:    sendBlk.Hash,
	}
	signBlock(t, backdatedRecv, relayKP)
	if err := l.AddBlock(backdatedRecv); err == nil ||
		!strings.Contains(err.Error(), "before source send timestamp") {
		t.Fatalf("expected AddBlock(receive) to reject backdated receive, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedRecv, 0); err == nil ||
		!strings.Contains(err.Error(), "before source send timestamp") {
		t.Fatalf("expected ValidateStagedBlock(receive) to reject backdated receive, got: %v", err)
	}

	validRecv := &core.Block{
		Type:      core.BlockReceive,
		Account:   relayKP.Address(),
		Previous:  "0",
		PubKey:    relayKP.PubKeyHex(),
		Balance:   1_000_000_000,
		Timestamp: sendTs,
		Asset:     "XE",
		Source:    sendBlk.Hash,
	}
	signBlock(t, validRecv, relayKP)
	if err := l.AddBlock(validRecv); err != nil {
		t.Fatalf("expected valid receive at sendTs to succeed, got: %v", err)
	}
}

func TestLeaseAcceptRejectsTimestampBeforeSourceLease(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	certHash := strings.Repeat("a", 64)
	l := setupLeaseTestLedger(t, s, consumerKP, providerKP, tkKP, certHash, now)

	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, cMint, consumerKP)
	if err := l.AddBlock(cMint); err != nil {
		t.Fatal(err)
	}

	pMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, pMint, providerKP)
	if err := l.AddBlock(pMint); err != nil {
		t.Fatal(err)
	}

	dur := core.LeaseMinDuration
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseTs := now + 5000
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         100_000_000 - baseCost,
		Timestamp:       leaseTs,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signBlock(t, leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	stake := core.LeaseStake(baseCost)
	acceptAtt, err := core.SignAttestation(leaseBlk.Hash, leaseTs+1000, tkKP)
	if err != nil {
		t.Fatal(err)
	}

	backdatedAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       leaseTs - 1,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*acceptAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, backdatedAccept, providerKP)
	if err := l.AddBlock(backdatedAccept); err == nil ||
		!strings.Contains(err.Error(), "before source lease timestamp") {
		t.Fatalf("expected AddBlock(lease_accept) to reject backdated accept, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedAccept, 100_000_000); err == nil ||
		!strings.Contains(err.Error(), "before source lease timestamp") {
		t.Fatalf("expected ValidateStagedBlock(lease_accept) to reject backdated accept, got: %v", err)
	}

	validAccept := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       leaseTs,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*acceptAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, validAccept, providerKP)
	if err := l.AddBlock(validAccept); err != nil {
		t.Fatalf("expected valid lease_accept at leaseTs to succeed, got: %v", err)
	}
}

func TestLeaseRenewRejectsTimestampBeforeCausalBound(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	certHash := strings.Repeat("b", 64)
	l := setupLeaseTestLedger(t, s, consumerKP, providerKP, tkKP, certHash, now)

	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, cMint, consumerKP)
	if err := l.AddBlock(cMint); err != nil {
		t.Fatal(err)
	}

	pMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, pMint, providerKP)
	if err := l.AddBlock(pMint); err != nil {
		t.Fatal(err)
	}

	dur := core.LeaseMinDuration
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         100_000_000 - baseCost,
		Timestamp:       now + 10,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signBlock(t, leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	acceptAtt, err := core.SignAttestation(leaseBlk.Hash, now+20, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	stake := core.LeaseStake(baseCost)
	acceptBlk := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       now + 20,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*acceptAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, acceptBlk, providerKP)
	if err := l.AddBlock(acceptBlk); err != nil {
		t.Fatal(err)
	}

	renewTime := now + 10*int64(time.Second)
	now = renewTime
	renewAtt, err := core.SignAttestation(leaseBlk.Hash, renewTime, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	renewCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}

	backdatedRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumerKP.Address(),
		Previous:        leaseBlk.Hash,
		Balance:         leaseBlk.Balance - renewCost,
		Timestamp:       acceptBlk.Timestamp - 1,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          renewCost,
		Duration:        dur,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*renewAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, backdatedRenew, consumerKP)
	if err := l.AddBlock(backdatedRenew); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected AddBlock(lease_renew) to reject backdated renew, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedRenew, leaseBlk.Balance); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected ValidateStagedBlock(lease_renew) to reject backdated renew, got: %v", err)
	}

	validRenew := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumerKP.Address(),
		Previous:        leaseBlk.Hash,
		Balance:         leaseBlk.Balance - renewCost,
		Timestamp:       renewTime,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          renewCost,
		Duration:        dur,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*renewAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, validRenew, consumerKP)
	if err := l.AddBlock(validRenew); err != nil {
		t.Fatalf("expected valid lease_renew to succeed, got: %v", err)
	}
}

func TestLeaseSettleRejectsTimestampBeforeEffectiveExpiryAndRenewals(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	certHash := strings.Repeat("c", 64)
	l := setupLeaseTestLedger(t, s, consumerKP, providerKP, tkKP, certHash, now)

	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, cMint, consumerKP)
	if err := l.AddBlock(cMint); err != nil {
		t.Fatal(err)
	}

	pMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, pMint, providerKP)
	if err := l.AddBlock(pMint); err != nil {
		t.Fatal(err)
	}

	dur := core.LeaseMinDuration
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         100_000_000 - baseCost,
		Timestamp:       now + 1,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signBlock(t, leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	acceptAtt, err := core.SignAttestation(leaseBlk.Hash, now+2, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	stake := core.LeaseStake(baseCost)
	acceptBlk := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       now + 2,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*acceptAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, acceptBlk, providerKP)
	if err := l.AddBlock(acceptBlk); err != nil {
		t.Fatal(err)
	}

	renewTime := now + 10*int64(time.Second)
	now = renewTime
	renewAtt, err := core.SignAttestation(leaseBlk.Hash, renewTime, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	renewCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	renewBlk := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumerKP.Address(),
		Previous:        leaseBlk.Hash,
		Balance:         leaseBlk.Balance - renewCost,
		Timestamp:       renewTime,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          renewCost,
		Duration:        dur,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*renewAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, renewBlk, consumerKP)
	if err := l.AddBlock(renewBlk); err != nil {
		t.Fatal(err)
	}

	lease, err := s.GetLease(leaseBlk.Hash)
	if err != nil || lease == nil {
		t.Fatalf("GetLease: %v", err)
	}
	expiry := lease.EffectiveExpiry()
	now = expiry
	settleAtt, err := core.SignAttestation(leaseBlk.Hash, expiry, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	expectedXE, err := core.LeaseTotalEmission(lease)
	if err != nil {
		t.Fatal(err)
	}

	backdatedSettle := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      providerKP.Address(),
		Previous:     acceptBlk.Hash,
		Balance:      expectedXE,
		Timestamp:    expiry - 1,
		Asset:        "XE",
		Source:       leaseBlk.Hash,
		Amount:       expectedXE,
		Attestations: []core.TimekeeperAttestation{*settleAtt},
	}
	signBlock(t, backdatedSettle, providerKP)
	if err := l.AddBlock(backdatedSettle); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected AddBlock(lease_settle) to reject backdated settle, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedSettle, 0); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected ValidateStagedBlock(lease_settle) to reject backdated settle, got: %v", err)
	}

	validSettle := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      providerKP.Address(),
		Previous:     acceptBlk.Hash,
		Balance:      expectedXE,
		Timestamp:    expiry,
		Asset:        "XE",
		Source:       leaseBlk.Hash,
		Amount:       expectedXE,
		Attestations: []core.TimekeeperAttestation{*settleAtt},
	}
	signBlock(t, validSettle, providerKP)
	if err := l.AddBlock(validSettle); err != nil {
		t.Fatalf("expected valid lease_settle at expiry to succeed, got: %v", err)
	}
}

func TestLeaseCancelRejectsTimestampBeforeSourceLease(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	certHash := strings.Repeat("d", 64)
	l := setupLeaseTestLedger(t, s, consumerKP, providerKP, tkKP, certHash, now)

	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, cMint, consumerKP)
	if err := l.AddBlock(cMint); err != nil {
		t.Fatal(err)
	}

	dur := core.LeaseMinDuration
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseTs := now + 5000
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         100_000_000 - baseCost,
		Timestamp:       leaseTs,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signBlock(t, leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	backdatedCancel := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumerKP.Address(),
		Previous:  leaseBlk.Hash,
		Balance:   100_000_000,
		Timestamp: leaseTs - 1,
		Asset:     "XUSD",
		Source:    leaseBlk.Hash,
	}
	signBlock(t, backdatedCancel, consumerKP)
	if err := l.AddBlock(backdatedCancel); err == nil ||
		!strings.Contains(err.Error(), "before source lease timestamp") {
		t.Fatalf("expected AddBlock(lease_cancel) to reject backdated cancel, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedCancel, leaseBlk.Balance); err == nil ||
		!strings.Contains(err.Error(), "before source lease timestamp") {
		t.Fatalf("expected ValidateStagedBlock(lease_cancel) to reject backdated cancel, got: %v", err)
	}

	validCancel := &core.Block{
		Type:      core.BlockLeaseCancel,
		Account:   consumerKP.Address(),
		Previous:  leaseBlk.Hash,
		Balance:   100_000_000,
		Timestamp: leaseTs,
		Asset:     "XUSD",
		Source:    leaseBlk.Hash,
	}
	signBlock(t, validCancel, consumerKP)
	if err := l.AddBlock(validCancel); err != nil {
		t.Fatalf("expected valid lease_cancel at leaseTs to succeed, got: %v", err)
	}
}

func TestLeaseForceSettleRejectsTimestampBeforeCausalBound(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	certHash := strings.Repeat("e", 64)
	l := setupLeaseTestLedger(t, s, consumerKP, providerKP, tkKP, certHash, now)

	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, cMint, consumerKP)
	if err := l.AddBlock(cMint); err != nil {
		t.Fatal(err)
	}

	pMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signBlock(t, pMint, providerKP)
	if err := l.AddBlock(pMint); err != nil {
		t.Fatal(err)
	}

	dur := core.LeaseMinDuration
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         100_000_000 - baseCost,
		Timestamp:       now + 1,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          baseCost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signBlock(t, leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	acceptAtt, err := core.SignAttestation(leaseBlk.Hash, now+2, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	stake := core.LeaseStake(baseCost)
	acceptBlk := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       now + 2,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		Attestations:    []core.TimekeeperAttestation{*acceptAtt},
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
	}
	signBlock(t, acceptBlk, providerKP)
	if err := l.AddBlock(acceptBlk); err != nil {
		t.Fatal(err)
	}

	lease, err := s.GetLease(leaseBlk.Hash)
	if err != nil || lease == nil {
		t.Fatalf("GetLease: %v", err)
	}

	eligibleAt := lease.EffectiveExpiry() + core.LeaseSettleGrace + core.LeaseForceSettleGap
	now = eligibleAt
	forceAtt, err := core.SignAttestation(leaseBlk.Hash, eligibleAt, tkKP)
	if err != nil {
		t.Fatal(err)
	}

	backdatedForce := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      consumerKP.Address(),
		Previous:     leaseBlk.Hash,
		Balance:      100_000_000,
		Timestamp:    eligibleAt - 1,
		Asset:        "XUSD",
		Source:       leaseBlk.Hash,
		Attestations: []core.TimekeeperAttestation{*forceAtt},
	}
	signBlock(t, backdatedForce, consumerKP)
	if err := l.AddBlock(backdatedForce); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected AddBlock(lease_force_settle) to reject backdated force settle, got: %v", err)
	}
	if err := l.ValidateStagedBlock(backdatedForce, leaseBlk.Balance); err == nil ||
		!strings.Contains(err.Error(), "before causal lease bound") {
		t.Fatalf("expected ValidateStagedBlock to reject backdated force settle, got: %v", err)
	}

	validForce := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      consumerKP.Address(),
		Previous:     leaseBlk.Hash,
		Balance:      100_000_000,
		Timestamp:    eligibleAt,
		Asset:        "XUSD",
		Source:       leaseBlk.Hash,
		Attestations: []core.TimekeeperAttestation{*forceAtt},
	}
	signBlock(t, validForce, consumerKP)
	if err := l.AddBlock(validForce); err != nil {
		t.Fatalf("expected valid lease_force_settle at eligibleAt to succeed, got: %v", err)
	}
}
