package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func signAndAdd(t *testing.T, l *core.Ledger, b *core.Block, kp *core.KeyPair) {
	t.Helper()
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock(%s): %v", b.Type, err)
	}
	if err := l.AddBlock(b); err != nil {
		t.Fatalf("AddBlock(%s): %v", b.Type, err)
	}
}

func TestRenewedLeaseSupplyConservationAndForceSettleValidation(t *testing.T) {
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
	l := core.NewLedger(s, core.LedgerConfig{
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

	// 1. Mint XUSD to consumer and provider
	consumerMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signAndAdd(t, l, consumerMint, consumerKP)

	providerMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	signAndAdd(t, l, providerMint, providerKP)

	// 2. Consumer creates a lease
	dur := uint64(3600)
	baseCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseBlock := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        consumerMint.Hash,
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
	signAndAdd(t, l, leaseBlock, consumerKP)

	// 3. Provider accepts the lease
	attAccept, err := core.SignAttestation(leaseBlock.Hash, now+2, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	stake := core.LeaseStake(baseCost)
	acceptBlock := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        providerMint.Hash,
		Balance:         100_000_000 - stake,
		Timestamp:       now + 2,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
		Attestations:    []core.TimekeeperAttestation{*attAccept},
	}
	signAndAdd(t, l, acceptBlock, providerKP)

	// 4. Consumer renews the lease
	renewCost, err := core.LeaseCost(1, 1024, 10, dur, 1000)
	if err != nil {
		t.Fatal(err)
	}
	attRenew, err := core.SignAttestation(leaseBlock.Hash, now+10, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	renewBlock := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         consumerKP.Address(),
		Previous:        leaseBlock.Hash,
		Balance:         100_000_000 - baseCost - renewCost,
		Timestamp:       now + 10,
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          renewCost,
		Duration:        dur,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
		Attestations:    []core.TimekeeperAttestation{*attRenew},
	}
	signAndAdd(t, l, renewBlock, consumerKP)

	// Verify EffectiveCost includes both base and renewal costs
	storedLease, err := s.GetLease(leaseBlock.Hash)
	if err != nil || storedLease == nil {
		t.Fatalf("GetLease: %v", err)
	}
	if got, want := storedLease.EffectiveCost(), baseCost+renewCost; got != want {
		t.Fatalf("EffectiveCost() = %d, want %d", got, want)
	}

	// 5. Advance time past effective expiry and settle the renewed lease
	settleTs := storedLease.EffectiveExpiry() + 100
	core.Now = func() time.Time { return time.Unix(0, settleTs) }
	attSettle, err := core.SignAttestation(leaseBlock.Hash, settleTs, tkKP)
	if err != nil {
		t.Fatal(err)
	}
	totalXE, err := core.LeaseTotalEmission(storedLease)
	if err != nil {
		t.Fatal(err)
	}
	settleBlock := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      providerKP.Address(),
		Previous:     acceptBlock.Hash,
		Balance:      totalXE,
		Timestamp:    settleTs,
		Asset:        "XE",
		Source:       leaseBlock.Hash,
		Amount:       totalXE,
		Attestations: []core.TimekeeperAttestation{*attSettle},
	}
	signAndAdd(t, l, settleBlock, providerKP)

	// 6. SupplyAuditor must report Conserved == true and EscrowBurned == baseCost + renewCost
	auditor := core.NewSupplyAuditor(l)
	auditor.SetCacheTTL(0)
	rep := auditor.Report()
	if !rep.Conserved {
		t.Fatalf("SupplyReport not conserved after settling renewed lease: notes=%v, XUSD=%+v", rep.Notes, rep.Assets["XUSD"])
	}
	xusdSupply := rep.Assets["XUSD"]
	if xusdSupply == nil {
		t.Fatal("missing XUSD asset supply")
	}
	if xusdSupply.EscrowBurned != baseCost+renewCost {
		t.Fatalf("XUSD EscrowBurned = %d, want %d", xusdSupply.EscrowBurned, baseCost+renewCost)
	}
	if xusdSupply.Discrepancy != 0 {
		t.Fatalf("XUSD Discrepancy = %d, want 0", xusdSupply.Discrepancy)
	}
}

func TestMultiAssetBalanceSpendableAndConflictStaging(t *testing.T) {
	s := store.NewMemStore()
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	consumerKP, err := core.GenerateKeyPair()
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
	l := core.NewLedger(s, core.LedgerConfig{
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
				Keys: []string{providerKP.Address(), consumerKP.Address()},
			}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             providerKP.Address(),
				ExpiresAt:            now + int64(365*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 0, TWAP: 1000}}
		},
		FeatureActiveFn: func(feature string) bool { return true },
	})

	// Open consumer with XUSD mint
	cMint := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   50_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    50_000_000,
	}
	signAndAdd(t, l, cMint, consumerKP)

	// Consumer has 0 XE and 50_000_000 XUSD; GetBalance(consumer) must return 0 (XE), not 50_000_000 (XUSD)
	if got := l.GetBalance(consumerKP.Address()); got != 0 {
		t.Fatalf("GetBalance(consumer) returned %d (XUSD frontier balance), want 0 XE", got)
	}

	// Open provider with XUSD mint, accept a lease, and settle it (earning XE + getting Stake back in XUSD)
	pMint := &core.Block{
		Type:      core.BlockMint,
		Account:   providerKP.Address(),
		Previous:  "0",
		PubKey:    providerKP.PubKeyHex(),
		Balance:   50_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    50_000_000,
	}
	signAndAdd(t, l, pMint, providerKP)

	dur := uint64(3600)
	cost, _ := core.LeaseCost(1, 1024, 10, dur, 1000)
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        cMint.Hash,
		Balance:         50_000_000 - cost,
		Timestamp:       now + 1,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	signAndAdd(t, l, leaseBlk, consumerKP)

	attAccept, _ := core.SignAttestation(leaseBlk.Hash, now+2, tkKP)
	stake := core.LeaseStake(cost)
	acceptBlk := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        pMint.Hash,
		Balance:         50_000_000 - stake,
		Timestamp:       now + 2,
		Asset:           "XUSD",
		Source:          leaseBlk.Hash,
		Amount:          stake,
		CertificateHash: certHash,
		LockedR:         1000,
		LockedPayoutCap: 0,
		LockedTWAP:      1000,
		Attestations:    []core.TimekeeperAttestation{*attAccept},
	}
	signAndAdd(t, l, acceptBlk, providerKP)

	settleTs := now + 2 + int64(dur)*int64(time.Second) + 10
	core.Now = func() time.Time { return time.Unix(0, settleTs) }
	attSettle, _ := core.SignAttestation(leaseBlk.Hash, settleTs, tkKP)
	leaseObj, _ := s.GetLease(leaseBlk.Hash)
	xeReward, _ := core.LeaseTotalEmission(leaseObj)

	settleBlk := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      providerKP.Address(),
		Previous:     acceptBlk.Hash,
		Balance:      xeReward,
		Timestamp:    settleTs,
		Asset:        "XE",
		Source:       leaseBlk.Hash,
		Amount:       xeReward,
		Attestations: []core.TimekeeperAttestation{*attSettle},
	}
	signAndAdd(t, l, settleBlk, providerKP)

	// Mark provider chain finalized through settleBlk (height 3)
	if err := s.SetFinalHeight(providerKP.Address(), 3); err != nil {
		t.Fatal(err)
	}

	// SpendableBalances must include the returned XUSD stake (50_000_000 - stake + stake == 50_000_000)
	spendable := l.SpendableBalances(providerKP.Address())
	if spendable["XUSD"] != 50_000_000 {
		t.Fatalf("SpendableBalances(provider)[XUSD] = %d, want 50_000_000 (including returned lease stake %d)", spendable["XUSD"], stake)
	}

	// Create two conflicting XUSD send blocks after settleBlk; the second (conflict) block must compute parentBalance == 50_000_000 (including stake)
	sendA := &core.Block{
		Type:        core.BlockSend,
		Account:     providerKP.Address(),
		Previous:    settleBlk.Hash,
		Balance:     50_000_000 - 1000,
		Timestamp:   settleTs + 1,
		Asset:       "XUSD",
		Destination: consumerKP.Address(),
		Amount:      1000,
	}
	signAndAdd(t, l, sendA, providerKP)

	sendB := &core.Block{
		Type:        core.BlockSend,
		Account:     providerKP.Address(),
		Previous:    settleBlk.Hash,
		Balance:     50_000_000 - 2000,
		Timestamp:   settleTs + 2,
		Asset:       "XUSD",
		Destination: consumerKP.Address(),
		Amount:      2000,
	}
	if err := core.SignBlock(sendB, providerKP); err != nil {
		t.Fatal(err)
	}
	if err := l.AddBlock(sendB); err != nil {
		t.Fatalf("expected sendB conflict block to pass ValidateStagedBlock and stage cleanly, got: %v", err)
	}
	if c := l.GetConflict(providerKP.Address(), settleBlk.Hash); c == nil {
		t.Fatal("expected conflict record to be created for sendA vs sendB")
	}
}
