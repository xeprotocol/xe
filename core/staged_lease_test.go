package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func newTestLedger(certLookup func(string) *core.CertificateInfo) (*core.Ledger, *store.MemStore) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	cfg := core.LedgerConfig{
		Difficulty:          0,
		TimestampWindow:     0,
		CertificateLookupFn: certLookup,
	}
	l := core.NewLedger(ms, cfg)
	return l, ms
}

func fundAccountXUSD(t *testing.T, l *core.Ledger, kp *core.KeyPair, amount uint64) *core.Block {
	t.Helper()
	b := &core.Block{
		Type:           core.BlockMint,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        amount,
		Amount:         amount,
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XUSD",
		PubKey:         kp.PubKeyHex(),
		Representative: kp.Address(),
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := l.SeedAssetForTesting(b); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return b
}

func signSend(t *testing.T, kp *core.KeyPair, prev string, balance, amount uint64, dest, asset string) *core.Block {
	t.Helper()
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    prev,
		Balance:     balance,
		Amount:      amount,
		Timestamp:   core.Now().UnixNano(),
		Asset:       asset,
		Destination: dest,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign send block: %v", err)
	}
	return b
}

func signLease(t *testing.T, kp *core.KeyPair, prev string, balance, amount uint64, dest, certHash string, vcpus, mem, disk, dur uint64) *core.Block {
	t.Helper()
	b := &core.Block{
		Type:            core.BlockLease,
		Account:         kp.Address(),
		Previous:        prev,
		Balance:         balance,
		Amount:          amount,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     dest,
		VCPUs:           vcpus,
		MemoryMB:        mem,
		DiskGB:          disk,
		Duration:        dur,
		CertificateHash: certHash,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign lease block: %v", err)
	}
	return b
}

func TestValidateStagedBlock_LeaseDecoyRejected(t *testing.T) {
	owner, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen owner: %v", err)
	}
	dest, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen dest: %v", err)
	}

	l, ms := newTestLedger(nil)
	const fundAmount = 1_000_000_000
	open := fundAccountXUSD(t, l, owner, fundAmount)

	// First, commit a legitimate send on chain to set up the conflict boundary
	sendA := signSend(t, owner, open.Hash, fundAmount-10, 10, dest.Address(), "XUSD")
	if err := l.AddBlock(sendA); err != nil {
		t.Fatalf("add sendA: %v", err)
	}

	parentBal := l.GetAssetBalanceAtBlock(owner.Address(), "XUSD", open.Hash)
	if parentBal != fundAmount {
		t.Fatalf("expected parent balance %d, got %d", fundAmount, parentBal)
	}

	// 1. Decoy with 0 dimensions (issue #52 PoC scenario)
	decoyZeroDim := signLease(t, owner, open.Hash, fundAmount-1, 1, dest.Address(), "", 0, 0, 0, 0)
	err = l.ValidateStagedBlock(decoyZeroDim, parentBal)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to reject lease with zero dimensions, got nil")
	}
	if !strings.Contains(err.Error(), "lease must request at least one resource") {
		t.Fatalf("expected error mentioning resource dimensions, got: %v", err)
	}

	// Staging via AddBlock conflict route must reject and NOT stage the block
	err = l.AddBlock(decoyZeroDim)
	if err == nil {
		t.Fatal("expected AddBlock conflict to reject zero-dimension lease decoy")
	}
	staged, _ := ms.GetStagedBlock(decoyZeroDim.Hash)
	if staged != nil {
		t.Fatal("decoy block should NOT be saved in staged store")
	}

	// 2. Decoy with valid dimensions but missing certificate_hash
	decoyMissingCert := signLease(t, owner, open.Hash, fundAmount-100, 100, dest.Address(), "", 2, 2048, 20, 3600)
	err = l.ValidateStagedBlock(decoyMissingCert, parentBal)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to reject lease with missing cert hash")
	}
	if !strings.Contains(err.Error(), "certificate_hash") {
		t.Fatalf("expected error mentioning certificate_hash, got: %v", err)
	}

	// 3. Decoy with certificate lookup not configured
	decoyWithHash := signLease(t, owner, open.Hash, fundAmount-100, 100, dest.Address(), "deadbeef1234", 2, 2048, 20, 3600)
	err = l.ValidateStagedBlock(decoyWithHash, parentBal)
	if err == nil {
		t.Fatal("expected ValidateStagedBlock to reject lease when cert lookup unconfigured")
	}
	if !strings.Contains(err.Error(), "certificate lookup not configured") {
		t.Fatalf("expected error mentioning certificate lookup not configured, got: %v", err)
	}
}

func TestValidateStagedBlock_CertificateAndCostEnforcement(t *testing.T) {
	owner, _ := core.GenerateKeyPair()
	dest, _ := core.GenerateKeyPair()
	otherProvider, _ := core.GenerateKeyPair()

	certHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	mockCert := &core.CertificateInfo{
		Provider:             dest.Address(),
		ExpiresAt:            time.Now().Add(24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000, // 1.0x
	}

	l, _ := newTestLedger(func(h string) *core.CertificateInfo {
		if h == certHash {
			return mockCert
		}
		return nil
	})

	const fundAmount = 1_000_000_000
	open := fundAccountXUSD(t, l, owner, fundAmount)

	vcpus, mem, disk, dur := uint64(2), uint64(2048), uint64(20), uint64(3600)
	expectedCost, err := core.LeaseCost(vcpus, mem, disk, dur, mockCert.PriceMultiplierMilli)
	if err != nil {
		t.Fatalf("LeaseCost calculation failed: %v", err)
	}

	// 1. Unknown certificate hash
	decoyUnknownCert := signLease(t, owner, open.Hash, fundAmount-expectedCost, expectedCost, dest.Address(), "000000000000", vcpus, mem, disk, dur)
	err = l.ValidateStagedBlock(decoyUnknownCert, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected cert not found error, got: %v", err)
	}

	// 2. Certificate provider mismatch (destination does not match cert provider)
	decoyWrongDest := signLease(t, owner, open.Hash, fundAmount-expectedCost, expectedCost, otherProvider.Address(), certHash, vcpus, mem, disk, dur)
	err = l.ValidateStagedBlock(decoyWrongDest, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("expected provider mismatch error, got: %v", err)
	}

	// 3. Expired certificate
	mockCert.ExpiresAt = time.Now().Add(-1 * time.Hour).UnixNano()
	decoyExpiredCert := signLease(t, owner, open.Hash, fundAmount-expectedCost, expectedCost, dest.Address(), certHash, vcpus, mem, disk, dur)
	err = l.ValidateStagedBlock(decoyExpiredCert, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired certificate error, got: %v", err)
	}
	mockCert.ExpiresAt = time.Now().Add(24 * time.Hour).UnixNano()

	// 4. Cost mismatch (b.Amount != expectedCost)
	wrongCost := expectedCost + 500
	decoyWrongCost := signLease(t, owner, open.Hash, fundAmount-wrongCost, wrongCost, dest.Address(), certHash, vcpus, mem, disk, dur)
	err = l.ValidateStagedBlock(decoyWrongCost, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "lease cost mismatch") {
		t.Fatalf("expected cost mismatch error, got: %v", err)
	}

	// 5. Valid lease block staging succeeds cleanly
	validLease := signLease(t, owner, open.Hash, fundAmount-expectedCost, expectedCost, dest.Address(), certHash, vcpus, mem, disk, dur)
	err = l.ValidateStagedBlock(validLease, fundAmount)
	if err != nil {
		t.Fatalf("expected valid lease to pass staged validation, got: %v", err)
	}
}

func TestValidateStagedBlock_LeaseAcceptValidation(t *testing.T) {
	provider, _ := core.GenerateKeyPair()
	consumer, _ := core.GenerateKeyPair()

	l, _ := newTestLedger(nil)
	const fundAmount = 500_000_000
	open := fundAccountXUSD(t, l, provider, fundAmount)

	// Missing or non-existent source block
	badAccept := &core.Block{
		Type:        core.BlockLeaseAccept,
		Account:     provider.Address(),
		Previous:    open.Hash,
		Source:      strings.Repeat("a", 64),
		Amount:      1000,
		Balance:     fundAmount - 1000,
		Asset:       "XUSD",
		Timestamp:   core.Now().UnixNano(),
		Destination: consumer.Address(),
	}
	if err := core.SignBlock(badAccept, provider); err != nil {
		t.Fatalf("sign accept: %v", err)
	}

	err := l.ValidateStagedBlock(badAccept, fundAmount)
	if err == nil || !strings.Contains(err.Error(), "source lease block not found") {
		t.Fatalf("expected source lease block not found error, got: %v", err)
	}
}
