package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

func TestAcceptSchedule_RecordAndDue(t *testing.T) {
	sched := &acceptSchedule{}
	now := time.Now()
	hash := "1111111111111111111111111111111111111111111111111111111111111111"

	// Unknown hash is due immediately
	if !sched.due(hash, now) {
		t.Fatalf("expected unknown hash to be due")
	}

	// Retryable failure schedules next retry with initial delay
	sched.record(hash, true, now)
	if sched.due(hash, now) {
		t.Fatalf("expected hash not to be due immediately after retryable record")
	}
	if !sched.due(hash, now.Add(6*time.Second)) {
		t.Fatalf("expected hash to be due after initial retry delay (5s)")
	}

	// Second retry failure applies exponential backoff
	now2 := now.Add(6 * time.Second)
	sched.record(hash, true, now2)
	expectedDelay := acceptRetryDelay(1)
	if sched.due(hash, now2.Add(expectedDelay-1*time.Second)) {
		t.Fatalf("expected hash not to be due before backoff delay %v", expectedDelay)
	}
	if !sched.due(hash, now2.Add(expectedDelay+1*time.Second)) {
		t.Fatalf("expected hash to be due after backoff delay %v", expectedDelay)
	}

	// Non-retryable record sets done=true forever
	sched.record(hash, false, now2)
	if sched.due(hash, now2.Add(1000*time.Hour)) {
		t.Fatalf("expected hash not to be due after being marked done")
	}
}

func TestAutoAcceptLease_RetriesOnPolicyReject(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	leaseHash := "2222222222222222222222222222222222222222222222222222222222222222"
	leaseBlock := &core.Block{
		Hash:        leaseHash,
		Type:        core.BlockLease,
		Account:     "consumer-addr",
		Destination: kp.Address(),
		Amount:      500, // 500 XUSD
		Duration:    3600,
		VCPUs:       1,
		MemoryMB:    1024,
		DiskGB:      10,
	}

	node := &Node{
		KeyPair: kp,
		Ledger:  ledger,
		store:   ms,
		acceptPolicy: LeaseAcceptPolicy{
			MinCostXUSD: 1000, // Policy requires >= 1000 XUSD, so 500 will be rejected
		},
	}

	node.autoAcceptLease(leaseBlock)

	// Verify that policy rejection schedules a retry instead of marking it permanently done
	now := time.Now()
	if node.acceptSched.due(leaseHash, now) {
		t.Fatalf("expected lease not to be due immediately")
	}
	if !node.acceptSched.due(leaseHash, now.Add(10*time.Second)) {
		t.Fatalf("expected lease to be scheduled for retry on policy rejection, but due() returned false")
	}
}

func TestAutoAcceptLease_RetriesOnCertError(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	leaseHash := "3333333333333333333333333333333333333333333333333333333333333333"
	leaseBlock := &core.Block{
		Hash:        leaseHash,
		Type:        core.BlockLease,
		Account:     "consumer-addr",
		Destination: kp.Address(),
		Amount:      50_000,
		Duration:    3600,
		VCPUs:       1,
		MemoryMB:    1024,
		DiskGB:      10,
		// No CertificateHash set -> acceptCertificateHash returns error
	}

	node := &Node{
		KeyPair: kp,
		Ledger:  ledger,
		store:   ms,
	}

	node.autoAcceptLease(leaseBlock)

	now := time.Now()
	if node.acceptSched.due(leaseHash, now) {
		t.Fatalf("expected lease not to be due immediately")
	}
	if !node.acceptSched.due(leaseHash, now.Add(10*time.Second)) {
		t.Fatalf("expected lease to be scheduled for retry on certificate error, but due() returned false")
	}
}

func TestAutoAcceptLease_RetriesOnCapacityExceeded(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	// Seed ample XUSD for stake
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   kp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XUSD",
		Timestamp: core.Now().UnixNano(),
	}
	if err := core.SignBlock(mintBlock, kp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	certHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	now := core.Now().UnixNano()
	cert := &perf.Certificate{
		Hash:                 certHash,
		Provider:             kp.Address(),
		PriceMultiplierMilli: 1000,
		IssuedAt:             now - int64(time.Hour),
		ExpiresAt:            now + int64(24*time.Hour),
	}

	leaseHash := "4444444444444444444444444444444444444444444444444444444444444444"
	leaseBlock := &core.Block{
		Hash:            leaseHash,
		Type:            core.BlockLease,
		Account:         "consumer-addr",
		Destination:     kp.Address(),
		Amount:          50_000,
		Duration:        3600,
		VCPUs:           2,
		MemoryMB:        2048,
		DiskGB:          20,
		CertificateHash: certHash,
	}

	mockVM := vm.NewMockManager()
	// Pre-provision a VM using 1 vCPU so that remaining capacity is insufficient
	_, _ = mockVM.Provision("existing-vm", vm.Resources{VCPUs: 1, MemoryMB: 1024, DiskGB: 10}, "ssh-key")

	node := &Node{
		KeyPair:          kp,
		Ledger:           ledger,
		store:            ms,
		VMManager:        mockVM,
		providerVCPUs:    2, // Max 2, 1 already used -> requesting 2 exceeds capacity (1+2 > 2)
		providerMemoryMB: 4096,
		providerDiskGB:   100,
		acceptAttestHook: func(lh string) ([]core.TimekeeperAttestation, error) {
			return []core.TimekeeperAttestation{}, nil
		},
	}
	node.certs().put(cert)

	node.autoAcceptLease(leaseBlock)

	nowTime := time.Now()
	if node.acceptSched.due(leaseHash, nowTime) {
		t.Fatalf("expected lease not to be due immediately")
	}
	if !node.acceptSched.due(leaseHash, nowTime.Add(10*time.Second)) {
		t.Fatalf("expected lease to be scheduled for retry on capacity exceeded, but due() returned false")
	}
}

func TestAutoAcceptLease_MarksDoneOnAlreadyAccepted(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	leaseHash := "5555555555555555555555555555555555555555555555555555555555555555"
	leaseBlock := &core.Block{
		Hash:        leaseHash,
		Type:        core.BlockLease,
		Account:     "consumer-addr",
		Destination: kp.Address(),
		Amount:      50_000,
		Duration:    3600,
		VCPUs:       1,
		MemoryMB:    1024,
		DiskGB:      10,
	}

	// Store lease as already accepted
	_ = ms.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
	})

	node := &Node{
		KeyPair: kp,
		Ledger:  ledger,
		store:   ms,
	}

	node.autoAcceptLease(leaseBlock)

	// Since it was already accepted, it should be marked done (never due)
	now := time.Now()
	if node.acceptSched.due(leaseHash, now.Add(100*time.Hour)) {
		t.Fatalf("expected already-accepted lease to be marked done permanently")
	}
}
