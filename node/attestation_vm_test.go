package node

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

func TestCanAttestAndForceSettleWindowChecksProvisionedVM(t *testing.T) {
	providerKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x02}, 32))
	consumerKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x01}, 32))
	leaseHash := hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))

	ms := store.NewMemStore()
	startTime := time.Unix(1_700_000_000, 0).UnixNano()
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
		VCPUs:     1,
		MemoryMB:  1024,
		Duration:  60,
		Cost:      500,
		Stake:     100,
		StartTime: startTime,
	}
	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	n := &Node{
		store:      ms,
		KeyPair:    providerKP,
		isProvider: true,
		VMManager:  vm.NewMockManager(),
	}

	// Without a provisioned VM, provider's canAttest must reject accepted lease attestation.
	if err := n.canAttest(leaseHash); err == nil {
		t.Fatalf("expected canAttest to fail when provider has not provisioned a VM for accepted lease")
	}

	// Once the VM is provisioned, canAttest succeeds.
	if _, err := n.VMManager.Provision(leaseHash, vm.Resources{VCPUs: 1, MemoryMB: 1024}, ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := n.canAttest(leaseHash); err != nil {
		t.Fatalf("expected canAttest to succeed after VM is provisioned, got: %v", err)
	}

	// Consumer force-settle eligibility opens at expiry.
	expiry := lease.EffectiveExpiry()
	if consumerShouldForceSettle(lease, consumerKP.Address(), expiry-1) {
		t.Fatalf("expected consumerShouldForceSettle to be false before expiry")
	}
	if !consumerShouldForceSettle(lease, consumerKP.Address(), expiry) {
		t.Fatalf("expected consumerShouldForceSettle to be true at expiry")
	}
}
