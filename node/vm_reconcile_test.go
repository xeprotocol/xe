package node

import (
	"context"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

func TestNodeVMReconcileAcrossRestart(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ms := store.NewMemStore()
	mockVM := vm.NewMockManager()

	n := &Node{
		KeyPair:    kp,
		store:      ms,
		VMManager:  mockVM,
		isProvider: true,
		ctx:        context.Background(),
	}

	leaseHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	now := core.Now().UnixNano()
	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		Provider:     kp.Address(),
		Consumer:     "consumer_addr",
		VCPUs:        4,
		MemoryMB:     8192,
		DiskGB:       40,
		Duration:     3600,
		StartTime:    now - 100*int64(time.Second),
		AccessPubKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}

	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("PutLease failed: %v", err)
	}

	// 1. Initially across restart, mock VM registry is empty
	if len(n.VMManager.List()) != 0 {
		t.Fatalf("Expected 0 VMs initially, got %d", len(n.VMManager.List()))
	}

	// 2. Reconcile running on node startup re-provisions VM for live accepted lease
	n.reconcileVMs()

	vms := n.VMManager.List()
	if len(vms) != 1 {
		t.Fatalf("Expected 1 VM provisioned after reconcile, got %d", len(vms))
	}
	if vms[0].LeaseHash != leaseHash {
		t.Fatalf("Expected VM leaseHash %s, got %s", leaseHash, vms[0].LeaseHash)
	}

	// 3. Reconcile again should be a no-op since VM is already running
	n.reconcileVMs()
	if len(n.VMManager.List()) != 1 {
		t.Fatalf("Expected still 1 VM, got %d", len(n.VMManager.List()))
	}

	// 4. When lease becomes terminal, cleanupOrphanedVMs tears it down
	lease.State = core.LeaseSettled
	lease.Settled = true
	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("PutLease failed: %v", err)
	}

	n.cleanupOrphanedVMs()
	if len(n.VMManager.List()) != 0 {
		t.Fatalf("Expected 0 VMs after cleanup of terminal lease, got %d", len(n.VMManager.List()))
	}
}
