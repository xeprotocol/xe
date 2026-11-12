package node

import (
	"errors"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

type errLeaseStore struct {
	*store.MemStore
	errLeaseHash string
}

func (e *errLeaseStore) GetLease(leaseHash string) (*core.Lease, error) {
	if leaseHash == e.errLeaseHash {
		return nil, errors.New("transient database connection error")
	}
	return e.MemStore.GetLease(leaseHash)
}

func TestCleanupOrphanedVMs(t *testing.T) {
	memStore := store.NewMemStore()
	mockVM := vm.NewMockManager()

	node := &Node{
		store:     memStore,
		VMManager: mockVM,
	}

	// 1. VM with missing lease row in store (orphaned) -> should be torn down
	missingLeaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	_, err := mockVM.Provision(missingLeaseHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "ssh-key-1")
	if err != nil {
		t.Fatalf("failed to provision VM 1: %v", err)
	}

	// 2. VM with terminal lease (settled) -> should be torn down
	settledLeaseHash := "2222222222222222222222222222222222222222222222222222222222222222"
	_, err = mockVM.Provision(settledLeaseHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "ssh-key-2")
	if err != nil {
		t.Fatalf("failed to provision VM 2: %v", err)
	}
	_ = memStore.PutLease(&core.Lease{
		LeaseHash: settledLeaseHash,
		State:     core.LeaseSettled,
	})

	// 3. VM with terminal lease (cancelled) -> should be torn down
	cancelledLeaseHash := "3333333333333333333333333333333333333333333333333333333333333333"
	_, err = mockVM.Provision(cancelledLeaseHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "ssh-key-3")
	if err != nil {
		t.Fatalf("failed to provision VM 3: %v", err)
	}
	_ = memStore.PutLease(&core.Lease{
		LeaseHash: cancelledLeaseHash,
		State:     core.LeaseCancelled,
	})

	// 4. VM with active lease (accepted) -> should NOT be torn down
	activeLeaseHash := "4444444444444444444444444444444444444444444444444444444444444444"
	_, err = mockVM.Provision(activeLeaseHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "ssh-key-4")
	if err != nil {
		t.Fatalf("failed to provision VM 4: %v", err)
	}
	_ = memStore.PutLease(&core.Lease{
		LeaseHash: activeLeaseHash,
		State:     core.LeaseAccepted,
	})

	if len(mockVM.List()) != 4 {
		t.Fatalf("expected 4 VMs before cleanup, got %d", len(mockVM.List()))
	}

	node.cleanupOrphanedVMs()

	remaining := mockVM.List()
	if len(remaining) != 1 {
		t.Fatalf("expected exactly 1 VM remaining, got %d", len(remaining))
	}
	if remaining[0].LeaseHash != activeLeaseHash {
		t.Fatalf("expected remaining VM to have lease %s, got %s", activeLeaseHash, remaining[0].LeaseHash)
	}
}

func TestCleanupOrphanedVMs_StoreErrorRetries(t *testing.T) {
	memStore := store.NewMemStore()
	mockVM := vm.NewMockManager()

	transientErrHash := "5555555555555555555555555555555555555555555555555555555555555555"
	_, err := mockVM.Provision(transientErrHash, vm.Resources{VCPUs: 1, MemoryMB: 512, DiskGB: 10}, "ssh-key-5")
	if err != nil {
		t.Fatalf("failed to provision VM: %v", err)
	}

	errStore := &errLeaseStore{
		MemStore:     memStore,
		errLeaseHash: transientErrHash,
	}

	node := &Node{
		store:     errStore,
		VMManager: mockVM,
	}

	// Should skip when store returns an error rather than tearing down prematurely
	node.cleanupOrphanedVMs()

	if len(mockVM.List()) != 1 {
		t.Fatalf("expected VM to be kept on transient error, got %d VMs", len(mockVM.List()))
	}
}
