package node

import (
	"fmt"
	"net"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

type dummyVMManager struct {
	vms map[string]*vm.Info
}

func newDummyVMManager() *dummyVMManager {
	return &dummyVMManager{vms: make(map[string]*vm.Info)}
}

func (d *dummyVMManager) Provision(leaseHash string, res vm.Resources, accessPubKey string) (*vm.Info, error) {
	info := &vm.Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &res,
	}
	d.vms[leaseHash] = info
	return info, nil
}

func (d *dummyVMManager) Teardown(leaseHash string) error {
	delete(d.vms, leaseHash)
	return nil
}

func (d *dummyVMManager) DialSSH(leaseHash string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}

func (d *dummyVMManager) Get(leaseHash string) (*vm.Info, error) {
	info, ok := d.vms[leaseHash]
	if !ok {
		return nil, fmt.Errorf("vm not found")
	}
	return info, nil
}

func (d *dummyVMManager) List() []*vm.Info {
	var list []*vm.Info
	for _, v := range d.vms {
		list = append(list, v)
	}
	return list
}

func setupTestNode(t *testing.T) (*Node, *core.KeyPair) {
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
	return n, kp
}

func TestSettleLease_RefusesWhenNoVMManager(t *testing.T) {
	n, kp := setupTestNode(t)
	n.VMManager = nil

	leaseHash := "testlease_no_vm_mgr"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		Cost:      1000,
		Provider:  kp.Address(),
		State:     core.LeaseAccepted,
	}

	n.settleLease(lease)

	// Since VMManager is nil, no settle block should be added to ledger
	chain := n.Ledger.GetChain(kp.Address())
	if len(chain) > 0 {
		t.Fatalf("expected 0 blocks created when VMManager=nil, got %d", len(chain))
	}
}

func TestSettleLease_RefusesWhenMockManager(t *testing.T) {
	n, kp := setupTestNode(t)
	n.VMManager = vm.NewMockManager()

	leaseHash := "testlease_mock_vm"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		Cost:      1000,
		Provider:  kp.Address(),
		State:     core.LeaseAccepted,
	}

	n.settleLease(lease)

	// Since VMManager is MockManager, settlement must be refused
	chain := n.Ledger.GetChain(kp.Address())
	if len(chain) > 0 {
		t.Fatalf("expected 0 blocks created when VMManager is MockManager, got %d", len(chain))
	}
}

func TestSettleLease_RefusesWhenVMNotRunning(t *testing.T) {
	n, kp := setupTestNode(t)
	dummy := newDummyVMManager()
	n.VMManager = dummy

	leaseHash := "testlease_stopped_vm"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		Cost:      1000,
		Provider:  kp.Address(),
		State:     core.LeaseAccepted,
	}

	// 1. VM does not exist in manager
	n.settleLease(lease)
	if chain := n.Ledger.GetChain(kp.Address()); len(chain) > 0 {
		t.Fatalf("expected 0 blocks when VM does not exist, got %d", len(chain))
	}

	// 2. VM exists but status is stopped / failed
	dummy.vms[leaseHash] = &vm.Info{
		LeaseHash: leaseHash,
		Status:    "stopped",
	}
	n.settleLease(lease)
	if chain := n.Ledger.GetChain(kp.Address()); len(chain) > 0 {
		t.Fatalf("expected 0 blocks when VM status is stopped, got %d", len(chain))
	}
}

func TestAutoAcceptLease_RefusesWhenNoVMManagerOrMock(t *testing.T) {
	n, kp := setupTestNode(t)

	leaseBlock := &core.Block{
		Hash:        "lease_to_accept_123",
		Type:        core.BlockLease,
		Account:     "consumer_address",
		Destination: kp.Address(),
		Amount:      500,
	}

	// Case 1: VMManager is nil
	n.VMManager = nil
	n.autoAcceptLease(leaseBlock)
	chain := n.Ledger.GetChain(kp.Address())
	if len(chain) > 0 {
		t.Fatalf("expected 0 accept blocks when VMManager is nil, got %d", len(chain))
	}

	// Case 2: VMManager is MockManager
	n.VMManager = vm.NewMockManager()
	n.autoAcceptLease(leaseBlock)
	chain = n.Ledger.GetChain(kp.Address())
	if len(chain) > 0 {
		t.Fatalf("expected 0 accept blocks when VMManager is MockManager, got %d", len(chain))
	}
}

func TestTrySettleExpiredLeases_SkipsWhenNoVMManagerOrMock(t *testing.T) {
	n, _ := setupTestNode(t)

	// Case 1: VMManager is nil -> exits without panic or error
	n.VMManager = nil
	n.trySettleExpiredLeases()

	// Case 2: VMManager is MockManager -> exits without panic or error
	n.VMManager = vm.NewMockManager()
	n.trySettleExpiredLeases()
}
