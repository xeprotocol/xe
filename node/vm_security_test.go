package node

import (
	"context"
	netpkg "net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/vm"
)

type mockVMManager struct {
	info *vm.Info
}

func (m *mockVMManager) Provision(string, vm.Resources, string) (*vm.Info, error) {
	return m.info, nil
}
func (m *mockVMManager) Teardown(string) error                  { return nil }
func (m *mockVMManager) DialSSH(string) (netpkg.Conn, error)    { return nil, nil }
func (m *mockVMManager) Get(leaseHash string) (*vm.Info, error) { return m.info, nil }
func (m *mockVMManager) List() []*vm.Info                       { return []*vm.Info{m.info} }

type mockNodeStore struct {
	core.Store
	leases map[string]*core.Lease
}

func (m *mockNodeStore) GetLease(leaseHash string) (*core.Lease, error) {
	if l, ok := m.leases[leaseHash]; ok {
		return l, nil
	}
	return nil, nil
}
func (m *mockNodeStore) PutLease(lease *core.Lease) error                               { return nil }
func (m *mockNodeStore) GetLeasesByProvider(provider string) ([]*core.Lease, error)     { return nil, nil }
func (m *mockNodeStore) GetLeasesByState(state core.LeaseState) ([]*core.Lease, error) { return nil, nil }
func (m *mockNodeStore) GetAllLeases() ([]*core.Lease, error)                           { return nil, nil }

func TestVMStatusAuthorizationAndCredentialRedaction(t *testing.T) {
	providerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("provider libp2p: %v", err)
	}
	defer providerHost.Close()

	consumerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("consumer libp2p: %v", err)
	}
	defer consumerHost.Close()

	unrelatedHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("unrelated libp2p: %v", err)
	}
	defer unrelatedHost.Close()

	// Connect peers to provider
	if err := consumerHost.Connect(context.Background(), peer.AddrInfo{
		ID:    providerHost.ID(),
		Addrs: providerHost.Addrs(),
	}); err != nil {
		t.Fatalf("consumer connect: %v", err)
	}

	if err := unrelatedHost.Connect(context.Background(), peer.AddrInfo{
		ID:    providerHost.ID(),
		Addrs: providerHost.Addrs(),
	}); err != nil {
		t.Fatalf("unrelated connect: %v", err)
	}

	// Register consumer in provider directory
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	reg := directory.NewRegistration(consumerHost.ID().String(), time.Now().UnixNano(), consumerKP)
	dir := directory.New(1 * time.Hour)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("register consumer in directory: %v", err)
	}

	const sentinelSecret = "secret-super-password-12345"
	mgr := &mockVMManager{
		info: &vm.Info{
			LeaseHash: "lease-xyz",
			Status:    "running",
			Credentials: &vm.Credentials{
				Username: "root",
				Password: sentinelSecret,
			},
		},
	}

	store := &mockNodeStore{
		leases: map[string]*core.Lease{
			"lease-xyz": {
				LeaseHash: "lease-xyz",
				Consumer:  consumerKP.Address(),
				Provider:  "prov-1",
			},
		},
	}

	provMsg := net.NewMessenger(providerHost, nil)
	consumerMsg := net.NewMessenger(consumerHost, nil)
	unrelatedMsg := net.NewMessenger(unrelatedHost, nil)

	n := &Node{
		VMManager: mgr,
		Msg:       provMsg,
		Directory: dir,
		store:     store,
	}
	n.registerVMHandlers()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Unrelated peer requesting status must be rejected
	_, err = unrelatedMsg.Request(ctx, providerHost.ID(), "vm_status", map[string]string{"lease_hash": "lease-xyz"})
	if err == nil {
		t.Fatalf("expected unrelated peer request to fail, but succeeded")
	}
	if !strings.Contains(err.Error(), "unauthorized peer") {
		t.Fatalf("expected 'unauthorized peer' error, got: %v", err)
	}

	// 2. Request for nonexistent lease must be rejected
	_, err = consumerMsg.Request(ctx, providerHost.ID(), "vm_status", map[string]string{"lease_hash": "unknown-lease"})
	if err == nil {
		t.Fatalf("expected unknown lease request to fail, but succeeded")
	}
	if !strings.Contains(err.Error(), "lease not found") {
		t.Fatalf("expected 'lease not found' error, got: %v", err)
	}

	// 3. Authorized consumer peer receives redacted status
	resp, err := consumerMsg.Request(ctx, providerHost.ID(), "vm_status", map[string]string{"lease_hash": "lease-xyz"})
	if err != nil {
		t.Fatalf("authorized consumer request failed: %v", err)
	}

	respStr := string(resp)
	if strings.Contains(respStr, sentinelSecret) {
		t.Fatalf("vm_status leaked plaintext credentials: %s", respStr)
	}
	if strings.Contains(respStr, `"password"`) {
		t.Fatalf("vm_status contains 'password' field: %s", respStr)
	}
	if !strings.Contains(respStr, "root") {
		t.Fatalf("vm_status missing username: %s", respStr)
	}
	if !strings.Contains(respStr, "running") {
		t.Fatalf("vm_status missing status: %s", respStr)
	}
}
