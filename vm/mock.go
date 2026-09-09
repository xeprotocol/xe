package vm

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type MockManager struct {
	mu  sync.RWMutex
	vms map[string]*mockVM
}

type mockVM struct {
	info    *Info
	workDir string
}

func NewMockManager() *MockManager {
	return &MockManager{
		vms: make(map[string]*mockVM),
	}
}

func (m *MockManager) Provision(leaseHash string, res Resources, accessPubKey string) (*Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.vms[leaseHash]; exists {
		return nil, fmt.Errorf("vm already exists for lease %s", leaseHash)
	}

	prefix := leaseHash
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	dir, err := os.MkdirTemp("", "xe-vm-"+prefix+"-")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	creds := GenerateCredentials()
	info := &Info{
		LeaseHash:   leaseHash,
		Status:      "running",
		Resources:   &res,
		Credentials: creds,
		CreatedAt:   time.Now().UnixNano(),
	}

	m.vms[leaseHash] = &mockVM{
		info:    info,
		workDir: dir,
	}

	return info, nil
}

func (m *MockManager) DialSSH(leaseHash string) (net.Conn, error) {
	return nil, fmt.Errorf("mock manager does not support SSH")
}

func (m *MockManager) Teardown(leaseHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	vm, ok := m.vms[leaseHash]
	if !ok {
		return fmt.Errorf("vm not found for lease %s", leaseHash)
	}

	_ = os.RemoveAll(vm.workDir)
	delete(m.vms, leaseHash)
	return nil
}

func (m *MockManager) Get(leaseHash string) (*Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vm, ok := m.vms[leaseHash]
	if !ok {
		return nil, fmt.Errorf("vm not found for lease %s", leaseHash)
	}
	cp := *vm.info
	return &cp, nil
}

func (m *MockManager) List() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Info, 0, len(m.vms))
	for _, vm := range m.vms {
		cp := *vm.info
		out = append(out, &cp)
	}
	return out
}
