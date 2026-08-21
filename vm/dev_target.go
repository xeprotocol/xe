package vm

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
)

type devTarget struct {
	accessPubKey string
	status       string
	resources    Resources
	createdAt    int64
}

type DevTargetManager struct {
	mu      sync.RWMutex
	targets map[string]*devTarget
}

func NewDevTargetManager() *DevTargetManager {
	return &DevTargetManager{
		targets: make(map[string]*devTarget),
	}
}

func (m *DevTargetManager) Provision(leaseHash string, res Resources, accessPubKey string) (*Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.targets[leaseHash]; exists {
		return nil, fmt.Errorf("target already exists for lease %s", leaseHash)
	}

	now := time.Now().UnixNano()
	m.targets[leaseHash] = &devTarget{
		accessPubKey: accessPubKey,
		status:       "running",
		resources:    res,
		createdAt:    now,
	}

	return &Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &res,
		CreatedAt: now,
	}, nil
}

func (m *DevTargetManager) DialSSH(leaseHash string) (net.Conn, error) {
	return nil, fmt.Errorf("dev target does not support SSH dial")
}

func (m *DevTargetManager) SpawnSession(leaseHash string, term string, winW, winH uint32) (*os.File, error) {
	m.mu.RLock()
	t, ok := m.targets[leaseHash]
	status := ""
	if ok {
		status = t.status
	}
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("target not found for lease %s", leaseHash)
	}
	if status != "running" {
		return nil, fmt.Errorf("target not running (status: %s)", status)
	}

	cmd := exec.Command("/bin/bash", "-l")
	cmd.Env = append(os.Environ(), "TERM="+term)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(winH),
		Cols: uint16(winW),
	})
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	// Reap the process when it exits to prevent zombies.
	go func() { _ = cmd.Wait() }()

	return ptmx, nil
}

func (m *DevTargetManager) Teardown(leaseHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.targets[leaseHash]
	if !ok {
		return fmt.Errorf("target not found for lease %s", leaseHash)
	}

	t.status = "stopped"
	delete(m.targets, leaseHash)
	return nil
}

func (m *DevTargetManager) Get(leaseHash string) (*Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.targets[leaseHash]
	if !ok {
		return nil, fmt.Errorf("target not found for lease %s", leaseHash)
	}

	return &Info{
		LeaseHash: leaseHash,
		Status:    t.status,
		Resources: &t.resources,
		CreatedAt: t.createdAt,
	}, nil
}

func (m *DevTargetManager) List() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Info, 0, len(m.targets))
	for hash, t := range m.targets {
		out = append(out, &Info{
			LeaseHash: hash,
			Status:    t.status,
			Resources: &t.resources,
			CreatedAt: t.createdAt,
		})
	}
	return out
}
