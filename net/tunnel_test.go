package net

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

type dummyCloser struct {
	closed atomic.Bool
}

func (d *dummyCloser) Close() error {
	d.closed.Store(true)
	return nil
}

func TestTunnelRegistry_Limits(t *testing.T) {
	r := NewTunnelRegistry()
	leaseA := strings.Repeat("a", 64)
	leaseB := strings.Repeat("b", 64)
	peer1 := peer.ID("peer-1")
	peer2 := peer.ID("peer-2")

	closers := make([]*dummyCloser, MaxTunnelsPerLease)
	for i := 0; i < MaxTunnelsPerLease; i++ {
		closers[i] = &dummyCloser{}
		if err := r.Acquire(leaseA, peer1, closers[i]); err != nil {
			t.Fatalf("acquire %d failed: %v", i, err)
		}
	}

	if r.CountForLease(leaseA) != MaxTunnelsPerLease {
		t.Fatalf("expected count %d, got %d", MaxTunnelsPerLease, r.CountForLease(leaseA))
	}
	if r.CountForPeer(peer1) != MaxTunnelsPerLease {
		t.Fatalf("expected peer count %d, got %d", MaxTunnelsPerLease, r.CountForPeer(peer1))
	}

	// 17th acquire on same lease must fail
	extra := &dummyCloser{}
	if err := r.Acquire(leaseA, peer1, extra); err == nil {
		t.Fatalf("expected lease cap error")
	}

	// Release one and re-acquire
	r.Release(leaseA, peer1, closers[0])
	if r.CountForLease(leaseA) != MaxTunnelsPerLease-1 {
		t.Fatalf("expected count %d after release", MaxTunnelsPerLease-1)
	}
	if err := r.Acquire(leaseA, peer1, extra); err != nil {
		t.Fatalf("re-acquire failed: %v", err)
	}

	// Fill peer1 up to MaxTunnelsPerPeer using leaseB
	remaining := MaxTunnelsPerPeer - MaxTunnelsPerLease
	moreClosers := make([]*dummyCloser, remaining)
	for i := 0; i < remaining; i++ {
		moreClosers[i] = &dummyCloser{}
		if err := r.Acquire(leaseB, peer1, moreClosers[i]); err != nil {
			t.Fatalf("acquire peer remaining %d failed: %v", i, err)
		}
	}

	// Peer cap reached
	peerExtra := &dummyCloser{}
	if err := r.Acquire("other-lease", peer1, peerExtra); err == nil {
		t.Fatalf("expected peer cap error")
	}

	// Different peer can still acquire
	leaseC := strings.Repeat("c", 64)
	if err := r.Acquire(leaseC, peer2, peerExtra); err != nil {
		t.Fatalf("peer2 acquire failed: %v", err)
	}
}

func TestTunnelRegistry_CloseTunnelsForLease(t *testing.T) {
	r := NewTunnelRegistry()
	leaseA := strings.Repeat("a", 64)
	peer1 := peer.ID("peer-1")

	c1 := &dummyCloser{}
	c2 := &dummyCloser{}
	if err := r.Acquire(leaseA, peer1, c1); err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	if err := r.Acquire(leaseA, peer1, c2); err != nil {
		t.Fatalf("acquire c2: %v", err)
	}

	r.CloseTunnelsForLease(leaseA)
	if !c1.closed.Load() || !c2.closed.Load() {
		t.Fatalf("expected closers to be closed")
	}
	if r.CountForLease(leaseA) != 0 {
		t.Fatalf("expected 0 tunnels for lease")
	}
	if r.CountForPeer(peer1) != 0 {
		t.Fatalf("expected 0 count for peer1")
	}

	// Calling release after CloseTunnelsForLease must not panic or underflow
	r.Release(leaseA, peer1, c1)
	if r.CountForPeer(peer1) != 0 {
		t.Fatalf("expected count to remain 0, got %d", r.CountForPeer(peer1))
	}
}

type mockTunnelValidator struct {
	mu           sync.Mutex
	authorized   map[peer.ID]bool
	dialSSHCalls atomic.Int32
	dialHook     func(leaseHash string) (net.Conn, error)
}

func (m *mockTunnelValidator) ValidateTunnelLease(leaseHash string, peerID peer.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.authorized[peerID] {
		return fmt.Errorf("unauthorized peer for lease")
	}
	return nil
}

func (m *mockTunnelValidator) DialSSH(leaseHash string) (net.Conn, error) {
	m.dialSSHCalls.Add(1)
	if m.dialHook != nil {
		return m.dialHook(leaseHash)
	}
	serverConn, clientConn := net.Pipe()
	go func() {
		defer func() { _ = serverConn.Close() }()
		_, _ = io.Copy(serverConn, serverConn)
	}()
	return clientConn, nil
}

func connectTestHosts(t *testing.T, a, b host.Host) {
	t.Helper()
	a.Peerstore().AddAddrs(b.ID(), b.Addrs(), peerstore.PermanentAddrTTL)
	b.Peerstore().AddAddrs(a.ID(), a.Addrs(), peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
		t.Fatalf("connect hosts: %v", err)
	}
}

func TestTunnel_P2PWorkflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	providerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("provider host: %v", err)
	}
	defer func() { _ = providerHost.Close() }()

	consumerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("consumer host: %v", err)
	}
	defer func() { _ = consumerHost.Close() }()

	attackerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("attacker host: %v", err)
	}
	defer func() { _ = attackerHost.Close() }()

	connectTestHosts(t, consumerHost, providerHost)
	connectTestHosts(t, attackerHost, providerHost)

	validator := &mockTunnelValidator{
		authorized: map[peer.ID]bool{
			consumerHost.ID(): true,
		},
	}
	registry := NewTunnelRegistry()
	SetupTunnelHandler(providerHost, validator, registry)

	leaseHash := strings.Repeat("f", 64)

	// 1. Authorized consumer peer establishes bidirectional tunnel
	stream, err := OpenTunnel(ctx, consumerHost, nil, providerHost.ID(), leaseHash)
	if err != nil {
		t.Fatalf("open tunnel failed for authorized consumer: %v", err)
	}
	testMsg := []byte("ping-xe-tunnel-stream")
	if _, err := stream.Write(testMsg); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}
	readBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(stream, readBuf); err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if !bytes.Equal(testMsg, readBuf) {
		t.Fatalf("data mismatch: got %q, want %q", string(readBuf), string(testMsg))
	}
	_ = stream.Close()

	// 2. Unauthorized peer receives error and DialSSH is NOT called
	callsBefore := validator.dialSSHCalls.Load()
	unauthStream, err := OpenTunnel(ctx, attackerHost, nil, providerHost.ID(), leaseHash)
	if err == nil {
		_ = unauthStream.Close()
		t.Fatalf("expected unauthorized tunnel attempt to fail")
	}
	if !strings.Contains(err.Error(), "unauthorized peer for lease") {
		t.Fatalf("expected unauthorized error message, got: %v", err)
	}
	if validator.dialSSHCalls.Load() != callsBefore {
		t.Fatalf("DialSSH must not be called for unauthorized peer")
	}

	// 3. Concurrent stream cap per lease and slot recovery
	activeStreams := make([]io.ReadWriteCloser, 0, MaxTunnelsPerLease)
	for i := 0; i < MaxTunnelsPerLease; i++ {
		s, err := OpenTunnel(ctx, consumerHost, nil, providerHost.ID(), leaseHash)
		if err != nil {
			t.Fatalf("open stream %d failed: %v", i, err)
		}
		activeStreams = append(activeStreams, s)
	}

	// 17th stream must exceed lease cap
	excess, err := OpenTunnel(ctx, consumerHost, nil, providerHost.ID(), leaseHash)
	if err == nil {
		_ = excess.Close()
		t.Fatalf("expected excess stream to fail")
	}
	if !strings.Contains(err.Error(), "max tunnels per lease reached") {
		t.Fatalf("expected cap error, got: %v", err)
	}

	// Close first stream to recover a slot
	_ = activeStreams[0].Close()

	recovered := false
	for attempt := 0; attempt < 50; attempt++ {
		time.Sleep(20 * time.Millisecond)
		s, err := OpenTunnel(ctx, consumerHost, nil, providerHost.ID(), leaseHash)
		if err == nil {
			recovered = true
			_ = s.Close()
			break
		}
	}
	if !recovered {
		t.Fatalf("failed to recover stream slot after closing active stream")
	}

	for _, s := range activeStreams[1:] {
		_ = s.Close()
	}

	// Wait briefly for all streams to finish unwinding
	for attempt := 0; attempt < 50; attempt++ {
		if registry.CountForPeer(consumerHost.ID()) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 4. Concurrent stream cap per peer and slot recovery
	peerStreams := make([]io.ReadWriteCloser, 0, MaxTunnelsPerPeer)
	for i := 0; i < MaxTunnelsPerPeer; i++ {
		perPeerLease := fmt.Sprintf("%064x", i+1)
		s, err := OpenTunnel(ctx, consumerHost, nil, providerHost.ID(), perPeerLease)
		if err != nil {
			t.Fatalf("open peer stream %d failed: %v", i, err)
		}
		peerStreams = append(peerStreams, s)
	}

	excessPeerStream, err := OpenTunnel(
		ctx, consumerHost, nil, providerHost.ID(), fmt.Sprintf("%064x", 9999),
	)
	if err == nil {
		_ = excessPeerStream.Close()
		t.Fatalf("expected excess peer stream to fail")
	}
	if !strings.Contains(err.Error(), "max tunnels per peer reached") {
		t.Fatalf("expected peer cap error, got: %v", err)
	}

	_ = peerStreams[0].Close()

	peerRecovered := false
	for attempt := 0; attempt < 50; attempt++ {
		time.Sleep(20 * time.Millisecond)
		s, err := OpenTunnel(
			ctx, consumerHost, nil, providerHost.ID(), fmt.Sprintf("%064x", 9999),
		)
		if err == nil {
			peerRecovered = true
			_ = s.Close()
			break
		}
	}
	if !peerRecovered {
		t.Fatalf("failed to recover peer stream slot after closing active stream")
	}

	for _, s := range peerStreams[1:] {
		_ = s.Close()
	}
}
