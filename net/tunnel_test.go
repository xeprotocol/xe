package net

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

type mockStreamConn struct {
	network.Conn
	remotePeer peer.ID
}

func (c *mockStreamConn) RemotePeer() peer.ID {
	return c.remotePeer
}

type mockStream struct {
	network.Stream
	pipe    net.Conn
	netConn network.Conn
}

func (m *mockStream) Read(p []byte) (int, error) {
	return m.pipe.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	return m.pipe.Write(p)
}

func (m *mockStream) Close() error {
	return m.pipe.Close()
}

func (m *mockStream) CloseWrite() error {
	return m.pipe.Close()
}

func (m *mockStream) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockStream) Conn() network.Conn {
	return m.netConn
}

type mockHost struct {
	host.Host
	handler network.StreamHandler
}

func (m *mockHost) SetStreamHandler(p protocol.ID, h network.StreamHandler) {
	m.handler = h
}

type mockValidator struct {
	validateErr error
	dialSSHConn net.Conn
	dialSSHErr  error
}

func (v *mockValidator) ValidateTunnelLease(leaseHash string, peerID peer.ID) error {
	return v.validateErr
}

func (v *mockValidator) DialSSH(leaseHash string) (net.Conn, error) {
	return v.dialSSHConn, v.dialSSHErr
}

func TestTunnelRegistry_Lifecycle(t *testing.T) {
	reg := NewTunnelRegistry()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()

	reg.add("lease1", c1)
	reg.mu.Lock()
	if len(reg.tunnels["lease1"]) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(reg.tunnels["lease1"]))
	}
	reg.mu.Unlock()

	reg.remove("lease1", c1)
	reg.mu.Lock()
	if len(reg.tunnels["lease1"]) != 0 {
		t.Fatalf("expected 0 tunnels, got %d", len(reg.tunnels["lease1"]))
	}
	reg.mu.Unlock()

	reg.add("lease2", c1)
	reg.CloseTunnelsForLease("lease2")
	reg.mu.Lock()
	if _, ok := reg.tunnels["lease2"]; ok {
		t.Fatal("expected lease2 to be removed after CloseTunnelsForLease")
	}
	reg.mu.Unlock()
}

func TestSetupTunnelHandler_BackendDisconnectUnblocks(t *testing.T) {
	h := &mockHost{}
	reg := NewTunnelRegistry()

	streamClient, streamServer := net.Pipe()
	backendVM, backendSSH := net.Pipe()

	validator := &mockValidator{
		dialSSHConn: backendSSH,
	}

	SetupTunnelHandler(h, validator, reg)
	if h.handler == nil {
		t.Fatal("handler not registered")
	}

	mockS := &mockStream{
		pipe:    streamServer,
		netConn: &mockStreamConn{remotePeer: peer.ID("peerA")},
	}

	done := make(chan struct{})
	go func() {
		h.handler(mockS)
		close(done)
	}()

	leaseBytes := make([]byte, 32)
	leaseBytes[0] = 0x42
	leaseHash := hex.EncodeToString(leaseBytes)

	// Send lease hash to stream
	if _, err := streamClient.Write(leaseBytes); err != nil {
		t.Fatalf("failed to write lease bytes: %v", err)
	}

	// Read handshake ok byte (0x00)
	status := make([]byte, 1)
	if _, err := io.ReadFull(streamClient, status); err != nil {
		t.Fatalf("failed to read handshake status: %v", err)
	}
	if status[0] != 0x00 {
		t.Fatalf("expected status 0x00, got 0x%02x", status[0])
	}

	// Wait until added to registry
	var inRegistry bool
	for i := 0; i < 50; i++ {
		reg.mu.Lock()
		if len(reg.tunnels[leaseHash]) == 1 {
			inRegistry = true
			reg.mu.Unlock()
			break
		}
		reg.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if !inRegistry {
		t.Fatal("expected tunnel in registry")
	}

	// Simulate backend VM terminating / closing connection
	_ = backendVM.Close()

	// Handler must unblock and terminate promptly
	select {
	case <-done:
		// Passed
	case <-time.After(2 * time.Second):
		t.Fatal("SetupTunnelHandler deadlocked after backend disconnect")
	}

	// Verify registry is cleaned up
	reg.mu.Lock()
	if _, ok := reg.tunnels[leaseHash]; ok {
		t.Fatal("expected lease to be removed from registry after session end")
	}
	reg.mu.Unlock()

	_ = streamClient.Close()
}

func TestSetupTunnelHandler_StreamDisconnectUnblocks(t *testing.T) {
	h := &mockHost{}
	reg := NewTunnelRegistry()

	streamClient, streamServer := net.Pipe()
	backendVM, backendSSH := net.Pipe()

	validator := &mockValidator{
		dialSSHConn: backendSSH,
	}

	SetupTunnelHandler(h, validator, reg)

	mockS := &mockStream{
		pipe:    streamServer,
		netConn: &mockStreamConn{remotePeer: peer.ID("peerB")},
	}

	done := make(chan struct{})
	go func() {
		h.handler(mockS)
		close(done)
	}()

	leaseBytes := make([]byte, 32)
	leaseBytes[0] = 0x99
	leaseHash := hex.EncodeToString(leaseBytes)

	// Send lease hash to stream
	if _, err := streamClient.Write(leaseBytes); err != nil {
		t.Fatalf("failed to write lease bytes: %v", err)
	}

	// Read handshake ok byte (0x00)
	status := make([]byte, 1)
	if _, err := io.ReadFull(streamClient, status); err != nil {
		t.Fatalf("failed to read handshake status: %v", err)
	}
	if status[0] != 0x00 {
		t.Fatalf("expected status 0x00, got 0x%02x", status[0])
	}

	// Simulate client closing the stream
	_ = streamClient.Close()

	// Handler must unblock and terminate promptly
	select {
	case <-done:
		// Passed
	case <-time.After(2 * time.Second):
		t.Fatal("SetupTunnelHandler deadlocked after stream disconnect")
	}

	// Verify backend is closed
	buf := make([]byte, 1)
	if _, err := backendVM.Read(buf); err == nil {
		t.Fatal("expected backend connection to be closed")
	}

	// Verify registry is cleaned up
	reg.mu.Lock()
	if _, ok := reg.tunnels[leaseHash]; ok {
		t.Fatal("expected lease to be removed from registry after session end")
	}
	reg.mu.Unlock()
}
