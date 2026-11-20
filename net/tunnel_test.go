package net

import (
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

type mockHost struct {
	host.Host
	handler network.StreamHandler
}

func (m *mockHost) SetStreamHandler(pid protocol.ID, h network.StreamHandler) {
	m.handler = h
}

type mockTunnelValidator struct {
	dialConn net.Conn
	dialErr  error
	valErr   error
}

func (m *mockTunnelValidator) ValidateTunnelLease(leaseHash string, peerID peer.ID) error {
	return m.valErr
}

func (m *mockTunnelValidator) DialSSH(leaseHash string) (net.Conn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	return m.dialConn, nil
}

type mockStreamConn struct {
	network.Conn
	remotePeer peer.ID
}

func (c *mockStreamConn) RemotePeer() peer.ID {
	return c.remotePeer
}

type mockStream struct {
	network.Stream
	rawConn net.Conn
	conn    network.Conn
	closed  bool
	mu      sync.Mutex
}

func newMockStream(pipe net.Conn, remotePeer peer.ID) *mockStream {
	return &mockStream{
		rawConn: pipe,
		conn:    &mockStreamConn{remotePeer: remotePeer},
	}
}

func (m *mockStream) Conn() network.Conn {
	return m.conn
}

func (m *mockStream) SetDeadline(t time.Time) error {
	return m.rawConn.SetDeadline(t)
}

func (m *mockStream) SetReadDeadline(t time.Time) error {
	return m.rawConn.SetReadDeadline(t)
}

func (m *mockStream) SetWriteDeadline(t time.Time) error {
	return m.rawConn.SetWriteDeadline(t)
}

func (m *mockStream) Read(p []byte) (int, error) {
	return m.rawConn.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	return m.rawConn.Write(p)
}

func (m *mockStream) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return m.rawConn.Close()
}

func (m *mockStream) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockStream) CloseWrite() error {
	return nil
}

type trackBackendConn struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (t *trackBackendConn) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return t.Conn.Close()
}

func (t *trackBackendConn) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func TestSetupTunnelHandler_BackendDisconnectUnblocks(t *testing.T) {
	h := &mockHost{}
	registry := NewTunnelRegistry()

	bServer, bRemote := net.Pipe()
	defer bRemote.Close()
	mBackend := &trackBackendConn{Conn: bServer}

	validator := &mockTunnelValidator{
		dialConn: mBackend,
	}

	SetupTunnelHandler(h, validator, registry)
	if h.handler == nil {
		t.Fatal("expected stream handler to be set on host")
	}

	sServer, sRemote := net.Pipe()
	defer sRemote.Close()
	dummyPeer, _ := peer.Decode("12D3KooWStn4L87j6cM8i1s3HqP9vL1c2y3Z4a5B6c7D8e9F1a2B")
	mStream := newMockStream(sServer, dummyPeer)

	leaseBytes := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	leaseHash := hex.EncodeToString(leaseBytes[:])

	done := make(chan struct{})
	go func() {
		h.handler(mStream)
		close(done)
	}()

	// Send handshake lease bytes from client side
	if _, err := sRemote.Write(leaseBytes[:]); err != nil {
		t.Fatalf("failed to write lease bytes: %v", err)
	}

	// Read handshake response (0x00)
	resp := make([]byte, 1)
	if _, err := io.ReadFull(sRemote, resp); err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("unexpected handshake response: %x", resp[0])
	}

	// Check registry has the tunnel added (allow handler goroutine to execute registry.add)
	var tunnelsCount int
	for i := 0; i < 50; i++ {
		registry.mu.Lock()
		tunnelsCount = len(registry.tunnels[leaseHash])
		registry.mu.Unlock()
		if tunnelsCount == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tunnelsCount != 1 {
		t.Fatalf("expected 1 tunnel in registry, got %d", tunnelsCount)
	}

	// Now simulate backend VM disconnect
	_ = bRemote.Close()

	select {
	case <-done:
		// Handler returned cleanly without hanging
	case <-time.After(1 * time.Second):
		t.Fatal("handler deadlocked after backend disconnected")
	}

	if !mStream.isClosed() {
		t.Errorf("expected stream to be closed after backend disconnect")
	}

	// Verify registry.remove was executed and registry is empty
	registry.mu.Lock()
	rem := len(registry.tunnels[leaseHash])
	registry.mu.Unlock()
	if rem != 0 {
		t.Errorf("expected 0 tunnels in registry after handler exit, got %d", rem)
	}
}

func TestSetupTunnelHandler_StreamDisconnectUnblocks(t *testing.T) {
	h := &mockHost{}
	registry := NewTunnelRegistry()

	bServer, bRemote := net.Pipe()
	defer bRemote.Close()
	mBackend := &trackBackendConn{Conn: bServer}

	validator := &mockTunnelValidator{
		dialConn: mBackend,
	}

	SetupTunnelHandler(h, validator, registry)

	sServer, sRemote := net.Pipe()
	defer sRemote.Close()
	dummyPeer, _ := peer.Decode("12D3KooWStn4L87j6cM8i1s3HqP9vL1c2y3Z4a5B6c7D8e9F1a2B")
	mStream := newMockStream(sServer, dummyPeer)

	leaseBytes := [32]byte{9, 9, 9}
	leaseHash := hex.EncodeToString(leaseBytes[:])

	done := make(chan struct{})
	go func() {
		h.handler(mStream)
		close(done)
	}()

	// Send handshake lease bytes
	if _, err := sRemote.Write(leaseBytes[:]); err != nil {
		t.Fatalf("failed to write lease bytes: %v", err)
	}

	// Read handshake response
	resp := make([]byte, 1)
	if _, err := io.ReadFull(sRemote, resp); err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("unexpected handshake response: %x", resp[0])
	}

	// Now simulate client stream disconnect
	_ = sRemote.Close()

	select {
	case <-done:
		// Handler returned cleanly without hanging
	case <-time.After(1 * time.Second):
		t.Fatal("handler deadlocked after stream disconnected")
	}

	if !mBackend.isClosed() {
		t.Errorf("expected backend to be closed after stream disconnect")
	}

	// Verify registry.remove was executed
	registry.mu.Lock()
	rem := len(registry.tunnels[leaseHash])
	registry.mu.Unlock()
	if rem != 0 {
		t.Errorf("expected 0 tunnels in registry after handler exit, got %d", rem)
	}
}
