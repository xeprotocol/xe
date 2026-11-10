package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"golang.org/x/crypto/ssh"
)

type mockChannel struct {
	net.Conn
	stderr bytes.Buffer
}

func (m *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *mockChannel) CloseWrite() error {
	return m.Conn.Close()
}

func (m *mockChannel) Stderr() io.ReadWriter {
	return &m.stderr
}

type mockGatewayBackend struct {
	lease        *core.Lease
	providerPeer peer.ID
	openTunnelFn func(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error)
}

func (m *mockGatewayBackend) GetLease(hash string) *core.Lease {
	return m.lease
}

func (m *mockGatewayBackend) PeerForAccount(account string) peer.ID {
	return m.providerPeer
}

func (m *mockGatewayBackend) OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	if m.openTunnelFn != nil {
		return m.openTunnelFn(ctx, providerPeer, leaseHash)
	}
	return nil, nil
}

func TestSSHGateway_DirectTCPIP_ClientDisconnectUnblocks(t *testing.T) {
	clientR, clientW := net.Pipe()
	tunnelR, tunnelW := net.Pipe()

	backend := &mockGatewayBackend{
		lease: &core.Lease{
			LeaseHash: "testlease",
			Provider:  "testprovider",
		},
		providerPeer: peer.ID("testpeer"),
		openTunnelFn: func(ctx context.Context, p peer.ID, hash string) (io.ReadWriteCloser, error) {
			return tunnelR, nil
		},
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	ch := &mockChannel{Conn: clientW}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(ch, backend.lease)
		close(done)
	}()

	// Simulate client disconnecting
	_ = clientR.Close()

	select {
	case <-done:
		// Succeeded in unblocking
	case <-time.After(2 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked after client disconnect")
	}

	// Verify tunnel side is closed
	buf := make([]byte, 1)
	if _, err := tunnelW.Read(buf); err == nil {
		t.Fatal("expected tunnel to be closed after client disconnect")
	}
}

func TestSSHGateway_DirectTCPIP_TunnelDisconnectUnblocks(t *testing.T) {
	clientR, clientW := net.Pipe()
	tunnelR, tunnelW := net.Pipe()

	backend := &mockGatewayBackend{
		lease: &core.Lease{
			LeaseHash: "testlease",
			Provider:  "testprovider",
		},
		providerPeer: peer.ID("testpeer"),
		openTunnelFn: func(ctx context.Context, p peer.ID, hash string) (io.ReadWriteCloser, error) {
			return tunnelR, nil
		},
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	ch := &mockChannel{Conn: clientW}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(ch, backend.lease)
		close(done)
	}()

	// Simulate tunnel side disconnecting
	_ = tunnelW.Close()

	select {
	case <-done:
		// Succeeded in unblocking
	case <-time.After(2 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked after tunnel disconnect")
	}

	// Verify channel side is closed
	buf := make([]byte, 1)
	if _, err := clientR.Read(buf); err == nil {
		t.Fatal("expected channel to be closed after tunnel disconnect")
	}
}

func TestSSHGateway_DirectTCPIP_GatewayStopUnblocks(t *testing.T) {
	clientR, clientW := net.Pipe()
	tunnelR, tunnelW := net.Pipe()

	backend := &mockGatewayBackend{
		lease: &core.Lease{
			LeaseHash: "testlease",
			Provider:  "testprovider",
		},
		providerPeer: peer.ID("testpeer"),
		openTunnelFn: func(ctx context.Context, p peer.ID, hash string) (io.ReadWriteCloser, error) {
			return tunnelR, nil
		},
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	ch := &mockChannel{Conn: clientW}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(ch, backend.lease)
		close(done)
	}()

	// Close gateway done channel (simulating gw.Stop)
	close(gw.done)

	select {
	case <-done:
		// Succeeded in unblocking
	case <-time.After(2 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked during gateway Stop")
	}

	_ = clientR.Close()
	_ = tunnelW.Close()
}

func TestSSHGateway_ExtractED25519Key(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	extracted, ok := extractED25519Key(sshPub.Marshal())
	if !ok {
		t.Fatal("failed to extract ed25519 key")
	}

	if !bytes.Equal(extracted, pub) {
		t.Fatalf("extracted key mismatch: got %x, want %x", extracted, pub)
	}

	// Test invalid keys
	if _, ok := extractED25519Key([]byte{1, 2, 3}); ok {
		t.Fatal("expected short key to fail extraction")
	}
}
