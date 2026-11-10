package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

type mockHijacker struct {
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (m *mockHijacker) Header() http.Header         { return http.Header{} }
func (m *mockHijacker) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockHijacker) WriteHeader(statusCode int)  {}
func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, m.rw, nil
}

type mockTunnelNodeBackend struct {
	nodeBackend
	lease      *core.Lease
	tunnelConn io.ReadWriteCloser
	tunnelErr  error
}

func (m *mockTunnelNodeBackend) GetLease(hash string) *core.Lease {
	return m.lease
}

func (m *mockTunnelNodeBackend) OpenTunnelForLease(ctx context.Context, hash string) (io.ReadWriteCloser, error) {
	return m.tunnelConn, m.tunnelErr
}

func tcpPipe(t *testing.T) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		connCh <- c
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-connCh
	return client, server
}

func setupTestLeaseAndSig(t *testing.T) (string, string, string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	leaseHashBytes := make([]byte, 32)
	leaseHashBytes[0] = 0x11
	leaseHash := hex.EncodeToString(leaseHashBytes)

	sig := ed25519.Sign(priv, leaseHashBytes)
	sigHex := hex.EncodeToString(sig)

	return leaseHash, pubHex, sigHex
}

func drainHeader(t *testing.T, r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("failed reading header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
}

func TestHandleTunnelTCP_RemoteDisconnectUnblocks(t *testing.T) {
	leaseHash, pubHex, sigHex := setupTestLeaseAndSig(t)

	clientSide, clientServer := tcpPipe(t)
	defer clientSide.Close()
	defer clientServer.Close()

	tunnelServer, tunnelRemote := tcpPipe(t)
	defer tunnelServer.Close()
	defer tunnelRemote.Close()

	backend := &mockTunnelNodeBackend{
		lease: &core.Lease{
			LeaseHash:    leaseHash,
			State:        core.LeaseAccepted,
			AccessPubKey: pubHex,
		},
		tunnelConn: tunnelServer,
	}

	handler := &Handler{node: backend}

	req := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req.SetPathValue("leaseHash", leaseHash)
	req.Header.Set("X-Signature", sigHex)

	rw := bufio.NewReadWriter(bufio.NewReader(clientServer), bufio.NewWriter(clientServer))
	w := &mockHijacker{conn: clientServer, rw: rw}

	done := make(chan struct{})
	go func() {
		handler.handleTunnelTCP(w, req)
		close(done)
	}()

	// Read full HTTP 200 response header from client side
	clientReader := bufio.NewReader(clientSide)
	drainHeader(t, clientReader)

	// Simulate remote tunnel disconnect
	_ = tunnelRemote.Close()

	// Handler must unblock promptly
	select {
	case <-done:
		// Passed
	case <-time.After(2 * time.Second):
		t.Fatal("handleTunnelTCP deadlocked after remote disconnect")
	}

	// Verify client side connection was closed
	buf := make([]byte, 1)
	if _, err := clientReader.Read(buf); err == nil {
		t.Fatal("expected client connection to be closed after remote disconnect")
	}
}

func TestHandleTunnelTCP_ClientDisconnectUnblocks(t *testing.T) {
	leaseHash, pubHex, sigHex := setupTestLeaseAndSig(t)

	clientSide, clientServer := tcpPipe(t)
	defer clientSide.Close()
	defer clientServer.Close()

	tunnelServer, tunnelRemote := tcpPipe(t)
	defer tunnelServer.Close()
	defer tunnelRemote.Close()

	backend := &mockTunnelNodeBackend{
		lease: &core.Lease{
			LeaseHash:    leaseHash,
			State:        core.LeaseAccepted,
			AccessPubKey: pubHex,
		},
		tunnelConn: tunnelServer,
	}

	handler := &Handler{node: backend}

	req := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req.SetPathValue("leaseHash", leaseHash)
	req.Header.Set("X-Signature", sigHex)

	rw := bufio.NewReadWriter(bufio.NewReader(clientServer), bufio.NewWriter(clientServer))
	w := &mockHijacker{conn: clientServer, rw: rw}

	done := make(chan struct{})
	go func() {
		handler.handleTunnelTCP(w, req)
		close(done)
	}()

	// Read full HTTP 200 response header from client side
	clientReader := bufio.NewReader(clientSide)
	drainHeader(t, clientReader)

	// Simulate client disconnect
	_ = clientSide.Close()

	// Handler must unblock promptly
	select {
	case <-done:
		// Passed
	case <-time.After(2 * time.Second):
		t.Fatal("handleTunnelTCP deadlocked after client disconnect")
	}

	// Verify tunnel connection was closed
	buf := make([]byte, 1)
	if _, err := tunnelRemote.Read(buf); err == nil {
		t.Fatal("expected tunnel connection to be closed after client disconnect")
	}
}

func TestHandleTunnelTCP_BufferedDataFlushed(t *testing.T) {
	leaseHash, pubHex, sigHex := setupTestLeaseAndSig(t)

	clientSide, clientServer := tcpPipe(t)
	defer clientSide.Close()
	defer clientServer.Close()

	tunnelServer, tunnelRemote := tcpPipe(t)
	defer tunnelServer.Close()
	defer tunnelRemote.Close()

	backend := &mockTunnelNodeBackend{
		lease: &core.Lease{
			LeaseHash:    leaseHash,
			State:        core.LeaseAccepted,
			AccessPubKey: pubHex,
		},
		tunnelConn: tunnelServer,
	}

	handler := &Handler{node: backend}

	req := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req.SetPathValue("leaseHash", leaseHash)
	req.Header.Set("X-Signature", sigHex)

	// Pre-populate buffer with pending bytes
	initialData := []byte("PRE_BUFFERED_DATA")
	bufReader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), clientServer))
	_, _ = bufReader.Peek(1) // Force buffering into bufio.Reader
	rw := bufio.NewReadWriter(bufReader, bufio.NewWriter(clientServer))
	w := &mockHijacker{conn: clientServer, rw: rw}

	done := make(chan struct{})
	go func() {
		handler.handleTunnelTCP(w, req)
		close(done)
	}()

	// Read full HTTP 200 response header from client side
	clientReader := bufio.NewReader(clientSide)
	drainHeader(t, clientReader)

	// Verify pre-buffered bytes reached the tunnel
	received := make([]byte, len(initialData))
	if _, err := io.ReadFull(tunnelRemote, received); err != nil {
		t.Fatalf("failed to read forwarded buffer: %v", err)
	}
	if !bytes.Equal(received, initialData) {
		t.Fatalf("buffered data mismatch: got %s, want %s", string(received), string(initialData))
	}

	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTunnelTCP timed out during buffered data test")
	}
}
