package api

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

type mockTunnelNode struct {
	nodeBackend
	lease       *core.Lease
	tunnelConn  net.Conn
	tunnelError error
}

func (m *mockTunnelNode) GetLease(hash string) *core.Lease {
	if m.lease != nil && m.lease.LeaseHash == hash {
		return m.lease
	}
	return nil
}

func (m *mockTunnelNode) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	if m.tunnelError != nil {
		return nil, m.tunnelError
	}
	return m.tunnelConn, nil
}

func TestHandleTunnelTCP_RemoteDisconnectUnblocks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaseHash := "1111111111111111111111111111111111111111111111111111111111111111"
	hashBytes, err := core.DecodeHash(leaseHash)
	if err != nil {
		t.Fatal(err)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, hashBytes))

	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		AccessPubKey: hex.EncodeToString(pub),
	}

	// Create pipe for tunnel backend (server side & remote VM side)
	tunnelServer, remoteVM := net.Pipe()

	mock := &mockTunnelNode{
		lease:      lease,
		tunnelConn: tunnelServer,
	}

	handler := &Handler{node: mock}
	ts := httptest.NewServer(handler.Mux())
	defer ts.Close()

	// Dial the HTTP server directly using raw TCP
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}
	defer conn.Close()

	// Send HTTP hijacking request
	req := fmt.Sprintf("POST /tunnel/%s/tcp HTTP/1.1\r\nHost: %s\r\nX-Signature: %s\r\n\r\n",
		leaseHash, ts.Listener.Addr().String(), sig)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	// Read 200 OK header
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	// Now remote VM sends a greeting, then disconnects
	go func() {
		_, _ = remoteVM.Write([]byte("SSH-2.0-TestVM\r\n"))
		_ = remoteVM.Close()
	}()

	line, err := reader.ReadString('\n')
	if err != nil || line != "SSH-2.0-TestVM\r\n" {
		t.Fatalf("failed to read greeting: line=%q, err=%v", line, err)
	}

	// After remoteVM closes, the handler MUST close the hijacked client connection
	// and not hang indefinitely.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, rErr := reader.Read(buf)
		readDone <- rErr
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatalf("expected EOF after remote disconnect, got nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("DEADLOCK/LEAK: handler failed to close client connection after remote VM disconnected")
	}
}

func TestHandleTunnelTCP_ClientDisconnectUnblocks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaseHash := "2222222222222222222222222222222222222222222222222222222222222222"
	hashBytes, err := core.DecodeHash(leaseHash)
	if err != nil {
		t.Fatal(err)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, hashBytes))

	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		AccessPubKey: hex.EncodeToString(pub),
	}

	tunnelServer, remoteVM := net.Pipe()

	mock := &mockTunnelNode{
		lease:      lease,
		tunnelConn: tunnelServer,
	}

	handler := &Handler{node: mock}
	ts := httptest.NewServer(handler.Mux())
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}

	req := fmt.Sprintf("POST /tunnel/%s/tcp HTTP/1.1\r\nHost: %s\r\nX-Signature: %s\r\n\r\n",
		leaseHash, ts.Listener.Addr().String(), sig)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	// Client closes connection
	_ = conn.Close()

	// After client closes, remoteVM MUST receive EOF/close and not hang
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, rErr := remoteVM.Read(buf)
		readDone <- rErr
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatalf("expected EOF on remote VM after client disconnect, got nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("DEADLOCK/LEAK: handler failed to close tunnel connection after client disconnected")
	}
}
