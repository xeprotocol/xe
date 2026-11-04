package node

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

type dummySSHBackend struct{}

func (d *dummySSHBackend) GetLease(hash string) *core.Lease {
	return nil
}

func (d *dummySSHBackend) PeerForAccount(account string) peer.ID {
	return ""
}

func (d *dummySSHBackend) OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestSSHGateway_PreAuthPerIPLimit(t *testing.T) {
	tempDir := t.TempDir()
	gw, err := NewSSHGateway("127.0.0.1:0", tempDir, &dummySSHBackend{})
	if err != nil {
		t.Fatalf("failed to create SSHGateway: %v", err)
	}
	gw.Start()
	defer gw.Stop()

	addr := gw.Addr().String()

	// Open maxPreAuthPerIP (10) silent connections
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	for i := 0; i < maxPreAuthPerIP; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("failed to dial connection %d: %v", i+1, err)
		}
		conns = append(conns, c)
	}

	// Give accept loop a moment to register slots
	time.Sleep(50 * time.Millisecond)

	// The 11th connection from the same IP must be immediately rejected and closed
	cExtra, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial extra connection: %v", err)
	}
	defer cExtra.Close()

	buf := make([]byte, 1)
	_ = cExtra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, readErr := cExtra.Read(buf)
	if n != 0 || readErr == nil {
		t.Fatalf("expected 11th connection to be closed immediately by gateway, got n=%d, err=%v", n, readErr)
	}

	// Now close one of the held connections
	_ = conns[0].Close()
	conns = conns[1:]
	time.Sleep(100 * time.Millisecond)

	// Now a new connection from the same IP should be accepted and not immediately closed
	cAllowed, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to dial allowed connection after slot freed: %v", err)
	}
	defer cAllowed.Close()

	// Verify gateway didn't immediately drop it: we can read until deadline without instant EOF
	_ = cAllowed.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = cAllowed.Read(buf)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// Expected timeout: connection was held open waiting for SSH banner
	} else if err != nil {
		t.Fatalf("expected connection to remain open (timeout), got: %v", err)
	}
}

func TestSSHGateway_AcquireReleasePreAuth(t *testing.T) {
	gw := &SSHGateway{
		preAuthIPs: make(map[string]int),
	}

	ip := "192.168.1.100"
	for i := 0; i < maxPreAuthPerIP; i++ {
		if !gw.acquirePreAuth(ip) {
			t.Fatalf("acquirePreAuth failed unexpectedly at iteration %d", i+1)
		}
	}

	// Should be full
	if gw.acquirePreAuth(ip) {
		t.Fatalf("acquirePreAuth succeeded when IP reached maxPreAuthPerIP")
	}

	// Other IP should still succeed
	otherIP := "192.168.1.101"
	if !gw.acquirePreAuth(otherIP) {
		t.Fatalf("acquirePreAuth failed for distinct IP")
	}

	// Release and re-acquire
	gw.releasePreAuth(ip)
	if !gw.acquirePreAuth(ip) {
		t.Fatalf("acquirePreAuth failed after slot released")
	}
}
