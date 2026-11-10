package node

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

type mockBackend struct {
	peerID peer.ID
	tunnel io.ReadWriteCloser
	err    error
}

func (m *mockBackend) GetLease(hash string) *core.Lease {
	return nil
}

func (m *mockBackend) PeerForAccount(account string) peer.ID {
	return m.peerID
}

func (m *mockBackend) OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.tunnel, nil
}

type mockChannel struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (m *mockChannel) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return m.Conn.Close()
}

func (m *mockChannel) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockChannel) CloseWrite() error {
	return nil
}

func (m *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (m *mockChannel) Stderr() io.ReadWriter {
	return nil
}

type trackCloser struct {
	net.Conn
	closed bool
	mu     sync.Mutex
}

func (t *trackCloser) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return t.Conn.Close()
}

func (t *trackCloser) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func TestHandleDirectTCPIP_TunnelDisconnectUnblocks(t *testing.T) {
	chServer, chClient := net.Pipe()
	defer chClient.Close()
	mChan := &mockChannel{Conn: chServer}

	tunServer, tunRemote := net.Pipe()
	defer tunRemote.Close()
	mTun := &trackCloser{Conn: tunServer}

	dummyPeer, _ := peer.Decode("12D3KooWStn4L87j6cM8i1s3HqP9vL1c2y3Z4a5B6c7D8e9F1a2B")
	backend := &mockBackend{
		peerID: dummyPeer,
		tunnel: mTun,
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	lease := &core.Lease{
		Provider:  "prov1",
		LeaseHash: "aabbccdd",
	}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(mChan, lease)
		close(done)
	}()

	// Simulate remote tunnel disconnect
	_ = tunRemote.Close()

	select {
	case <-done:
		// Succeeded in terminating cleanly without deadlock
	case <-time.After(1 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked after remote tunnel disconnected")
	}

	if !mChan.isClosed() {
		t.Errorf("expected SSH channel to be closed after tunnel disconnect")
	}
}

func TestHandleDirectTCPIP_ClientDisconnectUnblocks(t *testing.T) {
	chServer, chClient := net.Pipe()
	mChan := &mockChannel{Conn: chServer}

	tunServer, tunRemote := net.Pipe()
	defer tunRemote.Close()
	mTun := &trackCloser{Conn: tunServer}

	dummyPeer, _ := peer.Decode("12D3KooWStn4L87j6cM8i1s3HqP9vL1c2y3Z4a5B6c7D8e9F1a2B")
	backend := &mockBackend{
		peerID: dummyPeer,
		tunnel: mTun,
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	lease := &core.Lease{
		Provider:  "prov1",
		LeaseHash: "aabbccdd",
	}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(mChan, lease)
		close(done)
	}()

	// Simulate client SSH disconnect
	_ = chClient.Close()

	select {
	case <-done:
		// Succeeded in terminating cleanly without deadlock
	case <-time.After(1 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked after client SSH disconnected")
	}

	if !mTun.isClosed() {
		t.Errorf("expected provider tunnel to be closed after client disconnect")
	}
}

func TestHandleDirectTCPIP_GatewayStopUnblocks(t *testing.T) {
	chServer, chClient := net.Pipe()
	defer chClient.Close()
	mChan := &mockChannel{Conn: chServer}

	tunServer, tunRemote := net.Pipe()
	defer tunRemote.Close()
	mTun := &trackCloser{Conn: tunServer}

	dummyPeer, _ := peer.Decode("12D3KooWStn4L87j6cM8i1s3HqP9vL1c2y3Z4a5B6c7D8e9F1a2B")
	backend := &mockBackend{
		peerID: dummyPeer,
		tunnel: mTun,
	}

	gw := &SSHGateway{
		backend: backend,
		done:    make(chan struct{}),
	}

	lease := &core.Lease{
		Provider:  "prov1",
		LeaseHash: "aabbccdd",
	}

	done := make(chan struct{})
	go func() {
		gw.handleDirectTCPIP(mChan, lease)
		close(done)
	}()

	// Neither client nor tunnel disconnects; gateway stops
	close(gw.done)

	select {
	case <-done:
		// Succeeded in terminating cleanly on gateway stop
	case <-time.After(1 * time.Second):
		t.Fatal("handleDirectTCPIP deadlocked after gateway stopped")
	}

	if !mChan.isClosed() {
		t.Errorf("expected SSH channel to be closed after gateway stop")
	}
	if !mTun.isClosed() {
		t.Errorf("expected provider tunnel to be closed after gateway stop")
	}
}
