package net

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestSyncTracker_MarkDirtyFromPeer_RateLimiting(t *testing.T) {
	st := newSyncTracker()
	st.clearDirty() // reset dirty to 0

	pid1 := peer.ID("peer-1")
	pid2 := peer.ID("peer-2")

	// First call from pid1 should succeed and mark dirty
	if !st.MarkDirtyFromPeer(pid1) {
		t.Fatalf("expected first MarkDirtyFromPeer from pid1 to succeed")
	}
	if !st.isDirtyForTest() {
		t.Fatalf("expected tracker to be dirty after first call")
	}

	st.clearDirty()

	// Immediate second call from pid1 should be blocked by per-peer cooldown
	if st.MarkDirtyFromPeer(pid1) {
		t.Fatalf("expected second immediate MarkDirtyFromPeer from pid1 to be rate-limited")
	}
	if st.isDirtyForTest() {
		t.Fatalf("expected tracker not to be dirty after blocked call from pid1")
	}

	// Immediate call from pid2: clears pid2 frontiers cache, but global dirty is rate-limited by dirtyResyncCooldown
	if st.MarkDirtyFromPeer(pid2) {
		t.Fatalf("expected global dirty from pid2 to be rate-limited within dirtyResyncCooldown")
	}
	if st.isDirtyForTest() {
		t.Fatalf("expected tracker not to be dirty due to global resync cooldown")
	}

	// Advance lastPeerDirty and clear pid2 cooldown
	st.mu.Lock()
	st.lastPeerDirty = time.Now().Add(-2 * dirtyResyncCooldown)
	delete(st.lastDirtyByPeer, pid2)
	st.mu.Unlock()

	// Now pid2 call should succeed in setting global dirty
	if !st.MarkDirtyFromPeer(pid2) {
		t.Fatalf("expected pid2 to succeed after cooldown expired")
	}
	if !st.isDirtyForTest() {
		t.Fatalf("expected tracker to be dirty after pid2 call with expired cooldown")
	}
}

type mockConn struct {
	network.Conn
	remote peer.ID
}

func (c *mockConn) RemotePeer() peer.ID { return c.remote }

type mockStream struct {
	network.Stream
	r       io.Reader
	w       io.Writer
	conn    network.Conn
	isReset bool
}

func newMockStream(reqData []byte, remote peer.ID) (*mockStream, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &mockStream{
		r:    bytes.NewReader(reqData),
		w:    out,
		conn: &mockConn{remote: remote},
	}, out
}

func (s *mockStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *mockStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *mockStream) Close() error               { return nil }
func (s *mockStream) Reset() error               { s.isReset = true; return nil }
func (s *mockStream) Conn() network.Conn         { return s.conn }

func newTestLedger() *core.Ledger {
	return core.NewLedger(store.NewMemStore(), core.LedgerConfig{
		Difficulty:      core.DefaultDifficulty,
		TimestampWindow: core.DefaultTimestampWindow,
	})
}

func TestHandleSyncStream_UnauthenticatedPeer_RejectedWithoutPoW(t *testing.T) {
	gater := NewNetworkGater()
	st := newSyncTracker()
	st.clearDirty()

	pid := peer.ID("unauthenticated-peer")

	req := SyncRequest{
		Frontiers: map[string]string{"account1": "fake-hash-64"},
		PageSize:  10,
	}
	reqBytes, _ := json.Marshal(req)

	s, _ := newMockStream(reqBytes, pid)
	ledger := newTestLedger()

	handleSyncStream(s, ledger, st, gater)

	if !s.isReset {
		t.Fatalf("expected unauthenticated stream without pow to be reset")
	}
	if st.isDirtyForTest() {
		t.Fatalf("unauthenticated stream must not dirty tracker")
	}
}

func TestHandleSyncStream_UnauthenticatedPeer_AllowedWithValidPoW_DoesNotDirty(t *testing.T) {
	gater := NewNetworkGater()
	st := newSyncTracker()
	st.clearDirty()

	pid := peer.ID("unauthenticated-pow-peer")

	// Compute valid PoW for peer ID
	powHash := sha256.Sum256([]byte(pid.String()))
	nonce := core.ComputePoW(powHash[:], core.DefaultDifficulty)

	req := SyncRequest{
		Frontiers: map[string]string{"account1": "fake-hash-64"},
		PageSize:  10,
		PoWNonce:  nonce,
	}
	reqBytes, _ := json.Marshal(req)

	s, outBuf := newMockStream(reqBytes, pid)
	ledger := newTestLedger()

	handleSyncStream(s, ledger, st, gater)

	if s.isReset {
		t.Fatalf("stream with valid pow should not be reset")
	}
	if st.isDirtyForTest() {
		t.Fatalf("unauthenticated peer with pow must not dirty tracker (dirty flag is only hint for authenticated)")
	}
	if outBuf.Len() == 0 {
		t.Fatalf("expected response pages to be written for valid pow request")
	}
}

func TestHandleSyncStream_AuthenticatedPeer_Allowed_MarksDirty(t *testing.T) {
	gater := NewNetworkGater()
	st := newSyncTracker()
	st.clearDirty()

	pid := peer.ID("authenticated-peer")
	gater.RecordPeerCapabilities(pid, PeerCapabilities{Version: "1.0.0"})

	ledger := newTestLedger()
	var testAcc string
	for acc := range ledger.Frontiers() {
		testAcc = acc
		break
	}
	if testAcc == "" {
		t.Fatalf("expected ledger to have at least one account from genesis")
	}

	req := SyncRequest{
		Frontiers: map[string]string{testAcc: "0000000000000000000000000000000000000000000000000000000000000001"},
		PageSize:  10,
	}
	reqBytes, _ := json.Marshal(req)

	s, outBuf := newMockStream(reqBytes, pid)

	handleSyncStream(s, ledger, st, gater)

	if s.isReset {
		t.Fatalf("authenticated stream should not be reset")
	}
	if outBuf.Len() == 0 {
		t.Fatalf("expected response pages to be written for authenticated request")
	}
	if !st.isDirtyForTest() {
		t.Fatalf("expected authenticated peer with ahead frontier to mark tracker dirty")
	}
}

func TestHandleSyncStream_BannedPeer_RejectedImmediately(t *testing.T) {
	gater := NewNetworkGater()
	st := newSyncTracker()
	st.clearDirty()

	pid := peer.ID("banned-peer")
	gater.Ban(pid, 10*time.Minute)

	req := SyncRequest{
		Frontiers: map[string]string{"account1": "fake-hash"},
		PageSize:  10,
	}
	reqBytes, _ := json.Marshal(req)

	s, _ := newMockStream(reqBytes, pid)
	ledger := newTestLedger()

	handleSyncStream(s, ledger, st, gater)

	if !s.isReset {
		t.Fatalf("expected banned peer stream to be reset immediately")
	}
	if st.isDirtyForTest() {
		t.Fatalf("banned peer must not dirty tracker")
	}
}
