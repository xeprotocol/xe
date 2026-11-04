package api

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

type mockTunnelBackend struct {
	nodeBackend
	lease *core.Lease
}

func (m *mockTunnelBackend) GetLease(hash string) *core.Lease {
	if m.lease != nil && m.lease.LeaseHash == hash {
		return m.lease
	}
	return nil
}

func (m *mockTunnelBackend) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	c1, _ := net.Pipe()
	return c1, nil
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	serverConn net.Conn
	clientConn net.Conn
	hijacked   bool
}

func newHijackRecorder() *hijackRecorder {
	c1, c2 := net.Pipe()
	rec := &hijackRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		serverConn:       c1,
		clientConn:       c2,
	}
	go func() {
		buf := make([]byte, 1024)
		_, _ = c2.Read(buf)
		_ = c2.Close()
	}()
	return rec
}

func (r *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	rw := bufio.NewReadWriter(bufio.NewReader(r.serverConn), bufio.NewWriter(r.serverConn))
	return r.serverConn, rw, nil
}

func (r *hijackRecorder) Close() {
	_ = r.serverConn.Close()
	_ = r.clientConn.Close()
}

func TestTunnelReplayProtection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	leaseHashBytes := sha256.Sum256([]byte("test-lease-hash-48-94"))
	leaseHash := hex.EncodeToString(leaseHashBytes[:])

	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		AccessPubKey: pubHex,
		StartTime:    time.Now().Unix() - 100,
		Duration:     3600,
	}

	backend := &mockTunnelBackend{lease: lease}
	handler := &Handler{node: backend}

	// 1. Generate valid signature over lease hash
	sigBytes := ed25519.Sign(priv, leaseHashBytes[:])
	sigHex := hex.EncodeToString(sigBytes)

	// First request: should pass signature check and attempt hijack
	req1 := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req1.SetPathValue("leaseHash", leaseHash)
	req1.Header.Set("X-Signature", sigHex)
	rec1 := newHijackRecorder()
	defer rec1.Close()

	handler.handleTunnelTCP(rec1, req1)

	if rec1.Code != http.StatusOK && !rec1.hijacked {
		t.Fatalf("expected first request to succeed/hijack, got code %d, body: %s", rec1.Code, rec1.Body.String())
	}

	// Second request: Replay of the IDENTICAL signature must be rejected (Issue #48 / #94)
	req2 := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req2.SetPathValue("leaseHash", leaseHash)
	req2.Header.Set("X-Signature", sigHex)
	rec2 := newHijackRecorder()
	defer rec2.Close()

	handler.handleTunnelTCP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected replayed signature to return 403 Forbidden, got %d (body: %s)", rec2.Code, rec2.Body.String())
	}
}

func TestTunnelTimestampNonceBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	leaseHashBytes := sha256.Sum256([]byte("test-lease-ts-binding"))
	leaseHash := hex.EncodeToString(leaseHashBytes[:])

	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		AccessPubKey: pubHex,
		StartTime:    time.Now().Unix() - 100,
		Duration:     3600,
	}

	backend := &mockTunnelBackend{lease: lease}
	handler := &Handler{node: backend}

	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	nonce := "random-nonce-12345"
	path := "/tunnel/" + leaseHash + "/tcp"

	// Sign bound payload: sha256(leaseHash:METHOD:PATH:timestamp:nonce)
	hPayload := sha256.New()
	hPayload.Write([]byte(fmt.Sprintf("%s:POST:%s:%s:%s", leaseHash, path, tsStr, nonce)))
	boundBytes := hPayload.Sum(nil)
	sigBytes := ed25519.Sign(priv, boundBytes)
	sigHex := hex.EncodeToString(sigBytes)

	// Valid timestamped request: should succeed
	req := httptest.NewRequest("POST", path, nil)
	req.SetPathValue("leaseHash", leaseHash)
	req.Header.Set("X-Signature", sigHex)
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Nonce", nonce)
	rec := newHijackRecorder()
	defer rec.Close()

	handler.handleTunnelTCP(rec, req)

	if rec.Code != http.StatusOK && !rec.hijacked {
		t.Fatalf("expected timestamp-bound request to succeed/hijack, got code %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Expired timestamp: outside 300s window should fail
	oldTsStr := strconv.FormatInt(now-400, 10)
	hOld := sha256.New()
	hOld.Write([]byte(fmt.Sprintf("%s:POST:%s:%s:%s", leaseHash, path, oldTsStr, nonce)))
	oldSigBytes := ed25519.Sign(priv, hOld.Sum(nil))

	reqOld := httptest.NewRequest("POST", path, nil)
	reqOld.SetPathValue("leaseHash", leaseHash)
	reqOld.Header.Set("X-Signature", hex.EncodeToString(oldSigBytes))
	reqOld.Header.Set("X-Timestamp", oldTsStr)
	reqOld.Header.Set("X-Nonce", nonce)
	recOld := newHijackRecorder()
	defer recOld.Close()

	handler.handleTunnelTCP(recOld, reqOld)

	if recOld.Code != http.StatusForbidden {
		t.Fatalf("expected expired timestamp to return 403 Forbidden, got %d", recOld.Code)
	}
}

func TestTunnelConcurrencyCap(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	leaseHashBytes := sha256.Sum256([]byte("test-lease-concurrency"))
	leaseHash := hex.EncodeToString(leaseHashBytes[:])

	lease := &core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		AccessPubKey: pubHex,
		StartTime:    time.Now().Unix(),
		Duration:     3600,
	}

	backend := &mockTunnelBackend{lease: lease}
	handler := &Handler{node: backend}

	// Artificially saturate the semaphore to 100
	sem := handler.tunnelSem()
	for i := 0; i < maxTunnelConnections; i++ {
		sem <- struct{}{}
	}

	// Next connection must be rejected with 503
	sigBytes := ed25519.Sign(priv, leaseHashBytes[:])
	req := httptest.NewRequest("POST", "/tunnel/"+leaseHash+"/tcp", nil)
	req.SetPathValue("leaseHash", leaseHash)
	req.Header.Set("X-Signature", hex.EncodeToString(sigBytes))
	rec := newHijackRecorder()
	defer rec.Close()

	handler.handleTunnelTCP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable when semaphore is full, got %d", rec.Code)
	}

	// Drain semaphore
	for i := 0; i < maxTunnelConnections; i++ {
		<-sem
	}
}
