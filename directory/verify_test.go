package directory

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

// newTestKeyPair generates a fresh ed25519 key pair for testing.
func newTestKeyPair(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// TestVerifyRegistration_NodePeerTooShort verifies that a NodePeer value
// shorter than 12 characters is rejected by VerifyRegistration before any
// cryptographic check is reached, preventing the panic that previously
// occurred in node/node.go when reg.NodePeer[:12] was evaluated on a short
// string.
func TestVerifyRegistration_NodePeerTooShort(t *testing.T) {
	shortPeers := []string{
		"a",
		"ab",
		"12345",
		"11char-foo!", // 11 chars
	}
	for _, peer := range shortPeers {
		t.Run("peer="+peer, func(t *testing.T) {
			// Build a signed registration, then replace NodePeer with a short
			// value post-signing to isolate the length guard.
			kp := newTestKeyPair(t)
			ts := time.Now().Unix()
			reg := NewRegistration("valid-peer-address-xyz", ts, kp)
			reg.NodePeer = peer

			err := VerifyRegistration(reg)
			if err == nil {
				t.Fatalf("expected error for short NodePeer %q, got nil", peer)
			}
			if !strings.Contains(err.Error(), "node_peer too short") {
				t.Fatalf("expected 'node_peer too short' error, got: %v", err)
			}
		})
	}
}

// TestVerifyRegistration_NodePeerEmpty verifies that an empty NodePeer is
// still rejected with "missing node_peer".
func TestVerifyRegistration_NodePeerEmpty(t *testing.T) {
	kp := newTestKeyPair(t)
	ts := time.Now().Unix()
	reg := NewRegistration("valid-peer-address-xyz", ts, kp)
	reg.NodePeer = ""

	err := VerifyRegistration(reg)
	if err == nil {
		t.Fatal("expected error for empty NodePeer, got nil")
	}
	if !strings.Contains(err.Error(), "missing node_peer") {
		t.Fatalf("expected 'missing node_peer' error, got: %v", err)
	}
}

// TestVerifyRegistration_NodePeerExactMinimum verifies that a NodePeer of
// exactly 12 characters passes the length check (the registration is signed
// correctly so the full verification should succeed).
func TestVerifyRegistration_NodePeerExactMinimum(t *testing.T) {
	kp := newTestKeyPair(t)
	ts := time.Now().Unix()
	reg := NewRegistration("exactly12chr", ts, kp)

	err := VerifyRegistration(reg)
	if err != nil && strings.Contains(err.Error(), "node_peer too short") {
		t.Fatalf("unexpected 'node_peer too short' for exactly-12-char peer: %v", err)
	}
	// A nil error means the registration is fully valid — great.
	// A non-nil error unrelated to length (e.g., network-ID mismatch in test
	// environment) is acceptable; we only care that the length guard does not
	// fire.
}

// TestVerifyRegistration_NodePeerLong verifies that a long, valid NodePeer
// does not trigger the length rejection.
func TestVerifyRegistration_NodePeerLong(t *testing.T) {
	longPeer := "/ip4/192.0.2.1/tcp/4001/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
	kp := newTestKeyPair(t)
	ts := time.Now().Unix()
	reg := NewRegistration(longPeer, ts, kp)

	err := VerifyRegistration(reg)
	if err != nil && strings.Contains(err.Error(), "node_peer too short") {
		t.Fatalf("unexpected 'node_peer too short' for long peer: %v", err)
	}
}

// TestVerifyRegistration_NoPanicOnShortPeer is a regression test that
// explicitly demonstrates the original panic scenario: previously,
// node/node.go performed reg.NodePeer[:12] without a length guard, which
// would have panicked at runtime when NodePeer was short.  Passing a short
// NodePeer through the full validation pipeline must never panic.
func TestVerifyRegistration_NoPanicOnShortPeer(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic triggered for short NodePeer: %v", r)
		}
	}()

	kp := newTestKeyPair(t)
	ts := time.Now().Unix()
	reg := NewRegistration("valid-peer-address-xyz", ts, kp)
	reg.NodePeer = "a" // single character — previously caused panic

	// Must not panic; error is expected.
	err := VerifyRegistration(reg)
	if err == nil {
		t.Fatal("expected error for single-char NodePeer, got nil")
	}
}
