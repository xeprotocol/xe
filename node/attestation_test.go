package node

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/store"
)

func newTestAttestationNode(t *testing.T) (*Node, *store.MemStore) {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ms := store.NewMemStore()
	dir := directory.New(directory.DefaultTTL)
	n := &Node{
		KeyPair:    kp,
		store:      ms,
		Directory:  dir,
		attRateMap: make(map[string]time.Time),
	}
	return n, ms
}

func TestRequestAttestation_RejectsDirectoryAndZeroMidWithoutCallerProof(t *testing.T) {
	n, _ := newTestAttestationNode(t)

	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	providerPeer := "12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT"
	reg := directory.NewRegistration(providerPeer, core.Now().UnixNano(), providerKP)
	if err := n.Directory.Register(reg); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}

	acct := reg.Account
	zeroMidID := acct[:32] + "0000000000000000" + acct[48:]

	// Unauthenticated HTTP RequestAttestation (no caller proof) must reject both
	// the registered provider account and the zero-mid benchmark identifier.
	if _, err := n.RequestAttestation("198.51.100.10", acct); err == nil {
		t.Fatalf("expected unauthenticated RequestAttestation for directory account to fail")
	}
	if _, err := n.RequestAttestation("198.51.100.10", zeroMidID); err == nil {
		t.Fatalf("expected unauthenticated RequestAttestation for zero-mid identifier to fail")
	}

	// Another P2P peer (not owning the registration) must also be rejected.
	otherPeer, err := peer.Decode("12D3KooWEbQ5zDvSz6kKE5ppzwBXKRFsnZbHNjRx94QZFaPeGA4e")
	if err != nil {
		t.Fatalf("peer.Decode: %v", err)
	}
	if _, err := n.RequestAttestationFromPeer(otherPeer, acct); err == nil {
		t.Fatalf("expected RequestAttestationFromPeer from non-owner peer to fail for account")
	}
	if _, err := n.RequestAttestationFromPeer(otherPeer, zeroMidID); err == nil {
		t.Fatalf("expected RequestAttestationFromPeer from non-owner peer to fail for zero-mid")
	}

	// The registered provider peer itself can attest startID and endID in the same benchmark window.
	ownerPeer, err := peer.Decode(providerPeer)
	if err != nil {
		t.Fatalf("peer.Decode: %v", err)
	}
	startAtt, err := n.RequestAttestationFromPeer(ownerPeer, acct)
	if err != nil {
		t.Fatalf("expected owner peer startID attestation to succeed, got: %v", err)
	}
	if err := core.VerifyAttestation(startAtt, acct); err != nil {
		t.Fatalf("VerifyAttestation(startID): %v", err)
	}

	endAtt, err := n.RequestAttestationFromPeer(ownerPeer, zeroMidID)
	if err != nil {
		t.Fatalf("expected owner peer endID attestation to succeed in same window, got: %v", err)
	}
	if err := core.VerifyAttestation(endAtt, zeroMidID); err != nil {
		t.Fatalf("VerifyAttestation(endID): %v", err)
	}

	// Repeating startID or endID within the rate-limit window must be rejected.
	if _, err := n.RequestAttestationFromPeer(ownerPeer, acct); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected repeat startID within window to be rate limited, got: %v", err)
	}
	if _, err := n.RequestAttestationFromPeer(ownerPeer, zeroMidID); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected repeat endID within window to be rate limited, got: %v", err)
	}
}

func TestRequestAttestationWithProof_VerifiesCallerOwnership(t *testing.T) {
	n, _ := newTestAttestationNode(t)

	providerKP, _ := core.GenerateKeyPair()
	otherKP, _ := core.GenerateKeyPair()
	providerPeer := "12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT"
	reg := directory.NewRegistration(providerPeer, core.Now().UnixNano(), providerKP)
	if err := n.Directory.Register(reg); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}

	acct := reg.Account
	zeroMidID := acct[:32] + "0000000000000000" + acct[48:]
	ts := core.Now().UnixNano()

	// Proof signed by otherKP for providerKP's zeroMidID must be rejected.
	wrongSig := hex.EncodeToString(ed25519.Sign(otherKP.Private, AttestationRequestProofPayload(zeroMidID, ts)))
	if _, err := n.RequestAttestationWithProof("203.0.113.5", zeroMidID, otherKP.PubKeyHex(), ts, wrongSig); err == nil {
		t.Fatalf("expected proof from non-owner key to be rejected")
	}

	// Valid proof signed by providerKP succeeds for startID and endID.
	startSig := hex.EncodeToString(ed25519.Sign(providerKP.Private, AttestationRequestProofPayload(acct, ts)))
	if _, err := n.RequestAttestationWithProof("203.0.113.5", acct, providerKP.PubKeyHex(), ts, startSig); err != nil {
		t.Fatalf("expected valid owner proof for startID to succeed: %v", err)
	}
	endSig := hex.EncodeToString(ed25519.Sign(providerKP.Private, AttestationRequestProofPayload(zeroMidID, ts)))
	if _, err := n.RequestAttestationWithProof("203.0.113.5", zeroMidID, providerKP.PubKeyHex(), ts, endSig); err != nil {
		t.Fatalf("expected valid owner proof for endID to succeed: %v", err)
	}
}

func TestRequestAttestation_RateLimiterKeyedOnSourceAndAtomicUnderConcurrency(t *testing.T) {
	n, ms := newTestAttestationNode(t)

	lease1 := strings.Repeat("a", 64)
	lease2 := strings.Repeat("b", 64)
	_ = ms.PutLease(&core.Lease{LeaseHash: lease1, State: core.LeaseCreated})
	_ = ms.PutLease(&core.Lease{LeaseHash: lease2, State: core.LeaseAccepted})

	// Rejected request must not consume the caller's rate-limit window.
	unknown := strings.Repeat("c", 64)
	if _, err := n.RequestAttestation("192.0.2.1", unknown); err == nil {
		t.Fatalf("expected unknown lease to be rejected")
	}

	// First valid lease request from source succeeds.
	if _, err := n.RequestAttestation("192.0.2.1", lease1); err != nil {
		t.Fatalf("expected first lease attestation to succeed, got: %v", err)
	}

	// Second request from the SAME source with a DIFFERENT lease identifier within 15s
	// must be rate-limited because the limiter is keyed on source as well as identifier.
	if _, err := n.RequestAttestation("192.0.2.1", lease2); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected second request from same source with different identifier to be rate limited, got: %v", err)
	}

	// Concurrent requests from a fresh source must only allow exactly 1 attestation.
	var successCount int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := n.RequestAttestation("192.0.2.99", lease1); err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&successCount); got != 1 {
		t.Fatalf("expected exactly 1 concurrent request to succeed, got %d", got)
	}
}
