package node

import (
	"strings"
	"testing"
	"time"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/store"
)

func generateTestPeer(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return pid
}

func generateTestKeyPair(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func TestValidateTunnelLease(t *testing.T) {
	providerKP := generateTestKeyPair(t)
	consumerKP := generateTestKeyPair(t)
	unrelatedKP := generateTestKeyPair(t)

	providerPeer := generateTestPeer(t)
	consumerPeer := generateTestPeer(t)
	unrelatedPeer := generateTestPeer(t)

	memStore := store.NewMemStore()
	dir := directory.New(time.Hour)

	consumerReg := directory.NewRegistration(consumerPeer.String(), time.Now().UnixNano(), consumerKP)
	if err := dir.Register(consumerReg); err != nil {
		t.Fatalf("register consumer: %v", err)
	}

	n := &Node{
		KeyPair:   providerKP,
		store:     memStore,
		Directory: dir,
	}

	leaseHash := strings.Repeat("a", 64)
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	// 1. Authorized consumer peer succeeds
	if err := n.ValidateTunnelLease(leaseHash, consumerPeer); err != nil {
		t.Fatalf("authorized peer rejected: %v", err)
	}

	// 2. Empty peer ID is rejected
	if err := n.ValidateTunnelLease(leaseHash, ""); err == nil {
		t.Fatalf("expected empty peer ID to be rejected")
	}

	// 3. Unrelated peer ID is rejected
	if err := n.ValidateTunnelLease(leaseHash, unrelatedPeer); err == nil {
		t.Fatalf("expected unrelated peer to be rejected")
	}

	// 4. Provider's own peer ID is rejected when provider != consumer
	if err := n.ValidateTunnelLease(leaseHash, providerPeer); err == nil {
		t.Fatalf("expected provider peer to be rejected")
	}

	// 5. Unregistered consumer is rejected
	unregHash := strings.Repeat("b", 64)
	unregLease := &core.Lease{
		LeaseHash: unregHash,
		State:     core.LeaseAccepted,
		Consumer:  unrelatedKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := memStore.PutLease(unregLease); err != nil {
		t.Fatalf("put unreg lease: %v", err)
	}
	if err := n.ValidateTunnelLease(unregHash, unrelatedPeer); err == nil {
		t.Fatalf("expected unregistered consumer to be rejected")
	}

	// 6. Unknown lease is rejected
	unknownHash := strings.Repeat("c", 64)
	if err := n.ValidateTunnelLease(unknownHash, consumerPeer); err == nil {
		t.Fatalf("expected unknown lease to be rejected")
	}

	// 7. Settled lease is rejected
	settledHash := strings.Repeat("d", 64)
	settledLease := &core.Lease{
		LeaseHash: settledHash,
		State:     core.LeaseSettled,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := memStore.PutLease(settledLease); err != nil {
		t.Fatalf("put settled lease: %v", err)
	}
	if err := n.ValidateTunnelLease(settledHash, consumerPeer); err == nil {
		t.Fatalf("expected settled lease to be rejected")
	}

	// 8. Cancelled lease is rejected
	cancelledHash := strings.Repeat("e", 64)
	cancelledLease := &core.Lease{
		LeaseHash: cancelledHash,
		State:     core.LeaseCancelled,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := memStore.PutLease(cancelledLease); err != nil {
		t.Fatalf("put cancelled lease: %v", err)
	}
	if err := n.ValidateTunnelLease(cancelledHash, consumerPeer); err == nil {
		t.Fatalf("expected cancelled lease to be rejected")
	}

	// 9. Non-provider node is rejected
	otherKP := generateTestKeyPair(t)
	otherNode := &Node{
		KeyPair:   otherKP,
		store:     memStore,
		Directory: dir,
	}
	if err := otherNode.ValidateTunnelLease(leaseHash, consumerPeer); err == nil {
		t.Fatalf("expected non-provider node to be rejected")
	}
}
