package node

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/store"
)

func generateTestPeerID(t *testing.T) peer.ID {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("peer id from private key: %v", err)
	}
	return pid
}

func TestValidateTunnelLeaseUnauthorizedPeerRejected(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	dir := directory.New(10 * time.Minute)
	consumerPeer := generateTestPeerID(t)
	reg := directory.NewRegistration(consumerPeer.String(), time.Now().UnixNano(), consumerKP)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("register consumer: %v", err)
	}

	leaseHash := "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := st.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	n := &Node{
		store:     st,
		KeyPair:   providerKP,
		Directory: dir,
	}

	// Attacker peer unrelated to consumer
	attackerPeer := generateTestPeerID(t)

	err := n.ValidateTunnelLease(leaseHash, attackerPeer)
	if err == nil {
		t.Fatalf("expected error for unauthorized peer, but got nil")
	}
	if !strings.Contains(err.Error(), "unauthorized peer") {
		t.Fatalf("expected 'unauthorized peer' error, got: %v", err)
	}
}

func TestValidateTunnelLeaseAuthorizedPeerSuccess(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	dir := directory.New(10 * time.Minute)
	consumerPeer := generateTestPeerID(t)
	reg := directory.NewRegistration(consumerPeer.String(), time.Now().UnixNano(), consumerKP)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("register consumer: %v", err)
	}

	leaseHash := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := st.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	n := &Node{
		store:     st,
		KeyPair:   providerKP,
		Directory: dir,
	}

	// Legitimate consumer peer passes validation
	err := n.ValidateTunnelLease(leaseHash, consumerPeer)
	if err != nil {
		t.Fatalf("expected success for legitimate consumer peer, got: %v", err)
	}
}

func TestValidateTunnelLeaseMissingPeerID(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	leaseHash := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := st.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	n := &Node{
		store:   st,
		KeyPair: providerKP,
	}

	err := n.ValidateTunnelLease(leaseHash, "")
	if err == nil {
		t.Fatalf("expected error for empty peer ID, got nil")
	}
	if !strings.Contains(err.Error(), "missing remote peer ID") {
		t.Fatalf("expected 'missing remote peer ID' error, got: %v", err)
	}
}

func TestValidateTunnelLeaseConsumerNotRegistered(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	dir := directory.New(10 * time.Minute)
	// Notice: consumerKP is NOT registered in directory

	leaseHash := "222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := st.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	n := &Node{
		store:     st,
		KeyPair:   providerKP,
		Directory: dir,
	}

	somePeer := generateTestPeerID(t)
	err := n.ValidateTunnelLease(leaseHash, somePeer)
	if err == nil {
		t.Fatalf("expected error when consumer is not registered, got nil")
	}
	if !strings.Contains(err.Error(), "consumer peer not registered") {
		t.Fatalf("expected 'consumer peer not registered' error, got: %v", err)
	}
}

func TestValidateTunnelLeaseNilDirectorySafe(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()

	leaseHash := "33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222"
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	if err := st.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}

	// Node with nil Directory
	n := &Node{
		store:     st,
		KeyPair:   providerKP,
		Directory: nil,
	}

	somePeer := generateTestPeerID(t)
	err := n.ValidateTunnelLease(leaseHash, somePeer)
	if err == nil {
		t.Fatalf("expected error when directory is nil, got nil")
	}
	if !strings.Contains(err.Error(), "consumer peer not registered") {
		t.Fatalf("expected safe error, got: %v", err)
	}
}

func TestValidateTunnelLeaseNotFoundOrNotActive(t *testing.T) {
	st := store.NewMemStore()
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	otherKP, _ := core.GenerateKeyPair()

	leaseHash := "4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333"

	n := &Node{
		store:   st,
		KeyPair: providerKP,
	}

	somePeer := generateTestPeerID(t)

	// 1. Lease not found
	if err := n.ValidateTunnelLease(leaseHash, somePeer); err == nil || !strings.Contains(err.Error(), "lease not found") {
		t.Fatalf("expected 'lease not found' error, got: %v", err)
	}

	// 2. Lease not active (e.g. Pending)
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseCancelled,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	}
	_ = st.PutLease(lease)

	if err := n.ValidateTunnelLease(leaseHash, somePeer); err == nil || !strings.Contains(err.Error(), "lease not active") {
		t.Fatalf("expected 'lease not active' error, got: %v", err)
	}

	// 3. Not provider for this lease
	lease.State = core.LeaseAccepted
	lease.Provider = otherKP.Address()
	_ = st.PutLease(lease)

	if err := n.ValidateTunnelLease(leaseHash, somePeer); err == nil || !strings.Contains(err.Error(), "not the provider") {
		t.Fatalf("expected 'not the provider for this lease' error, got: %v", err)
	}
}
