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

func TestTunnel_UnauthorizedPeerRejected(t *testing.T) {
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attackerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = attackerKP

	leaseHash := strings.Repeat("ab", 32)
	mem := store.NewMemStore()
	if err := mem.PutLease(&core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		Consumer:     consumerKP.Address(),
		Provider:     providerKP.Address(),
		AccessPubKey: consumerKP.PubKeyHex(),
		Duration:     3600,
	}); err != nil {
		t.Fatal(err)
	}

	n := &Node{store: mem, KeyPair: providerKP}
	consumerPeer := peer.ID("consumer-peer-id-12345")
	attackerPeer := peer.ID("attacker-peer-id-67890")

	// Set the legitimate consumer peer mapping
	n.SetPeerForAccount(consumerKP.Address(), consumerPeer)

	// Legitimate consumer must be accepted
	if err := n.ValidateTunnelLease(leaseHash, consumerPeer); err != nil {
		t.Fatalf("expected consumer peer to be allowed, got error: %v", err)
	}

	// Attacker peer must be rejected
	if err := n.ValidateTunnelLease(leaseHash, attackerPeer); err == nil {
		t.Fatalf("expected attacker peer to be rejected, but ValidateTunnelLease succeeded")
	} else if !strings.Contains(err.Error(), "unauthorized peer") {
		t.Fatalf("expected unauthorized peer error, got: %v", err)
	}
}

func TestTunnel_ConsumerPeerViaDirectoryAllowed(t *testing.T) {
	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	consumerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	leaseHash := strings.Repeat("bc", 32)
	mem := store.NewMemStore()
	if err := mem.PutLease(&core.Lease{
		LeaseHash:    leaseHash,
		State:        core.LeaseAccepted,
		Consumer:     consumerKP.Address(),
		Provider:     providerKP.Address(),
		AccessPubKey: consumerKP.PubKeyHex(),
		Duration:     3600,
	}); err != nil {
		t.Fatal(err)
	}

	dir := directory.New(time.Hour)
	_, consumerPub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	consumerPeer, err := peer.IDFromPublicKey(consumerPub)
	if err != nil {
		t.Fatal(err)
	}
	reg := directory.NewRegistration(consumerPeer.String(), time.Now().UnixNano(), consumerKP)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("directory registration: %v", err)
	}

	n := &Node{
		store:     mem,
		KeyPair:   providerKP,
		Directory: dir,
	}

	// Legitimate consumer peer passes via directory
	if err := n.ValidateTunnelLease(leaseHash, consumerPeer); err != nil {
		t.Fatalf("expected consumer peer via directory to be allowed, got: %v", err)
	}

	// Unrelated peer is rejected
	_, attackerPub, _ := crypto.GenerateEd25519Key(rand.Reader)
	attackerPeer, _ := peer.IDFromPublicKey(attackerPub)
	if err := n.ValidateTunnelLease(leaseHash, attackerPeer); err == nil {
		t.Fatalf("expected attacker peer to be rejected")
	}
}

func TestTunnel_UnknownLeaseRejected(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	n := &Node{store: store.NewMemStore(), KeyPair: providerKP}

	consumerPeer := peer.ID("consumer-peer")
	n.SetPeerForAccount(consumerKP.Address(), consumerPeer)

	if err := n.ValidateTunnelLease(strings.Repeat("00", 32), consumerPeer); err == nil {
		t.Fatalf("expected unknown lease to be rejected")
	}
}

func TestTunnel_SettledOrCancelledLeaseRejected(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	mem := store.NewMemStore()
	consumerPeer := peer.ID("consumer-peer")

	n := &Node{store: mem, KeyPair: providerKP}
	n.SetPeerForAccount(consumerKP.Address(), consumerPeer)

	// Settled lease
	settledHash := strings.Repeat("11", 32)
	_ = mem.PutLease(&core.Lease{
		LeaseHash: settledHash,
		State:     core.LeaseSettled,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	})
	if err := n.ValidateTunnelLease(settledHash, consumerPeer); err == nil {
		t.Fatalf("expected settled lease to be rejected")
	}

	// Cancelled lease
	cancelledHash := strings.Repeat("22", 32)
	_ = mem.PutLease(&core.Lease{
		LeaseHash: cancelledHash,
		State:     core.LeaseCancelled,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	})
	if err := n.ValidateTunnelLease(cancelledHash, consumerPeer); err == nil {
		t.Fatalf("expected cancelled lease to be rejected")
	}
}

func TestTunnel_NotProviderRejected(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	otherKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	mem := store.NewMemStore()
	consumerPeer := peer.ID("consumer-peer")

	// Node is not the provider (KeyPair is otherKP)
	n := &Node{store: mem, KeyPair: otherKP}
	n.SetPeerForAccount(consumerKP.Address(), consumerPeer)

	leaseHash := strings.Repeat("33", 32)
	_ = mem.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	})

	if err := n.ValidateTunnelLease(leaseHash, consumerPeer); err == nil {
		t.Fatalf("expected node that is not the provider to reject tunnel")
	}
}

func TestTunnel_ConsumerNotInDirectoryRejected(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	mem := store.NewMemStore()

	// No peer mapping and no directory
	n := &Node{store: mem, KeyPair: providerKP}

	leaseHash := strings.Repeat("44", 32)
	_ = mem.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	})

	callerPeer := peer.ID("caller-peer")
	if err := n.ValidateTunnelLease(leaseHash, callerPeer); err == nil {
		t.Fatalf("expected rejection when consumer peer is not in directory")
	}
}

func TestTunnel_EmptyPeerIDRejected(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	mem := store.NewMemStore()

	n := &Node{store: mem, KeyPair: providerKP}
	n.SetPeerForAccount(consumerKP.Address(), peer.ID("consumer-peer"))

	leaseHash := strings.Repeat("55", 32)
	_ = mem.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
	})

	if err := n.ValidateTunnelLease(leaseHash, ""); err == nil {
		t.Fatalf("expected empty peer ID to be rejected")
	}
}
