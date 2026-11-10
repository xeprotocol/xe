package node

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
)

func TestCanAttestForRenewalPolicyEnforcement(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	memStore := store.NewMemStore()
	node := &Node{
		KeyPair:    kp,
		isProvider: true,
		store:      memStore,
		acceptPolicy: LeaseAcceptPolicy{
			MaxDurationSec: 3600,
			MaxCostXUSD:    100000,
		},
	}

	leaseHash := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

	// 1. Lease accepted, currently at 3600s (already at provider cap)
	fullLease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Provider:  kp.Address(),
		Consumer:  "consumer_addr_123",
		Duration:  3600,
		Cost:      50000,
	}
	if err := memStore.PutLease(fullLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Requesting attestation with 0 incremental duration when lease is already at cap
	err = node.canAttestForRenewal(leaseHash, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "cumulative duration 3600s >= policy max 3600s") {
		t.Fatalf("expected max duration rejection, got: %v", err)
	}

	// 2. Lease accepted, currently at 1800s
	partialLease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Provider:  kp.Address(),
		Consumer:  "consumer_addr_123",
		Duration:  1800,
		Cost:      40000,
	}
	if err := memStore.PutLease(partialLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Requesting renewal with +1000s, cost 20000 -> projected 2800s <= 3600s, cost 60000 <= 100000 -> Allowed
	if err := node.canAttestForRenewal(leaseHash, 1000, 20000); err != nil {
		t.Fatalf("expected renewal within policy to be attestable, got: %v", err)
	}

	// Requesting renewal with +2000s -> projected 3800s > 3600s -> Rejected
	err = node.canAttestForRenewal(leaseHash, 2000, 20000)
	if err == nil || !strings.Contains(err.Error(), "projected cumulative duration 3800s > policy max 3600s") {
		t.Fatalf("expected duration cap rejection, got: %v", err)
	}

	// Requesting renewal with cost 70000 -> projected 110000 > 100000 -> Rejected
	err = node.canAttestForRenewal(leaseHash, 1000, 70000)
	if err == nil || !strings.Contains(err.Error(), "projected cumulative cost 110000 XUSD > policy max 100000 XUSD") {
		t.Fatalf("expected cost cap rejection, got: %v", err)
	}
}

func TestProviderInfoSurfacesPolicyCaps(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	memStore := store.NewMemStore()
	node := &Node{
		KeyPair:    kp,
		isProvider: true,
		store:      memStore,
		acceptPolicy: LeaseAcceptPolicy{
			MinDurationSec: 60,
			MaxDurationSec: 3600,
			MinCostXUSD:    1000,
			MaxCostXUSD:    500000,
			MaxConcurrent:  5,
		},
	}

	// Simulate resource advertisement
	ad := &xenet.ResourceAdvertisement{
		Provider:            kp.Address(),
		VCPUs:               8,
		MemoryMB:            16384,
		DiskGB:              200,
		MaxConcurrentLeases: 5,
		MinDurationSec:      60,
		MaxDurationSec:      3600,
		MinCostXUSD:         1000,
		MaxCostXUSD:         500000,
		Timestamp:           core.Now().UnixNano(),
	}
	node.providerAds.Store(ad.Provider, ad)

	providers := node.GetProviders()
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	p := providers[0]
	if p.MinDurationSec != 60 || p.MaxDurationSec != 3600 {
		t.Errorf("expected duration bounds 60s..3600s, got %ds..%ds", p.MinDurationSec, p.MaxDurationSec)
	}
	if p.MinCostXUSD != 1000 || p.MaxCostXUSD != 500000 {
		t.Errorf("expected cost bounds 1000..500000, got %d..%d", p.MinCostXUSD, p.MaxCostXUSD)
	}
	if p.MaxConcurrentLeases != 5 {
		t.Errorf("expected max concurrent 5, got %d", p.MaxConcurrentLeases)
	}
}
