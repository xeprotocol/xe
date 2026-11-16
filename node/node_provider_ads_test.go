package node

import (
	"fmt"
	"testing"
	"time"

	xenet "github.com/xeprotocol/xe/net"
)

func TestRecordProviderAdCapacityAndEviction(t *testing.T) {
	n := &Node{
		providerAds: make(map[string]*xenet.ResourceAdvertisement),
	}

	// Add up to maxProviderAds
	for i := 0; i < maxProviderAds; i++ {
		addr := fmt.Sprintf("provider-%04d", i)
		ad := &xenet.ResourceAdvertisement{
			Provider:  addr,
			VCPUs:     4,
			MemoryMB:  8192,
			DiskGB:    50,
			Timestamp: time.Now().UnixNano(),
		}
		n.recordProviderAd(ad)
	}

	if len(n.providerAds) != maxProviderAds {
		t.Fatalf("expected %d providerAds, got %d", maxProviderAds, len(n.providerAds))
	}
	if len(n.providerAdsOrder) != maxProviderAds {
		t.Fatalf("expected order length %d, got %d", maxProviderAds, len(n.providerAdsOrder))
	}

	// First provider should exist
	if _, ok := n.providerAds["provider-0000"]; !ok {
		t.Fatalf("expected provider-0000 to exist before overflow")
	}

	// Now insert one more to trigger eviction of the oldest (provider-0000)
	overflowAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-overflow",
		VCPUs:     8,
		MemoryMB:  16384,
		DiskGB:    100,
		Timestamp: time.Now().UnixNano(),
	}
	n.recordProviderAd(overflowAd)

	if len(n.providerAds) != maxProviderAds {
		t.Fatalf("expected capped size %d, got %d", maxProviderAds, len(n.providerAds))
	}
	if _, ok := n.providerAds["provider-0000"]; ok {
		t.Fatalf("expected oldest provider-0000 to be evicted on overflow")
	}
	if _, ok := n.providerAds["provider-overflow"]; !ok {
		t.Fatalf("expected provider-overflow to be present")
	}

	// Updating an existing provider should not increase size or duplicates in order
	updateAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-0001",
		VCPUs:     16,
		MemoryMB:  32768,
		DiskGB:    200,
		Timestamp: time.Now().UnixNano(),
	}
	n.recordProviderAd(updateAd)

	if len(n.providerAds) != maxProviderAds {
		t.Fatalf("expected capped size %d after update, got %d", maxProviderAds, len(n.providerAds))
	}
	if n.providerAds["provider-0001"].VCPUs != 16 {
		t.Fatalf("expected updated VCPUs to be 16, got %d", n.providerAds["provider-0001"].VCPUs)
	}
}

func TestPruneExpiredProviderAds(t *testing.T) {
	n := &Node{
		providerAds: make(map[string]*xenet.ResourceAdvertisement),
	}

	now := time.Now().UnixNano()
	expiredTimestamp := now - int64(providerAdTTL) - int64(time.Minute)
	freshTimestamp := now

	expiredAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-expired",
		Timestamp: expiredTimestamp,
	}
	freshAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-fresh",
		Timestamp: freshTimestamp,
	}

	n.recordProviderAd(expiredAd)
	n.recordProviderAd(freshAd)

	if len(n.providerAds) != 2 {
		t.Fatalf("expected 2 ads before prune, got %d", len(n.providerAds))
	}

	pruned := n.pruneExpiredProviderAds()
	if pruned != 1 {
		t.Fatalf("expected 1 pruned ad, got %d", pruned)
	}
	if _, ok := n.providerAds["provider-expired"]; ok {
		t.Fatalf("expected provider-expired to be deleted")
	}
	if _, ok := n.providerAds["provider-fresh"]; !ok {
		t.Fatalf("expected provider-fresh to remain")
	}
	if len(n.providerAdsOrder) != 1 || n.providerAdsOrder[0] != "provider-fresh" {
		t.Fatalf("expected order to contain only provider-fresh, got %v", n.providerAdsOrder)
	}
}

func TestGetProvidersLinearScan(t *testing.T) {
	n := &Node{
		providerAds: make(map[string]*xenet.ResourceAdvertisement),
	}

	now := time.Now().UnixNano()
	p1 := "provider-1"
	p2 := "provider-2"

	n.recordProviderAd(&xenet.ResourceAdvertisement{
		Provider:  p1,
		VCPUs:     10,
		MemoryMB:  1024,
		DiskGB:    50,
		Timestamp: now,
	})
	n.recordProviderAd(&xenet.ResourceAdvertisement{
		Provider:  p2,
		VCPUs:     20,
		MemoryMB:  2048,
		DiskGB:    100,
		Timestamp: now,
	})

	providers := n.GetProviders()
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(providers))
	}

	var foundP1, foundP2 bool
	for _, p := range providers {
		if p.Account == p1 {
			foundP1 = true
			if p.VCPUs != 10 {
				t.Errorf("expected p1 VCPUs 10, got %d", p.VCPUs)
			}
		}
		if p.Account == p2 {
			foundP2 = true
			if p.VCPUs != 20 {
				t.Errorf("expected p2 VCPUs 20, got %d", p.VCPUs)
			}
		}
	}
	if !foundP1 || !foundP2 {
		t.Errorf("failed to find all providers: p1=%v, p2=%v", foundP1, foundP2)
	}
}
