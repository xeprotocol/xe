package node

import (
	"testing"
	"time"

	xenet "github.com/xeprotocol/xe/net"
)

func TestNode_GetProviders_TTLPrune(t *testing.T) {
	n := &Node{}

	// Add an expired advertisement (older than ProviderAdTTL)
	expiredAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-expired",
		VCPUs:     8,
		MemoryMB:  16384,
		DiskGB:    200,
		Timestamp: time.Now().Add(-20 * time.Minute).UnixNano(),
	}
	n.providerAds.Store(expiredAd.Provider, expiredAd)

	// Add a live advertisement
	liveAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-live",
		VCPUs:     16,
		MemoryMB:  32768,
		DiskGB:    500,
		Timestamp: time.Now().Add(-2 * time.Minute).UnixNano(),
	}
	n.providerAds.Store(liveAd.Provider, liveAd)

	providers := n.GetProviders()
	if len(providers) != 1 {
		t.Fatalf("expected exactly 1 provider, got %d", len(providers))
	}
	if providers[0].Account != "provider-live" {
		t.Fatalf("expected provider-live, got %s", providers[0].Account)
	}

	// Verify that the expired ad was deleted from n.providerAds
	if _, ok := n.providerAds.Load("provider-expired"); ok {
		t.Fatal("expected expired ad to be evicted from providerAds")
	}
}

func TestNode_ProviderAds_MonotonicUpdate(t *testing.T) {
	n := &Node{}
	now := time.Now()

	// Initial ad with timestamp T-5m
	ad1 := &xenet.ResourceAdvertisement{
		Provider:  "provider-1",
		VCPUs:     8,
		Timestamp: now.Add(-5 * time.Minute).UnixNano(),
	}
	n.providerAds.Store(ad1.Provider, ad1)

	// Helper matching monotonic store logic in handleMarketplace
	storeAd := func(ad *xenet.ResourceAdvertisement) bool {
		if existing, ok := n.providerAds.Load(ad.Provider); ok {
			if existing.(*xenet.ResourceAdvertisement).Timestamp >= ad.Timestamp {
				return false
			}
		}
		n.providerAds.Store(ad.Provider, ad)
		return true
	}

	// Newer ad with timestamp T-3m
	ad2 := &xenet.ResourceAdvertisement{
		Provider:  "provider-1",
		VCPUs:     16,
		Timestamp: now.Add(-3 * time.Minute).UnixNano(),
	}
	if !storeAd(ad2) {
		t.Fatal("expected newer ad to be accepted")
	}

	// Stale replayed ad with timestamp T-10m
	staleAd := &xenet.ResourceAdvertisement{
		Provider:  "provider-1",
		VCPUs:     32,
		Timestamp: now.Add(-10 * time.Minute).UnixNano(),
	}
	if storeAd(staleAd) {
		t.Fatal("expected stale replayed ad to be rejected")
	}

	// Ensure stored ad is still ad2 (16 vcpus)
	val, ok := n.providerAds.Load("provider-1")
	if !ok {
		t.Fatal("expected provider-1 to exist")
	}
	if val.(*xenet.ResourceAdvertisement).VCPUs != 16 {
		t.Fatalf("expected 16 vCPUs, got %d", val.(*xenet.ResourceAdvertisement).VCPUs)
	}
}
