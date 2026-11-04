package node

import (
	"bytes"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
)

func TestMarketplaceFreshnessMonotonicityAndDeduplication(t *testing.T) {
	refNow := time.Date(2026, 10, 23, 18, 1, 0, 0, time.UTC)
	now := refNow
	core.Now = func() time.Time { return now }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	ms := store.NewMemStore()
	n := &Node{
		store:         ms,
		pendingOffers: make(map[string]*xenet.ResourceOffer),
		seenRequests:  make(map[string]int64),
	}

	ghostKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x42}, 32))

	// Step 1 & 2: 90-day-old advertisement is rejected and never listed by GetProviders.
	staleAd := &xenet.ResourceAdvertisement{
		Provider:            ghostKP.Address(),
		VCPUs:               64,
		MemoryMB:            262144,
		DiskGB:              4096,
		MaxConcurrentLeases: 99,
		Timestamp:           now.Add(-90 * 24 * time.Hour).UnixNano(),
	}
	xenet.SignAdvertisement(staleAd, ghostKP.Private)

	ch := make(chan *xenet.MarketplaceMsg, 16)
	ch <- &xenet.MarketplaceMsg{Type: "advertisement", Ad: staleAd}

	// Step 5: 90-day future advertisement is rejected and never listed.
	futureAd := &xenet.ResourceAdvertisement{
		Provider:            ghostKP.Address(),
		VCPUs:               64,
		MemoryMB:            262144,
		DiskGB:              4096,
		MaxConcurrentLeases: 99,
		Timestamp:           now.Add(90 * 24 * time.Hour).UnixNano(),
	}
	xenet.SignAdvertisement(futureAd, ghostKP.Private)
	ch <- &xenet.MarketplaceMsg{Type: "advertisement", Ad: futureAd}
	close(ch)
	n.handleMarketplace(ch)

	if got := n.GetProviders(); len(got) != 0 {
		t.Fatalf("expected 0 providers after stale and future advertisements, got %d", len(got))
	}

	// Step 3: Monotonic guard and TTL expiry on providerAds.
	freshAd := &xenet.ResourceAdvertisement{
		Provider:            ghostKP.Address(),
		VCPUs:               111,
		MemoryMB:            262144,
		DiskGB:              4096,
		MaxConcurrentLeases: 99,
		Timestamp:           now.UnixNano(),
	}
	xenet.SignAdvertisement(freshAd, ghostKP.Private)

	olderButInWindowAd := &xenet.ResourceAdvertisement{
		Provider:            ghostKP.Address(),
		VCPUs:               222,
		MemoryMB:            262144,
		DiskGB:              4096,
		MaxConcurrentLeases: 99,
		Timestamp:           now.Add(-5 * time.Minute).UnixNano(),
	}
	xenet.SignAdvertisement(olderButInWindowAd, ghostKP.Private)

	ch2 := make(chan *xenet.MarketplaceMsg, 16)
	ch2 <- &xenet.MarketplaceMsg{Type: "advertisement", Ad: freshAd}
	ch2 <- &xenet.MarketplaceMsg{Type: "advertisement", Ad: olderButInWindowAd}
	ch2 <- &xenet.MarketplaceMsg{Type: "advertisement", Ad: freshAd} // byte-identical replay
	close(ch2)
	n.handleMarketplace(ch2)

	providers := n.GetProviders()
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].VCPUs != 111 || providers[0].Timestamp != freshAd.Timestamp {
		t.Fatalf("monotonic guard failed: got VCPUs=%d ts=%d, want VCPUs=111 ts=%d",
			providers[0].VCPUs, providers[0].Timestamp, freshAd.Timestamp)
	}

	// Advance clock past MaxAdvertisementAge and verify TTL eviction.
	now = now.Add(xenet.MaxAdvertisementAge + time.Second)
	if got := n.GetProviders(); len(got) != 0 {
		t.Fatalf("expected expired provider advertisement to be evicted, got %d listings", len(got))
	}

	// Step 4: Request deduplication prevents repeated provider work on replayed requests.
	consumerKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x55}, 32))
	req := &xenet.ResourceRequest{
		Consumer:  consumerKP.Address(),
		RequestID: "req-dedup-1",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    100,
		Duration:  3600,
		Timestamp: now.UnixNano(),
	}
	xenet.SignRequest(req, consumerKP.Private)

	acceptedCount := 0
	for i := 0; i < 10; i++ {
		if n.markRequestSeen(req) {
			acceptedCount++
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("expected exactly 1 accepted request out of 10 identical deliveries, got %d", acceptedCount)
	}
}
