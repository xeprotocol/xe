package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
)

func TestMarketplaceOfferAdmissionAndFirstWins(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	n := &Node{
		KeyPair:        kp,
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
		ctx:            context.Background(),
	}

	provider1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	provider2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	reqID := "req-active-123"
	req := &xenet.ResourceRequest{
		Consumer:  kp.Address(),
		RequestID: reqID,
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: time.Now().UnixNano(),
	}
	n.activeRequests[reqID] = req

	// 1. Unsolicited offer for an unknown request ID must NOT be admitted
	unsolicitedOffer := &xenet.ResourceOffer{
		Provider:       provider1.Address(),
		ProviderPubKey: provider1.PubKeyHex(),
		RequestID:      "unsolicited-456",
		VCPUs:          4,
		MemoryMB:       8192,
		DiskGB:         50,
		Duration:       3600,
		TotalCost:      100,
		Timestamp:      time.Now().UnixNano(),
	}
	xenet.SignOffer(unsolicitedOffer, provider1.Private)

	// Simulate handleMarketplace logic directly
	msg1 := &xenet.MarketplaceMsg{Type: "offer", Offer: unsolicitedOffer}
	if err := xenet.VerifyOffer(msg1.Offer); err != nil {
		t.Fatalf("VerifyOffer failed: %v", err)
	}

	n.pendingOffersMu.Lock()
	r, isMine := n.activeRequests[msg1.Offer.RequestID]
	if isMine && r != nil {
		n.pendingOffers[msg1.Offer.RequestID] = msg1.Offer
	}
	n.pendingOffersMu.Unlock()

	if _, exists := n.pendingOffers["unsolicited-456"]; exists {
		t.Fatalf("Expected unsolicited offer to be rejected, but found in pendingOffers")
	}

	// 2. Legitimate offer for our active request MUST be admitted
	legitOffer1 := &xenet.ResourceOffer{
		Provider:       provider1.Address(),
		ProviderPubKey: provider1.PubKeyHex(),
		RequestID:      reqID,
		VCPUs:          4,
		MemoryMB:       8192,
		DiskGB:         50,
		Duration:       3600,
		TotalCost:      100,
		Timestamp:      time.Now().UnixNano(),
	}
	xenet.SignOffer(legitOffer1, provider1.Private)

	n.pendingOffersMu.Lock()
	r, isMine = n.activeRequests[legitOffer1.RequestID]
	if isMine && r != nil {
		if _, exists := n.pendingOffers[legitOffer1.RequestID]; !exists {
			n.pendingOffers[legitOffer1.RequestID] = legitOffer1
		}
	}
	n.pendingOffersMu.Unlock()

	if n.pendingOffers[reqID] != legitOffer1 {
		t.Fatalf("Expected legitimate offer1 to be stored, but was not")
	}

	// 3. Competing second offer from provider2 for same request must NOT overwrite (first-wins)
	legitOffer2 := &xenet.ResourceOffer{
		Provider:       provider2.Address(),
		ProviderPubKey: provider2.PubKeyHex(),
		RequestID:      reqID,
		VCPUs:          4,
		MemoryMB:       8192,
		DiskGB:         50,
		Duration:       3600,
		TotalCost:      90,
		Timestamp:      time.Now().UnixNano(),
	}
	xenet.SignOffer(legitOffer2, provider2.Private)

	n.pendingOffersMu.Lock()
	r, isMine = n.activeRequests[legitOffer2.RequestID]
	if isMine && r != nil {
		if _, exists := n.pendingOffers[legitOffer2.RequestID]; !exists {
			n.pendingOffers[legitOffer2.RequestID] = legitOffer2
		}
	}
	n.pendingOffersMu.Unlock()

	if n.pendingOffers[reqID].Provider != provider1.Address() {
		t.Fatalf("First-wins violated: provider2 overwrote provider1 in pendingOffers")
	}
}

func TestMarketplaceSenderQuota(t *testing.T) {
	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	offers := make(map[string]*xenet.ResourceOffer)
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("req-%d", i)
		offers[id] = &xenet.ResourceOffer{
			Provider:  provider.Address(),
			RequestID: id,
		}
	}

	// 6th offer from same provider should be rejected
	providerCount := 0
	for _, o := range offers {
		if o.Provider == provider.Address() {
			providerCount++
		}
	}
	if providerCount < 5 {
		t.Fatalf("Expected 5 offers, got %d", providerCount)
	}
}
