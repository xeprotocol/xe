package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
)

func marketTestKey(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func marketTestOffer(kp *core.KeyPair, requestID string, ts int64, totalCost uint64, vcpus, memMB, diskGB, duration uint64) *xenet.ResourceOffer {
	o := &xenet.ResourceOffer{
		Provider:  kp.Address(),
		RequestID: requestID,
		VCPUs:     vcpus,
		MemoryMB:  memMB,
		DiskGB:    diskGB,
		Duration:  duration,
		TotalCost: totalCost,
		Timestamp: ts,
	}
	xenet.SignOffer(o, kp.Private)
	return o
}

func marketFeedMsgs(n *Node, msgs ...*xenet.MarketplaceMsg) {
	ch := make(chan *xenet.MarketplaceMsg, len(msgs))
	for _, m := range msgs {
		ch <- m
	}
	close(ch)
	n.handleMarketplace(ch)
}

// TestMarketPendingOffers_UnrequestedOffersIgnored verifies that offers for RequestIDs
// not issued by this node are ignored and not stored.
func TestMarketPendingOffers_UnrequestedOffersIgnored(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	attacker := marketTestKey(t)
	now := time.Now().UnixNano()

	o := marketTestOffer(attacker, "unrequested-id", now, 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: o})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	if len(n.pendingOffers) != 0 {
		t.Fatalf("expected 0 pending offers for unrequested ID, got %d", len(n.pendingOffers))
	}
}

// TestMarketPendingOffers_FloodDoesNotBlockLegit verifies that 1000 arbitrary attacker offers
// cannot flood pendingOffers and block a legitimate lease offer.
func TestMarketPendingOffers_FloodDoesNotBlockLegit(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	attacker := marketTestKey(t)
	legit := marketTestKey(t)
	now := time.Now().UnixNano()

	msgs := make([]*xenet.MarketplaceMsg, 0, 1000)
	for i := 0; i < 1000; i++ {
		o := marketTestOffer(attacker, fmt.Sprintf("flood-req-%d", i), now+int64(i), 517, 2, 2048, 20, 3600)
		msgs = append(msgs, &xenet.MarketplaceMsg{Type: "offer", Offer: o})
	}
	marketFeedMsgs(n, msgs...)

	n.pendingOffersMu.Lock()
	if len(n.pendingOffers) != 0 {
		n.pendingOffersMu.Unlock()
		t.Fatalf("flood offers should not have been stored, got %d", len(n.pendingOffers))
	}
	n.pendingOffersMu.Unlock()

	// Register legitimate request
	legitReq := &xenet.ResourceRequest{
		Consumer:  "consumer-addr",
		RequestID: "victim-request",
		VCPUs:     2,
		MemoryMB:  2048,
		DiskGB:    20,
		Duration:  3600,
		Timestamp: now,
	}
	n.RegisterActiveRequest(legitReq)

	legitOffer := marketTestOffer(legit, "victim-request", now+1000, 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: legitOffer})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	stored, ok := n.pendingOffers["victim-request"]
	if !ok {
		t.Fatalf("legitimate offer was dropped / not stored after flood")
	}
	if stored.Provider != legit.Address() || stored.TotalCost != 517 {
		t.Fatalf("unexpected stored offer: %+v", stored)
	}
}

// TestMarketPendingOffers_StaleAndFutureRejected verifies that offers older than 60s
// or > 10s in the future are rejected.
func TestMarketPendingOffers_StaleAndFutureRejected(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	kp := marketTestKey(t)
	now := time.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-freshness",
		VCPUs:     2,
		MemoryMB:  2048,
		DiskGB:    20,
		Duration:  3600,
		Timestamp: now,
	}
	n.RegisterActiveRequest(req)

	// 1-hour old offer
	staleOffer := marketTestOffer(kp, "req-freshness", now-int64(time.Hour), 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: staleOffer})

	// 1-hour future offer
	futureOffer := marketTestOffer(kp, "req-freshness", now+int64(time.Hour), 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: futureOffer})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	if _, ok := n.pendingOffers["req-freshness"]; ok {
		t.Fatalf("stale or future offer should not be stored")
	}
}

// TestMarketPendingOffers_OfferOlderThanRequestRejected verifies that an offer with timestamp
// earlier than the request timestamp is rejected.
func TestMarketPendingOffers_OfferOlderThanRequestRejected(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	kp := marketTestKey(t)
	now := time.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-ts-order",
		VCPUs:     2,
		MemoryMB:  2048,
		DiskGB:    20,
		Duration:  3600,
		Timestamp: now,
	}
	n.RegisterActiveRequest(req)

	// Offer created 5 seconds before the request
	preReqOffer := marketTestOffer(kp, "req-ts-order", now-int64(5*time.Second), 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: preReqOffer})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	if _, ok := n.pendingOffers["req-ts-order"]; ok {
		t.Fatalf("offer older than request should not be stored")
	}
}

// TestMarketPendingOffers_UnderDimensionedRejected verifies that offers with insufficient
// vCPUs, memory, disk, or duration are rejected.
func TestMarketPendingOffers_UnderDimensionedRejected(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	kp := marketTestKey(t)
	now := time.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-dims",
		VCPUs:     4,
		MemoryMB:  4096,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: now,
	}
	n.RegisterActiveRequest(req)

	// Less vCPUs (3 < 4)
	o1 := marketTestOffer(kp, "req-dims", now+100, 517, 3, 4096, 50, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: o1})

	// Less memory (2048 < 4096)
	o2 := marketTestOffer(kp, "req-dims", now+200, 517, 4, 2048, 50, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: o2})

	// Less disk (40 < 50)
	o3 := marketTestOffer(kp, "req-dims", now+300, 517, 4, 4096, 40, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: o3})

	// Less duration (1800 < 3600)
	o4 := marketTestOffer(kp, "req-dims", now+400, 517, 4, 4096, 50, 1800)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: o4})

	n.pendingOffersMu.Lock()
	if len(n.pendingOffers) != 0 {
		n.pendingOffersMu.Unlock()
		t.Fatalf("under-dimensioned offers were stored")
	}
	n.pendingOffersMu.Unlock()

	// Matching dimensions
	oGood := marketTestOffer(kp, "req-dims", now+500, 517, 4, 4096, 50, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: oGood})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	if _, ok := n.pendingOffers["req-dims"]; !ok {
		t.Fatalf("matching offer was not stored")
	}
}

// TestMarketPendingOffers_DisplacementPrevented verifies that a later offer with higher or
// equal TotalCost cannot displace an existing legitimate offer, while a cheaper offer can.
func TestMarketPendingOffers_DisplacementPrevented(t *testing.T) {
	n := &Node{
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}
	legit := marketTestKey(t)
	attacker := marketTestKey(t)
	cheaper := marketTestKey(t)
	now := time.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-R",
		VCPUs:     2,
		MemoryMB:  2048,
		DiskGB:    20,
		Duration:  3600,
		Timestamp: now,
	}
	n.RegisterActiveRequest(req)

	// Legit offer stored
	legitOffer := marketTestOffer(legit, "req-R", now+100, 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: legitOffer})

	n.pendingOffersMu.Lock()
	if n.pendingOffers["req-R"].Provider != legit.Address() {
		n.pendingOffersMu.Unlock()
		t.Fatalf("legit offer not stored")
	}
	n.pendingOffersMu.Unlock()

	// Attacker tries to displace with higher cost (9999 vs 517)
	attackerOffer := marketTestOffer(attacker, "req-R", now+200, 9999, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: attackerOffer})

	n.pendingOffersMu.Lock()
	got := n.pendingOffers["req-R"]
	if got.Provider != legit.Address() || got.TotalCost != 517 {
		n.pendingOffersMu.Unlock()
		t.Fatalf("attacker higher-cost offer displaced legit offer: %+v", got)
	}
	n.pendingOffersMu.Unlock()

	// Another provider with equal cost (517) tries to displace -> first seen wins
	equalOffer := marketTestOffer(attacker, "req-R", now+300, 517, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: equalOffer})

	n.pendingOffersMu.Lock()
	got = n.pendingOffers["req-R"]
	if got.Provider != legit.Address() {
		n.pendingOffersMu.Unlock()
		t.Fatalf("equal cost offer displaced earlier offer")
	}
	n.pendingOffersMu.Unlock()

	// Cheaper provider (400 < 517) arrives -> should update to the cheaper offer
	cheaperOffer := marketTestOffer(cheaper, "req-R", now+400, 400, 2, 2048, 20, 3600)
	marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: cheaperOffer})

	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	got = n.pendingOffers["req-R"]
	if got.Provider != cheaper.Address() || got.TotalCost != 400 {
		t.Fatalf("cheaper offer failed to replace existing offer: %+v", got)
	}
}

// TestMarketPendingOffers_RequestLeaseFlow verifies that RequestLease registers
// an active request, receives matching offer, returns it, and cleans up state.
func TestMarketPendingOffers_RequestLeaseFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kp := marketTestKey(t)
	n := &Node{
		KeyPair:        kp,
		ctx:            ctx,
		pendingOffers:  make(map[string]*xenet.ResourceOffer),
		activeRequests: make(map[string]*xenet.ResourceRequest),
	}

	provider := marketTestKey(t)

	// In background, wait for active request to appear, then send an offer
	go func() {
		var reqID string
		for i := 0; i < 50; i++ {
			time.Sleep(20 * time.Millisecond)
			n.pendingOffersMu.Lock()
			for id := range n.activeRequests {
				reqID = id
				break
			}
			n.pendingOffersMu.Unlock()
			if reqID != "" {
				break
			}
		}
		if reqID == "" {
			return
		}
		now := time.Now().UnixNano()
		offer := marketTestOffer(provider, reqID, now, 500, 2, 2048, 20, 3600)
		marketFeedMsgs(n, &xenet.MarketplaceMsg{Type: "offer", Offer: offer})
	}()

	offer, err := n.RequestLease(2, 2048, 20, 3600)
	if err != nil {
		t.Fatalf("RequestLease failed: %v", err)
	}
	if offer.Provider != provider.Address() || offer.TotalCost != 500 {
		t.Fatalf("unexpected offer returned: %+v", offer)
	}

	// Verify cleanup
	n.pendingOffersMu.Lock()
	defer n.pendingOffersMu.Unlock()
	if len(n.activeRequests) != 0 {
		t.Fatalf("activeRequests not cleaned up: %d", len(n.activeRequests))
	}
	if len(n.pendingOffers) != 0 {
		t.Fatalf("pendingOffers not cleaned up: %d", len(n.pendingOffers))
	}
}
