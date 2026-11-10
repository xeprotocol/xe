package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
)

func TestAllowMarketplaceRequest_Basic(t *testing.T) {
	n := &Node{}
	now := core.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-001",
		Consumer:  "consumer-addr-1",
		Timestamp: now,
	}

	if !n.allowMarketplaceRequest(req) {
		t.Fatalf("expected valid first request to be allowed")
	}
}

func TestAllowMarketplaceRequest_DuplicateID(t *testing.T) {
	n := &Node{}
	now := core.Now().UnixNano()

	req := &xenet.ResourceRequest{
		RequestID: "req-002",
		Consumer:  "consumer-addr-1",
		Timestamp: now,
	}

	if !n.allowMarketplaceRequest(req) {
		t.Fatalf("expected first request to be allowed")
	}

	// Immediate duplicate RequestID must be rejected
	if n.allowMarketplaceRequest(req) {
		t.Fatalf("expected duplicate RequestID to be rejected")
	}

	// Re-signed request with same RequestID but newer timestamp must also be rejected
	reqNewTimestamp := &xenet.ResourceRequest{
		RequestID: "req-002",
		Consumer:  "consumer-addr-1",
		Timestamp: now + int64(time.Second),
	}
	if n.allowMarketplaceRequest(reqNewTimestamp) {
		t.Fatalf("expected re-signed duplicate RequestID to be rejected")
	}
}

func TestAllowMarketplaceRequest_ConsumerRateLimit(t *testing.T) {
	n := &Node{}
	now := core.Now().UnixNano()
	consumer := "consumer-rate-test"

	// Issue 10 requests from same consumer with distinct RequestIDs
	for i := 0; i < maxMarketRequestsPerMinute; i++ {
		req := &xenet.ResourceRequest{
			RequestID: fmt.Sprintf("req-burst-%d", i),
			Consumer:  consumer,
			Timestamp: now,
		}
		if !n.allowMarketplaceRequest(req) {
			t.Fatalf("expected request %d within rate limit to be allowed", i)
		}
	}

	// 11th request from same consumer within the same minute must be rejected
	req11 := &xenet.ResourceRequest{
		RequestID: "req-burst-11",
		Consumer:  consumer,
		Timestamp: now,
	}
	if n.allowMarketplaceRequest(req11) {
		t.Fatalf("expected 11th request to be rejected by consumer rate limiter")
	}

	// But a request from another consumer must be allowed
	otherReq := &xenet.ResourceRequest{
		RequestID: "req-burst-other",
		Consumer:  "consumer-other",
		Timestamp: now,
	}
	if !n.allowMarketplaceRequest(otherReq) {
		t.Fatalf("expected other consumer to not be blocked by first consumer's rate limit")
	}
}

func TestAllowMarketplaceRequest_TimestampFreshness(t *testing.T) {
	n := &Node{}
	now := core.Now()

	// 15 minutes in the past
	staleReq := &xenet.ResourceRequest{
		RequestID: "req-stale",
		Consumer:  "consumer-1",
		Timestamp: now.Add(-15 * time.Minute).UnixNano(),
	}
	if n.allowMarketplaceRequest(staleReq) {
		t.Fatalf("expected stale timestamp request to be rejected")
	}

	// 15 minutes in the future
	futureReq := &xenet.ResourceRequest{
		RequestID: "req-future",
		Consumer:  "consumer-1",
		Timestamp: now.Add(15 * time.Minute).UnixNano(),
	}
	if n.allowMarketplaceRequest(futureReq) {
		t.Fatalf("expected future timestamp request to be rejected")
	}
}

func TestAllowMarketplaceRequest_Compaction(t *testing.T) {
	n := &Node{
		seenMarketReqs:    make(map[string]time.Time),
		consumerMarketReq: make(map[string][]time.Time),
	}
	past := time.Now().Add(-15 * time.Minute)

	// Seed expired entries
	for i := 0; i < 50; i++ {
		n.seenMarketReqs[fmt.Sprintf("old-%d", i)] = past
		n.consumerMarketReq[fmt.Sprintf("consumer-old-%d", i)] = []time.Time{past}
	}

	now := core.Now().UnixNano()
	freshReq := &xenet.ResourceRequest{
		RequestID: "fresh-req",
		Consumer:  "fresh-consumer",
		Timestamp: now,
	}

	if !n.allowMarketplaceRequest(freshReq) {
		t.Fatalf("expected fresh request to be allowed")
	}

	n.pruneSeenMarketReqsLocked(time.Now())
	n.pruneConsumerMarketReqsLocked(time.Now())

	if len(n.seenMarketReqs) != 1 {
		t.Errorf("expected 1 seen request after pruning, got %d", len(n.seenMarketReqs))
	}
	if len(n.consumerMarketReq) != 1 {
		t.Errorf("expected 1 consumer after pruning, got %d", len(n.consumerMarketReq))
	}
}
