package node

import (
	"fmt"
	"testing"
	"time"

	xenet "github.com/xeprotocol/xe/net"
)

func TestAllowMarketplaceRequestDedupAndRateLimit(t *testing.T) {
	n := &Node{
		seenMarketReqs:   make(map[string]int64),
		consumerReqTimes: make(map[string][]int64),
	}
	now := time.Now().UnixNano()
	req := &xenet.ResourceRequest{
		Consumer:  "consumer-a",
		RequestID: "req-1",
		Timestamp: now,
	}

	if !n.allowMarketplaceRequest(req, now) {
		t.Fatalf("expected first request to be allowed")
	}
	if n.allowMarketplaceRequest(req, now+int64(time.Second)) {
		t.Fatalf("expected duplicate RequestID to be rejected within TTL")
	}

	for i := 2; i <= maxMarketReqsPerConsumerPerMin; i++ {
		r := &xenet.ResourceRequest{
			Consumer:  "consumer-a",
			RequestID: fmt.Sprintf("req-%d", i),
			Timestamp: now,
		}
		if !n.allowMarketplaceRequest(r, now+int64(i)) {
			t.Fatalf("expected request %d within rate limit to be allowed", i)
		}
	}

	over := &xenet.ResourceRequest{
		Consumer:  "consumer-a",
		RequestID: "req-over",
		Timestamp: now,
	}
	if n.allowMarketplaceRequest(over, now+100) {
		t.Fatalf("expected request exceeding per-consumer rate limit to be rejected")
	}
}
