package node

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestAttestation_ConcurrentRateLimit(t *testing.T) {
	n := &Node{}
	ident := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	source := "http-client"

	const concurrentCallers = 10
	start := make(chan struct{})
	var wg sync.WaitGroup
	var passed atomic.Int32
	var rateLimited atomic.Int32

	wg.Add(concurrentCallers)
	for i := 0; i < concurrentCallers; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := n.allowAttestation(source, ident)
			if err == nil {
				passed.Add(1)
			} else {
				rateLimited.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if passed.Load() != 1 {
		t.Fatalf("expected exactly 1 concurrent caller to pass, got %d", passed.Load())
	}
	if rateLimited.Load() != concurrentCallers-1 {
		t.Fatalf("expected %d callers to be rate limited, got %d", concurrentCallers-1, rateLimited.Load())
	}
}

func TestAttestation_AcquireRollback(t *testing.T) {
	n := &Node{}
	ident := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	source := "client-1"

	// First acquire succeeds
	rollback, err := n.acquireAttestation(source, ident)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// Immediate second acquire fails
	_, err = n.acquireAttestation(source, ident)
	if err == nil {
		t.Fatalf("expected second acquire to be rate limited, got nil")
	}

	// Rollback first acquire
	rollback()

	// Third acquire now succeeds because slot was rolled back
	rollback2, err := n.acquireAttestation(source, ident)
	if err != nil {
		t.Fatalf("expected acquire after rollback to succeed, got: %v", err)
	}
	defer rollback2()
}

func TestAttestation_DifferentSourcesOrIdentifiers(t *testing.T) {
	n := &Node{}
	ident1 := "1111111111111111111111111111111111111111111111111111111111111111"
	ident2 := "2222222222222222222222222222222222222222222222222222222222222222"
	source1 := "source-1"
	source2 := "source-2"

	// Different identifier, same source: both succeed
	if err := n.allowAttestation(source1, ident1); err != nil {
		t.Fatalf("source1 ident1 failed: %v", err)
	}
	if err := n.allowAttestation(source1, ident2); err != nil {
		t.Fatalf("source1 ident2 failed: %v", err)
	}

	// Same identifier, different source: both succeed
	if err := n.allowAttestation(source2, ident1); err != nil {
		t.Fatalf("source2 ident1 failed: %v", err)
	}
}
