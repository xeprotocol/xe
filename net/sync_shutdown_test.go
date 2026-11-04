package net

import (
	"context"
	"testing"
	"time"
)

func TestSpawnGate_CloseAndTimeout(t *testing.T) {
	gate := &spawnGate{}

	// Verify spawning works
	ran := make(chan struct{})
	ok := gate.spawn(func() {
		close(ran)
	})
	if !ok {
		t.Fatalf("expected spawn to succeed")
	}

	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatalf("spawned function did not run")
	}

	// Verify gate.wait() terminates gracefully
	start := time.Now()
	gate.wait()
	if time.Since(start) > 2*time.Second {
		t.Fatalf("gate.wait took unexpectedly long: %v", time.Since(start))
	}

	// Once closed, new spawn must fail
	ok = gate.spawn(func() {})
	if ok {
		t.Fatalf("expected spawn to fail on closed gate")
	}
}

func TestRequestSync_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context immediately
	cancel()

	// Calling requestSync with an already-canceled context should fail fast without hanging
	err := requestSync(ctx, nil, "", nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error from cancelled context, got nil")
	}
}
