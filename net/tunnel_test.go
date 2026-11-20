package net

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

type dummyCloser struct {
	closed bool
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return nil
}

func TestTunnelRegistry_MaxTunnelsPerLease(t *testing.T) {
	r := NewTunnelRegistry()
	leaseHash := strings.Repeat("ee", 32)

	closers := make([]io.Closer, MaxTunnelsPerLease)
	for i := 0; i < MaxTunnelsPerLease; i++ {
		closers[i] = &dummyCloser{}
		if !r.add(leaseHash, closers[i]) {
			t.Fatalf("failed to add tunnel %d within cap", i)
		}
	}

	// 17th tunnel should exceed cap and be rejected
	overflowCloser := &dummyCloser{}
	if r.add(leaseHash, overflowCloser) {
		t.Fatalf("expected 17th tunnel to be rejected by MaxTunnelsPerLease cap")
	}

	// Remove one tunnel
	r.remove(leaseHash, closers[0])

	// Now adding one more should succeed
	if !r.add(leaseHash, overflowCloser) {
		t.Fatalf("expected adding tunnel after removal to succeed")
	}

	// Close all tunnels for lease
	r.CloseTunnelsForLease(leaseHash)

	r.mu.Lock()
	count := len(r.tunnels[leaseHash])
	r.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 tunnels after CloseTunnelsForLease, got %d", count)
	}

	// Verify closers were actually closed
	if !overflowCloser.closed {
		t.Fatalf("expected closer to be closed by CloseTunnelsForLease")
	}
}

func TestTunnelRegistry_MultipleLeasesIndependent(t *testing.T) {
	r := NewTunnelRegistry()
	lease1 := strings.Repeat("11", 32)
	lease2 := strings.Repeat("22", 32)

	for i := 0; i < MaxTunnelsPerLease; i++ {
		_ = r.add(lease1, &dummyCloser{})
		_ = r.add(lease2, &dummyCloser{})
	}

	// Both should be at capacity
	if r.add(lease1, &dummyCloser{}) {
		t.Fatalf("lease1 should be full")
	}
	if r.add(lease2, &dummyCloser{}) {
		t.Fatalf("lease2 should be full")
	}

	// Closing lease1 should not affect lease2
	r.CloseTunnelsForLease(lease1)

	r.mu.Lock()
	l1Count := len(r.tunnels[lease1])
	l2Count := len(r.tunnels[lease2])
	r.mu.Unlock()

	if l1Count != 0 {
		t.Fatalf("expected lease1 to be empty, got %d", l1Count)
	}
	if l2Count != MaxTunnelsPerLease {
		t.Fatalf("expected lease2 to retain %d tunnels, got %d", MaxTunnelsPerLease, l2Count)
	}
	_ = fmt.Sprintf("ok")
}
