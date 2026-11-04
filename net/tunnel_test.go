package net

import (
	"fmt"
	"sync"
	"testing"
)

type dummyCloser struct {
	mu     sync.Mutex
	closed bool
}

func (d *dummyCloser) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *dummyCloser) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func TestTunnelRegistryLimits(t *testing.T) {
	reg := NewTunnelRegistryWithLimits(3, 10)

	c1 := &dummyCloser{}
	c2 := &dummyCloser{}
	c3 := &dummyCloser{}
	c4 := &dummyCloser{}

	leaseHash := "lease1"

	if err := reg.Add(leaseHash, c1); err != nil {
		t.Fatalf("expected add c1 success, got %v", err)
	}
	if err := reg.Add(leaseHash, c2); err != nil {
		t.Fatalf("expected add c2 success, got %v", err)
	}
	if err := reg.Add(leaseHash, c3); err != nil {
		t.Fatalf("expected add c3 success, got %v", err)
	}

	if count := reg.CountForLease(leaseHash); count != 3 {
		t.Fatalf("expected 3 tunnels for lease, got %d", count)
	}
	if total := reg.TotalCount(); total != 3 {
		t.Fatalf("expected 3 total tunnels, got %d", total)
	}

	// 4th tunnel should exceed per-lease limit (3)
	if err := reg.Add(leaseHash, c4); err == nil {
		t.Fatalf("expected error exceeding lease limit, got nil")
	}

	// Remove c2
	reg.Remove(leaseHash, c2)
	if count := reg.CountForLease(leaseHash); count != 2 {
		t.Fatalf("expected 2 tunnels for lease after remove, got %d", count)
	}
	if total := reg.TotalCount(); total != 2 {
		t.Fatalf("expected 2 total tunnels after remove, got %d", total)
	}

	// Now c4 can be added
	if err := reg.Add(leaseHash, c4); err != nil {
		t.Fatalf("expected add c4 success after remove, got %v", err)
	}
	if count := reg.CountForLease(leaseHash); count != 3 {
		t.Fatalf("expected 3 tunnels for lease after re-add, got %d", count)
	}
}

func TestTunnelRegistryGlobalLimits(t *testing.T) {
	reg := NewTunnelRegistryWithLimits(5, 4)

	c1 := &dummyCloser{}
	c2 := &dummyCloser{}
	c3 := &dummyCloser{}
	c4 := &dummyCloser{}
	c5 := &dummyCloser{}

	if err := reg.Add("lease1", c1); err != nil {
		t.Fatalf("expected add c1 success, got %v", err)
	}
	if err := reg.Add("lease1", c2); err != nil {
		t.Fatalf("expected add c2 success, got %v", err)
	}
	if err := reg.Add("lease2", c3); err != nil {
		t.Fatalf("expected add c3 success, got %v", err)
	}
	if err := reg.Add("lease3", c4); err != nil {
		t.Fatalf("expected add c4 success, got %v", err)
	}

	if total := reg.TotalCount(); total != 4 {
		t.Fatalf("expected 4 total tunnels, got %d", total)
	}

	// 5th tunnel across leases exceeds global limit (4)
	if err := reg.Add("lease4", c5); err == nil {
		t.Fatalf("expected error exceeding global limit, got nil")
	}

	reg.Remove("lease2", c3)
	if total := reg.TotalCount(); total != 3 {
		t.Fatalf("expected 3 total tunnels after remove, got %d", total)
	}

	if err := reg.Add("lease4", c5); err != nil {
		t.Fatalf("expected add c5 success after room freed, got %v", err)
	}
}

func TestTunnelRegistryCloseTunnelsForLease(t *testing.T) {
	reg := NewTunnelRegistryWithLimits(5, 10)

	c1 := &dummyCloser{}
	c2 := &dummyCloser{}
	c3 := &dummyCloser{}

	_ = reg.Add("lease1", c1)
	_ = reg.Add("lease1", c2)
	_ = reg.Add("lease2", c3)

	if total := reg.TotalCount(); total != 3 {
		t.Fatalf("expected 3 total tunnels, got %d", total)
	}

	reg.CloseTunnelsForLease("lease1")

	if !c1.IsClosed() {
		t.Fatalf("expected c1 to be closed")
	}
	if !c2.IsClosed() {
		t.Fatalf("expected c2 to be closed")
	}
	if c3.IsClosed() {
		t.Fatalf("expected c3 for lease2 to remain open")
	}

	if count := reg.CountForLease("lease1"); count != 0 {
		t.Fatalf("expected 0 count for lease1, got %d", count)
	}
	if total := reg.TotalCount(); total != 1 {
		t.Fatalf("expected 1 total tunnel remaining, got %d", total)
	}

	// Redundant remove should be safe and not decrement total below 0
	reg.Remove("lease1", c1)
	if total := reg.TotalCount(); total != 1 {
		t.Fatalf("expected total to remain 1, got %d", total)
	}
}

func TestTunnelRegistryConcurrentRace(t *testing.T) {
	reg := NewTunnelRegistryWithLimits(10, 50)
	var wg sync.WaitGroup

	numGoroutines := 20
	iterations := 200

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			lease := fmt.Sprintf("lease-%d", gid%5)
			for i := 0; i < iterations; i++ {
				c := &dummyCloser{}
				if err := reg.Add(lease, c); err == nil {
					_ = reg.CountForLease(lease)
					_ = reg.TotalCount()
					if i%3 == 0 {
						reg.CloseTunnelsForLease(lease)
					} else {
						reg.Remove(lease, c)
					}
				}
			}
		}(g)
	}

	wg.Wait()

	if total := reg.TotalCount(); total < 0 {
		t.Fatalf("total tunnels negative after race: %d", total)
	}
}
