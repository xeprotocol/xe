package node

import (
	"sync"
	"testing"
)

func TestSatSub(t *testing.T) {
	if got := satSub(10, 5); got != 5 {
		t.Fatalf("satSub(10, 5) = %d, want 5", got)
	}
	if got := satSub(5, 10); got != 0 {
		t.Fatalf("satSub(5, 10) = %d, want 0", got)
	}
	if got := satSub(5, 5); got != 0 {
		t.Fatalf("satSub(5, 5) = %d, want 0", got)
	}
}

func TestReservedStakeConcurrency(t *testing.T) {
	n := &Node{}
	const initialBalance uint64 = 1000
	const stakePerLease uint64 = 150
	const concurrentAttempts = 10

	var acceptedCount int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrentAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			n.reservedResMu.Lock()
			availStake := satSub(initialBalance, n.reservedStake)
			if availStake < stakePerLease {
				n.reservedResMu.Unlock()
				return
			}
			n.reservedStake += stakePerLease
			n.reservedResMu.Unlock()

			mu.Lock()
			acceptedCount++
			mu.Unlock()
		}()
	}
	wg.Wait()

	maxPossible := int(initialBalance / stakePerLease) // 6
	if acceptedCount > maxPossible {
		t.Fatalf("Oversubscribed! Accepted %d leases, but max possible was %d", acceptedCount, maxPossible)
	}
	if n.reservedStake != uint64(acceptedCount*int(stakePerLease)) {
		t.Fatalf("reservedStake mismatch: got %d, want %d", n.reservedStake, acceptedCount*int(stakePerLease))
	}
}
