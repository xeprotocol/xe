package node

import (
	"fmt"

	"github.com/xeprotocol/xe/core"
)

type LeaseAcceptPolicy struct {
	MinDurationSec uint64
	MaxDurationSec uint64
	MinCostXUSD    uint64
	MaxCostXUSD    uint64
	MaxConcurrent  uint64
}

func (p LeaseAcceptPolicy) Validate() error {
	if p.MinDurationSec > 0 && p.MaxDurationSec > 0 && p.MinDurationSec > p.MaxDurationSec {
		return fmt.Errorf("min-lease-duration (%ds) must be ≤ max-lease-duration (%ds)", p.MinDurationSec, p.MaxDurationSec)
	}
	if p.MinCostXUSD > 0 && p.MaxCostXUSD > 0 && p.MinCostXUSD > p.MaxCostXUSD {
		return fmt.Errorf("min-lease-cost (%d) must be ≤ max-lease-cost (%d)", p.MinCostXUSD, p.MaxCostXUSD)
	}
	return nil
}

func (p LeaseAcceptPolicy) IsZero() bool {
	return p.MinDurationSec == 0 && p.MaxDurationSec == 0 &&
		p.MinCostXUSD == 0 && p.MaxCostXUSD == 0 &&
		p.MaxConcurrent == 0
}

func (p LeaseAcceptPolicy) Allow(b *core.Block, activeCount uint64) error {
	if p.MinDurationSec > 0 && b.Duration < p.MinDurationSec {
		return fmt.Errorf("duration %ds < policy min %ds", b.Duration, p.MinDurationSec)
	}
	if p.MaxDurationSec > 0 && b.Duration > p.MaxDurationSec {
		return fmt.Errorf("duration %ds > policy max %ds", b.Duration, p.MaxDurationSec)
	}
	if p.MinCostXUSD > 0 && b.Amount < p.MinCostXUSD {
		return fmt.Errorf("cost %d XUSD < policy min %d XUSD", b.Amount, p.MinCostXUSD)
	}
	if p.MaxCostXUSD > 0 && b.Amount > p.MaxCostXUSD {
		return fmt.Errorf("cost %d XUSD > policy max %d XUSD", b.Amount, p.MaxCostXUSD)
	}
	if p.MaxConcurrent > 0 && activeCount >= p.MaxConcurrent {
		return fmt.Errorf("active leases %d ≥ policy cap %d", activeCount, p.MaxConcurrent)
	}
	return nil
}

// AllowRenewal checks whether a lease_renew block, when applied to the existing lease,
// satisfies the provider's duration and cost policy caps on the cumulative lease (#162).

func safeAdd(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

// AllowRenewal checks whether a lease_renew block, when applied to the existing lease,
// satisfies the provider's duration and cost policy caps on the cumulative lease (#162).
func (p LeaseAcceptPolicy) AllowRenewal(lease *core.Lease, renewBlock *core.Block) error {
	if p.IsZero() {
		return nil
	}
	if lease == nil {
		return fmt.Errorf("lease is nil")
	}
	if renewBlock == nil {
		return fmt.Errorf("renew block is nil")
	}

	// Safe cumulative duration check with overflow defense
	cumDuration, ok := safeAdd(lease.EffectiveDurationSecs(), renewBlock.Duration)
	if !ok {
		return fmt.Errorf("cumulative duration overflow: %d + %d", lease.EffectiveDurationSecs(), renewBlock.Duration)
	}
	if p.MaxDurationSec > 0 && cumDuration > p.MaxDurationSec {
		return fmt.Errorf("cumulative duration %ds > policy max %ds", cumDuration, p.MaxDurationSec)
	}

	// Safe cumulative cost check with overflow defense
	cumCost, ok := safeAdd(lease.Cost, renewBlock.Amount)
	if !ok {
		return fmt.Errorf("cumulative cost overflow: %d + %d", lease.Cost, renewBlock.Amount)
	}
	for _, r := range lease.Renewals {
		cumCost, ok = safeAdd(cumCost, r.Cost)
		if !ok {
			return fmt.Errorf("cumulative cost overflow on renewal segment")
		}
	}
	if p.MaxCostXUSD > 0 && cumCost > p.MaxCostXUSD {
		return fmt.Errorf("cumulative cost %d XUSD > policy max %d XUSD", cumCost, p.MaxCostXUSD)
	}

	return nil
}
