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

// AllowRenewal validates whether an incremental renewal of an existing lease
// satisfies the accept policy, ensuring that incremental duration and cost meet
// minimum requirements and that projected cumulative duration and total cost
// do not exceed policy maximum caps.
func (p LeaseAcceptPolicy) AllowRenewal(lease *core.Lease, additionalSecs, additionalCost uint64) error {
	if lease == nil {
		return fmt.Errorf("lease is nil")
	}
	if p.MinDurationSec > 0 && additionalSecs < p.MinDurationSec {
		return fmt.Errorf("duration %ds < policy min %ds", additionalSecs, p.MinDurationSec)
	}
	if p.MinCostXUSD > 0 && additionalCost < p.MinCostXUSD {
		return fmt.Errorf("cost %d XUSD < policy min %d XUSD", additionalCost, p.MinCostXUSD)
	}

	projectedDuration, ok := core.SafeAdd(lease.EffectiveDurationSecs(), additionalSecs)
	if !ok {
		return fmt.Errorf("cumulative duration overflow (%d + %d)", lease.EffectiveDurationSecs(), additionalSecs)
	}
	if p.MaxDurationSec > 0 && projectedDuration > p.MaxDurationSec {
		return fmt.Errorf("projected cumulative duration %ds > policy max %ds", projectedDuration, p.MaxDurationSec)
	}

	projectedCost, ok := core.SafeAdd(lease.TotalCost(), additionalCost)
	if !ok {
		return fmt.Errorf("cumulative cost overflow (%d + %d)", lease.TotalCost(), additionalCost)
	}
	if p.MaxCostXUSD > 0 && projectedCost > p.MaxCostXUSD {
		return fmt.Errorf("projected cumulative cost %d XUSD > policy max %d XUSD", projectedCost, p.MaxCostXUSD)
	}

	return nil
}

// AllowRenewalBlock validates whether the renewal block b for lease satisfies the accept policy.
func (p LeaseAcceptPolicy) AllowRenewalBlock(lease *core.Lease, b *core.Block) error {
	if b == nil {
		return fmt.Errorf("block is nil")
	}
	return p.AllowRenewal(lease, b.Duration, b.Amount)
}

// AllowProjected evaluates policy for either an initial lease block (core.BlockLease)
// or an incremental renewal block (core.BlockLeaseRenew) against an existing lease.
func (p LeaseAcceptPolicy) AllowProjected(b *core.Block, activeCount uint64, lease *core.Lease) error {
	if b == nil {
		return fmt.Errorf("block is nil")
	}
	if b.Type == core.BlockLeaseRenew {
		if lease == nil {
			return fmt.Errorf("lease required for renewal policy check")
		}
		return p.AllowRenewalBlock(lease, b)
	}
	return p.Allow(b, activeCount)
}
