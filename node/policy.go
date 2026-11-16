package node

import (
	"fmt"

	"github.com/xeprotocol/xe/core"
)

type LeaseAcceptPolicy struct {
	MinDurationSec uint64
	MaxDurationSec uint64
	MinCostXCU     uint64
	MaxCostXCU     uint64
	MaxConcurrent  uint64
}

func (p LeaseAcceptPolicy) Validate() error {
	if p.MinDurationSec > 0 && p.MaxDurationSec > 0 && p.MinDurationSec > p.MaxDurationSec {
		return fmt.Errorf("min-lease-duration (%ds) must be ≤ max-lease-duration (%ds)", p.MinDurationSec, p.MaxDurationSec)
	}
	if p.MinCostXCU > 0 && p.MaxCostXCU > 0 && p.MinCostXCU > p.MaxCostXCU {
		return fmt.Errorf("min-lease-cost (%d) must be ≤ max-lease-cost (%d)", p.MinCostXCU, p.MaxCostXCU)
	}
	return nil
}

func (p LeaseAcceptPolicy) IsZero() bool {
	return p.MinDurationSec == 0 && p.MaxDurationSec == 0 &&
		p.MinCostXCU == 0 && p.MaxCostXCU == 0 &&
		p.MaxConcurrent == 0
}

func (p LeaseAcceptPolicy) Allow(b *core.Block, activeCount uint64) error {
	if p.MinDurationSec > 0 && b.Duration < p.MinDurationSec {
		return fmt.Errorf("duration %ds < policy min %ds", b.Duration, p.MinDurationSec)
	}
	if p.MaxDurationSec > 0 && b.Duration > p.MaxDurationSec {
		return fmt.Errorf("duration %ds > policy max %ds", b.Duration, p.MaxDurationSec)
	}
	if p.MinCostXCU > 0 && b.Amount < p.MinCostXCU {
		return fmt.Errorf("cost %d XCU < policy min %d XCU", b.Amount, p.MinCostXCU)
	}
	if p.MaxCostXCU > 0 && b.Amount > p.MaxCostXCU {
		return fmt.Errorf("cost %d XCU > policy max %d XCU", b.Amount, p.MaxCostXCU)
	}
	if p.MaxConcurrent > 0 && activeCount >= p.MaxConcurrent {
		return fmt.Errorf("active leases %d ≥ policy cap %d", activeCount, p.MaxConcurrent)
	}
	return nil
}
