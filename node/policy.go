package node

import (
	"fmt"
	"math"

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
	maxUnits := math.MaxUint64 / core.AssetXUSD.UnitsPerToken
	if p.MinCostXUSD > maxUnits {
		return fmt.Errorf("min-lease-cost (%d) overflows uint64 micro-XUSD", p.MinCostXUSD)
	}
	if p.MaxCostXUSD > maxUnits {
		return fmt.Errorf("max-lease-cost (%d) overflows uint64 micro-XUSD", p.MaxCostXUSD)
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
	if p.MinCostXUSD > 0 {
		var minMicro uint64
		if p.MinCostXUSD > math.MaxUint64/core.AssetXUSD.UnitsPerToken {
			minMicro = math.MaxUint64
		} else {
			minMicro = p.MinCostXUSD * core.AssetXUSD.UnitsPerToken
		}
		if b.Amount < minMicro {
			return fmt.Errorf("cost %s XUSD < policy min %d XUSD", core.FormatAmount(b.Amount, core.AssetXUSD), p.MinCostXUSD)
		}
	}
	if p.MaxCostXUSD > 0 {
		var maxMicro uint64
		if p.MaxCostXUSD > math.MaxUint64/core.AssetXUSD.UnitsPerToken {
			maxMicro = math.MaxUint64
		} else {
			maxMicro = p.MaxCostXUSD * core.AssetXUSD.UnitsPerToken
		}
		if b.Amount > maxMicro {
			return fmt.Errorf("cost %s XUSD > policy max %d XUSD", core.FormatAmount(b.Amount, core.AssetXUSD), p.MaxCostXUSD)
		}
	}
	if p.MaxConcurrent > 0 && activeCount >= p.MaxConcurrent {
		return fmt.Errorf("active leases %d ≥ policy cap %d", activeCount, p.MaxConcurrent)
	}
	return nil
}
