package node

import (
	"fmt"

	"github.com/xeprotocol/xe/core"
)

// LeaseAcceptPolicy is a provider's local filter for incoming leases. Each
// field is a soft constraint applied before the stake/resource/cert gates in
// autoAcceptLease. A zero value means "no constraint" — the default policy is
// permissive, matching pre-#229 behaviour. See #229.
type LeaseAcceptPolicy struct {
	MinDurationSec uint64
	MaxDurationSec uint64
	MinCostXUSD    uint64
	MaxCostXUSD    uint64
	MaxConcurrent  uint64
}

// Validate fails fast on inverted ranges.
func (p LeaseAcceptPolicy) Validate() error {
	if p.MinDurationSec > 0 && p.MaxDurationSec > 0 && p.MinDurationSec > p.MaxDurationSec {
		return fmt.Errorf("min-lease-duration (%ds) must be ≤ max-lease-duration (%ds)", p.MinDurationSec, p.MaxDurationSec)
	}
	if p.MinCostXUSD > 0 && p.MaxCostXUSD > 0 && p.MinCostXUSD > p.MaxCostXUSD {
		return fmt.Errorf("min-lease-cost (%d) must be ≤ max-lease-cost (%d)", p.MinCostXUSD, p.MaxCostXUSD)
	}
	return nil
}

// IsZero reports whether the policy imposes any constraint.
func (p LeaseAcceptPolicy) IsZero() bool {
	return p.MinDurationSec == 0 && p.MaxDurationSec == 0 &&
		p.MinCostXUSD == 0 && p.MaxCostXUSD == 0 &&
		p.MaxConcurrent == 0
}

// Allow returns nil if the lease block satisfies every configured constraint,
// otherwise an error naming the first violated rule. activeCount is the number
// of leases this provider is currently running or provisioning, used only for
// the MaxConcurrent check.
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
