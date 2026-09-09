package core

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

type AssetSupply struct {
	Genesis uint64 `json:"genesis"`
	Minted  uint64 `json:"minted"`
	Emitted uint64 `json:"emitted"`
	Created uint64 `json:"created"`

	Burned         uint64 `json:"burned"`
	EscrowBurned   uint64 `json:"escrow_burned"`
	StakeForfeited uint64 `json:"stake_forfeited"`
	Destroyed      uint64 `json:"destroyed"`

	LockedStake uint64 `json:"locked_stake"`

	Balances uint64 `json:"balances"`
	InFlight uint64 `json:"in_flight"`
	Observed uint64 `json:"observed"`

	Accounted   uint64 `json:"accounted"`
	Discrepancy int64  `json:"discrepancy"`
	Conserved   bool   `json:"conserved"`
}

type SupplyReport struct {
	GenesisSupply uint64 `json:"genesis_supply"`

	Assets map[string]*AssetSupply `json:"assets"`

	Accounts int `json:"accounts"`
	Blocks   int `json:"blocks"`
	Leases   int `json:"leases"`
	Pending  int `json:"pending"`

	Conserved bool `json:"conserved"`

	Notes []string `json:"notes"`

	Stable   bool `json:"stable"`
	Attempts int  `json:"attempts"`

	ComputedAt int64 `json:"computed_at"`
	DurationMs int64 `json:"duration_ms"`
}

type chainTerms struct {
	frontier   string
	blockCount int

	genesis map[string]uint64
	minted  map[string]uint64
	burned  map[string]uint64

	leaseCost      map[string]uint64
	acceptStake    map[string]uint64
	settleEmission map[string]uint64

	unknownAssets []string
}

func termsFromChain(blocks []*Block) *chainTerms {
	c := &chainTerms{
		blockCount:     len(blocks),
		genesis:        map[string]uint64{},
		minted:         map[string]uint64{},
		burned:         map[string]uint64{},
		leaseCost:      map[string]uint64{},
		acceptStake:    map[string]uint64{},
		settleEmission: map[string]uint64{},
	}
	if len(blocks) > 0 {
		c.frontier = blocks[len(blocks)-1].Hash
	}
	for _, b := range blocks {

		if !IsValidAsset(b.Asset) {
			c.unknownAssets = append(c.unknownAssets, fmt.Sprintf("%s %s asset=%q", b.Type, shortHash(b.Hash), b.Asset))
			continue
		}
		switch b.Type {
		case BlockGenesis:
			c.genesis[b.Asset] += b.Balance
		case BlockMint:
			c.minted[b.Asset] += b.Amount
		case BlockBurn:
			c.burned[b.Asset] += b.Amount
		case BlockLease:
			c.leaseCost[b.Hash] = b.Amount
		case BlockLeaseAccept:
			c.acceptStake[b.Source] = b.Amount
		case BlockLeaseSettle:
			c.settleEmission[b.Source] = b.Amount
		default:

		}
	}
	return c
}

const (
	supplyMaxAttempts = 3

	supplyCacheTTL = 2 * time.Second
)

type SupplyAuditor struct {
	l *Ledger

	mu     sync.Mutex
	cache  map[string]*chainTerms
	last   *SupplyReport
	lastAt time.Time
	ttl    time.Duration
}

func NewSupplyAuditor(l *Ledger) *SupplyAuditor {
	return &SupplyAuditor{l: l, cache: map[string]*chainTerms{}, ttl: supplyCacheTTL}
}

func (s *SupplyAuditor) SetCacheTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = d
}

func (s *SupplyAuditor) Report() *SupplyReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last != nil && time.Since(s.lastAt) < s.ttl {
		return s.last
	}
	rep := s.compute()
	s.last, s.lastAt = rep, time.Now()
	return rep
}

func (s *SupplyAuditor) compute() *SupplyReport {
	start := time.Now()
	var rep *SupplyReport
	for attempt := 1; attempt <= supplyMaxAttempts; attempt++ {
		rep = s.walk()
		rep.Attempts = attempt
		if rep.Stable {
			break
		}
	}
	rep.ComputedAt = time.Now().UnixNano()
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep
}

func (s *SupplyAuditor) walk() *SupplyReport {
	rep := &SupplyReport{
		GenesisSupply: GenesisSupply,
		Assets:        map[string]*AssetSupply{},
		Notes:         []string{},
		Stable:        true,
		Conserved:     true,
	}
	get := func(asset string) *AssetSupply {
		a := rep.Assets[asset]
		if a == nil {
			a = &AssetSupply{}
			rep.Assets[asset] = a
		}
		return a
	}
	var overflow bool
	add := func(dst *uint64, v uint64) {
		if *dst+v < *dst {
			overflow = true
			return
		}
		*dst += v
	}

	before := s.l.Frontiers()
	rep.Accounts = len(before)

	costs := map[string]uint64{}
	stakes := map[string]uint64{}
	emissions := map[string]uint64{}

	for account, frontier := range before {
		c := s.cache[account]
		if c == nil || c.frontier != frontier {
			chain := s.l.GetChain(account)
			c = termsFromChain(chain)

			if c.frontier != frontier {
				rep.Stable = false
			}
			s.cache[account] = c
		}
		rep.Blocks += c.blockCount
		for asset, v := range c.genesis {
			add(&get(asset).Genesis, v)
		}
		for asset, v := range c.minted {
			add(&get(asset).Minted, v)
		}
		for asset, v := range c.burned {
			add(&get(asset).Burned, v)
		}
		for h, v := range c.leaseCost {
			costs[h] = v
		}
		for h, v := range c.acceptStake {
			stakes[h] = v
		}
		for h, v := range c.settleEmission {
			emissions[h] = v
		}
		if len(c.unknownAssets) > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("account %s holds block(s) with an unsupported asset: %v", shortAddr(account), c.unknownAssets))
			rep.Conserved = false
		}

		for asset, v := range s.l.GetAssetBalances(account) {
			add(&get(asset).Balances, v)
		}
	}

	for _, p := range s.l.GetAllPending() {
		rep.Pending++
		if !IsValidAsset(p.Asset) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("pending send %s carries an unsupported asset %q", shortHash(p.SendHash), p.Asset))
			rep.Conserved = false
			continue
		}
		add(&get(p.Asset).InFlight, p.Amount)
	}

	for h, em := range emissions {
		add(&get(AssetXE.Symbol).Emitted, em)

		if cost, ok := costs[h]; ok {
			add(&get(AssetXUSD.Symbol).EscrowBurned, cost)
		} else {
			rep.Notes = append(rep.Notes, fmt.Sprintf("settle for lease %s has no lease block in the census; escrow unaccounted", shortHash(h)))
			rep.Conserved = false
		}
	}

	leases := s.allLeases()
	rep.Leases = len(leases)
	byHash := make(map[string]*Lease, len(leases))
	for _, l := range leases {
		byHash[l.LeaseHash] = l
	}
	unplaceable := make([]string, 0)
	for h, st := range stakes {
		if _, settled := emissions[h]; settled {
			continue
		}
		lease := byHash[h]
		switch {
		case lease == nil:
			unplaceable = append(unplaceable, shortHash(h))
			rep.Conserved = false
		case lease.State == LeaseAccepted && !lease.Settled:
			add(&get(AssetXUSD.Symbol).LockedStake, st)
		default:
			add(&get(AssetXUSD.Symbol).StakeForfeited, st)
		}
	}
	if len(unplaceable) > 0 {
		sort.Strings(unplaceable)
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d accept stake(s) have no lease record and cannot be classified: %v", len(unplaceable), unplaceable))
	}

	for _, l := range leases {
		if l.State == LeaseExpired {
			add(&get(AssetXUSD.Symbol).EscrowBurned, l.Cost)
		}
	}

	after := s.l.Frontiers()
	if len(after) != len(before) {
		rep.Stable = false
	} else {
		for account, frontier := range after {
			if before[account] != frontier {
				rep.Stable = false
				break
			}
		}
	}

	for _, a := range rep.Assets {
		a.Created = sumU64(&overflow, a.Genesis, a.Minted, a.Emitted)
		a.Destroyed = sumU64(&overflow, a.Burned, a.EscrowBurned, a.StakeForfeited)
		a.Observed = sumU64(&overflow, a.Balances, a.InFlight)
		a.Accounted = sumU64(&overflow, a.Observed, a.LockedStake, a.Destroyed)
		a.Conserved = a.Accounted == a.Created
		a.Discrepancy = signedDelta(a.Accounted, a.Created)
		if !a.Conserved {
			rep.Conserved = false
		}
	}
	if overflow {
		rep.Notes = append(rep.Notes, "supply arithmetic overflowed uint64; totals are not trustworthy")
		rep.Conserved = false
	}

	if !rep.Stable {
		rep.Conserved = false
		rep.Notes = append(rep.Notes, "frontier set moved during the walk; the snapshot is torn and the identity was not evaluated")
	}
	return rep
}

func (s *SupplyAuditor) allLeases() []*Lease {
	ls, ok := s.l.store.(LeaseStore)
	if !ok {
		return nil
	}
	leases, err := ls.GetAllLeases()
	if err != nil {
		return nil
	}
	return leases
}

func sumU64(overflow *bool, vs ...uint64) uint64 {
	var total uint64
	for _, v := range vs {
		if total+v < total {
			*overflow = true
			return math.MaxUint64
		}
		total += v
	}
	return total
}

func signedDelta(a, b uint64) int64 {
	if a >= b {
		if d := a - b; d <= math.MaxInt64 {
			return int64(d)
		}
		return math.MaxInt64
	}
	if d := b - a; d <= math.MaxInt64 {
		return -int64(d)
	}
	return math.MinInt64
}
