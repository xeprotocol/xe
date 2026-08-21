package core

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Supply conservation accounting (#837).
//
// XE is created only by the genesis block and by lease_settle emission (S1), and
// destroyed only by burn blocks (S3). XUSD is created only by authorized mint
// blocks (S2) and destroyed only when a lease's escrow is burnt at settle or at
// #493 escrow expiry, or when a provider's stake is forfeited by absence (E3).
// Everything else — send, receive, cancel, force-settle, multisig — is
// supply-neutral. That closes into an exact per-asset identity:
//
//	balances + in_flight + locked_stake + burned + escrow_burned + stake_forfeited
//	  == genesis + minted + emitted
//
// which this file computes from the chains themselves rather than from a running
// tally, so a concurrent actor, a late-landing block or a restart cannot desync
// it. The block-movement table below is the same one soak-496/census.go derives
// and its test pins (scripts/soak-496/census_test.go); this is that reconciliation
// promoted out of the soak driver so every node can serve it continuously.
//
//	genesis             +Balance   (initial allocation, XE)
//	mint                +Amount    (XUSD; XE mints are rejected outright, S1)
//	send / receive       0         (balance <-> pending)
//	burn                -Amount    (XE only, S3)
//	lease                0         (consumer balance -> escrow pending)
//	lease_accept        -Amount    (XUSD stake leaves balances onto the lease
//	                                record: invisible to balances AND pending)
//	lease_settle        +Amount XE (emission, S4); +stake XUSD returned as a
//	                                side effect with NO block; -cost XUSD escrow
//	                                pending burnt
//	lease_cancel         0         (escrow pending deleted, consumer refunded)
//	lease_force_settle   0         (escrow refunded; the provider stake stays
//	                                burned-by-absence, already counted at accept)
//	multisig_*           0
//
// Because lease_settle returns the stake with no block, chain-derived balances
// are stale for XUSD after a settle. Observed balances therefore come from the
// ledger's per-asset balance map — the same source /accounts serves — and only
// the created/destroyed terms come from the block walk.
//
// PRIVACY: a SupplyReport is aggregate-only. It carries no addresses, no
// per-account amounts and nothing that identifies a holder, so it discloses
// strictly less than GET /accounts already does.

// AssetSupply is the conservation identity for a single asset, in micro-units.
// Both sides are reported so a client can check the identity in one request
// instead of re-deriving it.
type AssetSupply struct {
	// Created.
	Genesis uint64 `json:"genesis"` // genesis allocation
	Minted  uint64 `json:"minted"`  // authorized mint blocks (XUSD; S2)
	Emitted uint64 `json:"emitted"` // lease_settle emission (XE; S1/S4)
	Created uint64 `json:"created"` // genesis + minted + emitted

	// Destroyed.
	Burned         uint64 `json:"burned"`          // burn blocks (XE only; S3)
	EscrowBurned   uint64 `json:"escrow_burned"`   // escrow burnt at settle or #493 expiry
	StakeForfeited uint64 `json:"stake_forfeited"` // stake burned-by-absence (E3)
	Destroyed      uint64 `json:"destroyed"`       // burned + escrow_burned + stake_forfeited

	// Held off-balance: staked at accept, returned at settle. Neither a balance
	// nor a pending send, so a naive balances+pending sum under-counts by this.
	LockedStake uint64 `json:"locked_stake"`

	// Observed on this node right now.
	Balances uint64 `json:"balances"`  // sum of every account's balance
	InFlight uint64 `json:"in_flight"` // unreceived sends, including lease escrow
	Observed uint64 `json:"observed"`  // balances + in_flight

	// Identity.
	Accounted   uint64 `json:"accounted"`   // observed + locked_stake + destroyed
	Discrepancy int64  `json:"discrepancy"` // accounted - created; 0 iff conserved
	Conserved   bool   `json:"conserved"`   // accounted == created
}

// SupplyReport is the whole-network supply position as one node sees it.
type SupplyReport struct {
	// GenesisSupply is the XE total this build enforces as an exact equality on
	// every genesis block it loads (ValidateGenesisBlock). It is exported here so
	// clients have one authority for the figure instead of hardcoding a copy.
	GenesisSupply uint64 `json:"genesis_supply"`

	Assets map[string]*AssetSupply `json:"assets"`

	Accounts int `json:"accounts"`
	Blocks   int `json:"blocks"`
	Leases   int `json:"leases"`
	Pending  int `json:"pending"`

	// Conserved is the AND over every asset, and is false whenever any term
	// could not be computed. It never reports true on incomplete data.
	Conserved bool `json:"conserved"`

	// Notes carries every reason the report is not clean: an unplaceable stake,
	// an unknown asset, an arithmetic overflow. Empty on a healthy network.
	Notes []string `json:"notes"`

	// Stable reports whether the frontier set was identical before and after the
	// walk. All supply movement is block-driven, so an unchanged frontier set
	// means the walk saw one consistent instant. A false here means "retry",
	// NOT "pass" — a client that treats an unstable report as conclusive is
	// reading a torn snapshot.
	Stable   bool `json:"stable"`
	Attempts int  `json:"attempts"`

	ComputedAt int64 `json:"computed_at"` // unix nanos
	DurationMs int64 `json:"duration_ms"`
}

// chainTerms is one account chain's contribution to the created/destroyed terms.
// Cached by frontier hash so an unchanged chain is never re-walked: every block
// commits to its predecessor, so a frontier hash determines the whole chain
// prefix behind it — including after a rollback back to an earlier frontier.
type chainTerms struct {
	frontier   string
	blockCount int

	genesis map[string]uint64 // asset -> genesis allocation
	minted  map[string]uint64 // asset -> minted
	burned  map[string]uint64 // asset -> burned

	leaseCost      map[string]uint64 // lease hash -> escrowed cost (consumer chain)
	acceptStake    map[string]uint64 // lease hash -> stake (provider chain)
	settleEmission map[string]uint64 // lease hash -> XE emission (provider chain)

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
		// Every accepted block carries a validated asset (ledger.go rejects an
		// empty or unlisted one), so an unknown asset here means the store holds
		// something the ledger would not have accepted. Record it rather than
		// bucketing it as XE — a silently mis-bucketed amount is exactly the
		// class of error this file exists to catch.
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
			// send, receive, lease_cancel, lease_force_settle, multisig_* are
			// supply-neutral (see the table above).
		}
	}
	return c
}

const (
	// supplyMaxAttempts bounds the re-walk when the frontier set moves under the
	// walk. A busy network can genuinely lose the race; a report that never
	// stabilises is reported as unstable rather than retried forever.
	supplyMaxAttempts = 3

	// supplyCacheTTL bounds how often a full walk runs. The walk is O(blocks) on
	// a cold cache, so an unthrottled public endpoint would be a cheap way to
	// make a node do unbounded work.
	supplyCacheTTL = 2 * time.Second
)

// SupplyAuditor computes SupplyReports over a ledger, caching per-chain terms so
// the steady-state cost is proportional to what changed rather than to the size
// of the lattice.
type SupplyAuditor struct {
	l *Ledger

	mu     sync.Mutex
	cache  map[string]*chainTerms
	last   *SupplyReport
	lastAt time.Time
	ttl    time.Duration
}

// NewSupplyAuditor returns an auditor over l.
func NewSupplyAuditor(l *Ledger) *SupplyAuditor {
	return &SupplyAuditor{l: l, cache: map[string]*chainTerms{}, ttl: supplyCacheTTL}
}

// SetCacheTTL overrides how long a computed report is reused. Zero disables
// reuse entirely, which is what a test that mutates the ledger between reads
// wants. Not for production tuning — the default exists to stop an unthrottled
// caller making a node re-walk the lattice.
func (s *SupplyAuditor) SetCacheTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = d
}

// Report returns the current supply position, reusing a report younger than the
// cache TTL. Never returns nil.
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

// compute walks the lattice and reconciles both sides of the identity. Caller
// holds s.mu.
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
			// The chain moved between the frontier snapshot and the fetch. The
			// terms are internally consistent but no longer match the snapshot.
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

		// Observed balances come from the ledger's per-asset map, not from the
		// chain: lease_settle returns the provider's stake with no block, so the
		// chain tail is stale for XUSD after a settle.
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

	// Join the lease lifecycle across chains. Emission is XE; cost and stake are
	// XUSD, which the lease blocks themselves already asserted.
	for h, em := range emissions {
		add(&get(AssetXE.Symbol).Emitted, em)
		// A settle burns the escrowed cost. The cost is read from the consumer's
		// lease block, so a settle whose lease is not in the census cannot be
		// reconciled and must not be silently dropped.
		if cost, ok := costs[h]; ok {
			add(&get(AssetXUSD.Symbol).EscrowBurned, cost)
		} else {
			rep.Notes = append(rep.Notes, fmt.Sprintf("settle for lease %s has no lease block in the census; escrow unaccounted", shortHash(h)))
			rep.Conserved = false
		}
	}

	// Classify every accept stake that no settle returned. A stake on a live
	// accepted lease is held (returnable); on any terminal lease it is forfeited
	// (destroyed). The split needs the lease record, which is derived state — so
	// a missing record is reported, never guessed.
	leases := s.allLeases()
	rep.Leases = len(leases)
	byHash := make(map[string]*Lease, len(leases))
	for _, l := range leases {
		byHash[l.LeaseHash] = l
	}
	unplaceable := make([]string, 0)
	for h, st := range stakes {
		if _, settled := emissions[h]; settled {
			continue // returned to the provider at settle
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

	// #493: an abandoned lease's escrow is deleted by a local sweep with no
	// block, so the burn has to come off the lease record.
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
	// An unstable walk is a torn read: the terms and the balances came from
	// different instants, so the identity carries no information either way.
	if !rep.Stable {
		rep.Conserved = false
		rep.Notes = append(rep.Notes, "frontier set moved during the walk; the snapshot is torn and the identity was not evaluated")
	}
	return rep
}

// allLeases returns every lease record, or nil if the store cannot hold leases
// (a memory store in a test with no lease support).
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

// sumU64 adds without wrapping, flagging overflow instead.
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

// signedDelta returns a-b clamped to int64, so a corrupt total cannot make the
// discrepancy field itself wrap and read as zero.
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
