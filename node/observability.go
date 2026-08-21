package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/metrics"
	xenet "github.com/xeprotocol/xe/net"
)

// Observability: /health, /ready and the data behind /metrics (#841).
//
// The design constraint that shapes everything here is that this system's worst
// failure mode is SILENT. If total delegated vote weight reaches zero, blocks
// keep committing, votes keep flowing, peers stay connected, block count keeps
// climbing — and nothing ever finalizes again (core/quorum.go: a zero total
// weight yields no quorum result at all). SpendableBalances goes empty for
// every account on the network because spendable counts finalized inflows only.
// A liveness check that reports "the process is up" reports green throughout.
//
// So the two endpoints are deliberately NOT the same check at different
// strengths:
//
//	/health  liveness  — is this process alive and are its internal loops
//	                     running? It must NOT depend on peers or consensus,
//	                     because a supervisor that restarts a node for being
//	                     isolated or for waiting on quorum turns a network
//	                     problem into a crash loop.
//	/ready   readiness — is this node in a state where serving traffic gives a
//	                     correct answer? That requires finality to actually be
//	                     advancing: delegated weight present, quorum reachable,
//	                     no stalled backlog, synced, peered.
//
// Every readiness check fails CLOSED. A value that could not be computed is a
// failure, never an omission — a check that cannot see the thing it guards is
// exactly the case the gate exists for. The one deliberate exception is
// quorum_reachable, which is marked "not evaluated" (and exported as such) when
// there is genuinely nothing to observe; an alert covers prolonged
// unobservability so it cannot hide.

// ObsConfig configures the observability sampler and the readiness thresholds.
// The zero value is usable: Defaults fills everything in.
type ObsConfig struct {
	// SampleInterval is how often the background sampler refreshes the
	// snapshot behind /ready and /metrics.
	SampleInterval time.Duration
	// MinPeers is the connected-peer floor for readiness. Zero is a valid,
	// meaningful setting: it is the operator declaring this node standalone,
	// which also makes the sync check inapplicable rather than unevaluated.
	// Negative means "unset" and takes the default.
	MinPeers int
	// FinalityStallThreshold is how long the final-height watermark may stay
	// flat, while unfinalized positions exist, before readiness fails.
	FinalityStallThreshold time.Duration
	// VoteWindow is how recently a representative must have voted to count as
	// active weight.
	VoteWindow time.Duration
	// SyncStaleThreshold is how long since the last successful sync round
	// before readiness fails. The periodic resync forces a full round every
	// 60s, so this is three cycles.
	SyncStaleThreshold time.Duration
	// DataDir is used to report store size. Empty disables that metric.
	DataDir string
	// Role labels xe_build_info (for example "bootstrap", "provider").
	Role string
}

// Defaults returns cfg with unset fields filled in.
func (c ObsConfig) Defaults() ObsConfig {
	if c.SampleInterval <= 0 {
		c.SampleInterval = 15 * time.Second
	}
	if c.MinPeers < 0 {
		c.MinPeers = 1
	}
	if c.FinalityStallThreshold <= 0 {
		// The stall fallback fires at 10s; a healthy network finalizes well
		// inside a minute. 90s is comfortably past normal variance and well
		// short of an operator noticing by hand.
		c.FinalityStallThreshold = 90 * time.Second
	}
	if c.VoteWindow <= 0 {
		c.VoteWindow = 10 * time.Minute
	}
	if c.SyncStaleThreshold <= 0 {
		c.SyncStaleThreshold = 180 * time.Second
	}
	if c.Role == "" {
		c.Role = "node"
	}
	return c
}

// Snapshot is one pass of the sampler. Everything /ready and /metrics report is
// derived from it, so a stale snapshot is itself a failure signal rather than a
// set of quietly frozen gauges.
type Snapshot struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`

	Accounts      int `json:"accounts"`
	Blocks        int `json:"blocks"`
	PendingSends  int `json:"pending_sends"`
	ConflictsOpen int `json:"conflicts_open"`

	UnfinalizedPositions int       `json:"unfinalized_positions"`
	FinalHeightSum       uint64    `json:"final_height_sum"`
	FinalityAdvances     uint64    `json:"finality_advances"`
	LastFinalityAdvance  time.Time `json:"last_finality_advance"`

	DelegatedWeight       uint64  `json:"delegated_weight_micro_xe"`
	DelegatedWeightRatio  float64 `json:"delegated_weight_ratio"`
	Representatives       int     `json:"representatives"`
	ActiveRepresentatives int     `json:"active_representatives"`
	ActiveWeight          uint64  `json:"active_representative_weight_micro_xe"`
	QuorumMargin          float64 `json:"quorum_margin_ratio"`
	QuorumObservable      bool    `json:"quorum_observable"`
	DelegationUnderflows  uint64  `json:"delegation_underflows"`

	// Representative eligibility (#832). DelegatedWeight above is already the
	// quorum DENOMINATOR — Ledger.GetVoteWeights is the consensus view and
	// excludes representatives the policy holds out — so these three describe
	// what the policy is doing to it, which is otherwise invisible.
	IneligibleWeight      uint64 `json:"ineligible_weight_micro_xe"`
	EligibilityRestricted bool   `json:"rep_eligibility_restricted"`
	EligibilityFailedOpen bool   `json:"rep_eligibility_failed_open"`

	Supply              map[string]uint64 `json:"supply_micro_units"`
	SupplyConserved     map[string]bool   `json:"supply_conserved"`
	SupplyDiscrepancy   map[string]int64  `json:"supply_discrepancy_micro_units"`
	FrontierFingerprint string            `json:"frontier_fingerprint"`
	StoreSizeBytes      int64             `json:"store_size_bytes"`
	CertificateValid    bool              `json:"certificate_valid"`
}

// observer holds the sampler's cross-sample state.
type observer struct {
	cfg  ObsConfig
	node *Node

	snap atomic.Pointer[Snapshot]

	startedAt time.Time

	// peersFn and lastSyncFn override the two live inputs that do not come
	// from the snapshot. Set only by NewFixedObserver, which has no node to
	// read them from.
	peersFn    func() int
	lastSyncFn func() time.Time
}

// StartObservability launches the background sampler and returns the observer
// handle used by the /health and /ready handlers. It also registers the
// counter-func metrics that read totals the node already maintains.
//
// The sampler stops with the node's context.
//
// The Prometheus registry is process-global while a node is not, so in a
// process running several nodes (the in-process test harness) the xe_* gauges
// reflect whichever node sampled last. That is inherent to Prometheus and
// harmless in tests; a deployed node is one node per process. Calling this more
// than once is safe — registration is idempotent — but only the most recent
// observer drives the scrape-time refresh.
func (n *Node) StartObservability(cfg ObsConfig) *Observer {
	cfg = cfg.Defaults()
	o := &observer{cfg: cfg, node: n, startedAt: core.Now()}

	// Install the consensus-side finality hook. core deliberately does not
	// import the metrics package (see core.SetFinalityObserver), so this is
	// where the two are joined — on the observability side, which is the side
	// that is allowed to know about both.
	core.SetFinalityObserver(func(blocks uint64, winner *core.Block) {
		metrics.Finalizations.Add(float64(blocks))
		if winner == nil || winner.Timestamp <= 0 {
			return
		}
		if d := core.Now().UnixNano() - winner.Timestamp; d > 0 {
			metrics.FinalityLatency.Observe(float64(d) / float64(time.Second))
		}
	})

	metrics.BuildInfo.WithLabelValues(n.version, core.GetNetworkID(), cfg.Role).Set(1)
	metrics.InitReadyChecks(ReadyCheckNames)
	metrics.RegisterCounterFunc("xe_dropped_blocks_total",
		"Blocks shed from the gossip receive path because the receive channel was full (#731).",
		func() float64 { return float64(xenet.DroppedBlocks()) })
	// Read straight off the ledger's own counter (#833) rather than mirrored
	// through the snapshot: it is monotonic and already maintained, so a
	// CounterFunc is both cheaper and correctly typed for rate()/increase().
	metrics.RegisterCounterFunc("xe_finality_advances_total",
		"Times a per-account final-height watermark has advanced since this process started (#833). Flat forever means nothing is finalizing.",
		func() float64 { return float64(n.Ledger.FinalityAdvances()) })

	// Prime a snapshot synchronously so the very first probe after start has
	// something real to report rather than an unexplained empty body.
	o.sample()
	metrics.SetPreScrape(o.publishDerived)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		t := time.NewTicker(cfg.SampleInterval)
		defer t.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-t.C:
				o.sample()
			}
		}
	}()
	return &Observer{o: o}
}

// Observer is the read side of the observability sampler. It is what the API
// handler holds; it exposes only the report builders, never the node.
type Observer struct{ o *observer }

// Snapshot returns the most recent sample, or nil before the first one lands.
func (ob *Observer) Snapshot() *Snapshot { return ob.o.snap.Load() }

// Health builds the liveness report. See the package comment: liveness is
// deliberately independent of peers and of consensus.
func (ob *Observer) Health() *HealthReport { return ob.o.health() }

// Ready builds the readiness report.
func (ob *Observer) Ready() *ReadyReport { return ob.o.ready() }

// NewFixedObserver returns an Observer that serves the snapshot it is given
// instead of sampling a node. It does not start a sampler and never touches a
// ledger, so the snapshot it serves is exactly the one constructed here.
//
// It exists because the conditions this endpoint is FOR cannot all be produced
// by booting a cluster. Zero total delegated vote weight is the sharpest of
// them, and since #833 a node refuses to start on a genesis that names no
// representative — so the one arrangement that used to produce it for free is
// gone by design. Before that, this test inherited the condition from the
// committed core/genesis.json; when #866 seeded a representative there, the
// test would have had to be weakened to keep passing, and weakening the
// zero-weight assertion is precisely how the coverage disappears without anyone
// noticing. Constructing the condition explicitly removes that coupling: the
// test now says what it is testing instead of depending on a file to keep
// meaning what it used to mean.
//
// Everything downstream of the snapshot is real — the same evaluateReady, the
// same report types, served through the same HTTP handler and published to the
// same registry — so what is faked is the state of the world, not the logic
// under test.
func NewFixedObserver(cfg ObsConfig, snap *Snapshot, peers int, lastSync time.Time) *Observer {
	o := &observer{
		cfg:        cfg.Defaults(),
		startedAt:  core.Now().Add(-time.Hour),
		peersFn:    func() int { return peers },
		lastSyncFn: func() time.Time { return lastSync },
	}
	metrics.InitReadyChecks(ReadyCheckNames)
	if snap != nil {
		o.snap.Store(snap)
		o.publish(snap)
	}
	metrics.SetPreScrape(o.publishDerived)
	return &Observer{o: o}
}

// ---- sampling -----------------------------------------------------------

func (o *observer) sample() {
	now := core.Now()
	s := &Snapshot{
		At:                now,
		Supply:            map[string]uint64{},
		SupplyConserved:   map[string]bool{},
		SupplyDiscrepancy: map[string]int64{},
	}

	defer func() {
		// A panic in a sampling pass must not take the node down, but it must
		// not be invisible either: the snapshot is published carrying the
		// error, which fails both liveness (store_readable) and readiness.
		if r := recover(); r != nil {
			s.Error = fmt.Sprintf("sampler panic: %v", r)
			o.snap.Store(s)
			o.publish(s)
			logging.Errorf("observability: sampler panic: %v", r)
		}
	}()

	// Read the ledger in process, not through the paginated HTTP API. /accounts
	// and /frontiers clamp ?limit server-side (defaultPageLimit 100,
	// maxPageLimit 1000), so anything derived by walking those endpoints has to
	// paginate to completion or it silently reports a prefix of the account set
	// as if it were the whole network. Going direct removes that class of bug.
	accounts := o.node.GetAllAccounts()
	s.Accounts = len(accounts)

	lines := make([]string, 0, len(accounts))
	for _, a := range accounts {
		s.Blocks += a.BlockCount
		fh := o.node.Ledger.FinalHeight(a.Address)
		s.FinalHeightSum += fh
		if uint64(a.BlockCount) > fh {
			s.UnfinalizedPositions++
		}
		lines = append(lines, a.Address+":"+a.Frontier+":"+strconv.Itoa(a.BlockCount))
	}
	// Same canonical form the deploy runbook's frontier-parity gate uses:
	// sorted "account:frontier:block_count" lines, newline-joined, sha256,
	// first 16 hex digits.
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	s.FrontierFingerprint = hex.EncodeToString(sum[:])[:16]

	s.PendingSends = len(o.node.Ledger.GetAllPending())

	// Supply comes from the #837 auditor, which is the node's one supply
	// authority (core/supply.go, also behind GET /supply). Summing balances and
	// pending here would have been a fifth independent derivation of a figure
	// #848 exists to consolidate — and a worse one: the auditor also knows
	// about stake locked off-balance at lease_accept, which a naive
	// balances+in-flight sum silently omits.
	//
	// Observed (= balances + in_flight) is the series exported as
	// xe_supply_micro_units, because that is what the cross-node supply-
	// agreement alert compares. The conservation identity is exported
	// alongside it: a node whose own books do not balance is a strictly
	// stronger signal than two nodes disagreeing, and it costs nothing extra
	// now that the auditor has already computed it.
	for asset, a := range o.node.GetSupply().Assets {
		if a == nil {
			continue
		}
		s.Supply[asset] = a.Observed
		s.SupplyConserved[asset] = a.Conserved
		s.SupplyDiscrepancy[asset] = a.Discrepancy
	}

	s.ConflictsOpen = len(o.node.Ledger.GetAllConflicts())
	s.DelegationUnderflows = o.node.Ledger.DelegationUnderflows()

	// #832's eligibility gate can fail OPEN: an allowlist that matches zero
	// delegated weight is ignored and every representative counted again. That
	// is the right call — the alternative is halting finality — but a policy
	// silently not being enforced is exactly the class of thing this endpoint
	// exists to refuse to hide, and nothing else reports it.
	s.EligibilityRestricted = o.node.Ledger.RepEligibilityRestricted()
	s.EligibilityFailedOpen = o.node.Ledger.RepEligibilityFailedOpen()
	s.IneligibleWeight = clampBig(o.node.Ledger.GetIneligibleWeight())

	// ---- the weight picture --------------------------------------------
	weights := o.node.Ledger.GetVoteWeights()
	total := new(big.Int)
	for _, w := range weights {
		total.Add(total, new(big.Int).SetUint64(w))
		s.Representatives++
	}
	s.DelegatedWeight = clampBig(total)

	// Both sides of this join are keyed by representative ADDRESS: the weight
	// map by construction, the activity set because node.handleIncomingVotes
	// records Vote.RepAccount() rather than the key the vote carries (#829).
	// If that ever drifts apart again the join misses and ActiveWeight reads
	// zero — which fails CLOSED, and is the direction to fail in. There is
	// deliberately no fallback onto the weight a vote reports for itself: that
	// figure is not covered by the vote signature, and substituting it here is
	// exactly how a dead network comes to look reachable.
	active := metrics.ActiveReps(o.cfg.VoteWindow)
	s.ActiveRepresentatives = len(active)
	var activeWeight uint64
	for rep := range active {
		activeWeight = addSat(activeWeight, weights[rep])
	}
	s.ActiveWeight = activeWeight

	if s.DelegatedWeight > 0 {
		s.QuorumMargin = float64(s.ActiveWeight)/float64(s.DelegatedWeight) - metrics.QuorumRatio
	} else {
		// No weight at all: the margin is as bad as it can be. Reporting 0
		// here would read as "exactly at quorum" on a dashboard.
		s.QuorumMargin = -metrics.QuorumRatio
	}
	if xe := s.Supply[core.AssetXE.Symbol]; xe > 0 {
		s.DelegatedWeightRatio = float64(s.DelegatedWeight) / float64(xe)
	}

	// ---- finality progress ----------------------------------------------
	// Read from the ledger's own counters (#833), not inferred by watching
	// FinalHeightSum move between samples. The ledger records the advance at
	// the moment it happens, so it cannot miss one that lands and is undone
	// between two ticks, and it distinguishes "nothing has finalized since
	// startup" from "we have not looked yet" — which the inference could not,
	// because it had to seed itself with the current time and so reported a
	// node that had never finalized anything as having just finalized.
	s.FinalityAdvances = o.node.Ledger.FinalityAdvances()
	if ns := o.node.Ledger.LastFinalityNs(); ns > 0 {
		s.LastFinalityAdvance = time.Unix(0, ns)
	} else {
		// Nothing has finalized since this process started. The stall clock
		// therefore runs from startup, which is the honest reading: a node that
		// has never finalized anything has been stalled for its whole uptime.
		s.LastFinalityAdvance = o.startedAt
	}

	if cert := o.node.GetPerformanceCertificate(); cert != nil && cert.ExpiresAt > now.UnixNano() {
		s.CertificateValid = true
	}
	if o.cfg.DataDir != "" {
		s.StoreSizeBytes = dirSize(o.cfg.DataDir)
	}

	o.snap.Store(s)
	o.publish(s)
}

// boolGauge renders a boolean as the 0/1 a Prometheus gauge carries.
func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// publish pushes the snapshot into the Prometheus gauges. Readiness gauges are
// derived from the same report the endpoint serves, so /ready and the metric
// can never disagree.
func (o *observer) publish(s *Snapshot) {
	metrics.Accounts.Set(float64(s.Accounts))
	metrics.Blocks.Set(float64(s.Blocks))
	metrics.PendingSends.Set(float64(s.PendingSends))
	metrics.ConflictsOpen.Set(float64(s.ConflictsOpen))
	metrics.UnfinalizedPositions.Set(float64(s.UnfinalizedPositions))
	metrics.FinalHeightSum.Set(float64(s.FinalHeightSum))
	metrics.DelegatedWeight.Set(float64(s.DelegatedWeight))
	metrics.DelegatedWeightRatio.Set(s.DelegatedWeightRatio)
	metrics.Representatives.Set(float64(s.Representatives))
	metrics.ActiveRepresentatives.Set(float64(s.ActiveRepresentatives))
	metrics.ActiveWeight.Set(float64(s.ActiveWeight))
	metrics.QuorumMargin.Set(s.QuorumMargin)
	metrics.DelegationUnderflows.Set(float64(s.DelegationUnderflows))
	metrics.IneligibleWeight.Set(float64(s.IneligibleWeight))
	metrics.RepEligibilityRestricted.Set(boolGauge(s.EligibilityRestricted))
	metrics.RepEligibilityFailedOpen.Set(boolGauge(s.EligibilityFailedOpen))
	metrics.FrontierFingerprint.Set(fingerprintValue(s.FrontierFingerprint))
	metrics.StoreSize.Set(float64(s.StoreSizeBytes))
	metrics.PeerCount.Set(float64(o.peerCount()))
	for asset, v := range s.Supply {
		metrics.Supply.WithLabelValues(asset).Set(float64(v))
		metrics.SupplyConserved.WithLabelValues(asset).Set(boolGauge(s.SupplyConserved[asset]))
		metrics.SupplyDiscrepancy.WithLabelValues(asset).Set(float64(s.SupplyDiscrepancy[asset]))
	}
	if s.CertificateValid {
		metrics.CertificateValid.Set(1)
	} else {
		metrics.CertificateValid.Set(0)
	}

	o.publishDerived()
}

// publishDerived refreshes everything whose value depends on the current time
// rather than on the last sample: sample age, finality stall, and the health
// and readiness gauges. It runs both at the end of a sample AND at the start of
// every scrape (metrics.SetPreScrape).
//
// The scrape-time half is the important one. If the sampler goroutine wedges,
// every gauge it owns freezes — including a frozen xe_ready=1, which is
// indistinguishable from a genuinely ready node. Recomputing here against the
// wall clock means a wedged sampler shows as a climbing xe_sample_age_seconds
// and xe_ready dropping to 0, because sample_fresh and the liveness check both
// fail on age.
func (o *observer) publishDerived() {
	s := o.snap.Load()
	if s == nil {
		metrics.Healthy.Set(0)
		metrics.Ready.Set(0)
		return
	}
	now := core.Now()
	stall := 0.0
	if s.UnfinalizedPositions > 0 && !s.LastFinalityAdvance.IsZero() {
		stall = now.Sub(s.LastFinalityAdvance).Seconds()
	}
	metrics.FinalityStall.Set(stall)
	metrics.SampleAge.Set(now.Sub(s.At).Seconds())
	metrics.PeerCount.Set(float64(o.peerCount()))

	if o.health().OK {
		metrics.Healthy.Set(1)
	} else {
		metrics.Healthy.Set(0)
	}
	r := o.ready()
	if r.Ready {
		metrics.Ready.Set(1)
	} else {
		metrics.Ready.Set(0)
	}
	for _, c := range r.Checks {
		v := 0.0
		if c.OK {
			v = 1
		}
		metrics.ReadyCheck.WithLabelValues(c.Name).Set(v)
		ev := 1.0
		if !c.Evaluated {
			ev = 0
		}
		metrics.ReadyCheckEvaluated.WithLabelValues(c.Name).Set(ev)
	}
}

func (o *observer) lastSync() time.Time {
	if o.lastSyncFn != nil {
		return o.lastSyncFn()
	}
	return metrics.LastSuccessfulSync()
}

func (o *observer) peerCount() int {
	if o.peersFn != nil {
		return o.peersFn()
	}
	if o.node == nil || o.node.Host == nil {
		return 0
	}
	return len(o.node.Host.Network().Peers())
}

// ---- reports ------------------------------------------------------------

// Check is one named probe within a health or readiness report.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Evaluated is false when the check could not be assessed for a documented
	// reason. An unevaluated check does not fail the report, so it is exported
	// separately (xe_ready_check_evaluated) and alerted on: unobservability
	// must be visible, never silent.
	Evaluated bool   `json:"evaluated"`
	Detail    string `json:"detail,omitempty"`
}

func pass(name, detail string) Check { return Check{name, true, true, detail} }
func fail(name, detail string) Check { return Check{name, false, true, detail} }

// unevaluated marks a check that could not be assessed. Nothing uses it today
// and that is the point: every readiness check below answers in every state,
// because an unchecked invariant that reads like a passed one is exactly how a
// gate fails open. It exists so that a future check which genuinely cannot
// answer must say so out loud — the report keeps the flag, and
// xe_ready_check_evaluated alerts on it — rather than quietly returning pass.
func unevaluated(name, detail string) Check { return Check{name, false, false, detail} } //nolint:unused // contract marker; see comment

// HealthReport is the body of GET /health.
type HealthReport struct {
	Status        string  `json:"status"` // "ok" | "unhealthy"
	OK            bool    `json:"ok"`
	Version       string  `json:"version"`
	NetworkID     string  `json:"network_id,omitempty"`
	NodeID        string  `json:"node_id,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Checks        []Check `json:"checks"`
	// Note states in the response itself that health is not a network-health
	// signal, so nobody wires a dashboard to it and believes the chain is fine.
	Note string `json:"note"`
}

// ReadyReport is the body of GET /ready.
type ReadyReport struct {
	Status string  `json:"status"` // "ready" | "not_ready"
	Ready  bool    `json:"ready"`
	Checks []Check `json:"checks"`

	PeerCount             int     `json:"peer_count"`
	DelegatedWeight       uint64  `json:"delegated_weight_micro_xe"`
	ActiveWeight          uint64  `json:"active_representative_weight_micro_xe"`
	Representatives       int     `json:"representatives"`
	ActiveRepresentatives int     `json:"active_representatives"`
	QuorumMarginRatio     float64 `json:"quorum_margin_ratio"`
	FinalityStallSeconds  float64 `json:"finality_stall_seconds"`
	FinalityAdvances      uint64  `json:"finality_advances"`
	UnfinalizedPositions  int     `json:"unfinalized_positions"`
	ConflictsOpen         int     `json:"conflicts_open"`
	FrontierFingerprint   string  `json:"frontier_fingerprint,omitempty"`
	SampleAgeSeconds      float64 `json:"sample_age_seconds"`
}

const healthNote = "liveness only: this reports that the process is up and its internal sampler is running. " +
	"It says NOTHING about consensus — a node with zero delegated vote weight finalizes nothing and still reports healthy here. Use /ready for that."

// healthInputs is everything the liveness decision reads. Split out so the
// decision itself is a pure function and can be tested against every state,
// including the ones that are hard to stage on a live node.
type healthInputs struct {
	cfg       ObsConfig
	now       time.Time
	uptime    time.Duration
	snap      *Snapshot
	version   string
	networkID string
	nodeID    string
}

type readyInputs struct {
	cfg       ObsConfig
	now       time.Time
	uptime    time.Duration
	live      bool
	snap      *Snapshot
	peerCount int
	lastSync  time.Time
}

func (o *observer) health() *HealthReport {
	now := core.Now()
	in := healthInputs{
		cfg:       o.cfg,
		now:       now,
		uptime:    now.Sub(o.startedAt),
		snap:      o.snap.Load(),
		networkID: core.GetNetworkID(),
	}
	if o.node != nil {
		in.version = o.node.version
		if o.node.Host != nil {
			in.nodeID = o.node.Host.ID().String()
		}
	}
	return evaluateHealth(in)
}

func (o *observer) ready() *ReadyReport {
	now := core.Now()
	return evaluateReady(readyInputs{
		cfg:       o.cfg,
		now:       now,
		uptime:    now.Sub(o.startedAt),
		live:      o.health().OK,
		snap:      o.snap.Load(),
		peerCount: o.peerCount(),
		lastSync:  o.lastSync(),
	})
}

func evaluateHealth(in healthInputs) *HealthReport {
	r := &HealthReport{
		Version:       in.version,
		NetworkID:     in.networkID,
		NodeID:        in.nodeID,
		UptimeSeconds: in.uptime.Seconds(),
		Note:          healthNote,
	}
	r.Checks = append(r.Checks, pass("serving", "HTTP handler reached"))

	// StartObservability primes a snapshot synchronously before it returns, so
	// by the time anything can reach this handler a sample exists. Its absence
	// is therefore a real fault, not a warm-up state, and is treated as one.
	maxAge := 3 * in.cfg.SampleInterval
	if in.snap == nil {
		r.Checks = append(r.Checks, fail("sampler_alive", "no observability sample has ever been produced"))
		r.Checks = append(r.Checks, fail("store_readable", "no sample to read"))
	} else {
		age := in.now.Sub(in.snap.At)
		if age > maxAge {
			r.Checks = append(r.Checks, fail("sampler_alive",
				fmt.Sprintf("newest sample is %s old (max %s) — the node's internal loops are wedged or blocked on the ledger", age.Round(time.Second), maxAge)))
		} else {
			r.Checks = append(r.Checks, pass("sampler_alive", fmt.Sprintf("sample %s old", age.Round(time.Second))))
		}
		if in.snap.Error != "" {
			r.Checks = append(r.Checks, fail("store_readable", in.snap.Error))
		} else {
			r.Checks = append(r.Checks, pass("store_readable", ""))
		}
	}

	r.OK = allOK(r.Checks)
	r.Status = "ok"
	if !r.OK {
		r.Status = "unhealthy"
	}
	return r
}

func evaluateReady(in readyInputs) *ReadyReport {
	cfg, now, s := in.cfg, in.now, in.snap
	r := &ReadyReport{}

	if in.live {
		r.Checks = append(r.Checks, pass("live", ""))
	} else {
		r.Checks = append(r.Checks, fail("live", "liveness failing; see /health"))
	}

	if s == nil {
		// Fail closed. A node that has never sampled cannot assert anything
		// about finality, and "no data" must never read as ready.
		r.Checks = append(r.Checks, fail("sample_present", "no observability sample yet"))
		r.finish()
		return r
	}
	// Emitted on every path, not only the failing one: a check that appears
	// only when it fails leaves its gauge pinned at the pre-created 0 forever
	// on a healthy node, which would make `xe_ready_check == 0` alert
	// permanently and train operators to ignore it.
	r.Checks = append(r.Checks, pass("sample_present", ""))
	r.SampleAgeSeconds = now.Sub(s.At).Seconds()
	r.PeerCount = in.peerCount
	r.DelegatedWeight = s.DelegatedWeight
	r.ActiveWeight = s.ActiveWeight
	r.FinalityAdvances = s.FinalityAdvances
	r.Representatives = s.Representatives
	r.ActiveRepresentatives = s.ActiveRepresentatives
	r.QuorumMarginRatio = s.QuorumMargin
	r.UnfinalizedPositions = s.UnfinalizedPositions
	r.ConflictsOpen = s.ConflictsOpen
	r.FrontierFingerprint = s.FrontierFingerprint

	if maxAge := 3 * cfg.SampleInterval; now.Sub(s.At) > maxAge {
		r.Checks = append(r.Checks, fail("sample_fresh",
			fmt.Sprintf("sample %s old (max %s)", now.Sub(s.At).Round(time.Second), maxAge)))
	} else {
		r.Checks = append(r.Checks, pass("sample_fresh", ""))
	}

	// --- peers ---
	if r.PeerCount >= cfg.MinPeers {
		r.Checks = append(r.Checks, pass("peers", fmt.Sprintf("%d connected", r.PeerCount)))
	} else {
		r.Checks = append(r.Checks, fail("peers",
			fmt.Sprintf("%d connected, need %d", r.PeerCount, cfg.MinPeers)))
	}

	// --- sync ---
	// A node that has not completed a sync round is serving a view of the
	// lattice it has not reconciled with anyone. That is NOT ready, and it is
	// not a warm-up exemption either: holding traffic back during initial sync
	// is the entire purpose of a readiness gate.
	switch {
	case cfg.MinPeers == 0 && r.PeerCount == 0:
		// The operator has declared this node standalone (-ready-min-peers=0)
		// and it has no peers. There is no remote state to be behind, so the
		// check is answered, not waived.
		r.Checks = append(r.Checks, pass("synced", "standalone node (min-peers=0, no peers connected): no remote state to reconcile"))
	case in.lastSync.IsZero():
		r.Checks = append(r.Checks, fail("synced",
			fmt.Sprintf("no successful sync round in %s of uptime — this node has not reconciled its view of the lattice with any peer",
				in.uptime.Round(time.Second))))
	case now.Sub(in.lastSync) > cfg.SyncStaleThreshold:
		r.Checks = append(r.Checks, fail("synced",
			fmt.Sprintf("last successful sync %s ago (max %s)", now.Sub(in.lastSync).Round(time.Second), cfg.SyncStaleThreshold)))
	default:
		r.Checks = append(r.Checks, pass("synced", fmt.Sprintf("last sync %s ago", now.Sub(in.lastSync).Round(time.Second))))
	}

	// --- delegated weight: the #833 silent-death gate ---
	if s.DelegatedWeight == 0 {
		r.Checks = append(r.Checks, fail("delegated_weight",
			"total delegated vote weight is ZERO — no block on this network can ever finalize; spendable balances will read empty for every account. See runbook: quorum loss."))
	} else {
		r.Checks = append(r.Checks, pass("delegated_weight",
			fmt.Sprintf("%d micro-XE across %d representatives", s.DelegatedWeight, s.Representatives)))
	}

	// --- quorum participation ---
	// Phrased as "is finality blocked for want of participation", which is
	// answerable in every state — rather than "what is the live quorum margin",
	// which is not, and would have to be skipped on a quiet network. A skip
	// here would be the worst possible outcome: the one check that catches the
	// project's top fear, silently indistinguishable from a pass.
	//
	// A quiet network passes on direct evidence (nothing is waiting to
	// finalize), not on absence of evidence. A network with a backlog and no
	// votes fails — pending work plus silent representatives is precisely the
	// condition this gate exists for.
	switch {
	case s.DelegatedWeight == 0:
		r.Checks = append(r.Checks, fail("quorum_reachable", "no delegated weight to reach quorum with"))
	case s.UnfinalizedPositions == 0:
		r.Checks = append(r.Checks, pass("quorum_reachable",
			"no unfinalized backlog: nothing is blocked waiting for representative participation"))
	case s.ActiveRepresentatives == 0:
		r.Checks = append(r.Checks, fail("quorum_reachable",
			fmt.Sprintf("%d position(s) waiting to finalize and NO representative has voted in the last %s — participation is zero against a live backlog",
				s.UnfinalizedPositions, cfg.VoteWindow)))
	case s.QuorumMargin < 0:
		r.Checks = append(r.Checks, fail("quorum_reachable",
			fmt.Sprintf("only %.1f%% of delegated weight is voting (need %.0f%%); margin %.3f. Every position is falling to the stall fallback; at 50%% dead weight finalization halts network-wide.",
				100*(s.QuorumMargin+metrics.QuorumRatio), 100*metrics.QuorumRatio, s.QuorumMargin)))
	default:
		r.Checks = append(r.Checks, pass("quorum_reachable",
			fmt.Sprintf("margin %.3f above the %.0f%% threshold, %d/%d representatives voting",
				s.QuorumMargin, 100*metrics.QuorumRatio, s.ActiveRepresentatives, s.Representatives)))
	}

	// --- finality actually advancing ---
	stall := 0.0
	if s.UnfinalizedPositions > 0 && !s.LastFinalityAdvance.IsZero() {
		stall = now.Sub(s.LastFinalityAdvance).Seconds()
	}
	r.FinalityStallSeconds = stall
	switch {
	case s.UnfinalizedPositions == 0:
		r.Checks = append(r.Checks, pass("finality_advancing", "no unfinalized backlog"))
	case stall > cfg.FinalityStallThreshold.Seconds():
		r.Checks = append(r.Checks, fail("finality_advancing",
			fmt.Sprintf("%d unfinalized position(s) and the final-height watermark has not advanced for %.0fs (max %.0fs)",
				s.UnfinalizedPositions, stall, cfg.FinalityStallThreshold.Seconds())))
	default:
		r.Checks = append(r.Checks, pass("finality_advancing",
			fmt.Sprintf("%d unfinalized position(s), watermark advanced %.0fs ago", s.UnfinalizedPositions, stall)))
	}

	r.finish()
	return r
}

func (r *ReadyReport) finish() {
	r.Ready = allOK(r.Checks)
	r.Status = "ready"
	if !r.Ready {
		r.Status = "not_ready"
	}
}

// ReadyCheckNames is every check GET /ready can emit. It exists so the
// readiness gauges can be pre-created in the failing state before the first
// evaluation — an alert cannot fire against a series that does not exist.
// TestReadyCheckNamesAreComplete pins it against the evaluator so it cannot
// drift.
var ReadyCheckNames = []string{
	"live",
	"sample_present",
	"sample_fresh",
	"peers",
	"synced",
	"delegated_weight",
	"quorum_reachable",
	"finality_advancing",
}

func allOK(checks []Check) bool {
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}

// ---- small helpers ------------------------------------------------------

func clampBig(v *big.Int) uint64 {
	if v == nil || v.Sign() <= 0 {
		return 0
	}
	if !v.IsUint64() {
		return ^uint64(0)
	}
	return v.Uint64()
}

func addSat(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// fingerprintValue projects the frontier fingerprint onto a float64 that can
// hold it exactly (13 hex digits = 52 bits, the float64 mantissa). Prometheus
// has no string values, and putting the digest in a label would churn a new
// time series on every block. Comparing the number across nodes is exactly the
// frontier-parity gate the deploy runbook already mandates.
func fingerprintValue(fp string) float64 {
	if len(fp) < 13 {
		return 0
	}
	v, err := strconv.ParseUint(fp[:13], 16, 64)
	if err != nil {
		return 0
	}
	return float64(v)
}

func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort: a missing subtree must not fail the sample
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr
		}
		total += info.Size()
		return nil
	})
	return total
}
