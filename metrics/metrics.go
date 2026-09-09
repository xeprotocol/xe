package metrics

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Registry = prometheus.NewRegistry()

const QuorumRatio = 0.67

var (
	BuildInfo = newGaugeVec("xe_build_info",
		"Always 1; carries the node's version, network id and role as labels.",
		"version", "network_id", "role")

	Healthy = newGauge("xe_healthy",
		"1 when GET /health reports live (the process is up and its internal sampler is running), 0 otherwise.")

	Ready = newGauge("xe_ready",
		"1 when GET /ready reports ready, 0 otherwise. Readiness asserts finality is actually advancing, not merely that the process is up.")

	ReadyCheck = newGaugeVec("xe_ready_check",
		"Per-check readiness result: 1 pass, 0 fail. Check names match the JSON body of GET /ready.",
		"check")

	SampleAge = newGauge("xe_sample_age_seconds",
		"Age of the newest observability sample. A rising value means the sampler goroutine is wedged and every gauge below is stale.")

	DelegatedWeight = newGauge("xe_delegated_weight_micro_xe",
		"Total delegated vote weight in micro-XE. ZERO MEANS FINALITY IS DEAD: blocks still commit, nothing ever finalizes, and no other signal changes.")

	DelegatedWeightRatio = newGauge("xe_delegated_weight_ratio",
		"Total delegated vote weight divided by circulating XE supply. Undelegated XE is excluded from the quorum denominator, so this is how much of the coin supply is actually backing consensus.")

	Representatives = newGauge("xe_representatives_total",
		"Number of representatives holding non-zero delegated weight.")

	ActiveRepresentatives = newGauge("xe_active_representatives_total",
		"Representatives observed casting a vote within the activity window.")

	ActiveWeight = newGauge("xe_active_representative_weight_micro_xe",
		"Delegated weight held by representatives observed voting within the activity window. Weight that never votes is dead weight in the quorum denominator.")

	QuorumMargin = newGauge("xe_quorum_margin_ratio",
		"active_representative_weight / delegated_weight - 0.67. Below 0 finalization halts network-wide: the 67% quorum is the only finalize path, with no in-protocol recovery short of a sys.representatives allowlist.")

	FinalityStall = newGauge("xe_finality_stall_seconds",
		"Seconds since the final-height watermark last advanced while unfinalized positions exist. 0 when there is no backlog to finalize.")

	UnfinalizedPositions = newGauge("xe_unfinalized_positions",
		"Account chains whose frontier height is above their final-height watermark.")

	FinalHeightSum = newGauge("xe_final_height_sum",
		"Sum of every account's final-height watermark. Monotonic on a healthy node; a flat line with a non-zero backlog is a finality stall.")

	Finalizations = newCounter("xe_finalizations_total",
		"Blocks finalized by this node since start.")

	FinalityLatency = newHistogram("xe_finality_latency_seconds",
		"Seconds from a block's timestamp to its finalization on this node.",
		[]float64{0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300})

	ConflictsOpen = newGauge("xe_conflicts_open",
		"Open (unresolved) conflicts across all accounts.")

	DelegationUnderflows = newGauge("xe_delegation_underflows",
		"Running total of representative vote-weight underflows. Any non-zero value means in-memory weight has diverged from the ledger and is feeding quorum math.")

	Accounts = newGauge("xe_accounts_total", "Accounts known to this node's ledger.")

	Blocks = newGauge("xe_blocks_total", "Blocks held by this node's ledger.")

	PendingSends = newGauge("xe_pending_sends", "Unreceived sends across all accounts.")

	Supply = newGaugeVec("xe_supply_micro_units",
		"Circulating supply per asset in micro-units, as this node computes it (account balances plus in-flight sends).",
		"asset")

	IneligibleWeight = newGauge("xe_ineligible_weight_micro_xe",
		"Delegated vote weight the representative-eligibility policy is holding OUT of the quorum denominator. Zero when unrestricted.")
	RepEligibilityRestricted = newGauge("xe_rep_eligibility_restricted",
		"1 when a representative-eligibility allowlist is actually in force, 0 when the denominator counts every representative.")
	RepEligibilityFailedOpen = newGauge("xe_rep_eligibility_failed_open",
		"1 when a published sys.representatives allowlist matched ZERO delegated weight and is being IGNORED. The policy is not being enforced; alert on it.")

	SupplyConserved = newGaugeVec("xe_supply_conserved",
		"1 when this node's supply identity balances for the asset, 0 when it does not. Zero is a supply-conservation breach; page immediately.",
		"asset")
	SupplyDiscrepancy = newGaugeVec("xe_supply_discrepancy_micro_units",
		"Signed accounted-minus-created discrepancy in the supply identity, in micro-units. Zero iff conserved.",
		"asset")

	FrontierFingerprint = newGauge("xe_frontier_fingerprint",
		"Numeric projection of the sha256 over this node's sorted account:frontier:block_count set. Nodes in agreement report an identical value; the documented health gate is frontier parity, not block count.")

	StoreSize = newGauge("xe_store_size_bytes", "On-disk size of the node's data directory.")

	PeerCount = newGauge("xe_peer_count", "Currently connected libp2p peers.")

	QuarantinedBlocks = newGauge("xe_quarantined_blocks",
		"Block hashes currently held in the sync quarantine. A node that starts quarantining blocks it cannot decode is how a chain split first shows up: there is no fork machinery, so an unknown block type hard-rejects and the account chain freezes (net/sync.go).")

	BlocksQuarantined = newCounter("xe_blocks_quarantined_total",
		"Blocks permanently rejected during sync and quarantined since start.")

	SyncRounds = newCounterVec("xe_sync_rounds_total",
		"Outbound sync rounds by outcome.", "result")

	VotesIngested = newCounterVec("xe_votes_ingested_total",
		"Votes received from peers by outcome.", "result")

	BlocksAdded = newCounterVec("xe_blocks_added_total",
		"Blocks accepted into the ledger by ingress path.", "source")

	CertificateValid = newGauge("xe_certificate_valid",
		"1 when this node holds a valid unexpired performance certificate, 0 otherwise. Providers without one cannot be leased from at all.")
)

func newGauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
	Registry.MustRegister(g)
	return g
}

func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
	Registry.MustRegister(g)
	return g
}

func newCounter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	Registry.MustRegister(c)
	return c
}

func newCounterVec(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
	Registry.MustRegister(c)
	return c
}

func RegisterCounterFunc(name, help string, fn func() float64) {
	err := Registry.Register(prometheus.NewCounterFunc(
		prometheus.CounterOpts{Name: name, Help: help}, fn))
	var dup prometheus.AlreadyRegisteredError
	if err != nil && !errors.As(err, &dup) {
		panic(err)
	}
}

var preScrape atomic.Pointer[func()]

func SetPreScrape(fn func()) { preScrape.Store(&fn) }

func Handler() http.Handler {
	inner := promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, Registry},
		promhttp.HandlerOpts{
			ErrorHandling:       promhttp.HTTPErrorOnError,
			MaxRequestsInFlight: 4,
			Timeout:             10 * time.Second,
		},
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fn := preScrape.Load(); fn != nil && *fn != nil {
			(*fn)()
		}
		inner.ServeHTTP(w, r)
	})
}

type voteActivity struct {
	mu    sync.Mutex
	last  map[string]time.Time
	max   int
	nowFn func() time.Time
}

const maxTrackedReps = 8192

var activity = &voteActivity{last: make(map[string]time.Time), max: maxTrackedReps, nowFn: time.Now}

func RecordVote(rep string) {
	if rep == "" {
		return
	}
	activity.mu.Lock()
	defer activity.mu.Unlock()
	if _, ok := activity.last[rep]; !ok && len(activity.last) >= activity.max {
		return
	}
	activity.last[rep] = activity.nowFn()
}

func ActiveReps(window time.Duration) map[string]struct{} {
	activity.mu.Lock()
	defer activity.mu.Unlock()
	cutoff := activity.nowFn().Add(-window)
	out := make(map[string]struct{}, len(activity.last))
	for rep, at := range activity.last {
		if at.Before(cutoff) {
			delete(activity.last, rep)
			continue
		}
		out[rep] = struct{}{}
	}
	return out
}

func ResetVoteActivity() {
	activity.mu.Lock()
	defer activity.mu.Unlock()
	activity.last = make(map[string]time.Time)
}

var ReadyCheckEvaluated = newGaugeVec("xe_ready_check_evaluated",
	"1 when the readiness check could be assessed, 0 when it could not. Alert on a check that stays unevaluated.",
	"check")

var lastSyncOK atomic.Int64

func RecordSyncRound(ok bool) {
	if ok {
		SyncRounds.WithLabelValues("ok").Inc()
		lastSyncOK.Store(time.Now().UnixNano())
		return
	}
	SyncRounds.WithLabelValues("failed").Inc()
}

func LastSuccessfulSync() time.Time {
	ns := lastSyncOK.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func ResetSyncProgress() { lastSyncOK.Store(0) }

func init() {
	for _, r := range []string{"accepted", "rejected"} {
		VotesIngested.WithLabelValues(r)
	}
	for _, r := range []string{"ok", "failed"} {
		SyncRounds.WithLabelValues(r)
	}
	for _, src := range []string{"gossip", "gossip_rejected", "sync"} {
		BlocksAdded.WithLabelValues(src)
	}
}

func InitReadyChecks(names []string) {
	for _, n := range names {
		ReadyCheck.WithLabelValues(n).Set(0)
		ReadyCheckEvaluated.WithLabelValues(n).Set(0)
	}
}
