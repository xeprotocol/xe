// Package metrics is the node's Prometheus surface (#841).
//
// Design rules, in priority order:
//
//   - It must make the SILENT failure modes loud. A node whose total delegated
//     vote weight is zero commits blocks forever and finalizes nothing
//     (core/quorum.go: a zero total weight returns no quorum result), spendable
//     balances go empty for everyone, and every naive "is the process up" check
//     stays green. xe_delegated_weight_micro_xe, xe_quorum_margin_ratio and
//     xe_finality_stall_seconds exist specifically so that condition alerts.
//   - It must not leak account-level data. Every series here is a network-wide
//     aggregate. No metric carries an account address, a representative
//     address, a block hash, a peer ID or a key as a label — /metrics is an
//     operator endpoint that may end up scraped from a shared network, and
//     per-account labels would be both a privacy leak and unbounded
//     cardinality.
//   - It must fail closed. Values that could not be computed are not reported
//     as zero-and-healthy; the readiness gauges report 0 (not ready) and the
//     scrape carries the stale-sample age so an alert can catch a sampler that
//     stopped.
//
// This package has no xe dependencies on purpose: core, net and node all
// record into it, so it must sit below all of them in the import graph.
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

// Registry holds the xe_* series. Runtime, process and libp2p collectors live
// on the default registry (client_golang and go-libp2p register there), and
// Handler gathers from both.
var Registry = prometheus.NewRegistry()

// QuorumRatio is the fraction of total delegated vote weight that must be
// backing a position for it to finalize on the fast path. It mirrors the
// consensus constant (67%) and is the reference point for
// xe_quorum_margin_ratio.
const QuorumRatio = 0.67

var (
	// ---- identity -------------------------------------------------------

	BuildInfo = newGaugeVec("xe_build_info",
		"Always 1; carries the node's version, network id and role as labels.",
		"version", "network_id", "role")

	// ---- liveness / readiness ------------------------------------------

	Healthy = newGauge("xe_healthy",
		"1 when GET /health reports live (the process is up and its internal sampler is running), 0 otherwise.")

	Ready = newGauge("xe_ready",
		"1 when GET /ready reports ready, 0 otherwise. Readiness asserts finality is actually advancing, not merely that the process is up.")

	ReadyCheck = newGaugeVec("xe_ready_check",
		"Per-check readiness result: 1 pass, 0 fail. Check names match the JSON body of GET /ready.",
		"check")

	SampleAge = newGauge("xe_sample_age_seconds",
		"Age of the newest observability sample. A rising value means the sampler goroutine is wedged and every gauge below is stale.")

	// ---- consensus: the ones that matter -------------------------------

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
		"active_representative_weight / delegated_weight - 0.67. Below 0 every position falls to the 10s stall fallback; at -0.17 (50% dead weight) finalization halts network-wide with no in-protocol recovery.")

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
		"Running total of representative vote-weight underflows. Any non-zero value means in-memory weight has diverged from the ledger and is feeding quorum math (#728).")

	// ---- ledger ---------------------------------------------------------

	Accounts = newGauge("xe_accounts_total", "Accounts known to this node's ledger.")

	Blocks = newGauge("xe_blocks_total", "Blocks held by this node's ledger.")

	PendingSends = newGauge("xe_pending_sends", "Unreceived sends across all accounts.")

	Supply = newGaugeVec("xe_supply_micro_units",
		"Circulating supply per asset in micro-units, as this node computes it (account balances plus in-flight sends).",
		"asset")

	// Representative eligibility (#832). The delegated-weight gauge above is
	// the quorum denominator; these say what the eligibility policy is doing
	// to it — including when it is not being enforced at all.
	IneligibleWeight = newGauge("xe_ineligible_weight_micro_xe",
		"Delegated vote weight the representative-eligibility policy is holding OUT of the quorum denominator (#832). Zero when unrestricted.")
	RepEligibilityRestricted = newGauge("xe_rep_eligibility_restricted",
		"1 when a representative-eligibility allowlist is actually in force, 0 when the denominator counts every representative (#832).")
	RepEligibilityFailedOpen = newGauge("xe_rep_eligibility_failed_open",
		"1 when a published sys.representatives allowlist matched ZERO delegated weight and is being IGNORED (#832). The policy is not being enforced; alert on it.")

	// Supply conservation, straight from the #837 auditor. A node whose own
	// books do not balance is a stronger and earlier signal than two nodes
	// disagreeing about a total, and both are worth alerting on.
	SupplyConserved = newGaugeVec("xe_supply_conserved",
		"1 when this node's supply identity balances for the asset, 0 when it does not (#837). Zero is a supply-conservation breach; page immediately.",
		"asset")
	SupplyDiscrepancy = newGaugeVec("xe_supply_discrepancy_micro_units",
		"Signed accounted-minus-created discrepancy in the supply identity, in micro-units (#837). Zero iff conserved.",
		"asset")

	FrontierFingerprint = newGauge("xe_frontier_fingerprint",
		"Numeric projection of the sha256 over this node's sorted account:frontier:block_count set. Nodes in agreement report an identical value; the documented health gate is frontier parity, not block count.")

	StoreSize = newGauge("xe_store_size_bytes", "On-disk size of the node's data directory.")

	// ---- p2p ------------------------------------------------------------

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
		"1 when this node holds a valid unexpired performance certificate, 0 otherwise. Providers without one cannot be leased from at all (#812).")
)

// ---- registration helpers ------------------------------------------------

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

// RegisterCounterFunc exposes an already-maintained monotonic total (for
// example net.DroppedBlocks) as a counter without duplicating the state.
//
// Re-registering the same name is a no-op rather than a panic. The registry is
// process-global while a node is not: the in-process test harness runs several
// nodes in one process, and an observability failure must never be the thing
// that crashes them.
func RegisterCounterFunc(name, help string, fn func() float64) {
	err := Registry.Register(prometheus.NewCounterFunc(
		prometheus.CounterOpts{Name: name, Help: help}, fn))
	var dup prometheus.AlreadyRegisteredError
	if err != nil && !errors.As(err, &dup) {
		panic(err)
	}
}

var preScrape atomic.Pointer[func()]

// SetPreScrape registers a cheap hook run at the start of every scrape.
//
// It exists because the time-derived series (sample age, finality stall) and
// the readiness gauges must not be refreshed by the background sampler alone.
// If the sampler wedges — which is one of the faults being watched for — every
// gauge it owns freezes at its last healthy value, and a frozen "ready=1" is
// indistinguishable from a live one. Recomputing the derived series against the
// wall clock at scrape time makes a wedged sampler show up as a climbing
// xe_sample_age_seconds and a readiness gauge that goes to 0, instead of a
// dashboard that quietly stops moving while claiming everything is fine.
func SetPreScrape(fn func()) { preScrape.Store(&fn) }

// Handler serves the Prometheus text exposition for both the xe_* registry and
// the default registry (Go runtime, process and libp2p collectors).
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

// ---- representative vote activity ---------------------------------------

// voteActivity tracks which representatives have been observed voting
// recently. It is what turns "weight exists" into "weight is actually
// participating": delegated weight that never votes still counts in the quorum
// denominator, so a chain can hold plenty of weight and still be unable to
// finalize anything.
//
// Bounded on both axes: entries older than the retention window are swept, and
// the map is hard-capped so a peer flooding distinct representative keys cannot
// grow it without limit.
type voteActivity struct {
	mu    sync.Mutex
	last  map[string]time.Time
	max   int
	nowFn func() time.Time
}

const maxTrackedReps = 8192

var activity = &voteActivity{last: make(map[string]time.Time), max: maxTrackedReps, nowFn: time.Now}

// RecordVote notes that a representative cast a vote this node accepted. rep is
// the representative's ADDRESS (see Vote.RepAccount), because the activity set
// is joined against the ledger's weight map, which delegation keys by address.
//
// Only the identity is kept. The weight a vote reports is advisory — it is not
// covered by the vote signature — so it must never stand in for the ledger's
// own figure. Keeping it here would only make it available to be used, and the
// one place it could be used is the quorum-margin computation, where believing
// a peer would turn a dead network into a healthy-looking dashboard.
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

// ActiveReps returns the set of representative addresses observed voting within
// window. Entries older than window are dropped.
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

// ResetVoteActivity clears the tracker. Tests only.
func ResetVoteActivity() {
	activity.mu.Lock()
	defer activity.mu.Unlock()
	activity.last = make(map[string]time.Time)
}

// ReadyCheckEvaluated reports, per readiness check, whether it could be
// assessed at all: 1 evaluated, 0 not evaluated. A check that is persistently
// unevaluated is its own alert — an unobservable gate protects nothing.
var ReadyCheckEvaluated = newGaugeVec("xe_ready_check_evaluated",
	"1 when the readiness check could be assessed, 0 when it could not. Alert on a check that stays unevaluated.",
	"check")

// ---- sync progress -------------------------------------------------------

var lastSyncOK atomic.Int64 // unix nanos of the last successful sync round

// RecordSyncRound notes the outcome of an outbound sync round.
func RecordSyncRound(ok bool) {
	if ok {
		SyncRounds.WithLabelValues("ok").Inc()
		lastSyncOK.Store(time.Now().UnixNano())
		return
	}
	SyncRounds.WithLabelValues("failed").Inc()
}

// LastSuccessfulSync returns when this node last completed a sync round with a
// peer, or the zero time if it never has.
func LastSuccessfulSync() time.Time {
	ns := lastSyncOK.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// ResetSyncProgress clears the sync-progress timestamp. Tests only.
func ResetSyncProgress() { lastSyncOK.Store(0) }

// Prometheus creates a labelled child series only on first use, so a counter
// that has not fired yet is absent from the exposition entirely — and an absent
// series is not zero, it is "no data": rate() returns nothing and an alert that
// should fire on silence never evaluates. Pre-creating the known label values
// means these series read 0 from the first scrape, so silence is visible as
// silence.
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

// InitReadyChecks pre-creates the readiness gauges for a known set of check
// names, in the failing-and-unevaluated state.
//
// Same reasoning as the counter children above, with sharper consequences: an
// alert written as `xe_ready_check == 0` cannot fire against a series that does
// not exist, so a node whose readiness evaluation never runs would be silently
// exempt from every readiness alert. Starting them at "not passing" means the
// default before any evidence arrives is failure, not silence.
func InitReadyChecks(names []string) {
	for _, n := range names {
		ReadyCheck.WithLabelValues(n).Set(0)
		ReadyCheckEvaluated.WithLabelValues(n).Set(0)
	}
}
