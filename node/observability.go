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

type ObsConfig struct {
	SampleInterval time.Duration

	MinPeers int

	FinalityStallThreshold time.Duration

	VoteWindow time.Duration

	SyncStaleThreshold time.Duration

	DataDir string

	Role string
}

func (c ObsConfig) Defaults() ObsConfig {
	if c.SampleInterval <= 0 {
		c.SampleInterval = 15 * time.Second
	}
	if c.MinPeers < 0 {
		c.MinPeers = 1
	}
	if c.FinalityStallThreshold <= 0 {

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

type observer struct {
	cfg  ObsConfig
	node *Node

	snap atomic.Pointer[Snapshot]

	startedAt time.Time

	peersFn    func() int
	lastSyncFn func() time.Time
}

func (n *Node) StartObservability(cfg ObsConfig) *Observer {
	cfg = cfg.Defaults()
	o := &observer{cfg: cfg, node: n, startedAt: core.Now()}

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
		"Blocks shed from the gossip receive path because the receive channel was full.",
		func() float64 { return float64(xenet.DroppedBlocks()) })

	metrics.RegisterCounterFunc("xe_finality_advances_total",
		"Times a per-account final-height watermark has advanced since this process started. Flat forever means nothing is finalizing.",
		func() float64 { return float64(n.Ledger.FinalityAdvances()) })

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

type Observer struct{ o *observer }

func (ob *Observer) Snapshot() *Snapshot { return ob.o.snap.Load() }

func (ob *Observer) Health() *HealthReport { return ob.o.health() }

func (ob *Observer) Ready() *ReadyReport { return ob.o.ready() }

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

func (o *observer) sample() {
	now := core.Now()
	s := &Snapshot{
		At:                now,
		Supply:            map[string]uint64{},
		SupplyConserved:   map[string]bool{},
		SupplyDiscrepancy: map[string]int64{},
	}

	defer func() {

		if r := recover(); r != nil {
			s.Error = fmt.Sprintf("sampler panic: %v", r)
			o.snap.Store(s)
			o.publish(s)
			logging.Errorf("observability: sampler panic: %v", r)
		}
	}()

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

	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	s.FrontierFingerprint = hex.EncodeToString(sum[:])[:16]

	s.PendingSends = len(o.node.Ledger.GetAllPending())

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

	s.EligibilityRestricted = o.node.Ledger.RepEligibilityRestricted()
	s.EligibilityFailedOpen = o.node.Ledger.RepEligibilityFailedOpen()
	s.IneligibleWeight = clampBig(o.node.Ledger.GetIneligibleWeight())

	weights := o.node.Ledger.GetVoteWeights()
	total := new(big.Int)
	for _, w := range weights {
		total.Add(total, new(big.Int).SetUint64(w))
		s.Representatives++
	}
	s.DelegatedWeight = clampBig(total)

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

		s.QuorumMargin = -metrics.QuorumRatio
	}
	if xe := s.Supply[core.AssetXE.Symbol]; xe > 0 {
		s.DelegatedWeightRatio = float64(s.DelegatedWeight) / float64(xe)
	}

	s.FinalityAdvances = o.node.Ledger.FinalityAdvances()
	if ns := o.node.Ledger.LastFinalityNs(); ns > 0 {
		s.LastFinalityAdvance = time.Unix(0, ns)
	} else {

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

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

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

type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`

	Evaluated bool   `json:"evaluated"`
	Detail    string `json:"detail,omitempty"`
}

func pass(name, detail string) Check { return Check{name, true, true, detail} }
func fail(name, detail string) Check { return Check{name, false, true, detail} }

func unevaluated(name, detail string) Check { return Check{name, false, false, detail} }

type HealthReport struct {
	Status        string  `json:"status"`
	OK            bool    `json:"ok"`
	Version       string  `json:"version"`
	NetworkID     string  `json:"network_id,omitempty"`
	NodeID        string  `json:"node_id,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Checks        []Check `json:"checks"`

	Note string `json:"note"`
}

type ReadyReport struct {
	Status string  `json:"status"`
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

		r.Checks = append(r.Checks, fail("sample_present", "no observability sample yet"))
		r.finish()
		return r
	}

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

	if r.PeerCount >= cfg.MinPeers {
		r.Checks = append(r.Checks, pass("peers", fmt.Sprintf("%d connected", r.PeerCount)))
	} else {
		r.Checks = append(r.Checks, fail("peers",
			fmt.Sprintf("%d connected, need %d", r.PeerCount, cfg.MinPeers)))
	}

	switch {
	case cfg.MinPeers == 0 && r.PeerCount == 0:

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

	if s.DelegatedWeight == 0 {
		r.Checks = append(r.Checks, fail("delegated_weight",
			"total delegated vote weight is ZERO — no block on this network can ever finalize; spendable balances will read empty for every account. See runbook: quorum loss."))
	} else {
		r.Checks = append(r.Checks, pass("delegated_weight",
			fmt.Sprintf("%d micro-XE across %d representatives", s.DelegatedWeight, s.Representatives)))
	}

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
			fmt.Sprintf("only %.1f%% of delegated weight is voting (need %.0f%%); margin %.3f. Finality is halted network-wide: the 67%% quorum is the only finalize path, and nothing finalizes until the silent weight votes again or the DAO gates the denominator.",
				100*(s.QuorumMargin+metrics.QuorumRatio), 100*metrics.QuorumRatio, s.QuorumMargin)))
	default:
		r.Checks = append(r.Checks, pass("quorum_reachable",
			fmt.Sprintf("margin %.3f above the %.0f%% threshold, %d/%d representatives voting",
				s.QuorumMargin, 100*metrics.QuorumRatio, s.ActiveRepresentatives, s.Representatives)))
	}

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
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}
