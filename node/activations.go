package node

import (
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"

	xenet "github.com/xeprotocol/xe/net"
)

// ── Activation observability and operator warnings (#830) ───────────────────
//
// The registry and the gate make an activation SAFE. This file makes it
// VISIBLE, which is the other half of what an operator we do not control
// needs: a node must say, loudly and early, that the chain has scheduled
// something it cannot enforce — long before the trigger fires, and every time
// the state chain moves, not once at boot.
//
// Note what a node CANNOT do about a feature it does not implement: nothing.
// An old binary has no validator for a type introduced by a newer one, and no
// mechanism can conjure one. What ships here is the honest alternative — the
// node knows it is about to be wrong, says so with escalating volume, and
// governance can evict it via sys.min_protocol_version rather than leaving it
// half-synced and serving stale reads to its users.

// ActivationsInfo is the node's view of the feature registry, for GET
// /network/activations.
type ActivationsInfo struct {
	// TipIndex/TipTimestamp are the state-chain coordinates every activation
	// decision on this node was made against.
	TipIndex     uint64 `json:"tip_index"`
	TipTimestamp int64  `json:"tip_timestamp"`

	Features []statechain.FeatureStatus `json:"features"`

	// KnownFeatures is what this BINARY implements. A chain feature outside
	// this list is one the node cannot enforce.
	KnownFeatures []string `json:"known_features"`

	// GatedBlockTypes maps a block type this binary ships dark to the feature
	// that unlocks it. Empty in the Genesis(1) binary.
	GatedBlockTypes map[string]string `json:"gated_block_types"`

	// UnsupportedActive names features that are ACTIVE on chain and unknown to
	// this binary. Non-empty means this node is, or soon will be, validating
	// differently from an upgraded one. It is the single field an operator
	// should alert on.
	UnsupportedActive []string `json:"unsupported_active"`

	// UnsupportedPending names scheduled features unknown to this binary — the
	// upgrade warning, delivered before the deadline rather than after.
	UnsupportedPending []string `json:"unsupported_pending"`

	// MinProtocolVersion is the governance-set floor, "" when unset.
	MinProtocolVersion string `json:"min_protocol_version,omitempty"`

	// ProtocolVersion is what this node advertises in the netcheck handshake.
	ProtocolVersion string `json:"protocol_version"`
}

// GetActivations renders the registry against the current state-chain tip.
func (n *Node) GetActivations() *ActivationsInfo {
	known := core.KnownFeatureSet()
	statuses := n.StateChain.FeatureStatuses(known)
	tip := n.StateChain.Tip()

	info := &ActivationsInfo{
		Features:           statuses,
		KnownFeatures:      core.KnownFeatures(),
		GatedBlockTypes:    core.GatedBlockTypes(),
		MinProtocolVersion: n.StateChain.MinProtocolVersion(),
		ProtocolVersion:    xenet.NetcheckVersion,
	}
	if tip != nil {
		info.TipIndex = tip.Index
		info.TipTimestamp = tip.Timestamp
	}
	for _, f := range statuses {
		if f.KnownToBinary {
			continue
		}
		if f.Active {
			info.UnsupportedActive = append(info.UnsupportedActive, f.Name)
		} else {
			info.UnsupportedPending = append(info.UnsupportedPending, f.Name)
		}
	}
	return info
}

// activationReporter holds the log de-duplication state so a chain that moves
// every few seconds does not reprint the same countdown every time.
type activationReporter struct {
	mu       sync.Mutex
	reported map[string]string // feature → last line printed for it
	lastLoud time.Time
}

func newActivationReporter() *activationReporter {
	return &activationReporter{reported: map[string]string{}}
}

// reportActivations logs the state of the registry, printing a line per feature
// only when that feature's line has CHANGED — except the unsupported-active
// warning, which reprints on a timer because it is the one an operator must not
// be able to miss in a busy log.
func (n *Node) reportActivations() {
	info := n.GetActivations()
	r := n.activationLog

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, f := range info.Features {
		var line string
		switch {
		case f.Active && f.KnownToBinary:
			line = "activation: feature " + f.Name + " is ACTIVE and enforced by this build"
		case f.Active && !f.KnownToBinary:
			line = "activation: feature " + f.Name + " is ACTIVE and UNKNOWN to this build"
		case f.KnownToBinary:
			line = "activation: feature " + f.Name + " scheduled (" + triggerDesc(f) + "); this build implements it"
		default:
			line = "activation: feature " + f.Name + " scheduled (" + triggerDesc(f) + "); this build does NOT implement it — UPGRADE REQUIRED"
		}
		if r.reported[f.Name] != line {
			r.reported[f.Name] = line
			log.Print(line)
		}
	}

	if len(info.UnsupportedActive) > 0 && time.Since(r.lastLoud) > 5*time.Minute {
		r.lastLoud = time.Now()
		sort.Strings(info.UnsupportedActive)
		log.Printf("CRITICAL: this node cannot enforce active network feature(s) %v — it is validating DIFFERENTLY from upgraded peers. Upgrade now; blocks belonging to these features will be refused and their account chains will stall on this node.",
			info.UnsupportedActive)
	}
}

func triggerDesc(f statechain.FeatureStatus) string {
	desc := ""
	if f.AtIndex != 0 {
		desc = "at statechain index " + strconv.FormatUint(f.AtIndex, 10)
	}
	if f.NotBeforeNS != 0 {
		if desc != "" {
			desc += ", "
		}
		desc += "not before " + time.Unix(0, f.NotBeforeNS).UTC().Format(time.RFC3339)
	}
	if desc == "" {
		desc = "immediately"
	}
	return desc
}

// syncActivationPolicy re-reads the governance floor and refreshes the
// operator-facing log after every state-chain movement. Cheap: two map reads
// under the chain mutex plus a string compare per feature.
func (n *Node) syncActivationPolicy() {
	if n.gater != nil {
		n.gater.SetMinProtocolVersion(n.StateChain.MinProtocolVersion())
	}
	n.reportActivations()
}

// ── Readiness (#830) ────────────────────────────────────────────────────────

// VersionWeight is delegated vote weight attributed to one advertised version.
type VersionWeight struct {
	Version string `json:"version"`
	Weight  uint64 `json:"weight"`
}

// ReadinessInfo answers the only question worth asking before the DAO signs an
// activation: what share of DELEGATED VOTE WEIGHT is behind a build that can
// enforce the feature?
//
// Peer count is the wrong measure — finality is weighted, and a thousand
// zero-weight nodes signalling readiness say nothing about whether the chain
// can finalise a block of the new type. The mapping is
// representative → directory registration → peer → advertised features; every
// representative that cannot be resolved that way lands in UnknownWeight, and
// the honest reading is that UnknownWeight is NOT ready.
type ReadinessInfo struct {
	TotalWeight uint64 `json:"total_weight"`
	// FeatureWeight maps feature name → delegated weight whose representative
	// is reachable at a peer advertising it.
	FeatureWeight map[string]uint64 `json:"feature_weight"`
	// FeatureReadyMilli is FeatureWeight as a share of TotalWeight, ×1000, so
	// the 90% gate reads as 900 without float rounding arguments.
	FeatureReadyMilli map[string]uint64 `json:"feature_ready_milli"`
	// VersionWeight breaks the same total down by advertised protocol version.
	VersionWeight []VersionWeight `json:"version_weight"`
	// UnknownWeight is delegated weight this node cannot attribute to any
	// peer — an unregistered representative, a peer not currently connected,
	// or a peer that never completed a handshake. Count it as NOT ready.
	UnknownWeight uint64 `json:"unknown_weight"`
	// ResolvedReps / TotalReps show how much of the picture is visible at all.
	ResolvedReps int `json:"resolved_reps"`
	TotalReps    int `json:"total_reps"`
}

// GetReadiness computes delegated-weight-by-version and by-feature.
func (n *Node) GetReadiness() *ReadinessInfo {
	del := n.GetDelegation()
	caps := n.peerCapabilitiesByID()

	// Representative address → advertised capabilities, via the directory.
	byAccount := map[string]xenet.PeerCapabilities{}
	for _, reg := range n.ListDirectory() {
		if reg == nil || reg.NodePeer == "" {
			continue
		}
		if c, ok := caps[reg.NodePeer]; ok {
			byAccount[reg.Account] = c
		}
	}

	// This node's own account is resolvable without a directory round trip.
	byAccount[n.KeyPair.Address()] = xenet.PeerCapabilities{
		Version:  xenet.NetcheckVersion,
		Features: core.KnownFeatures(),
	}

	info := &ReadinessInfo{
		TotalWeight:       del.TotalWeight,
		FeatureWeight:     map[string]uint64{},
		FeatureReadyMilli: map[string]uint64{},
		TotalReps:         len(del.Weights),
	}
	versionWeights := map[string]uint64{}
	for rep, w := range del.Weights {
		c, ok := byAccount[rep]
		if !ok {
			info.UnknownWeight += w
			continue
		}
		info.ResolvedReps++
		versionWeights[c.Version] += w
		for _, f := range c.Features {
			info.FeatureWeight[f] += w
		}
	}
	for f, w := range info.FeatureWeight {
		if info.TotalWeight == 0 {
			// Total delegated weight of zero is silent finality death
			// (core/quorum.go) — report 0 rather than dividing by it, and let
			// the caller notice that total_weight is zero.
			info.FeatureReadyMilli[f] = 0
			continue
		}
		// w ≤ total delegated XE ≤ GenesisSupply = 4.2e13 micro-XE, so w×1000
		// tops out around 4.2e16 — three orders of magnitude below uint64
		// (S5). Multiplying first keeps the per-thousand figure exact.
		info.FeatureReadyMilli[f] = w * 1000 / info.TotalWeight
	}
	for v, w := range versionWeights {
		info.VersionWeight = append(info.VersionWeight, VersionWeight{Version: v, Weight: w})
	}
	sort.Slice(info.VersionWeight, func(i, j int) bool {
		if info.VersionWeight[i].Weight != info.VersionWeight[j].Weight {
			return info.VersionWeight[i].Weight > info.VersionWeight[j].Weight
		}
		return info.VersionWeight[i].Version < info.VersionWeight[j].Version
	})
	return info
}

// peerCapabilitiesByID snapshots the netcheck capability table keyed by peer-ID
// string, matching the directory record's NodePeer encoding.
func (n *Node) peerCapabilitiesByID() map[string]xenet.PeerCapabilities {
	out := map[string]xenet.PeerCapabilities{}
	if n.gater == nil {
		return out
	}
	for p, c := range n.gater.AllPeerCapabilities() {
		out[p.String()] = c
	}
	return out
}
