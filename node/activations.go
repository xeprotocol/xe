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

type ActivationsInfo struct {
	TipIndex     uint64 `json:"tip_index"`
	TipTimestamp int64  `json:"tip_timestamp"`

	Features []statechain.FeatureStatus `json:"features"`

	KnownFeatures []string `json:"known_features"`

	GatedBlockTypes map[string]string `json:"gated_block_types"`

	UnsupportedActive []string `json:"unsupported_active"`

	UnsupportedPending []string `json:"unsupported_pending"`

	MinProtocolVersion string `json:"min_protocol_version,omitempty"`

	ProtocolVersion string `json:"protocol_version"`
}

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

type activationReporter struct {
	mu       sync.Mutex
	reported map[string]string
	lastLoud time.Time
}

func newActivationReporter() *activationReporter {
	return &activationReporter{reported: map[string]string{}}
}

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

func (n *Node) syncActivationPolicy() {
	if n.gater != nil {
		n.gater.SetMinProtocolVersion(n.StateChain.MinProtocolVersion())
	}
	n.reportActivations()
}

type VersionWeight struct {
	Version string `json:"version"`
	Weight  uint64 `json:"weight"`
}

type ReadinessInfo struct {
	TotalWeight uint64 `json:"total_weight"`

	FeatureWeight map[string]uint64 `json:"feature_weight"`

	FeatureReadyMilli map[string]uint64 `json:"feature_ready_milli"`

	VersionWeight []VersionWeight `json:"version_weight"`

	UnknownWeight uint64 `json:"unknown_weight"`

	ResolvedReps int `json:"resolved_reps"`
	TotalReps    int `json:"total_reps"`
}

func (n *Node) GetReadiness() *ReadinessInfo {
	del := n.GetDelegation()
	caps := n.peerCapabilitiesByID()

	byAccount := map[string]xenet.PeerCapabilities{}
	for _, reg := range n.ListDirectory() {
		if reg == nil || reg.NodePeer == "" {
			continue
		}
		if c, ok := caps[reg.NodePeer]; ok {
			byAccount[reg.Account] = c
		}
	}

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

			info.FeatureReadyMilli[f] = 0
			continue
		}

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
