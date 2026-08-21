package net

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

// ── Capability negotiation (#830) ───────────────────────────────────────────
//
// The netcheck handshake gains a `features` field carrying the activation
// features the peer's BINARY implements — not the ones the chain has activated
// (that is chain state every node already agrees on), but what this build can
// actually enforce. encoding/json ignores unknown fields, so a node that
// predates the field reads the message fine and simply advertises nothing.
//
// The point is measurement. "Did operators upgrade?" is otherwise a guess, and
// the answer that matters is not a peer count but a share of DELEGATED VOTE
// WEIGHT: finality needs 67%, so activating a feature while more than a third
// of delegated weight cannot validate it wedges the network. /network/readiness
// turns that into a number the DAO reads before it signs.

// maxPeerCapEntries bounds the capability table. A peer ID costs one keygen, so
// any map keyed by one needs a cap and O(1) eviction — the #840 lesson, applied
// pre-emptively rather than after the flood.
const maxPeerCapEntries = 4096

// PeerCapabilities is what a peer advertised in its netcheck handshake.
type PeerCapabilities struct {
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
}

// HasFeature reports whether the peer advertised support for a feature.
func (c PeerCapabilities) HasFeature(f string) bool {
	for _, have := range c.Features {
		if have == f {
			return true
		}
	}
	return false
}

type peerCapTable struct {
	mu    sync.RWMutex
	caps  map[peer.ID]PeerCapabilities
	order []peer.ID
}

func newPeerCapTable() *peerCapTable {
	return &peerCapTable{caps: make(map[peer.ID]PeerCapabilities)}
}

func (t *peerCapTable) record(p peer.ID, c PeerCapabilities) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, seen := t.caps[p]; !seen {
		t.order = append(t.order, p)
	}
	t.caps[p] = c
	for len(t.order) > maxPeerCapEntries {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.caps, oldest)
	}
}

func (t *peerCapTable) get(p peer.ID) (PeerCapabilities, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.caps[p]
	return c, ok
}

func (t *peerCapTable) all() map[peer.ID]PeerCapabilities {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[peer.ID]PeerCapabilities, len(t.caps))
	for k, v := range t.caps {
		out[k] = v
	}
	return out
}

// LocalFeatures is what this binary advertises: the activation features it can
// enforce. It is derived from the compiled-in dark-validator registry, never
// configured, so a node cannot claim readiness it does not have.
//
// Truncated to maxAdvertisedFeatures, sorted, so the handshake stays inside the
// 256-byte limit older peers read with. Truncation is deterministic rather than
// arbitrary; if the list ever approaches the cap, retire the settled names
// rather than raising it silently.
// Memoized: the registry is written only from package init functions, so this
// is constant for the life of the process, and it is on the handshake path
// every stranger reaches.
var LocalFeatures = sync.OnceValue(func() []string {
	f := core.KnownFeatures()
	if len(f) > maxAdvertisedFeatures {
		f = f[:maxAdvertisedFeatures]
	}
	return f
})

// RecordPeerCapabilities stores what a peer advertised. Exported for the
// netcheck handlers in this package and for tests.
func (g *NetworkGater) RecordPeerCapabilities(p peer.ID, c PeerCapabilities) {
	g.caps.record(p, c)
}

// PeerCapabilities returns what a peer advertised, if it completed a handshake.
func (g *NetworkGater) PeerCapabilities(p peer.ID) (PeerCapabilities, bool) {
	return g.caps.get(p)
}

// AllPeerCapabilities snapshots the capability table.
func (g *NetworkGater) AllPeerCapabilities() map[peer.ID]PeerCapabilities {
	return g.caps.all()
}

// SetMinProtocolVersion installs the governance-set version floor from
// sys.min_protocol_version. Empty disables the floor.
//
// This is the DAO's eviction lever, and it exists because the only other one is
// circular: maxMinorDrift bans peers more than two minor versions apart, which
// means enforcing an upgrade requires everyone to have upgraded first. A
// chain-published floor is enforced by whoever HAS upgraded, immediately.
func (g *NetworkGater) SetMinProtocolVersion(v string) {
	g.mu.Lock()
	g.minVersion = v
	g.mu.Unlock()
}

func (g *NetworkGater) getMinProtocolVersion() string {
	g.mu.RLock()
	v := g.minVersion
	g.mu.RUnlock()
	return v
}

// checkVersionFloor rejects a peer below the governance-set protocol floor. It
// is separate from checkPeer so the two policies stay independently testable:
// drift is a compiled-in compatibility rule, the floor is chain state that can
// change under a running node.
func checkVersionFloor(msg netcheckMsg, floor string) string {
	if floor == "" || msg.Version == "" {
		return ""
	}
	if statechain.CompareProtocolVersion(msg.Version, floor) < 0 {
		return "version " + msg.Version + " is below the network floor " + floor + " (sys.min_protocol_version)"
	}
	return ""
}
