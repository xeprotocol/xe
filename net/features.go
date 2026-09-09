package net

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

const maxPeerCapEntries = 4096

type PeerCapabilities struct {
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
}

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

var LocalFeatures = sync.OnceValue(func() []string {
	f := core.KnownFeatures()
	if len(f) > maxAdvertisedFeatures {
		f = f[:maxAdvertisedFeatures]
	}
	return f
})

func (g *NetworkGater) RecordPeerCapabilities(p peer.ID, c PeerCapabilities) {
	g.caps.record(p, c)
}

func (g *NetworkGater) PeerCapabilities(p peer.ID) (PeerCapabilities, bool) {
	return g.caps.get(p)
}

func (g *NetworkGater) AllPeerCapabilities() map[peer.ID]PeerCapabilities {
	return g.caps.all()
}

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

func checkVersionFloor(msg netcheckMsg, floor string) string {
	if floor == "" || msg.Version == "" {
		return ""
	}
	if statechain.CompareProtocolVersion(msg.Version, floor) < 0 {
		return "version " + msg.Version + " is below the network floor " + floor + " (sys.min_protocol_version)"
	}
	return ""
}
