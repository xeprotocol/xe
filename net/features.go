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

type PeerRetainPolicy func(peer.ID) bool

type peerCapTable struct {
	mu     sync.RWMutex
	max    int
	caps   map[peer.ID]PeerCapabilities
	order  []peer.ID
	retain PeerRetainPolicy
}

func newPeerCapTable(max ...int) *peerCapTable {
	limit := maxPeerCapEntries
	if len(max) > 0 && max[0] > 0 {
		limit = max[0]
	}
	return &peerCapTable{
		max:  limit,
		caps: make(map[peer.ID]PeerCapabilities),
	}
}

func (t *peerCapTable) setRetainPolicy(fn PeerRetainPolicy) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.retain = fn
}

func (t *peerCapTable) record(p peer.ID, c PeerCapabilities) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If already tracked, reposition to back of order (LRU update)
	if _, seen := t.caps[p]; seen {
		for i, id := range t.order {
			if id == p {
				t.order = append(t.order[:i], t.order[i+1:]...)
				break
			}
		}
	}
	t.order = append(t.order, p)
	t.caps[p] = c

	limit := t.max
	if limit <= 0 {
		limit = maxPeerCapEntries
	}

	for len(t.order) > limit {
		victimIdx := -1
		if t.retain != nil {
			for i, cand := range t.order {
				if !t.retain(cand) {
					victimIdx = i
					break
				}
			}
		}
		// Fallback: if all entries are retained or no policy is set, evict oldest
		if victimIdx == -1 {
			victimIdx = 0
		}
		victim := t.order[victimIdx]
		t.order = append(t.order[:victimIdx], t.order[victimIdx+1:]...)
		delete(t.caps, victim)
	}
}

func (t *peerCapTable) remove(p peer.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.caps[p]; !ok {
		return
	}
	delete(t.caps, p)
	for i, id := range t.order {
		if id == p {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
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

func (g *NetworkGater) RemovePeerCapabilities(p peer.ID) {
	g.caps.remove(p)
}

func (g *NetworkGater) PeerCapabilities(p peer.ID) (PeerCapabilities, bool) {
	return g.caps.get(p)
}

func (g *NetworkGater) AllPeerCapabilities() map[peer.ID]PeerCapabilities {
	return g.caps.all()
}

func (g *NetworkGater) SetPeerRetainPolicy(fn PeerRetainPolicy) {
	g.caps.setRetainPolicy(fn)
}

func (g *NetworkGater) PeerRetainPolicy() PeerRetainPolicy {
	g.caps.mu.RLock()
	defer g.caps.mu.RUnlock()
	return g.caps.retain
}

func (g *NetworkGater) SetMaxPeerCapEntries(n int) {
	g.caps.mu.Lock()
	defer g.caps.mu.Unlock()
	g.caps.max = n
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
