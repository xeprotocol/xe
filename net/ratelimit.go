package net

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/time/rate"
)

// peerRateLimiter is a two-tier ingress limiter for peer-driven work: a
// per-peer token bucket plus a global token bucket.
//
// Both tiers are needed and neither is sufficient alone. The per-peer bucket
// stops one established peer from monopolising a handler, but peer IDs cost a
// keygen, so a per-peer limit alone is evaded by rotating identity. The global
// bucket is the one that actually bounds total work; it is deliberately set
// well above honest aggregate demand so it only engages under flood.
//
// The per-peer bucket map is bounded and evicted FIFO for the same reason the
// ban map is (#840): an unbounded map keyed by a free identity is itself the
// DoS. Evicting a limiter is fail-open for that peer for one refill period,
// which is harmless — the global bucket still applies.
type peerRateLimiter struct {
	mu      sync.Mutex
	buckets map[peer.ID]*peerBucket
	order   []peer.ID
	max     int

	limit rate.Limit
	burst int

	global *rate.Limiter

	// idleTTL drops per-peer buckets untouched for this long, so a quiet
	// network does not carry limiters for peers that have gone away.
	idleTTL time.Duration

	// lastSweep throttles the inline sweep, which is O(n) over the bucket
	// map. Sweeping on every insert once the map is full would turn an
	// identity-rotation flood into a CPU denial of service: the attacker pays
	// one keygen, we pay a full map scan. FIFO eviction is the O(1) fallback.
	lastSweep time.Time

	allowed atomic.Uint64
	denied  atomic.Uint64
}

type peerBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// newPeerRateLimiter builds a limiter allowing perPeerRPS sustained requests
// per peer (bursting to perPeerBurst) and globalRPS sustained overall
// (bursting to globalBurst). maxPeers bounds the per-peer bucket map.
func newPeerRateLimiter(perPeerRPS float64, perPeerBurst int, globalRPS float64, globalBurst, maxPeers int) *peerRateLimiter {
	if maxPeers <= 0 {
		maxPeers = 2048
	}
	return &peerRateLimiter{
		buckets: make(map[peer.ID]*peerBucket),
		max:     maxPeers,
		limit:   rate.Limit(perPeerRPS),
		burst:   perPeerBurst,
		global:  rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		idleTTL: 5 * time.Minute,
	}
}

// allow reports whether a request from p may proceed.
//
// The per-peer bucket is checked FIRST, and a peer that is over its own budget
// never touches the global bucket. Checking global first would let one noisy
// peer burn the shared allowance on requests that were going to be refused
// anyway, which is a denial of service against every other peer — the opposite
// of what the limiter is for.
func (l *peerRateLimiter) allow(p peer.ID) bool {
	if !l.allowPeer(p) {
		l.denied.Add(1)
		return false
	}
	if !l.global.Allow() {
		l.denied.Add(1)
		return false
	}
	l.allowed.Add(1)
	return true
}

func (l *peerRateLimiter) allowPeer(p peer.ID) bool {
	now := time.Now()

	l.mu.Lock()
	b, ok := l.buckets[p]
	if !ok {
		if len(l.buckets) >= l.max && now.Sub(l.lastSweep) >= inlineSweepInterval {
			l.lastSweep = now
			l.sweepLocked(now)
		}
		for len(l.buckets) >= l.max {
			if !l.evictOldestLocked() {
				break
			}
		}
		b = &peerBucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[p] = b
		l.order = append(l.order, p)
		l.compactLocked()
	}
	b.seen = now
	lim := b.lim
	l.mu.Unlock()

	return lim.Allow()
}

func (l *peerRateLimiter) sweepLocked(now time.Time) {
	for p, b := range l.buckets {
		if now.Sub(b.seen) > l.idleTTL {
			delete(l.buckets, p)
		}
	}
	l.compactLocked()
}

func (l *peerRateLimiter) evictOldestLocked() bool {
	for len(l.order) > 0 {
		p := l.order[0]
		l.order = l.order[1:]
		if _, ok := l.buckets[p]; ok {
			delete(l.buckets, p)
			return true
		}
	}
	return false
}

func (l *peerRateLimiter) compactLocked() {
	if len(l.order) <= 2*l.max {
		return
	}
	compacted := make([]peer.ID, 0, len(l.buckets))
	for _, p := range l.order {
		if _, ok := l.buckets[p]; ok {
			compacted = append(compacted, p)
		}
	}
	l.order = compacted
}

// stats reports allow/deny counters and the live bucket count.
func (l *peerRateLimiter) stats() (allowed, denied uint64, buckets int) {
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	return l.allowed.Load(), l.denied.Load(), n
}
