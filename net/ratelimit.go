package net

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/time/rate"
)

type peerRateLimiter struct {
	mu      sync.Mutex
	buckets map[peer.ID]*peerBucket
	order   []peer.ID
	max     int

	limit rate.Limit
	burst int

	global *rate.Limiter

	idleTTL time.Duration

	lastSweep time.Time

	allowed atomic.Uint64
	denied  atomic.Uint64
}

type peerBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

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

func (l *peerRateLimiter) stats() (allowed, denied uint64, buckets int) {
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	return l.allowed.Load(), l.denied.Load(), n
}
