package net

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/time/rate"
)

type peerRateLimiter struct {
	mu sync.Mutex

	buckets   map[peer.ID]*peerBucket
	peerLRU   *list.List
	max       int
	peerLimit rate.Limit
	peerBurst int

	ipBuckets map[string]*ipBucket
	ipLRU     *list.List
	maxIPs    int
	ipLimit   rate.Limit
	ipBurst   int

	global *rate.Limiter

	idleTTL time.Duration

	lastSweep time.Time

	allowed atomic.Uint64
	denied  atomic.Uint64
}

type peerBucket struct {
	lim     *rate.Limiter
	seen    time.Time
	element *list.Element
}

type ipBucket struct {
	lim     *rate.Limiter
	seen    time.Time
	element *list.Element
}

func newPeerRateLimiter(perPeerRPS float64, perPeerBurst int, globalRPS float64, globalBurst, maxPeers int) *peerRateLimiter {
	if maxPeers <= 0 {
		maxPeers = 2048
	}
	return &peerRateLimiter{
		buckets:   make(map[peer.ID]*peerBucket),
		peerLRU:   list.New(),
		max:       maxPeers,
		peerLimit: rate.Limit(perPeerRPS),
		peerBurst: perPeerBurst,

		ipBuckets: make(map[string]*ipBucket),
		ipLRU:     list.New(),
		maxIPs:    maxPeers,
		ipLimit:   rate.Limit(perPeerRPS),
		ipBurst:   perPeerBurst,

		global:  rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
		idleTTL: 5 * time.Minute,
	}
}

func (l *peerRateLimiter) allow(p peer.ID) bool {
	return l.allowPeerAndIP(p, "")
}

func (l *peerRateLimiter) allowConn(c network.Conn) bool {
	if c == nil {
		return false
	}
	return l.allowPeerAndIP(c.RemotePeer(), remoteIPFromConn(c))
}

func (l *peerRateLimiter) allowPeerAndIP(p peer.ID, ip string) bool {
	if !l.allowPeer(p) {
		l.denied.Add(1)
		return false
	}
	if !l.allowIP(ip) {
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
			if !l.evictOldestPeerLocked() {
				break
			}
		}
		elem := l.peerLRU.PushBack(p)
		b = &peerBucket{
			lim:     rate.NewLimiter(l.peerLimit, l.peerBurst),
			element: elem,
		}
		l.buckets[p] = b
	} else {
		l.peerLRU.MoveToBack(b.element)
	}
	b.seen = now
	lim := b.lim
	l.mu.Unlock()

	return lim.Allow()
}

func (l *peerRateLimiter) allowIP(ip string) bool {
	if ip == "" {
		return true
	}
	now := time.Now()

	l.mu.Lock()
	b, ok := l.ipBuckets[ip]
	if !ok {
		if len(l.ipBuckets) >= l.maxIPs && now.Sub(l.lastSweep) >= inlineSweepInterval {
			l.lastSweep = now
			l.sweepLocked(now)
		}
		for len(l.ipBuckets) >= l.maxIPs {
			if !l.evictOldestIPLocked() {
				break
			}
		}
		elem := l.ipLRU.PushBack(ip)
		b = &ipBucket{
			lim:     rate.NewLimiter(l.ipLimit, l.ipBurst),
			element: elem,
		}
		l.ipBuckets[ip] = b
	} else {
		l.ipLRU.MoveToBack(b.element)
	}
	b.seen = now
	lim := b.lim
	l.mu.Unlock()

	return lim.Allow()
}

func (l *peerRateLimiter) sweepLocked(now time.Time) {
	for p, b := range l.buckets {
		if now.Sub(b.seen) > l.idleTTL {
			l.peerLRU.Remove(b.element)
			delete(l.buckets, p)
		}
	}
	for ip, b := range l.ipBuckets {
		if now.Sub(b.seen) > l.idleTTL {
			l.ipLRU.Remove(b.element)
			delete(l.ipBuckets, ip)
		}
	}
}

func (l *peerRateLimiter) evictOldestPeerLocked() bool {
	elem := l.peerLRU.Front()
	if elem == nil {
		return false
	}
	p := elem.Value.(peer.ID)
	l.peerLRU.Remove(elem)
	delete(l.buckets, p)
	return true
}

func (l *peerRateLimiter) evictOldestIPLocked() bool {
	elem := l.ipLRU.Front()
	if elem == nil {
		return false
	}
	ip := elem.Value.(string)
	l.ipLRU.Remove(elem)
	delete(l.ipBuckets, ip)
	return true
}

func (l *peerRateLimiter) stats() (allowed, denied uint64, buckets int) {
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	return l.allowed.Load(), l.denied.Load(), n
}

func remoteIPFromConn(c network.Conn) string {
	if c == nil {
		return ""
	}
	return remoteIPFromMultiaddr(c.RemoteMultiaddr())
}

func remoteIPFromMultiaddr(addr ma.Multiaddr) string {
	if addr == nil {
		return ""
	}
	var ip string
	ma.ForEach(addr, func(comp ma.Component) bool {
		switch comp.Protocol().Code {
		case ma.P_IP4, ma.P_IP6:
			ip = comp.Value()
			return false
		}
		return true
	})
	return ip
}
