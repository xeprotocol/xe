package net

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	routingdisc "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	discutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
)

const (
	discoveryNamespacePrefix = "xe/discovery/1"

	discoveryInterval = 60 * time.Second

	discoveryBackoff = 5 * time.Minute

	defaultDiscoveryTarget = 24

	discoveryFindLimit = 64

	discoveryDialTimeout = 15 * time.Second

	discoveryDialsPerRound = 8
)

type AmbientDiscovery struct {
	host   host.Host
	disc   *routingdisc.RoutingDiscovery
	ns     string
	target int

	rounds    atomic.Uint64
	found     atomic.Uint64
	connected atomic.Uint64
}

func StartAmbientDiscovery(ctx context.Context, h host.Host, d *dht.IpfsDHT, networkID string, target int) *AmbientDiscovery {
	if d == nil || h == nil {
		return nil
	}
	if target <= 0 {
		target = defaultDiscoveryTarget
	}
	ns := discoveryNamespacePrefix
	if networkID != "" {
		ns += "/" + networkID
	}

	ad := &AmbientDiscovery{
		host:   h,
		disc:   routingdisc.NewRoutingDiscovery(d),
		ns:     ns,
		target: target,
	}

	discutil.Advertise(ctx, ad.disc, ns)

	go ad.loop(ctx)
	log.Printf("Ambient peer discovery started (rendezvous %q, target %d peers)", ns, target)
	return ad
}

func (a *AmbientDiscovery) loop(ctx context.Context) {

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		wait := discoveryInterval
		if a.peerCount() < a.target {
			if n := a.round(ctx); n == 0 {

				wait = discoveryBackoff
			}
		}
		timer.Reset(wait)
	}
}

func (a *AmbientDiscovery) round(ctx context.Context) int {
	a.rounds.Add(1)

	findCtx, cancel := context.WithTimeout(ctx, discoveryInterval)
	defer cancel()

	ch, err := a.disc.FindPeers(findCtx, a.ns, discovery.Limit(discoveryFindLimit))
	if err != nil {
		log.Printf("discovery: find peers: %v", err)
		return 0
	}

	found, dialed := 0, 0
	for pi := range ch {
		found++
		if dialed >= discoveryDialsPerRound || a.peerCount() >= a.target {
			continue
		}
		if pi.ID == a.host.ID() || len(pi.Addrs) == 0 {
			continue
		}
		if a.host.Network().Connectedness(pi.ID) == network.Connected {
			continue
		}
		dialCtx, dcancel := context.WithTimeout(ctx, discoveryDialTimeout)
		err := a.host.Connect(dialCtx, pi)
		dcancel()
		if err != nil {
			continue
		}
		dialed++
		a.connected.Add(1)
		log.Printf("discovery: connected to %s", pi.ID.ShortString())
	}

	a.found.Add(uint64(found))
	if found > 0 {
		log.Printf("discovery: round found %d peer record(s), dialled %d, now %d peer(s)",
			found, dialed, a.peerCount())
	}
	return found
}

func (a *AmbientDiscovery) peerCount() int {
	return len(a.host.Network().Peers())
}

func (a *AmbientDiscovery) Stats() (rounds, found, connected uint64) {
	if a == nil {
		return 0, 0, 0
	}
	return a.rounds.Load(), a.found.Load(), a.connected.Load()
}

func ProtectPeers(h host.Host, gater *NetworkGater, tag string, pids ...peer.ID) {
	for _, p := range pids {
		if cm := h.ConnManager(); cm != nil {
			cm.Protect(p, tag)
		}
	}
	if gater != nil {
		gater.Trust(pids...)
	}
}
