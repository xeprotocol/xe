package net

import (
	"context"
	"log"
	"sync"
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

	discoveryDialTimeout = 5 * time.Second

	discoveryMaxInFlight = 4

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

	found := 0
	var candidates []peer.AddrInfo
	for pi := range ch {
		found++
		if pi.ID == a.host.ID() || len(pi.Addrs) == 0 {
			continue
		}
		if a.host.Network().Connectedness(pi.ID) == network.Connected {
			continue
		}
		candidates = append(candidates, pi)
	}

	dialed := a.dialCandidates(ctx, candidates)

	a.found.Add(uint64(found))
	if found > 0 {
		log.Printf("discovery: round found %d peer record(s), dialled %d, now %d peer(s)",
			found, dialed, a.peerCount())
	}
	return found
}

func (a *AmbientDiscovery) dialCandidates(ctx context.Context, candidates []peer.AddrInfo) int {
	if len(candidates) == 0 || a.peerCount() >= a.target {
		return 0
	}

	var successful atomic.Int32
	sem := make(chan struct{}, discoveryMaxInFlight)
	var wg sync.WaitGroup

	roundCtx, roundCancel := context.WithTimeout(ctx, discoveryInterval)
	defer roundCancel()

	for _, pi := range candidates {
		if int(successful.Load()) >= discoveryDialsPerRound || a.peerCount() >= a.target {
			break
		}

		select {
		case <-roundCtx.Done():
			break
		case sem <- struct{}{}:
		}

		if int(successful.Load()) >= discoveryDialsPerRound || a.peerCount() >= a.target {
			<-sem
			break
		}

		wg.Add(1)
		go func(target peer.AddrInfo) {
			defer func() {
				<-sem
				wg.Done()
			}()

			dialCtx, dcancel := context.WithTimeout(roundCtx, discoveryDialTimeout)
			defer dcancel()

			err := a.host.Connect(dialCtx, target)
			if err != nil {
				return
			}

			successful.Add(1)
			a.connected.Add(1)
			log.Printf("discovery: connected to %s", target.ID.ShortString())
		}(pi)
	}

	wg.Wait()
	return int(successful.Load())
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
