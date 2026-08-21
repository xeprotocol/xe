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

// Ambient peer discovery (#840).
//
// Before this, the DHT was built in server mode and bootstrapped, and then used
// for exactly one thing: resolving a peer ID we already knew to its addresses
// (Messenger.FindPeer, OpenTunnel). Nothing ever advertised, nothing ever
// searched, and nothing dialled a peer learned from the routing table. mDNS
// only reaches the local broadcast domain. So a node's honest peer set was
// precisely its --dial list, and the resulting topology is a star centred on
// whoever runs the bootstraps.
//
// That is an eclipse problem and an availability problem at once: every
// stranger's view of the chain is mediated by the same few nodes, and if those
// nodes are unreachable — or hostile — the stranger has no second opinion and
// no way to acquire one.
//
// This loop advertises the node under a network-scoped rendezvous key in the
// DHT and periodically searches for others, dialling until the peer count
// reaches a target. It is additive: bootstrap peers remain protected and
// re-dialled, and discovery only ever ADDS links.
//
// What this does not claim to be: discovered peers are unauthenticated (they
// still pass the netcheck handshake, but any keypair can advertise), so a
// well-resourced attacker can populate the rendezvous with Sybils. The defence
// against that is the combination here — protected bootstraps that cannot be
// evicted, an inbound slot cap that keeps outbound capacity free, and per-IP
// caps at the transport — not the discovery loop by itself. ASN/subnet
// diversity selection is a further step and is not implemented.

const (
	// discoveryNamespacePrefix is combined with the network id so that two XE
	// networks sharing a DHT never discover each other. Peers of the wrong
	// network would be banned by netcheck anyway; not finding them at all is
	// cheaper.
	discoveryNamespacePrefix = "xe/discovery/1"

	// discoveryInterval is how often we look for new peers when below target.
	discoveryInterval = 60 * time.Second

	// discoveryBackoff is the pause after a failed or empty search round.
	discoveryBackoff = 5 * time.Minute

	// defaultDiscoveryTarget is the peer count at or above which the loop
	// stops dialling. Well below the connection manager's low watermark (100)
	// so discovery never fights the connection manager for slots.
	defaultDiscoveryTarget = 24

	// discoveryFindLimit bounds how many rendezvous records one round pulls.
	discoveryFindLimit = 64

	// discoveryDialTimeout bounds a single dial to a discovered peer.
	discoveryDialTimeout = 15 * time.Second

	// discoveryDialsPerRound bounds how many new peers one round will dial, so
	// a rendezvous stuffed with Sybil records cannot be drained into our
	// connection table in a single pass.
	discoveryDialsPerRound = 8
)

// AmbientDiscovery periodically advertises this node and dials peers found at
// the network's rendezvous point.
type AmbientDiscovery struct {
	host   host.Host
	disc   *routingdisc.RoutingDiscovery
	ns     string
	target int

	rounds    atomic.Uint64
	found     atomic.Uint64
	connected atomic.Uint64
}

// StartAmbientDiscovery begins advertising and searching. It returns nil (and
// does nothing) when there is no DHT, which is the case in tests and in
// single-node runs. Cancel ctx to stop.
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

	// Advertise persistently; the helper re-advertises at 7/8 of the record
	// TTL and backs off on failure.
	discutil.Advertise(ctx, ad.disc, ns)

	go ad.loop(ctx)
	log.Printf("Ambient peer discovery started (rendezvous %q, target %d peers)", ns, target)
	return ad
}

func (a *AmbientDiscovery) loop(ctx context.Context) {
	// A first pass shortly after start, once bootstrap dials have had a chance
	// to populate the routing table. Searching an empty routing table just
	// fails, so there is no value in going immediately.
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
				// Nothing found: the rendezvous is empty or the routing table
				// is not usable yet. Back off rather than hammering the DHT.
				wait = discoveryBackoff
			}
		}
		timer.Reset(wait)
	}
}

// round performs one search-and-dial pass and returns how many peers it found.
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
			continue // drain the channel; do not dial further this round
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

// Stats reports rounds run, peer records seen and successful new connections.
func (a *AmbientDiscovery) Stats() (rounds, found, connected uint64) {
	if a == nil {
		return 0, 0, 0
	}
	return a.rounds.Load(), a.found.Load(), a.connected.Load()
}

// ProtectPeers marks peers as protected in the connection manager so the
// trimmer can never close them, and trusts them at the gater so they bypass
// the inbound slot cap and can never be banned.
//
// Together these are the "we chose this peer" half of eclipse resistance: an
// attacker who fills every other slot still cannot displace the links the
// operator configured.
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
