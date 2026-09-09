package net

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/xeprotocol/xe/logging"
)

const (
	NetcheckProtocolID = protocol.ID("/xe/netcheck/1")

	NetcheckVersion = "1.0.0"

	netcheckTimeout = 5 * time.Second
	defaultBanDur   = 10 * time.Minute
	versionBanDur   = 1 * time.Hour

	maxNetcheckBytes = 1024

	maxAdvertisedFeatures = 8

	maxMinorDrift = 2

	defaultMaxInboundConns = 256

	netcheckPerPeerRPS   = 0.2
	netcheckPerPeerBurst = 3
	netcheckGlobalRPS    = 32
	netcheckGlobalBurst  = 128
	netcheckLimiterPeers = 2048
)

type netcheckMsg struct {
	NetworkID string `json:"network_id"`
	Version   string `json:"version,omitempty"`

	Features []string `json:"features,omitempty"`

	GenesisHash string `json:"genesis_hash,omitempty"`
}

type semver struct {
	Major int
	Minor int
	Patch int
}

func parseSemver(s string) (semver, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, false
	}
	return semver{major, minor, patch}, true
}

func (v semver) compatible(other semver) bool {
	if v.Major != other.Major {
		return false
	}
	diff := v.Minor - other.Minor
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxMinorDrift
}

type NetworkGater struct {
	mu          sync.RWMutex
	banDur      time.Duration
	networkID   string
	genesisHash string

	minVersion string

	caps *peerCapTable

	trusted map[peer.ID]struct{}

	bans *banStore

	inbound        atomic.Int64
	maxInbound     int64
	inboundRefused atomic.Uint64

	handshakes *peerRateLimiter

	banPath string

	rejects      int
	aborted      int
	lastMismatch *NetworkMismatch
}

type NetworkMismatch struct {
	Peer             string
	Reason           string
	OurNetworkID     string
	TheirNetworkID   string
	OurGenesisHash   string
	TheirGenesisHash string
	At               time.Time
}

func NewNetworkGater() *NetworkGater {
	return &NetworkGater{
		banDur:     defaultBanDur,
		trusted:    make(map[peer.ID]struct{}),
		bans:       newBanStore(maxBannedPeers),
		maxInbound: defaultMaxInboundConns,
		handshakes: newPeerRateLimiter(netcheckPerPeerRPS, netcheckPerPeerBurst,
			netcheckGlobalRPS, netcheckGlobalBurst, netcheckLimiterPeers),

		caps: newPeerCapTable(),
	}
}

func (g *NetworkGater) SetMaxInboundConns(n int) {
	atomic.StoreInt64(&g.maxInbound, int64(n))
}

func (g *NetworkGater) Trust(pids ...peer.ID) {
	g.mu.Lock()
	for _, p := range pids {
		g.trusted[p] = struct{}{}
	}
	g.mu.Unlock()

	for _, p := range pids {
		g.bans.clear(p)
	}
}

func (g *NetworkGater) IsTrusted(p peer.ID) bool {
	return g.isTrusted(p)
}

func (g *NetworkGater) isTrusted(p peer.ID) bool {
	g.mu.RLock()
	_, ok := g.trusted[p]
	g.mu.RUnlock()
	return ok
}

func (g *NetworkGater) BanStats() (live int, evictions, sweeps uint64) {
	return g.bans.stats()
}

func (g *NetworkGater) InboundStats() (current int64, max int64, refused uint64) {
	return g.inbound.Load(), atomic.LoadInt64(&g.maxInbound), g.inboundRefused.Load()
}

func (g *NetworkGater) HandshakeStats() (allowed, denied uint64) {
	a, d, _ := g.handshakes.stats()
	return a, d
}

func (g *NetworkGater) StartBanMaintenance(ctx context.Context, dataDir string) {
	if dataDir != "" {
		g.banPath = filepath.Join(dataDir, banFileName)
		if n, err := g.bans.load(g.banPath); err != nil {
			logging.Warnf("netcheck: ban snapshot not restored: %v", err)
		} else if n > 0 {
			logging.Infof("netcheck: restored %d ban(s) from %s", n, g.banPath)
		}
	}

	go func() {
		ticker := time.NewTicker(banSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				g.persistBans()
				return
			case <-ticker.C:
				g.bans.sweep()
				g.persistBans()
			}
		}
	}()
}

func (g *NetworkGater) persistBans() {
	if g.banPath == "" || !g.bans.dirty.Load() {
		return
	}
	if err := g.bans.save(g.banPath); err != nil {
		logging.Warnf("netcheck: ban snapshot not saved: %v", err)
	}
}

func (g *NetworkGater) SetNetworkID(id string) {
	g.mu.Lock()
	g.networkID = id
	g.mu.Unlock()
}

func (g *NetworkGater) SetGenesisHash(h string) {
	g.mu.Lock()
	g.genesisHash = h
	g.mu.Unlock()
}

func (g *NetworkGater) ourMsg() netcheckMsg {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return netcheckMsg{
		NetworkID:   g.networkID,
		Version:     NetcheckVersion,
		Features:    LocalFeatures(),
		GenesisHash: g.genesisHash,
	}
}

func (g *NetworkGater) recordMismatch(pid peer.ID, reason string, theirs netcheckMsg) {
	g.mu.Lock()
	g.rejects++
	g.lastMismatch = &NetworkMismatch{
		Peer:             pid.ShortString(),
		Reason:           reason,
		OurNetworkID:     g.networkID,
		TheirNetworkID:   theirs.NetworkID,
		OurGenesisHash:   g.genesisHash,
		TheirGenesisHash: theirs.GenesisHash,
		At:               time.Now(),
	}
	g.mu.Unlock()
}

func (g *NetworkGater) noteHandshakeAborted() {
	g.mu.Lock()
	g.aborted++
	g.mu.Unlock()
}

func (g *NetworkGater) LastMismatch() (last *NetworkMismatch, rejected, aborted int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastMismatch, g.rejects, g.aborted
}

func (g *NetworkGater) isBanned(p peer.ID) bool {
	return g.bans.banned(p)
}

func (g *NetworkGater) Ban(p peer.ID, d time.Duration) {
	g.banFor(p, d)
}

func (g *NetworkGater) IsBanned(p peer.ID) bool {
	return g.isBanned(p)
}

func (g *NetworkGater) ban(p peer.ID) {
	g.banFor(p, g.banDur)
}

func (g *NetworkGater) banFor(p peer.ID, d time.Duration) {
	if g.isTrusted(p) {

		return
	}
	g.bans.ban(p, time.Now().Add(d))
}

func (g *NetworkGater) InterceptPeerDial(p peer.ID) bool {
	return !g.isBanned(p)
}

func (g *NetworkGater) InterceptAddrDial(_ peer.ID, _ ma.Multiaddr) bool {
	return true
}

func (g *NetworkGater) InterceptAccept(_ network.ConnMultiaddrs) bool {
	return true
}

func (g *NetworkGater) InterceptSecured(dir network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	if g.isBanned(p) {
		return false
	}

	if dir == network.DirInbound && !g.isTrusted(p) {
		max := atomic.LoadInt64(&g.maxInbound)
		if max > 0 && g.inbound.Load() >= max {
			g.inboundRefused.Add(1)
			return false
		}
	}
	return true
}

func (g *NetworkGater) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

func SetupNetworkCheck(h host.Host, gater *NetworkGater) {
	h.SetStreamHandler(NetcheckProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()

		if !gater.handshakes.allow(s.Conn().RemotePeer()) {
			_ = s.Reset()
			return
		}
		_ = s.SetDeadline(time.Now().Add(netcheckTimeout))
		handleNetcheckInbound(s, h, gater)
	})

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			if conn.Stat().Direction == network.DirInbound {
				gater.inbound.Add(1)
			}
			go verifyPeer(h, conn.RemotePeer(), gater)
		},
		DisconnectedF: func(_ network.Network, conn network.Conn) {
			if conn.Stat().Direction == network.DirInbound {
				if gater.inbound.Add(-1) < 0 {
					gater.inbound.Store(0)
				}
			}
		},
	})
}

func checkPeer(msg netcheckMsg, ours netcheckMsg) (reason string, banDuration time.Duration) {

	if ours.NetworkID != "" {
		if msg.NetworkID == "" {
			return "missing network_id (we are on " + ours.NetworkID + "); peer is running a build whose genesis sets no sys.network_id", defaultBanDur
		}
		if msg.NetworkID != ours.NetworkID {
			return fmt.Sprintf("network_id mismatch: peer is on %q, we are on %q — one of us is running the wrong genesis (see --genesis-dir)",
				msg.NetworkID, ours.NetworkID), defaultBanDur
		}
	}

	if ours.GenesisHash != "" && msg.GenesisHash != "" && msg.GenesisHash != ours.GenesisHash {

		return fmt.Sprintf("statechain genesis mismatch on network %q: peer genesis %q, ours %s — same network id, different chain start",
			ours.NetworkID, msg.GenesisHash, ours.GenesisHash), defaultBanDur
	}

	if ours.NetworkID != "" && msg.Version == "" {
		return "missing version", versionBanDur
	}

	if msg.Version != "" {
		remote, ok := parseSemver(msg.Version)
		if !ok {
			return fmt.Sprintf("unparseable version %q", msg.Version), versionBanDur
		}
		local, _ := parseSemver(NetcheckVersion)
		if !local.compatible(remote) {
			return fmt.Sprintf("incompatible version %s (ours: %s, require same major and minor within %d)",
				msg.Version, NetcheckVersion, maxMinorDrift), versionBanDur
		}
	}

	return "", 0
}

func handleNetcheckInbound(s network.Stream, h host.Host, gater *NetworkGater) {
	pid := s.Conn().RemotePeer()

	var msg netcheckMsg
	if err := json.NewDecoder(io.LimitReader(s, maxNetcheckBytes)).Decode(&msg); err != nil {
		return
	}

	our := gater.ourMsg()
	_ = json.NewEncoder(s).Encode(&our)

	if reason, dur := checkPeer(msg, our); reason != "" {
		logging.Warnf("netcheck: rejecting inbound peer %s: %s", pid.ShortString(), reason)
		gater.recordMismatch(pid, reason, msg)
		gater.banFor(pid, dur)
		_ = h.Network().ClosePeer(pid)
		return
	}
	if reason := checkVersionFloor(msg, gater.getMinProtocolVersion()); reason != "" {
		logging.Warnf("netcheck: rejecting inbound peer %s: %s", pid.ShortString(), reason)
		gater.banFor(pid, versionBanDur)
		_ = h.Network().ClosePeer(pid)
		return
	}
	gater.RecordPeerCapabilities(pid, PeerCapabilities{Version: msg.Version, Features: msg.Features})
}

func verifyPeer(h host.Host, pid peer.ID, gater *NetworkGater) {
	our := gater.ourMsg()
	if our.NetworkID == "" {
		return
	}
	if gater.isBanned(pid) {
		_ = h.Network().ClosePeer(pid)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), netcheckTimeout)
	defer cancel()

	s, err := h.NewStream(ctx, pid, NetcheckProtocolID)
	if err != nil {

		logging.Warnf("netcheck: closing peer %s: handshake unavailable (%v)", pid.ShortString(), err)
		_ = h.Network().ClosePeer(pid)
		return
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(netcheckTimeout))

	if err := json.NewEncoder(s).Encode(&our); err != nil {
		return
	}
	if err := s.CloseWrite(); err != nil {
		return
	}

	var msg netcheckMsg
	if err := json.NewDecoder(io.LimitReader(s, maxNetcheckBytes)).Decode(&msg); err != nil {

		logging.Warnf("netcheck: peer %s closed the handshake before replying (%v) — if this repeats for every bootstrap peer, this node is almost certainly on the wrong network (ours: network_id=%q genesis=%s)",
			pid.ShortString(), err, our.NetworkID, our.GenesisHash)
		gater.noteHandshakeAborted()
		_ = h.Network().ClosePeer(pid)
		return
	}

	if reason, dur := checkPeer(msg, our); reason != "" {
		logging.Warnf("netcheck: rejecting peer %s: %s", pid.ShortString(), reason)
		gater.recordMismatch(pid, reason, msg)
		gater.banFor(pid, dur)
		_ = h.Network().ClosePeer(pid)
		return
	}
	if reason := checkVersionFloor(msg, gater.getMinProtocolVersion()); reason != "" {
		logging.Warnf("netcheck: rejecting peer %s: %s", pid.ShortString(), reason)
		gater.banFor(pid, versionBanDur)
		_ = h.Network().ClosePeer(pid)
		return
	}
	gater.RecordPeerCapabilities(pid, PeerCapabilities{Version: msg.Version, Features: msg.Features})
}
