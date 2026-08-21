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
	// NetcheckProtocolID uses only the major version so that any 1.x.y
	// node can open a stream to any other 1.x.y node. Minor/patch
	// compatibility is checked inside the handshake message.
	NetcheckProtocolID = protocol.ID("/xe/netcheck/1")

	NetcheckVersion = "1.0.0"

	netcheckTimeout = 5 * time.Second
	defaultBanDur   = 10 * time.Minute
	versionBanDur   = 1 * time.Hour
	// maxNetcheckBytes is the READ limit. It was raised from 256 with the
	// #830 features field and again carries the #839 genesis_hash (82 bytes on
	// the wire); what this node SENDS is still kept under 256 bytes — see
	// maxAdvertisedFeatures and TestNetcheckMsg_WireCompatibleWithPreChangeBinary,
	// which measures the FULL outbound message, genesis hash included — so a
	// node built before the raise can still decode our handshake. Overflowing an
	// old peer's limit would not ban anyone — its decode fails and it never
	// replies — but it would silently void the network_id and version gates for
	// that pair, which is worse.
	maxNetcheckBytes = 1024

	// maxAdvertisedFeatures caps the feature list in an outbound handshake so
	// the encoded message stays inside the historical 256-byte read limit.
	maxAdvertisedFeatures = 8

	// maxMinorDrift is the maximum difference in minor versions that two
	// peers will tolerate. A node on 1.2.x accepts 1.0.x through 1.4.x
	// but rejects 1.5.x+. Patch versions are unrestricted.
	maxMinorDrift = 2

	// defaultMaxInboundConns bounds how many connections may be INBOUND at
	// once, reserving the remainder of the connection manager's budget for
	// connections this node chose to make.
	//
	// Eclipse resistance (#840): without a split, an attacker who can open
	// connections faster than we dial fills every slot, and the connection
	// manager then trims to its high watermark without regard to direction.
	// A node whose entire peer set is attacker-chosen sees an
	// attacker-chosen chain. With the connection manager's high watermark at
	// 400 (net/host.go), 256 inbound leaves 144 slots that only outbound
	// dials and protected peers can occupy.
	//
	// The cap is deliberately generous: it is a floor under our outbound
	// capacity, not a serving limit. Trusted (protected) peers bypass it
	// entirely, so a bootstrap node can always be reached by the operators
	// it has protected.
	defaultMaxInboundConns = 256

	// netcheck handshake rate limits. The handshake is unauthenticated by
	// construction — it is what decides whether a peer is allowed at all —
	// so it must be cheap to refuse. Per-peer: 0.2 rps (one every 5s)
	// bursting to 3, which is far above the one handshake per connection an
	// honest peer needs. Global: 32 rps bursting to 128, which bounds total
	// handshake work no matter how many identities an attacker rotates
	// through.
	netcheckPerPeerRPS   = 0.2
	netcheckPerPeerBurst = 3
	netcheckGlobalRPS    = 32
	netcheckGlobalBurst  = 128
	netcheckLimiterPeers = 2048
)

type netcheckMsg struct {
	NetworkID string `json:"network_id"`
	Version   string `json:"version,omitempty"`
	// Features are the activation features this peer's BINARY implements
	// (#830). encoding/json ignores unknown fields, so this is wire-compatible
	// with every node that predates it: such a peer advertises nothing and is
	// counted as not-ready rather than rejected.
	Features []string `json:"features,omitempty"`
	// GenesisHash is the statechain genesis hash — the network's identity root.
	// Optional and additive (#839): the decoder does not use
	// DisallowUnknownFields, so a node that predates this field still parses the
	// message, and a peer that omits it simply skips the genesis comparison.
	// It exists to turn "network_id mismatch" into a diagnosis: two nodes can
	// share a network_id string and still be on different chains if one was
	// built from a stale genesis archive.
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

// NetworkGater enforces network_id and protocol version at the peer
// level. It implements connmgr.ConnectionGater to reject banned peers
// before stream negotiation, and runs a lightweight handshake protocol
// to ban peers whose network_id or version doesn't match ours.
type NetworkGater struct {
	mu          sync.RWMutex
	banDur      time.Duration
	networkID   string
	genesisHash string
	// minVersion is the governance-set protocol floor from
	// sys.min_protocol_version (#830); empty means no floor.
	minVersion string
	// caps records what each peer advertised in its handshake (#830).
	caps *peerCapTable

	// trusted peers bypass the inbound slot cap and are never banned. This
	// is the peer-admission half of eclipse resistance; the connection
	// manager half is Protect() (see node.bootstrapWithRetry).
	trusted map[peer.ID]struct{}

	// bans is bounded and sweepable; see banstore.go.
	bans *banStore

	// inbound tracks established inbound connections for the slot split.
	// Maintained by the connection notifier in SetupNetworkCheck; when that
	// is not wired the count stays zero and the cap never engages
	// (fail-open, so a bare host in a test is unaffected).
	inbound        atomic.Int64
	maxInbound     int64
	inboundRefused atomic.Uint64

	// handshakes limits inbound netcheck streams.
	handshakes *peerRateLimiter

	banPath string

	// Mismatch bookkeeping (#839). A node pointed at the wrong genesis used to
	// fail as silence: every handshake was rejected, the peer count stayed 0,
	// and the only surface symptom was "connection reset by peer" from the
	// remote side closing first. Recording what we actually saw lets the node
	// tell the operator which network it landed on instead.
	rejects      int
	aborted      int
	lastMismatch *NetworkMismatch
}

// NetworkMismatch is the last identity disagreement observed in a completed
// handshake — what we presented, and what the peer presented back.
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
		// Peer capability table from the sys.activations handshake (#830).
		caps: newPeerCapTable(),
	}
}

// SetMaxInboundConns overrides the inbound connection cap. A value <= 0
// disables the cap.
func (g *NetworkGater) SetMaxInboundConns(n int) {
	atomic.StoreInt64(&g.maxInbound, int64(n))
}

// Trust marks peers as trusted: they are exempt from the inbound slot cap and
// cannot be banned. Bootstrap peers supplied by the operator are the intended
// use — an operator-chosen peer is the one link an eclipse attacker must not
// be able to squeeze out.
func (g *NetworkGater) Trust(pids ...peer.ID) {
	g.mu.Lock()
	for _, p := range pids {
		g.trusted[p] = struct{}{}
	}
	g.mu.Unlock()
	// Trusting a peer clears any ban it picked up before it was known to be
	// an operator-chosen bootstrap.
	for _, p := range pids {
		g.bans.clear(p)
	}
}

// IsTrusted reports whether p is an operator-chosen peer. Exported for the
// gossip layer, which gives trusted peers an application score that no
// accumulation of penalties can overcome.
func (g *NetworkGater) IsTrusted(p peer.ID) bool {
	return g.isTrusted(p)
}

func (g *NetworkGater) isTrusted(p peer.ID) bool {
	g.mu.RLock()
	_, ok := g.trusted[p]
	g.mu.RUnlock()
	return ok
}

// BanStats reports the live ban count, total evictions and total sweeps, for
// observability and for asserting boundedness under flood.
func (g *NetworkGater) BanStats() (live int, evictions, sweeps uint64) {
	return g.bans.stats()
}

// InboundStats reports the current inbound connection count, the cap, and how
// many inbound connections have been refused because the cap was full.
func (g *NetworkGater) InboundStats() (current int64, max int64, refused uint64) {
	return g.inbound.Load(), atomic.LoadInt64(&g.maxInbound), g.inboundRefused.Load()
}

// HandshakeStats reports allowed/denied netcheck handshakes.
func (g *NetworkGater) HandshakeStats() (allowed, denied uint64) {
	a, d, _ := g.handshakes.stats()
	return a, d
}

// StartBanMaintenance loads any persisted ban set from dataDir and runs the
// periodic sweep-and-persist loop until ctx is done. Bans are soft state: any
// error is logged and ignored, never fatal.
//
// Persistence matters because the bans that are worth keeping are precisely
// the ones for stable identities (wrong network_id, incompatible version) —
// exactly the peers that reconnect after a restart. Bans of rotating
// identities are worthless either way.
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

// SetGenesisHash records this node's statechain genesis hash so it can be
// advertised in the handshake and named in mismatch diagnostics.
func (g *NetworkGater) SetGenesisHash(h string) {
	g.mu.Lock()
	g.genesisHash = h
	g.mu.Unlock()
}

// ourMsg builds the handshake message this node presents to peers: network id
// and genesis hash (#839) plus the version and feature list (#830). It is the
// single place the outbound message is constructed, so a field can never be
// advertised on one code path and omitted on the other.
//
// LocalFeatures is a sync.OnceValue over a registry written only from package
// init, so calling it under the gater's read lock takes no other lock.
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

// recordMismatch stores the details of a rejected handshake.
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

// noteHandshakeAborted records a handshake the remote closed before replying.
// That is the shape a network-id rejection takes on THIS side of the wire: the
// remote banned us and hung up, so we never see its identity. Counting these
// separately lets the join watchdog distinguish "nobody is home" from "we are
// being refused".
func (g *NetworkGater) noteHandshakeAborted() {
	g.mu.Lock()
	g.aborted++
	g.mu.Unlock()
}

// LastMismatch returns the most recent identity disagreement, the number of
// handshakes we rejected, and the number the remote aborted on us.
func (g *NetworkGater) LastMismatch() (last *NetworkMismatch, rejected, aborted int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastMismatch, g.rejects, g.aborted
}

func (g *NetworkGater) isBanned(p peer.ID) bool {
	return g.bans.banned(p)
}

// Ban bans a peer for the given duration. Trusted (operator-chosen) peers are
// never banned. Exported for adversarial drivers and for callers outside this
// package that detect protocol abuse.
func (g *NetworkGater) Ban(p peer.ID, d time.Duration) {
	g.banFor(p, d)
}

// IsBanned reports whether a peer is currently banned.
func (g *NetworkGater) IsBanned(p peer.ID) bool {
	return g.isBanned(p)
}

func (g *NetworkGater) ban(p peer.ID) {
	g.banFor(p, g.banDur)
}

func (g *NetworkGater) banFor(p peer.ID, d time.Duration) {
	if g.isTrusted(p) {
		// An operator-chosen bootstrap is never banned: a transient
		// misconfiguration on a bootstrap must not cost us the one link we
		// know is honest.
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
	// Inbound/outbound slot split (#840). Applied at InterceptSecured rather
	// than InterceptAccept because this is the first hook that knows the peer
	// identity, and trusted peers must be exempt.
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

// SetupNetworkCheck registers the netcheck protocol handler and a
// connection notifier that verifies every new peer's network_id and
// protocol version. Mismatched peers are disconnected and banned.
func SetupNetworkCheck(h host.Host, gater *NetworkGater) {
	h.SetStreamHandler(NetcheckProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		// Refuse the handshake before reading a byte when the peer (or the
		// network as a whole) is over budget. The netcheck handler is the
		// one protocol every stranger can reach before being admitted, so
		// it is the cheapest thing to abuse and must be the cheapest to
		// refuse (#840).
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

// checkPeer validates network_id, genesis hash and version from a remote
// peer's handshake message. Returns a non-empty reason string on rejection.
//
// ours is this node's own handshake message (network id + genesis hash +
// version), i.e. exactly what we presented to the peer. Reasons are
// written for a human reading a log line, not for a parser: they name what we
// expected AND what arrived, because the operator debugging this has exactly
// one question — which network am I on, and which one is everyone else on.
func checkPeer(msg netcheckMsg, ours netcheckMsg) (reason string, banDuration time.Duration) {
	// When we have a network_id configured, require the peer to present a
	// matching one. #570/M7: previously an EMPTY remote network_id bypassed this
	// gate (the check only fired when msg.NetworkID was non-empty), letting a
	// deliberate empty-id peer stay connected and occupy a slot. The version
	// field used to be optional too; #830 made it mandatory whenever we have a
	// network id, closing the same shape of bypass (see TestCheckPeer_NoVersion).
	if ours.NetworkID != "" {
		if msg.NetworkID == "" {
			return "missing network_id (we are on " + ours.NetworkID + "); peer is running a build whose genesis sets no sys.network_id", defaultBanDur
		}
		if msg.NetworkID != ours.NetworkID {
			return fmt.Sprintf("network_id mismatch: peer is on %q, we are on %q — one of us is running the wrong genesis (see --genesis-dir)",
				msg.NetworkID, ours.NetworkID), defaultBanDur
		}
	}

	// Same network_id, different chain start: two genesis documents can carry
	// the same sys.network_id and still disagree on the treasury, the DAO
	// keyset or the ops order (the statechain genesis is hashed byte-exactly,
	// whitespace and op order included). Without this the pair peers happily
	// and then diverges at the first block. Optional on both sides so a node
	// that predates the field is not banned for omitting it (#839).
	if ours.GenesisHash != "" && msg.GenesisHash != "" && msg.GenesisHash != ours.GenesisHash {
		// %q on the REMOTE value, always: it is attacker-controlled bytes on
		// their way into a log file, and an unquoted newline in it forges log
		// lines. Same reason network_id is quoted above.
		return fmt.Sprintf("statechain genesis mismatch on network %q: peer genesis %q, ours %s — same network id, different chain start",
			ours.NetworkID, msg.GenesisHash, ours.GenesisHash), defaultBanDur
	}

	// #830: version is MANDATORY once we have a network id. It was optional,
	// and the gate only fired on a non-empty field — so any node could opt out
	// of the compatibility rule by omitting it, which made the drift rule and
	// the sys.min_protocol_version floor both trivially bypassable. Every XE
	// build has always SENT the field, so requiring it breaks nothing.
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
		// Transport-level failure: the peer is unreachable or still mounting
		// its protocols (mid-restart), not provably hostile. Close but do NOT
		// ban — banning here made every serial bootstrap roll self-partition
		// the mesh for the full ban window, with the watchdog's own redials
		// gater-blocked (#637). Bans are reserved for a COMPLETED handshake
		// presenting a wrong network_id or version.
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
		// THE silent failure (#839). When our identity is the wrong one, the
		// remote completes ITS check first, bans us and closes the connection —
		// so our read fails with "connection reset by peer" and this function
		// used to return without a word. The operator saw peer_count 0 and no
		// explanation anywhere. Say it out loud; the join watchdog in node/
		// turns a run of these into the full diagnostic.
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
