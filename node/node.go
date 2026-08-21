package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/metrics"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

// Node ties together a ledger, libp2p host, and gossip layer.
type Node struct {
	Ledger                 *core.Ledger
	Host                   host.Host
	Gossip                 *xenet.Gossip
	VoteGossip             *xenet.VoteGossip
	MarketGossip           *xenet.MarketplaceGossip
	StateChain             *statechain.Chain
	StateChainGossip       *xenet.StateChainGossip
	DirGossip              *xenet.DirectoryGossip
	Msg                    *xenet.Messenger
	Directory              *directory.Directory
	DHT                    *dht.IpfsDHT
	ChatStore              *chat.ChatStore
	KeyPair                *core.KeyPair
	VoteMgr                *core.VoteManager
	QuorumMgr              *core.QuorumManager
	store                  core.Store
	supplyOnce             sync.Once
	supplyAuditor          *core.SupplyAuditor
	difficulty             uint64
	chatDifficulty         uint64
	version                string
	isProvider             bool
	providerVCPUs          uint64
	providerMemoryMB       uint64
	providerDiskGB         uint64
	providerPriceMultMilli uint64                           // scaled ×1000; 0 = baseline (1000). See #297.
	acceptPolicy           LeaseAcceptPolicy                // local auto-accept filter; zero = permissive. See #229.
	VMManager              vm.Manager                       // nil for non-providers
	perfCert               atomic.Pointer[perf.Certificate] // provider's current performance certificate (#570/L2: written by the cert goroutine, read by many handlers)
	CertGossip             *xenet.CertificateGossip
	certCache              *certSet // certificates held by this node, keyed by hash (#816); use n.certs()
	certsOnce              sync.Once

	// Attestation rate-limit state (#634): per "peerID:identifier" last-served
	// time; the slot is recorded only after a request passes validation.
	attRateMu        sync.Mutex
	attRateMap       map[string]time.Time
	consumerVMs      sync.Map // leaseHash → *vm.Info
	pendingOffersMu  sync.Mutex
	pendingOffers    map[string]*xenet.ResourceOffer // requestID → offer
	providerAds      sync.Map                        // account → *xenet.ResourceAdvertisement
	blockCreateMu    sync.Mutex                      // serializes all block creation to prevent self-equivocation
	reservedRes      vm.Resources                    // resources reserved by in-flight provisions (guarded by blockCreateMu)
	reservedResMu    sync.Mutex
	syncTracker      *xenet.SyncTracker
	syncWait         func()
	gater            *xenet.NetworkGater // #830: holds the sys.min_protocol_version floor and the peer capability table; #839: advertises the genesis hash and records identity mismatches
	activationLog    *activationReporter // #830: de-duplicates the activation/upgrade log lines
	tunnelRegistry   *xenet.TunnelRegistry
	acceptInFlight   map[string]struct{}
	acceptInFlightMu sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// Config holds parameters for creating a Node.
type Config struct {
	Port       int
	DialAddrs  []string
	DataDir    string
	Difficulty uint64 // 0 = no PoW check (tests); default = core.DefaultDifficulty
	// ChatDifficulty is the anti-spam PoW threshold for chat envelopes.
	// 0 = derive: disabled when Difficulty is 0 (PoW-off dev/test nodes),
	// otherwise chat.DefaultPoWDifficulty.
	ChatDifficulty uint64
	DisableMDNS    bool
	Store          core.Store // optional; if nil, opens BadgerStore at DataDir
	Version        string
	Provide        bool   // if true, this node provides compute
	VCPUs          uint64 // vCPUs to offer
	MemoryMB       uint64 // memory in MB to offer
	DiskGB         uint64 // disk in GB to offer
	// PriceMultiplierMilli, if non-zero, is embedded on this provider's
	// performance certificate. Scaled ×1000 (1000 = baseline). Bounds
	// 500..10000 enforced. Sim-only — production perf-weighted pricing
	// requires the anti-cheat chain in #213/#214/#215. See #297.
	PriceMultiplierMilli uint64
	// AcceptPolicy is the local provider-side filter applied to incoming
	// leases before the stake/resource/cert gates in autoAcceptLease.
	// Zero value = permissive (no constraint), preserving pre-#229 behaviour.
	AcceptPolicy  LeaseAcceptPolicy
	GenesisBlock  *statechain.Block // optional; if nil, uses embedded genesis
	MsgTTL        time.Duration     // account registration TTL; 0 = 30 minutes
	LimactlPath   string            // path to limactl binary; empty = "limactl"
	MaxConnsPerIP int               // per-IP inbound connection limit; 0 = default (8)
	// MaxInboundConns caps simultaneous INBOUND connections, reserving the
	// rest of the connection budget for peers this node chose to dial. 0 =
	// default (256); negative disables the split. Eclipse resistance (#840).
	MaxInboundConns int
	// DisableDiscovery turns off the ambient DHT rendezvous loop. Tests and
	// closed deployments set this; a public node should not.
	DisableDiscovery bool
	// DiscoveryTarget is the peer count at or above which ambient discovery
	// stops dialling. 0 = default (24).
	DiscoveryTarget int
}

// New creates a Node from the given Config.
func New(ctx context.Context, cfg Config) (*Node, error) {
	ctx, cancel := context.WithCancel(ctx)

	gater := xenet.NewNetworkGater()
	if cfg.MaxInboundConns != 0 {
		gater.SetMaxInboundConns(cfg.MaxInboundConns)
	}
	// Bans are bounded in memory and persisted across restarts (#840). The
	// bans worth keeping are for stable identities — wrong network_id, an
	// incompatible version — which are exactly the peers that reconnect after
	// a restart.
	gater.StartBanMaintenance(ctx, cfg.DataDir)

	// Resolve the statechain genesis and set the network id BEFORE the host
	// exists: the id lives in the genesis ops and can never change after
	// genesis (it is bound into every block hash). Waiting for the statechain
	// replay to rebuild the KV left this node answering netcheck with an
	// empty network_id for the entire replay window — a completed handshake
	// that every remote peer bans for 10 minutes (#652, with #637/#649).
	scGenesis := cfg.GenesisBlock
	if scGenesis == nil {
		var gerr error
		scGenesis, gerr = statechain.LoadGenesis()
		if gerr != nil {
			cancel()
			return nil, fmt.Errorf("statechain genesis: %w", gerr)
		}
	}
	// Advertise the statechain genesis hash alongside the network id (#839).
	// Two genesis documents can share a network_id and still be different
	// chains; carrying the hash in the handshake turns that from a silent
	// divergence into a named rejection.
	gater.SetGenesisHash(scGenesis.Hash)
	if id := statechain.NetworkIDFromGenesis(scGenesis); id != "" {
		core.SetNetworkID(id)
		gater.SetNetworkID(id)
		log.Printf("Network ID (from genesis): %s", id)
		log.Printf("Statechain genesis: %s", scGenesis.Hash)
	} else {
		log.Printf("WARNING: genesis sets no sys.network_id — this node will be banned by every peer that completes a handshake with it (#652)")
	}

	h, err := xenet.NewHost(ctx, cfg.Port, cfg.DataDir, cfg.Version, true, gater, cfg.MaxConnsPerIP)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("host: %w", err)
	}

	// Register the netcheck protocol handler immediately so that incoming
	// connections during the rest of init find the handler. The gater already
	// carries the genesis network id, so peers handshaking while the rest of
	// init (statechain replay etc.) runs get the real id, not an empty one.
	xenet.SetupNetworkCheck(h, gater)

	ps, err := xenet.NewPubSub(ctx, h, xenet.GossipConfig{
		Difficulty: cfg.Difficulty,
		Trusted:    gater.IsTrusted,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("pubsub: %w", err)
	}

	gossip, err := xenet.NewGossip(ctx, h, ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gossip: %w", err)
	}

	voteGossip, err := xenet.NewVoteGossip(ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("vote gossip: %w", err)
	}

	marketGossip, err := xenet.NewMarketplaceGossip(ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("marketplace gossip: %w", err)
	}

	dirGossip, err := xenet.NewDirectoryGossip(ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("directory gossip: %w", err)
	}

	certGossip, err := xenet.NewCertificateGossip(ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("certificate gossip: %w", err)
	}

	dir := directory.New(cfg.MsgTTL)

	if !cfg.DisableMDNS {
		if err := xenet.SetupDiscovery(ctx, h); err != nil {
			cancel()
			return nil, fmt.Errorf("mdns: %w", err)
		}
	}

	if cfg.Difficulty == 0 {
		log.Printf("WARNING: PoW difficulty is 0 — proof-of-work validation disabled")
	}

	chatDifficulty := cfg.ChatDifficulty
	if chatDifficulty == 0 && cfg.Difficulty != 0 {
		chatDifficulty = chat.DefaultPoWDifficulty
	}

	kp, err := loadOrCreateKeyPair(cfg.DataDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("keypair: %w", err)
	}

	s := cfg.Store
	if s == nil {
		s, err = store.NewBadgerStore(filepath.Join(cfg.DataDir, "ledger"))
		if err != nil {
			cancel()
			return nil, fmt.Errorf("store: %w", err)
		}
	}

	// Refuse to boot a data dir that belongs to a different network before
	// NewLedger reaches its opaque panic (#839). Cheap: one keyed read on the
	// happy path.
	if err := preflightDataDirGenesis(s, cfg.DataDir); err != nil {
		cancel()
		return nil, err
	}

	// Placeholder — timekeeperConfigFn is set after statechain init below.
	var timekeeperConfigFn func() *core.TimekeeperConfig

	// Placeholder — minterConfigFn is set after statechain init below.
	var minterConfigFn func() *core.MinterConfig

	// Placeholder — repConfigFn is set after statechain init below (#832).
	var repConfigFn func() *core.RepresentativeConfig

	// Placeholders — epoch lookup functions are set after statechain init below.
	var epochRFn func() uint64
	var epochPayoutCapFn func() uint64
	var epochTWAPFn func() uint64
	var epochAtFn func(ns int64) []core.EpochParams

	// Placeholder — the activation reader is set after statechain init below.
	var featureActiveFn func(feature string) bool

	// Certificate lookup is wired after the node is created (needs cert cache).
	var certLookupFn func(hash string) *core.CertificateInfo
	ledger := core.NewLedger(s, core.LedgerConfig{
		Difficulty:          cfg.Difficulty,
		TimestampWindow:     core.DefaultTimestampWindow,
		TimekeeperConfigFn:  func() *core.TimekeeperConfig { return timekeeperConfigFn() },
		MinterConfigFn:      func() *core.MinterConfig { return minterConfigFn() },
		CertificateLookupFn: func(hash string) *core.CertificateInfo { return certLookupFn(hash) },
		EpochRFn:            func() uint64 { return epochRFn() },
		EpochPayoutCapFn:    func() uint64 { return epochPayoutCapFn() },
		EpochTWAPFn:         func() uint64 { return epochTWAPFn() },
		EpochAtFn:           func(ns int64) []core.EpochParams { return epochAtFn(ns) },
		FeatureActiveFn:     func(feature string) bool { return featureActiveFn(feature) },
	})

	// Wire voting and quorum for conflict resolution.
	// Both BadgerStore and MemStore implement all optional interfaces.
	vs := s.(core.VoteStore)
	cs := s.(core.ConflictStore)
	qs := s.(core.QuorumStore)
	voteMgr := core.NewVoteManager(vs, kp, ledger)
	quorumMgr := core.NewQuorumManager(qs, cs, vs, ledger)
	voteMgr.SetQuorumManager(quorumMgr)
	quorumMgr.StartStaleConflictSweep(ctx.Done())
	quorumMgr.RevoteFn = func(account, previous string) { voteMgr.CastVote(account, previous) } // re-drive elections during the stale sweep (#526)
	quorumMgr.OnFinalized = voteMgr.SweepFrontiers                                              // re-drive dependents immediately on finalize (#526)
	ledger.SetConflictCallback(voteMgr.OnConflict)
	ledger.SetBlockAddedCallback(voteMgr.OnBlockAdded) // per-block finalization trigger (#526)

	// Frontier finalization sweep: liveness backstop that re-drives voting for any
	// unfinalized account frontier (e.g. a vote withheld until a dependency
	// finalized, or a block whose add-trigger this node missed). (#526)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				voteMgr.SweepFrontiers()
			}
		}
	}()

	// Wire vote emitter to broadcast votes via gossip.
	voteMgr.VoteEmitter = func(v *core.Vote) {
		if err := voteGossip.Publish(ctx, v); err != nil {
			log.Printf("vote broadcast failed: %v", err)
		}
	}

	// Register sync protocol for frontier exchange on peer connect.
	syncTracker, syncWait := xenet.SetupSync(ctx, h, ledger)

	dhtInst, err := xenet.SetupDHT(ctx, h)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dht: %w", err)
	}

	// Ambient peer discovery (#840): without it a node's honest peer set is
	// exactly its --dial list, which makes every stranger's view of the chain
	// depend on whoever runs the bootstraps.
	if !cfg.DisableDiscovery {
		xenet.StartAmbientDiscovery(ctx, h, dhtInst, statechain.NetworkIDFromGenesis(scGenesis), cfg.DiscoveryTarget)
	}

	msg := xenet.NewMessenger(h, dhtInst)

	chatStore := chat.NewChatStore(1000)

	// State chain: gossip, initialize chain (replays the stored chain), sync.
	// scGenesis was resolved before the host came up so its network id could
	// be set pre-handshake (#652).
	scGossip, err := xenet.NewStateChainGossip(ps)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("statechain gossip: %w", err)
	}

	scStore := s.(statechain.StateChainStore)
	sc, err := statechain.NewChain(scStore, scGenesis)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("statechain: %w", err)
	}

	statechain.SetupSync(h, sc)

	// Re-assert the network ID from the replayed state chain. Normally a
	// no-op (genesis already set it pre-host, #652); kept as the consistency
	// backstop should the KV ever disagree with the genesis ops.
	if raw, ok := sc.GetKV("sys.network_id"); ok {
		var networkID string
		if json.Unmarshal(raw, &networkID) == nil && networkID != "" {
			if g := statechain.NetworkIDFromGenesis(scGenesis); g != "" && g != networkID {
				logging.Warnf("WARNING: statechain KV network_id %q != genesis network_id %q — keeping KV value", networkID, g)
			}
			core.SetNetworkID(networkID)
			gater.SetNetworkID(networkID)
			log.Printf("Network ID: %s", networkID)
		}
	}

	// Now that statechain is initialized, wire the timekeeper config function.
	// This closure is captured by the ledger's TimekeeperConfigFn above.
	timekeeperConfigFn = func() *core.TimekeeperConfig {
		raw, ok := sc.GetKV("sys.timekeepers")
		if !ok {
			return nil
		}
		var config core.TimekeeperConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil
		}
		if config.Threshold == 0 || len(config.Keys) == 0 {
			return nil
		}
		return &config
	}

	// Wire the minter config function (sys.minter). Captured by the ledger's
	// MinterConfigFn above. Returns nil when sys.minter is absent or empty, in
	// which case no account can mint XUSD.
	minterConfigFn = func() *core.MinterConfig {
		raw, ok := sc.GetKV("sys.minter")
		if !ok {
			return nil
		}
		var config core.MinterConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil
		}
		if len(config.Keys) == 0 {
			return nil
		}
		return &config
	}

	// Wire the activation reader (#830). It is the state chain and nothing
	// else: sys.activations as of the converged tip, evaluated against that
	// same tip's index and timestamp. No local clock, no config, no peer set —
	// the #501 invariant, restated for feature gates.
	featureActiveFn = func(feature string) bool {
		return sc.FeatureActive(feature)
	}

	// Wire the representative-eligibility policy (sys.representatives, #832).
	// Captured by ledger.SetRepresentativeConfigFn below. Absent, malformed or
	// mode "open" all mean unrestricted — the quorum denominator then counts
	// every representative, exactly as it did before the key existed.
	//
	// The parsed value is cached on the raw bytes: this closure is on the vote
	// path (every GetVoteWeight lookup), and it must return a STABLE pointer
	// while the key is unchanged so the ledger's own cache hits. A statechain
	// write swaps the bytes, the pointer changes, and both caches refresh.
	var repCfgMu sync.Mutex
	var repCfgRaw string
	var repCfgVal *core.RepresentativeConfig
	repConfigFn = func() *core.RepresentativeConfig {
		raw, ok := sc.GetKV("sys.representatives")
		if !ok {
			return nil
		}
		repCfgMu.Lock()
		defer repCfgMu.Unlock()
		if string(raw) == repCfgRaw {
			return repCfgVal
		}
		var rc core.RepresentativeConfig
		if err := json.Unmarshal(raw, &rc); err != nil {
			log.Printf("WARN: sys.representatives is not valid JSON (%v) — treating the quorum denominator as unrestricted (#832)", err)
			repCfgRaw, repCfgVal = string(raw), nil
			return nil
		}
		repCfgRaw, repCfgVal = string(raw), &rc
		return repCfgVal
	}
	ledger.SetRepresentativeConfigFn(func() *core.RepresentativeConfig { return repConfigFn() })

	// Wire epoch lookup functions. All three scan epoch.* keys in the state
	// chain and read the latest epoch. R_effective drives emission magnitude;
	// payout_cap + TWAP drive the Hermite self-lease cap (returns 0 if the
	// epoch lacks the field, in which case the ledger treats the cap as
	// no-op). See "XE Token Economy Model" §Dual R Emission + v13 §Hermite Cap.
	latestEpoch := func() (statechain.EpochValue, bool) {
		epochs := sc.GetKVByPrefix("epoch.")
		var best statechain.EpochValue
		var found bool
		for _, raw := range epochs {
			var ev statechain.EpochValue
			if err := json.Unmarshal(raw, &ev); err != nil {
				continue
			}
			if !found || ev.Epoch > best.Epoch {
				best = ev
				found = true
			}
		}
		return best, found
	}
	epochRFn = func() uint64 {
		ev, ok := latestEpoch()
		if !ok {
			return 0
		}
		return ev.REffective
	}
	epochPayoutCapFn = func() uint64 {
		ev, ok := latestEpoch()
		if !ok {
			return 0
		}
		return ev.PayoutCap
	}
	epochTWAPFn = func() uint64 {
		ev, ok := latestEpoch()
		if !ok {
			return 0
		}
		return ev.TWAPMilliUSD
	}
	// epochAtFn returns the emission params of the epoch active at unix-nanos ns:
	// the highest-numbered epoch whose StartNS <= ns (matching latestEpoch's
	// "latest published" semantics at ns = now). Used by the ledger to verify a
	// lease_accept's locked params match the canonical epoch-at-accept. Reads the
	// converged state chain, so it returns the same value on every node for a
	// given (signed, fixed) accept timestamp — see #501.
	// Returns the covering epoch and up to EpochLockTolerance predecessors,
	// newest first: an accept admitted before later epochs were published
	// locked the then-latest epoch's params, so re-validation (boundary races
	// #574, cold sync #630) must be able to check the publish-lag window.
	epochAtFn = func(ns int64) []core.EpochParams {
		epochs := sc.GetKVByPrefix("epoch.")
		var active []statechain.EpochValue
		for _, raw := range epochs {
			var ev statechain.EpochValue
			if err := json.Unmarshal(raw, &ev); err != nil {
				continue
			}
			if ev.StartNS > ns {
				continue // not yet active at the accept time
			}
			active = append(active, ev)
		}
		if len(active) == 0 {
			return nil
		}
		sort.Slice(active, func(i, j int) bool { return active[i].Epoch > active[j].Epoch })
		if len(active) > core.EpochLockTolerance+1 {
			active = active[:core.EpochLockTolerance+1]
		}
		out := make([]core.EpochParams, 0, len(active))
		for _, ev := range active {
			out = append(out, core.EpochParams{R: ev.REffective, PayoutCap: ev.PayoutCap, TWAP: ev.TWAPMilliUSD})
		}
		return out
	}

	n := &Node{
		Ledger:                 ledger,
		Host:                   h,
		Gossip:                 gossip,
		VoteGossip:             voteGossip,
		MarketGossip:           marketGossip,
		StateChain:             sc,
		StateChainGossip:       scGossip,
		DirGossip:              dirGossip,
		CertGossip:             certGossip,
		Msg:                    msg,
		Directory:              dir,
		DHT:                    dhtInst,
		ChatStore:              chatStore,
		KeyPair:                kp,
		VoteMgr:                voteMgr,
		QuorumMgr:              quorumMgr,
		store:                  s,
		difficulty:             cfg.Difficulty,
		chatDifficulty:         chatDifficulty,
		version:                cfg.Version,
		isProvider:             cfg.Provide,
		providerVCPUs:          cfg.VCPUs,
		providerMemoryMB:       cfg.MemoryMB,
		providerDiskGB:         cfg.DiskGB,
		providerPriceMultMilli: cfg.PriceMultiplierMilli,
		acceptPolicy:           cfg.AcceptPolicy,
		syncTracker:            syncTracker,
		syncWait:               syncWait,
		gater:                  gater,
		activationLog:          newActivationReporter(),
		pendingOffers:          make(map[string]*xenet.ResourceOffer),
		acceptInFlight:         make(map[string]struct{}),
		ctx:                    ctx,
		cancel:                 cancel,
	}

	// #830: seed the governance version floor and print the activation state
	// once at boot, before any peer handshake, so an operator sees an
	// upgrade warning in the first screen of logs rather than after the fact.
	n.syncActivationPolicy()

	// …and again on every state-chain movement, whichever path delivered it:
	// gossip, the gap resync (#656) or the startup sync. The callback fires
	// while AddBlock holds the chain mutex and syncActivationPolicy re-takes
	// it, so the refresh runs on its own goroutine — a self-deadlock here
	// would freeze the whole state chain, not just the reporting.
	sc.SetOnBlock(func(*statechain.Block) { go n.syncActivationPolicy() })

	n.registerAttestationHandler()
	// Wire certificate lookup for ledger validation.
	certLookupFn = n.certificateInfoByHash

	n.registerVMHandlers()
	n.registerChatHandler()

	if n.isProvider {
		// Providers MUST have timekeepers configured — without attested
		// timestamps, leases cannot be accepted or settled.
		if raw, ok := sc.GetKV("sys.timekeepers"); !ok || len(raw) == 0 {
			cancel()
			return nil, fmt.Errorf("provider mode requires sys.timekeepers in state chain — cannot start without trusted timekeepers")
		}

		if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
			cancel()
			return nil, fmt.Errorf("provider mode requires /dev/kvm access — add the service user to the kvm group or set SupplementaryGroups=kvm in the systemd unit: %w", err)
		} else {
			_ = f.Close()
		}

		vmm, err := vm.NewLimaManager(cfg.DataDir, cfg.LimactlPath)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("lima manager: %w", err)
		}
		n.VMManager = vmm
		n.tunnelRegistry = xenet.NewTunnelRegistry()
		log.Printf("Provider mode (lima): %d vCPUs, %d MB memory, %d GB disk", n.providerVCPUs, n.providerMemoryMB, n.providerDiskGB)
		if !n.acceptPolicy.IsZero() {
			log.Printf("Provider auto-accept policy: duration=[%ds, %ds] cost=[%d, %d] XUSD max_concurrent=%d (0=unset)",
				n.acceptPolicy.MinDurationSec, n.acceptPolicy.MaxDurationSec,
				n.acceptPolicy.MinCostXUSD, n.acceptPolicy.MaxCostXUSD,
				n.acceptPolicy.MaxConcurrent)
		}
		xenet.SetupTunnelHandler(h, n, n.tunnelRegistry)

		// Generate performance certificate in the background (needs peers for
		// attestations). Waits for a peer to actually connect rather than a fixed
		// delay, then retries until the certificate is issued — a provider that
		// fails this once on a cold boot is unleasable until restarted (#812).
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if !n.waitForAttestationPeers() {
				return
			}
			certGenerationLoop(n.ctx, n.generatePerformanceCertificate, certRetryInitialDelay, certRetryMaxDelay)
		}()

		// Periodically re-broadcast the cert so post-wipe peers can recover (#409).
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.certRebroadcastLoop()
		}()
	}

	// Auto-register node's own account in directory.
	n.selfRegister()

	// Start listening for gossiped blocks, votes, marketplace, state chain, directory, and certificates.
	n.wg.Add(9)
	go func() { defer n.wg.Done(); n.handleIncoming(gossip.Subscribe(ctx)) }()
	go func() { defer n.wg.Done(); n.handleIncomingVotes(voteGossip.Subscribe(ctx)) }()
	go func() { defer n.wg.Done(); n.handleMarketplace(marketGossip.Subscribe(ctx)) }()
	go func() { defer n.wg.Done(); n.settleLoop() }()
	go func() { defer n.wg.Done(); n.handleStateChain(scGossip.Subscribe(ctx)) }()
	go func() { defer n.wg.Done(); n.handleDirectoryGossip(dirGossip.Subscribe(ctx)) }()
	go func() { defer n.wg.Done(); n.directoryPruneLoop() }()
	go func() { defer n.wg.Done(); n.directoryReRegisterLoop() }()
	go func() { defer n.wg.Done(); n.handleCertificateGossip(certGossip.Subscribe(ctx)) }()

	// #502: pull certificates from peers on connect so a restarted or
	// late-joining node can validate cert-referencing lease blocks immediately,
	// instead of waiting up to 5 minutes for the next gossip rebroadcast. Wired
	// for all nodes — a non-provider restarting into a backlog of lease blocks
	// is the common catch-up case. Best-effort; gossip remains the backstop.
	// Re-seed the certificate cache from the store before serving pulls — a
	// restarted node must keep serving certs for the lease history it holds
	// even when the original provider's gossip is long gone (#630).
	n.loadPersistedCertificates()
	xenet.SetupCertSync(ctx, n.Host, n.Msg, n.collectCertificates, n.ingestCertificate)

	// #540: serve and pull conflicting block bodies by hash. When two equivocated
	// siblings race to two nodes, the sibling HASHES cross-propagate (via votes,
	// forming a conflict record naming both) but the sibling BODIES do not — gossip
	// missed one and the frontier-sync server refuses to backfill an unrecognised
	// frontier. With only one body a node cannot run weighted 2-block voting, so the
	// account stalls. PhantomPullFn asks peers for the missing sibling body by hash;
	// once both bodies are present the existing weight-gated voting resolves the fork.
	xenet.SetupBlockSync(n.Msg, n.Ledger.GetBlockOrStaged)
	n.QuorumMgr.PhantomPullFn = n.pullPhantomBlocks

	// #703: serve and pull votes by conflict position. Frontier-sync carries block
	// bodies but no finalization state, so a node holding its own non-final losing
	// fork at a position stages the network winner as a conflict it can never
	// resolve from local votes (the network finalized the winner and, after the
	// post-finalization cleanup deleted everyone's votes, won't re-gossip them).
	// VotePullFn asks peers for their votes at the position; a peer that finalized
	// the child answers with a fresh signed final vote, which ReceiveVote ingests
	// to drive the weight-gated tally and reorg the laggard off its losing fork.
	xenet.SetupVoteSync(n.Msg, n.VoteMgr.VotesForPosition)
	n.QuorumMgr.VotePullFn = n.pullConflictVotes

	// Dial bootstrap peers with retry.
	if len(cfg.DialAddrs) > 0 {
		n.bootstrapWithRetry(cfg.DialAddrs)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.joinDiagnosticLoop()
		}()
	}

	// Re-gossip directory registration after peers connect.
	// We check repeatedly because bootstrap may take a while when all nodes
	// restart simultaneously.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if len(n.Host.Network().Peers()) > 0 {
					n.selfRegister()
					if n.isProvider {
						n.advertiseResources()
					}
					return
				}
			case <-n.ctx.Done():
				return
			}
		}
	}()

	// Provider: periodically advertise resources and check for unaccepted leases.
	if n.isProvider {
		n.wg.Add(2)
		go func() {
			defer n.wg.Done()
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n.advertiseResources()
				case <-n.ctx.Done():
					return
				}
			}
		}()
		go func() {
			defer n.wg.Done()
			n.leaseWatchLoop()
		}()
	}

	return n, nil
}

// bootstrapWithRetry dials bootstrap peers and runs a permanent watchdog that
// re-dials any disconnected bootstrap every 30s for the lifetime of the node.
func (n *Node) bootstrapWithRetry(addrs []string) {
	var targets []peer.AddrInfo
	for _, addr := range addrs {
		pi, err := xenet.ParsePeerAddr(addr)
		if err != nil {
			logging.Warnf("Invalid bootstrap addr %s: %v", addr, err)
			continue
		}
		targets = append(targets, *pi)
	}

	// Eclipse resistance (#840): bootstrap peers are operator-chosen, so they
	// are protected in the connection manager (never trimmed), exempt from
	// the inbound slot cap, unbannable, and scored so gossip peer scoring can
	// never graylist them. An attacker who fills every other slot still
	// cannot displace the links the operator configured.
	pids := make([]peer.ID, 0, len(targets))
	for _, pi := range targets {
		pids = append(pids, pi.ID)
	}
	xenet.ProtectPeers(n.Host, n.gater, "xe-bootstrap", pids...)

	for _, pi := range targets {
		dialCtx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		if err := n.Host.Connect(dialCtx, pi); err != nil {
			log.Printf("Bootstrap dial %s %s → failed: %v", pi.ID.ShortString(), pi.Addrs, err)
		} else {
			log.Printf("Bootstrap dial %s %s → connected", pi.ID.ShortString(), pi.Addrs)
		}
		cancel()
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				connected := n.Host.Network().Peers()
				connSet := make(map[peer.ID]bool, len(connected))
				for _, p := range connected {
					connSet[p] = true
				}

				for _, pi := range targets {
					if connSet[pi.ID] {
						continue
					}
					dialCtx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
					if err := n.Host.Connect(dialCtx, pi); err != nil {
						log.Printf("Bootstrap watchdog: dial %s failed: %v", pi.ID.ShortString(), err)
					} else {
						log.Printf("Bootstrap watchdog: reconnected to %s", pi.ID.ShortString())
					}
					cancel()
				}
			}
		}
	}()
}

func (n *Node) handleIncoming(blocks <-chan *core.Block) {
	for b := range blocks {
		// Skip blocks for our own account (GossipSub echoes back our own
		// publishes). This is equivalent to a peer-identity check because
		// only the account key holder can create valid blocks for an account.
		if b.Account == n.KeyPair.Address() {
			continue
		}
		err := n.Ledger.AddBlock(b)
		if err != nil {
			// Per-block, per-rejection: one of the two hottest log lines in the
			// tree. The rate belongs in a metric; the detail belongs at debug
			// (#841).
			metrics.BlocksAdded.WithLabelValues("gossip_rejected").Inc()
			logging.Debugf("Rejected block %s: %v", shortHash(b.Hash), err)
		} else {
			metrics.BlocksAdded.WithLabelValues("gossip").Inc()
			logging.Debugf("Accepted block %s (%s on %s)", shortHash(b.Hash), b.Type, shortAddr(b.Account))
			n.syncTracker.MarkDirty()
			// Auto-accept lease blocks addressed to this provider.
			if b.Type == core.BlockLease && b.Destination == n.KeyPair.Address() && n.isProvider {
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					n.autoAcceptLease(b)
				}()
			}
			// Mark consumer VM as stopped when we see a lease_settle.
			// Store a new copy rather than mutating the shared pointer
			// to avoid a data race with concurrent readers.
			if b.Type == core.BlockLeaseSettle && b.Source != "" {
				if v, ok := n.consumerVMs.Load(b.Source); ok {
					old := v.(*vm.Info)
					updated := *old
					updated.Status = "stopped"
					updated.Credentials = nil
					n.consumerVMs.Store(b.Source, &updated)
				}
			}
		}
	}
}

func (n *Node) handleIncomingVotes(votes <-chan *core.Vote) {
	for v := range votes {
		if err := n.VoteMgr.ReceiveVote(v); err != nil {
			metrics.VotesIngested.WithLabelValues("rejected").Inc()
			logging.Debugf("Rejected vote from %s: %v", shortHash(v.RepPubKey), err)
			continue
		}
		metrics.VotesIngested.WithLabelValues("accepted").Inc()
		// Weight that never votes still sits in the quorum denominator, so
		// "which representatives are actually participating" is a first-class
		// health signal, not a curiosity (#841). Recorded only for votes that
		// passed ReceiveVote's validation.
		//
		// Keyed by the rep's ADDRESS, not its public key: a vote carries the
		// key, but delegated weight is keyed by address (#829), and the
		// activity set is joined against the ledger's weight map. Recording
		// the key here would make every join miss and report a live network
		// as having no participating weight.
		metrics.RecordVote(v.RepAccount())
	}
}

// Send creates a send block and broadcasts it. Asset defaults to "XE" if empty.
func (n *Node) Send(destination string, amount uint64, asset string) error {
	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()
	if asset == "" {
		asset = "XE"
	}
	chain := n.Ledger.GetChain(n.KeyPair.Address())
	if len(chain) == 0 {
		return fmt.Errorf("account not open")
	}
	frontier := chain[len(chain)-1]
	assetBal := n.Ledger.GetAssetBalances(n.KeyPair.Address())[asset]
	if amount > assetBal {
		return fmt.Errorf("insufficient %s balance: have %d, sending %d", asset, assetBal, amount)
	}

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     n.KeyPair.Address(),
		Previous:    frontier.Hash,
		Balance:     assetBal - amount,
		Amount:      amount,
		Destination: destination,
		Timestamp:   core.Now().UnixNano(),
		Asset:       asset,
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		return fmt.Errorf("sign send block: %w", err)
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		return err
	}
	return n.Gossip.Publish(n.ctx, b)
}

// Receive creates receive blocks for all pending sends addressed to this account.
func (n *Node) Receive() (int, error) {
	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()
	myAddr := n.KeyPair.Address()
	pending := n.Ledger.GetPendingForAccount(myAddr)
	if len(pending) == 0 {
		return 0, nil
	}

	count := 0
	for _, p := range pending {
		chain := n.Ledger.GetChain(myAddr)
		prev := "0"
		if len(chain) > 0 {
			prev = chain[len(chain)-1].Hash
		}

		asset := p.Asset
		if asset == "" {
			asset = "XE" // legacy pending sends
		}
		assetBal := n.Ledger.GetAssetBalances(myAddr)[asset]
		if len(chain) == 0 {
			assetBal = 0
		}

		b := &core.Block{
			Type:      core.BlockReceive,
			Account:   myAddr,
			Previous:  prev,
			Balance:   assetBal + p.Amount,
			Source:    p.SendHash,
			Timestamp: core.Now().UnixNano(),
			Asset:     asset,
		}
		if err := core.SignBlock(b, n.KeyPair); err != nil {
			return count, fmt.Errorf("sign receive block: %w", err)
		}
		n.solvePoW(b)

		if err := n.Ledger.AddBlock(b); err != nil {
			return count, fmt.Errorf("receive %s: %w", shortHash(p.SendHash), err)
		}
		if err := n.Gossip.Publish(n.ctx, b); err != nil {
			return count, fmt.Errorf("publish receive: %w", err)
		}
		count++
	}
	return count, nil
}

// Address returns this node's ledger ACCOUNT ADDRESS — since #829 that is
// sha256("xe/account/v1" || pubkey), not the public key itself. The node's
// verifying key is n.KeyPair.PubKeyHex(); the two are different values and are
// not interchangeable.
func (n *Node) Address() string {
	return n.KeyPair.Address()
}

// GetBalance returns the current balance for an account (0 if not found).
func (n *Node) GetBalance(account string) uint64 {
	return n.Ledger.GetBalance(account)
}

// GetAssetBalances returns all asset balances for an account.
func (n *Node) GetAssetBalances(account string) map[string]uint64 {
	return n.Ledger.GetAssetBalances(account)
}

// GetSpendableBalances returns per-asset balances counting only finalized
// (irreversible) inflows — the funds safe to spend. (#528)
func (n *Node) GetSpendableBalances(account string) map[string]uint64 {
	return n.Ledger.SpendableBalances(account)
}

// IsBlockFinalized reports whether a block is finalized on its account's chain. (#528)
func (n *Node) IsBlockFinalized(account, hash string) bool {
	return n.Ledger.IsFinalized(account, hash)
}

// FinalHeight returns the account's final-height watermark (0 = nothing finalized). (#528)
func (n *Node) FinalHeight(account string) uint64 {
	return n.Ledger.FinalHeight(account)
}

// GetKeyset returns the multisig keyset for an account, or nil for single-key accounts.
func (n *Node) GetKeyset(account string) *core.Keyset {
	return n.Ledger.GetKeyset(account)
}

// GetReputation returns the reputation aggregate for an account, or nil if
// no lease activity has touched the account yet.
func (n *Node) GetReputation(account string) *core.ReputationAggregate {
	return n.Ledger.GetReputation(account)
}

// GetAllReputations returns every account's reputation aggregate.
func (n *Node) GetAllReputations() map[string]*core.ReputationAggregate {
	return n.Ledger.AllReputations()
}

// GetChain returns the ordered list of blocks for an account.
func (n *Node) GetChain(account string) []*core.Block {
	return n.Ledger.GetChain(account)
}

// GetBlock returns a block by hash, or nil if not found.
func (n *Node) GetBlock(hash string) *core.Block {
	return n.Ledger.GetBlock(hash)
}

// pullPhantomBlocks is QuorumManager.PhantomPullFn: it requests the bodies of an
// open conflict's missing sibling hashes from connected peers and ingests them
// via AddBlock, which routes a conflicting block into the conflict machinery
// (staging the second sibling). Once both bodies are present on a node the
// existing weight-gated voting resolves the fork. The pull runs asynchronously
// so this returns immediately (it is called under the quorum lock). (#540)
func (n *Node) pullPhantomBlocks(account, previous string, hashes []string) {
	if len(hashes) == 0 {
		return
	}
	want := append([]string(nil), hashes...)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		peers := n.Host.Network().Peers()
		if len(peers) == 0 {
			return
		}
		xenet.PullBlocks(n.ctx, n.Msg, peers, want, func(b *core.Block) error {
			if err := n.Ledger.AddBlock(b); err != nil {
				return err
			}
			n.syncTracker.MarkDirty()
			return nil
		})
	}()
}

// pullConflictVotes is QuorumManager.VotePullFn: it requests peers' votes at a
// conflict position the node is stuck on and ingests them via ReceiveVote, which
// re-drives the weight-gated tally. When the node holds its own non-final losing
// fork while the network finalized the sibling, each weighted peer answers with a
// fresh signed final vote for the finalized child (its stored votes were cleaned
// up post-finalization), so the laggard accumulates the quorum needed to reorg
// off its losing fork (confirmConflict → swapBlockLocked, finality wall intact).
// The pull runs asynchronously so this returns immediately (called under no lock
// by the sweep, but kept async to match PhantomPullFn). (#703)
func (n *Node) pullConflictVotes(account, previous string) {
	if account == "" {
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		peers := n.Host.Network().Peers()
		if len(peers) == 0 {
			return
		}
		if xenet.PullVotes(n.ctx, n.Msg, peers, account, previous, n.VoteMgr.ReceiveVote) > 0 {
			n.syncTracker.MarkDirty()
		}
	}()
}

// GetPending returns the list of unreceived sends addressed to account.
func (n *Node) GetPending(account string) []*core.PendingSend {
	return n.Ledger.GetPendingForAccount(account)
}

// GetFrontiers returns a map of account → frontier block hash.
func (n *Node) GetFrontiers() map[string]string {
	return n.Ledger.Frontiers()
}

// FrontierInfo describes the head block of an account chain along with the
// metadata needed to render a useful overview row.
type FrontierInfo struct {
	Account        string `json:"account"`
	Frontier       string `json:"frontier"`
	BlockType      string `json:"block_type"`
	Timestamp      int64  `json:"timestamp"`
	BlockCount     int    `json:"block_count"`
	Representative string `json:"representative,omitempty"`
}

// GetFrontiersDetailed returns one FrontierInfo per known account, enriched
// with the frontier block's type, timestamp, chain depth, and representative.
func (n *Node) GetFrontiersDetailed() []FrontierInfo {
	frontiers := n.Ledger.Frontiers()
	out := make([]FrontierInfo, 0, len(frontiers))
	for account, hash := range frontiers {
		info := FrontierInfo{Account: account, Frontier: hash}
		if b := n.Ledger.GetBlock(hash); b != nil {
			info.BlockType = string(b.Type)
			info.Timestamp = b.Timestamp
			info.Representative = b.Representative
		}
		info.BlockCount = len(n.Ledger.GetChain(account))
		out = append(out, info)
	}
	return out
}

// AccountSummary describes an account with balance and block count.
type AccountSummary struct {
	Address            string            `json:"address"`
	Balance            uint64            `json:"balance"`
	Balances           map[string]uint64 `json:"balances"`
	BlockCount         int               `json:"block_count"`
	Frontier           string            `json:"frontier"`
	LastBlockTimestamp int64             `json:"last_block_timestamp"`
}

// GetAllAccounts returns a summary for each account in the ledger.
func (n *Node) GetAllAccounts() []AccountSummary {
	frontiers := n.Ledger.Frontiers()
	out := make([]AccountSummary, 0, len(frontiers))
	for account, hash := range frontiers {
		chain := n.Ledger.GetChain(account)
		var balance uint64
		if len(chain) > 0 {
			balance = chain[len(chain)-1].Balance
		}
		var ts int64
		if len(chain) > 0 {
			ts = chain[len(chain)-1].Timestamp
		}
		out = append(out, AccountSummary{
			Address:            account,
			Balance:            balance,
			Balances:           n.Ledger.GetAssetBalances(account),
			BlockCount:         len(chain),
			Frontier:           hash,
			LastBlockTimestamp: ts,
		})
	}
	return out
}

// GetAllPending returns all unreceived sends across all accounts.
func (n *Node) GetAllPending() []*core.PendingSend {
	return n.Ledger.GetAllPending()
}

// GetSupply returns the aggregate supply position and conservation identity
// (#837). The auditor is created on first use and caches per-chain terms, so
// the steady-state cost is proportional to what changed rather than to the size
// of the lattice. Aggregate-only: it exposes no address and no per-account
// amount.
func (n *Node) GetSupply() *core.SupplyReport {
	n.supplyOnce.Do(func() { n.supplyAuditor = core.NewSupplyAuditor(n.Ledger) })
	return n.supplyAuditor.Report()
}

// GetRecentBlocks returns the most recent blocks across all chains.
func (n *Node) GetRecentBlocks(limit int) []*core.Block {
	return n.Ledger.GetRecentBlocks(limit)
}

func (n *Node) advertiseResources() {
	ad := &xenet.ResourceAdvertisement{
		Provider:            n.KeyPair.Address(),
		VCPUs:               n.providerVCPUs,
		MemoryMB:            n.providerMemoryMB,
		DiskGB:              n.providerDiskGB,
		MaxConcurrentLeases: n.acceptPolicy.MaxConcurrent,
		Timestamp:           core.Now().UnixNano(),
	}
	// #829: Provider is a ledger ADDRESS — GetProviders matches it against
	// lease.Provider and CreateLeaseBlock puts an offer's Provider straight into
	// Block.Destination, so it can never be a raw key. The verifying key travels
	// separately in ProviderPubKey, which SignAdvertisement fills from the
	// signing key itself (so it always matches the signature) and
	// VerifyAdvertisement checks derives Provider before checking the signature.
	xenet.SignAdvertisement(ad, n.KeyPair.Private)
	msg := &xenet.MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	}
	if err := n.MarketGossip.Publish(n.ctx, msg); err != nil {
		log.Printf("Failed to publish resource advertisement: %v", err)
	}
	// Also store our own ad
	n.providerAds.Store(ad.Provider, ad)
}

// ProviderInfo describes a compute provider's resources and lease activity.
type ProviderInfo struct {
	Account             string `json:"account"`
	VCPUs               uint64 `json:"vcpus"`
	MemoryMB            uint64 `json:"memory_mb"`
	DiskGB              uint64 `json:"disk_gb"`
	MaxConcurrentLeases uint64 `json:"max_concurrent_leases,omitempty"`
	UsedVCPUs           uint64 `json:"used_vcpus"`
	UsedMemoryMB        uint64 `json:"used_memory_mb"`
	UsedDiskGB          uint64 `json:"used_disk_gb"`
	ActiveLeases        int    `json:"active_leases"`
	TotalLeases         int    `json:"total_leases"`
	Timestamp           int64  `json:"timestamp"`
}

// GetProviders returns information about all known compute providers.
func (n *Node) GetProviders() []*ProviderInfo {
	leases := n.GetLeases()

	providers := make([]*ProviderInfo, 0)
	n.providerAds.Range(func(key, value any) bool {
		ad := value.(*xenet.ResourceAdvertisement)
		info := &ProviderInfo{
			Account:             ad.Provider,
			VCPUs:               ad.VCPUs,
			MemoryMB:            ad.MemoryMB,
			DiskGB:              ad.DiskGB,
			MaxConcurrentLeases: ad.MaxConcurrentLeases,
			Timestamp:           ad.Timestamp,
		}
		for _, l := range leases {
			if l.Provider == ad.Provider {
				info.TotalLeases++
				if !l.State.Terminal() {
					info.ActiveLeases++
					info.UsedVCPUs += l.VCPUs
					info.UsedMemoryMB += l.MemoryMB
					info.UsedDiskGB += l.DiskGB
				}
			}
		}
		providers = append(providers, info)
		return true
	})
	return providers
}

// GetConflicts returns conflict records for the given account.
func (n *Node) GetConflicts(account string) []*core.Conflict {
	return n.Ledger.GetConflictsForAccount(account)
}

// GetAllConflicts returns all conflict records across all accounts.
func (n *Node) GetAllConflicts() []*core.Conflict {
	return n.Ledger.GetAllConflicts()
}

// DelegationInfo summarises representative vote weights (#515) and how much of
// that weight the representative-eligibility policy is holding out of the quorum
// denominator (#832).
type DelegationInfo struct {
	// Weights maps ELIGIBLE representative address to delegated vote weight in
	// micro-XE — the consensus view. TotalWeight is their sum, and is exactly the
	// quorum denominator finality is measured against.
	Weights map[string]uint64 `json:"weights"`
	// TotalWeight is the quorum denominator in micro-XE.
	TotalWeight uint64 `json:"total_weight"`

	// IneligibleWeights maps representative address to delegated weight that the
	// eligibility policy EXCLUDES from quorum, and IneligibleWeight is their sum.
	// Both are empty/zero when no policy is published. This is the dead weight
	// that used to deadlock finality: watch it, but it costs the network nothing
	// while it sits here. (#832)
	IneligibleWeights map[string]uint64 `json:"ineligible_weights,omitempty"`
	IneligibleWeight  uint64            `json:"ineligible_weight"`

	// EligibilityRestricted reports whether a sys.representatives allowlist is
	// actually in force. EligibilityFailedOpen reports that one is published but
	// is being IGNORED because it matches zero delegated weight — a
	// misconfiguration that must be visible rather than silently inert.
	EligibilityRestricted bool `json:"eligibility_restricted"`
	EligibilityFailedOpen bool `json:"eligibility_failed_open"`
}

// GetDelegation returns the current representative vote weights, split into the
// weight that counts toward quorum and the weight the eligibility policy
// excludes.
func (n *Node) GetDelegation() *DelegationInfo {
	eligible := n.Ledger.GetVoteWeights()
	all := n.Ledger.GetAllVoteWeights()
	info := &DelegationInfo{
		Weights:               eligible,
		EligibilityFailedOpen: n.Ledger.RepEligibilityFailedOpen(),
	}
	for _, w := range eligible {
		info.TotalWeight += w
	}
	for rep, w := range all {
		if _, ok := eligible[rep]; ok {
			continue
		}
		if info.IneligibleWeights == nil {
			info.IneligibleWeights = make(map[string]uint64)
		}
		info.IneligibleWeights[rep] = w
		info.IneligibleWeight += w
	}
	info.EligibilityRestricted = n.Ledger.RepEligibilityRestricted()
	return info
}

// PeerInfo describes a connected peer.
type PeerInfo struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	Version     string `json:"version"`
	ConnectedAt int64  `json:"connected_at"` // unix nanos
}

// NodeInfo holds information about this node exposed via the API.
type NodeInfo struct {
	ID string `json:"id"`
	// Address is the node's ledger ACCOUNT ADDRESS, PublicKey its ed25519
	// VERIFYING KEY. Since #829 the address is sha256("xe/account/v1" || pubkey)
	// and the key is not recoverable from it, so both have to be published:
	// tooling that configures sys.timekeepers (a list of verifying keys) needs
	// PublicKey, while anything sending to or querying the node's account needs
	// Address. The alternative — reading pub_key off the opening block of the
	// node's own chain — does not exist for a node that has never transacted.
	Address    string     `json:"address"`
	PublicKey  string     `json:"public_key"`
	Version    string     `json:"version"`
	NetworkID  string     `json:"network_id,omitempty"`
	Peers      []PeerInfo `json:"peers"`
	PeerCount  int        `json:"peer_count"`
	Accounts   int        `json:"accounts"`
	BlockCount int        `json:"block_count"`

	// DroppedBlocks is the running total of blocks shed from the gossip receive
	// path because the receive channel was full — a rising value indicates the
	// node is falling behind under load. (#731)
	DroppedBlocks uint64 `json:"dropped_blocks"`

	// DelegationUnderflows is the running total of representative vote-weight
	// underflows. Any non-zero value signals in-memory weight divergence from
	// the ledger (data corruption feeding quorum math) and must alert (#728).
	DelegationUnderflows uint64 `json:"delegation_underflows"`

	// Consensus liveness (#833). Zero total delegated weight is silent finality
	// death: blocks commit and gossip, nothing ever finalizes, every balance is
	// unspendable — and nothing else on this endpoint changes. Both fields are
	// needed, not either one:
	//
	//   TotalDelegatedWeight == 0  → no quorum denominator exists at all.
	//   FinalityAdvances == 0      → weight exists but nothing votes it. Weight
	//     delegated to an address no key controls (e.g. a public key used as an
	//     address, #829) reads as perfectly healthy weight and finalizes nothing.
	//
	// Representatives counts the accounts currently holding non-zero weight, so a
	// collapsing representative set is visible before it reaches zero.
	// LastFinalityNs is 0 until something finalizes after startup; genesis, which
	// is final on every node by construction, is deliberately not counted.
	TotalDelegatedWeight uint64 `json:"total_delegated_weight"`
	Representatives      int    `json:"representatives"`
	FinalityAdvances     uint64 `json:"finality_advances"`
	LastFinalityNs       int64  `json:"last_finality_ns"`

	// PoWDifficulty / ChatPoWDifficulty advertise the thresholds clients must
	// solve against (block submission and chat envelopes respectively, #729).
	// Hex strings, not JSON numbers: the values live near 2^64, far past the
	// 2^53 integer-safe range of JSON readers. "0" = PoW disabled.
	PoWDifficulty     string `json:"pow_difficulty"`
	ChatPoWDifficulty string `json:"chat_pow_difficulty"`

	// LeaseTiming is the network's effective lease timing, pinned by the genesis
	// block (#524) or defaulted to production. Clients (e.g. the soak harness) that
	// never load a genesis should read these rather than their compiled-in defaults,
	// which may not match a compressed network.
	LeaseTiming LeaseTimingInfo `json:"lease_timing"`

	// Certificate reports this node's own performance-certificate status. A
	// provider holding none cannot be leased from at all — a lease block requires
	// a valid CertificateHash — and nothing else on this endpoint reveals that,
	// so a certless provider otherwise looks healthy (#812).
	Certificate CertificateStatus `json:"certificate"`
}

// CertificateStatus reports whether this node currently holds a valid (issued
// and unexpired) performance certificate of its own (#812). Non-providers, and
// providers that have not issued one yet, report valid=false with no hash.
type CertificateStatus struct {
	Valid     bool   `json:"valid"`
	Hash      string `json:"hash,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// LeaseTimingInfo reports a network's effective lease timing (#524).
type LeaseTimingInfo struct {
	MinDurationSecs  uint64 `json:"min_duration_secs"`
	SettleGraceNs    int64  `json:"settle_grace_ns"`
	ForceSettleGapNs int64  `json:"force_settle_gap_ns"`
	EscrowExpiryNs   int64  `json:"escrow_expiry_ns"`
	ArchiveGapNs     int64  `json:"archive_gap_ns"`
	MaxAttestSkewNs  int64  `json:"max_attestation_skew_ns"`
}

// GetNodeInfo returns information about this node.
func (n *Node) GetNodeInfo() *NodeInfo {
	peers := n.Host.Network().Peers()
	peerInfos := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		var addr string
		conns := n.Host.Network().ConnsToPeer(p)
		if len(conns) > 0 {
			addr = addrToIPPort(conns[0].RemoteMultiaddr())
		}

		var version string
		if v, err := n.Host.Peerstore().Get(p, "AgentVersion"); err == nil {
			version, _ = v.(string)
		}

		var connectedAt int64
		if len(conns) > 0 {
			connectedAt = conns[0].Stat().Opened.UnixNano()
		}

		peerInfos = append(peerInfos, PeerInfo{
			ID:          p.String(),
			Address:     addr,
			Version:     version,
			ConnectedAt: connectedAt,
		})
	}

	var certStatus CertificateStatus
	if cert := n.GetPerformanceCertificate(); cert != nil && cert.ExpiresAt > core.Now().UnixNano() {
		certStatus = CertificateStatus{Valid: true, Hash: cert.Hash, ExpiresAt: cert.ExpiresAt}
	}

	// #833: the quorum denominator, reported in micro-XE. It cannot exceed the
	// 42M genesis supply, so it always fits a uint64; clamp defensively rather
	// than reporting a wrapped value on a corrupt weight map.
	totalWeight := uint64(math.MaxUint64)
	if w := n.Ledger.GetTotalDelegatedWeight(); w.IsUint64() {
		totalWeight = w.Uint64()
	}

	return &NodeInfo{
		ID:                   n.Host.ID().String(),
		Address:              n.KeyPair.Address(),
		PublicKey:            n.KeyPair.PubKeyHex(),
		Version:              "xe/" + n.version,
		NetworkID:            core.GetNetworkID(),
		Peers:                peerInfos,
		PeerCount:            len(peers),
		Accounts:             len(n.Ledger.Frontiers()),
		BlockCount:           n.Ledger.BlockCount(),
		DroppedBlocks:        xenet.DroppedBlocks(),
		DelegationUnderflows: n.Ledger.DelegationUnderflows(),
		TotalDelegatedWeight: totalWeight,
		Representatives:      len(n.Ledger.GetVoteWeights()),
		FinalityAdvances:     n.Ledger.FinalityAdvances(),
		LastFinalityNs:       n.Ledger.LastFinalityNs(),
		PoWDifficulty:        strconv.FormatUint(n.difficulty, 16),
		ChatPoWDifficulty:    strconv.FormatUint(n.chatDifficulty, 16),
		LeaseTiming: LeaseTimingInfo{
			MinDurationSecs:  core.LeaseMinDuration,
			SettleGraceNs:    core.LeaseSettleGrace,
			ForceSettleGapNs: core.LeaseForceSettleGap,
			EscrowExpiryNs:   core.LeaseEscrowExpiry,
			ArchiveGapNs:     core.LeaseArchiveGap,
			MaxAttestSkewNs:  core.MaxAttestationSkew,
		},
		Certificate: certStatus,
	}
}

// addrToIPPort extracts "ip:port" from a multiaddr like /ip4/1.2.3.4/tcp/9000.
func addrToIPPort(addr ma.Multiaddr) string {
	var ip, port string
	ma.ForEach(addr, func(c ma.Component) bool {
		switch c.Protocol().Code {
		case ma.P_IP4, ma.P_IP6:
			ip = c.Value()
		case ma.P_TCP, ma.P_UDP:
			port = c.Value()
		}
		return true
	})
	if ip == "" {
		return ""
	}
	return ip + ":" + port
}

// SubmitBlock validates and adds a pre-signed block to the ledger, then
// broadcasts it to the gossip network so other nodes learn about it.
//
// A gossip publish failure after a successful AddBlock is not a submission
// failure: the block is already committed locally and MarkDirty ensures sync
// re-broadcasts it, so returning the publish error would tell the client its
// (committed) block was rejected — and a resubmit would then hit a
// duplicate/frontier error. The publish failure is logged and swallowed so only
// a genuine ledger rejection propagates to the caller (#801, Finding 2).
func (n *Node) SubmitBlock(b *core.Block) error {
	if err := n.Ledger.AddBlock(b); err != nil {
		return err
	}
	n.syncTracker.MarkDirty()
	if err := n.Gossip.Publish(n.ctx, b); err != nil {
		log.Printf("block %s committed locally but gossip publish failed (sync will propagate): %v", b.Hash, err)
	}
	return nil
}

// Multiaddr returns this node's first listen multiaddr with p2p ID appended.
func (n *Node) Multiaddr() string {
	addrs := n.Host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	return fmt.Sprintf("%s/p2p/%s", addrs[0], n.Host.ID())
}

// Stop shuts down the node. It cancels the context, waits for handler
// goroutines to finish, then closes the host and store. Sync goroutines are
// awaited after Host.Close (so in-flight streams fail fast) but before
// store.Close, so no sync round touches a closed store (#602).
func (n *Node) Stop() {
	n.cancel()
	n.wg.Wait()
	// Cancel pending finalization-lock stability re-drives and wait out any
	// in-flight one before the stores go away (#600).
	n.VoteMgr.Close()
	_ = n.Host.Close()
	n.syncWait()
	_ = n.store.Close()
}

func (n *Node) handleMarketplace(msgs <-chan *xenet.MarketplaceMsg) {
	for msg := range msgs {
		switch msg.Type {
		case "request":
			if msg.Request == nil || !n.isProvider {
				continue
			}
			// #829: Consumer is an ADDRESS; the key it is checked against rides
			// in ConsumerPubKey — see the note in advertiseResources.
			if err := xenet.VerifyRequest(msg.Request); err != nil {
				logging.Warnf("Rejecting resource request: %v", err)
				continue
			}
			req := msg.Request
			// Never quote a request the chain could not turn into a valid lease
			// (#809) — a signed offer for an unfulfillable duration or an
			// out-of-bounds machine is noise no consumer can act on.
			if err := core.ValidateLeaseDimensions(req.VCPUs, req.MemoryMB, req.DiskGB, req.Duration); err != nil {
				log.Printf("Skipping request %s: %v", shortHash(req.RequestID), err)
				continue
			}
			// Check against available resources (total minus provisioned and
			// reserved). Saturating subtraction: an unguarded -= wraps on any
			// bookkeeping inconsistency and reports near-infinite capacity (#808).
			availVCPUs, availMemMB, availDiskGB := n.providerVCPUs, n.providerMemoryMB, n.providerDiskGB
			if n.VMManager != nil {
				for _, vi := range n.VMManager.List() {
					if vi.Resources != nil {
						availVCPUs = satSub(availVCPUs, vi.Resources.VCPUs)
						availMemMB = satSub(availMemMB, vi.Resources.MemoryMB)
						availDiskGB = satSub(availDiskGB, vi.Resources.DiskGB)
					}
				}
			}
			n.reservedResMu.Lock()
			availVCPUs = satSub(availVCPUs, n.reservedRes.VCPUs)
			availMemMB = satSub(availMemMB, n.reservedRes.MemoryMB)
			availDiskGB = satSub(availDiskGB, n.reservedRes.DiskGB)
			n.reservedResMu.Unlock()
			if req.VCPUs > availVCPUs || req.MemoryMB > availMemMB || req.DiskGB > availDiskGB {
				log.Printf("Skipping request %s: exceeds available capacity (req %d/%d/%d, avail %d/%d/%d)",
					shortHash(req.RequestID), req.VCPUs, req.MemoryMB, req.DiskGB,
					availVCPUs, availMemMB, availDiskGB)
				continue
			}
			xusdBal := n.Ledger.GetAssetBalances(n.KeyPair.Address())["XUSD"]
			// Quote cost using the provider's own multiplier from its
			// active certificate. Consumer will lock this in on the
			// lease block via the cert hash (#297). Providers without a
			// cert cannot offer.
			pc := n.perfCert.Load()
			if pc == nil {
				log.Printf("Skipping request %s: no active certificate", shortHash(req.RequestID))
				continue
			}
			totalCost, err := core.LeaseCost(req.VCPUs, req.MemoryMB, req.DiskGB, req.Duration, pc.PriceMultiplierMilli)
			if err != nil {
				log.Printf("Offer cost overflow for request %s: %v", shortHash(req.RequestID), err)
				continue
			}
			stake := core.LeaseStake(totalCost)
			if xusdBal < stake {
				log.Printf("Skipping request %s: insufficient XUSD for stake (%d < %d)",
					shortHash(req.RequestID), xusdBal, stake)
				continue
			}
			offer := &xenet.ResourceOffer{
				Provider:        n.KeyPair.Address(),
				RequestID:       req.RequestID,
				VCPUs:           req.VCPUs,
				MemoryMB:        req.MemoryMB,
				DiskGB:          req.DiskGB,
				Duration:        req.Duration,
				TotalCost:       totalCost,
				CertificateHash: pc.Hash,
				Timestamp:       core.Now().UnixNano(),
			}
			xenet.SignOffer(offer, n.KeyPair.Private)
			outMsg := &xenet.MarketplaceMsg{
				Type:  "offer",
				Offer: offer,
			}
			if err := n.MarketGossip.Publish(n.ctx, outMsg); err != nil {
				log.Printf("Failed to publish offer: %v", err)
			} else {
				log.Printf("Published offer for request %s", shortHash(req.RequestID))
			}
		case "advertisement":
			if msg.Ad == nil {
				continue
			}
			// #829: same address-vs-key split as VerifyRequest above.
			if err := xenet.VerifyAdvertisement(msg.Ad); err != nil {
				logging.Warnf("Rejecting resource advertisement: %v", err)
				continue
			}
			n.providerAds.Store(msg.Ad.Provider, msg.Ad)

		case "offer":
			if msg.Offer == nil {
				continue
			}
			// #829: same address-vs-key split as VerifyRequest above.
			if err := xenet.VerifyOffer(msg.Offer); err != nil {
				logging.Warnf("Rejecting resource offer: %v", err)
				continue
			}
			// Store for consumer to pick up, with TTL eviction and size cap.
			n.pendingOffersMu.Lock()
			// Evict offers older than 60 seconds.
			cutoff := time.Now().Add(-60 * time.Second).UnixNano()
			for id, o := range n.pendingOffers {
				if o.Timestamp < cutoff {
					delete(n.pendingOffers, id)
				}
			}
			// Cap at 1000 entries to bound memory.
			if len(n.pendingOffers) < 1000 {
				n.pendingOffers[msg.Offer.RequestID] = msg.Offer
			}
			n.pendingOffersMu.Unlock()
			log.Printf("Received offer from %s for request %s", shortAddr(msg.Offer.Provider), shortHash(msg.Offer.RequestID))
		}
	}
}

// activeLeaseCount returns the number of leases this provider is currently
// running or provisioning, used by acceptPolicy.MaxConcurrent. Best-effort:
// the VMManager tracks both running and in-flight VMs (added on Provision),
// but two leases passing the cap simultaneously may both proceed before
// either is reflected in the count. Resource over-commit is prevented by the
// blockCreateMu / reservedRes mechanism in autoAcceptLease, so the cap is
// operational rather than safety-critical.
func (n *Node) activeLeaseCount() uint64 {
	if n.VMManager == nil {
		return 0
	}
	return uint64(len(n.VMManager.List()))
}

// leaseAlreadyAccepted reports whether a lease has moved past the created state
// (accepted, settled, cancelled, unfulfilled) and so should be skipped by the
// auto-accept paths. A bare Lease record exists from lease-creation time
// (state=created, persisted on every node including via sync, since the
// lease-lifecycle tracking change), so a nil-only check would make a provider
// skip every lease it should accept — the #503 regression. Both autoAcceptLease
// and leaseWatchLoop must use this predicate so their guards can't drift apart
// (#570/H6).
func leaseAlreadyAccepted(lease *core.Lease) bool {
	return lease != nil && lease.State != core.LeaseCreated
}

// beginAccept marks an auto-accept as in flight for the lease, or reports
// false if one is already running. Gossip arrival and the watch tick can both
// invoke autoAcceptLease for the same lease during the attestation window
// (before any VM exists), and both entry guards are check-then-act — pre-fix
// the loser's error path tore down the winner's live VM (#598).
func (n *Node) beginAccept(leaseHash string) bool {
	n.acceptInFlightMu.Lock()
	defer n.acceptInFlightMu.Unlock()
	if _, busy := n.acceptInFlight[leaseHash]; busy {
		return false
	}
	n.acceptInFlight[leaseHash] = struct{}{}
	return true
}

func (n *Node) endAccept(leaseHash string) {
	n.acceptInFlightMu.Lock()
	defer n.acceptInFlightMu.Unlock()
	delete(n.acceptInFlight, leaseHash)
}

// shouldTeardownOnAcceptFailure reports whether the provisioned VM should be
// torn down after a failed accept commit. When THIS provider's accept already
// stands on-chain, the failure was a duplicate-accept race and the VM serves
// the winning accept — keep it (#598). Any other failure (no record, still
// created, or a rival provider won the lease) tears down as before.
func shouldTeardownOnAcceptFailure(lease *core.Lease, myAddr string) bool {
	return !leaseAlreadyAccepted(lease) || lease.Provider != myAddr
}

func (n *Node) autoAcceptLease(leaseBlock *core.Block) {
	if !n.beginAccept(leaseBlock.Hash) {
		return
	}
	defer n.endAccept(leaseBlock.Hash)
	if leaseAlreadyAccepted(n.GetLease(leaseBlock.Hash)) {
		return
	}
	// Skip if VM already provisioned (provision-before-accept in progress).
	if n.VMManager != nil {
		if _, err := n.VMManager.Get(leaseBlock.Hash); err == nil {
			return
		}
	}

	// Local accept policy filter — runs before stake/attestation/resource/cert
	// work so providers see the most informative rejection log line. Zero-value
	// policy is permissive. See #229.
	if err := n.acceptPolicy.Allow(leaseBlock, n.activeLeaseCount()); err != nil {
		log.Printf("Auto-accept policy rejected lease %s: %v", shortHash(leaseBlock.Hash), err)
		return
	}

	myAddr := n.KeyPair.Address()
	stake := core.LeaseStake(leaseBlock.Amount)

	// Pre-check balance before spending time on attestations.
	if stake > n.Ledger.GetAssetBalances(myAddr)["XUSD"] {
		log.Printf("Cannot auto-accept lease %s: insufficient XUSD for stake", shortHash(leaseBlock.Hash))
		return
	}

	// Gather timekeeper attestations BEFORE acquiring the block creation mutex,
	// since this can take up to 15 seconds. No point holding the mutex idle.
	var attestations []core.TimekeeperAttestation
	if tkConfig := n.getTimekeeperConfig(); tkConfig != nil {
		var err error
		attestations, err = n.gatherAttestations(leaseBlock.Hash, tkConfig)
		if err != nil {
			log.Printf("Failed to gather attestations for lease_accept %s: %v", shortHash(leaseBlock.Hash), err)
			return
		}
		log.Printf("Gathered %d attestations for lease_accept %s", len(attestations), shortHash(leaseBlock.Hash))
	}

	// Acquire mutex and re-read fresh chain state. Lock is manually managed
	// below because we release it during VM provisioning and re-acquire after.
	n.blockCreateMu.Lock()

	xusdBal := n.Ledger.GetAssetBalances(myAddr)["XUSD"]
	if stake > xusdBal {
		n.blockCreateMu.Unlock()
		log.Printf("Cannot auto-accept lease %s: insufficient XUSD for stake (have %d, need %d)", shortHash(leaseBlock.Hash), xusdBal, stake)
		return
	}

	// Check resource availability — reject if accepting would exceed capacity.
	// Includes both running VMs and resources reserved by in-flight provisions.
	if n.VMManager != nil {
		var usedVCPUs, usedMemMB, usedDiskGB uint64
		for _, vi := range n.VMManager.List() {
			if vi.Resources != nil {
				usedVCPUs += vi.Resources.VCPUs
				usedMemMB += vi.Resources.MemoryMB
				usedDiskGB += vi.Resources.DiskGB
			}
		}
		n.reservedResMu.Lock()
		usedVCPUs += n.reservedRes.VCPUs
		usedMemMB += n.reservedRes.MemoryMB
		usedDiskGB += n.reservedRes.DiskGB
		n.reservedResMu.Unlock()

		if exceedsCapacity(usedVCPUs, leaseBlock.VCPUs, n.providerVCPUs) ||
			exceedsCapacity(usedMemMB, leaseBlock.MemoryMB, n.providerMemoryMB) ||
			exceedsCapacity(usedDiskGB, leaseBlock.DiskGB, n.providerDiskGB) {
			n.blockCreateMu.Unlock()
			log.Printf("Cannot auto-accept lease %s: insufficient resources (used %d/%d/%d + req %d/%d/%d > cap %d/%d/%d)",
				shortHash(leaseBlock.Hash),
				usedVCPUs, usedMemMB, usedDiskGB,
				leaseBlock.VCPUs, leaseBlock.MemoryMB, leaseBlock.DiskGB,
				n.providerVCPUs, n.providerMemoryMB, n.providerDiskGB)
			return
		}

		// Reserve resources for provisioning (released after provision completes).
		n.reservedResMu.Lock()
		n.reservedRes.VCPUs += leaseBlock.VCPUs
		n.reservedRes.MemoryMB += leaseBlock.MemoryMB
		n.reservedRes.DiskGB += leaseBlock.DiskGB
		n.reservedResMu.Unlock()
	}

	// Provision the VM BEFORE committing the accept block. If provisioning
	// fails, we don't accept the lease — no orphaned accepts without VMs.
	// Release the block creation lock during provisioning (can take minutes),
	// then re-acquire to commit. The resource check above (inside the lock)
	// prevents concurrent over-provisioning via the reserved resources counter.
	n.blockCreateMu.Unlock()

	n.provisionVM(leaseBlock)

	// Release reserved resources — the VM is now either provisioned (tracked
	// by the VMManager) or failed (nothing to track).
	if n.VMManager != nil {
		n.reservedResMu.Lock()
		n.reservedRes.VCPUs -= leaseBlock.VCPUs
		n.reservedRes.MemoryMB -= leaseBlock.MemoryMB
		n.reservedRes.DiskGB -= leaseBlock.DiskGB
		n.reservedResMu.Unlock()
	}

	// Check if provisioning actually succeeded.
	if n.VMManager != nil {
		if _, err := n.VMManager.Get(leaseBlock.Hash); err != nil {
			log.Printf("Lease %s: VM provision failed, not accepting", shortHash(leaseBlock.Hash))
			return
		}
	}

	// Re-acquire lock and re-read chain state (may have changed during provisioning).
	n.blockCreateMu.Lock()

	chain := n.Ledger.GetChain(myAddr)
	prev := "0"
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}
	xusdBal = n.Ledger.GetAssetBalances(myAddr)["XUSD"]
	if stake > xusdBal {
		n.blockCreateMu.Unlock()
		log.Printf("Lease %s: XUSD balance changed during provisioning (have %d, need %d), tearing down",
			shortHash(leaseBlock.Hash), xusdBal, stake)
		n.teardownVM(&core.Lease{LeaseHash: leaseBlock.Hash})
		return
	}

	// Attach performance certificate hash.
	var certHash string
	if pc := n.perfCert.Load(); pc != nil {
		certHash = pc.Hash
	}
	if certHash == "" {
		n.blockCreateMu.Unlock()
		log.Printf("Lease %s: no performance certificate, cannot accept", shortHash(leaseBlock.Hash))
		n.teardownVM(&core.Lease{LeaseHash: leaseBlock.Hash})
		return
	}

	b := &core.Block{
		Type:            core.BlockLeaseAccept,
		Account:         myAddr,
		Previous:        prev,
		Balance:         xusdBal - stake,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Source:          leaseBlock.Hash,
		Amount:          stake,
		Attestations:    attestations,
		CertificateHash: certHash,
		// #501: lock the emission params into the signed block so every node
		// records the same settle rate regardless of which epoch it applies the
		// accept in. Validated against epoch-at-accept on the live path.
		LockedR:         n.Ledger.CurrentR(),
		LockedPayoutCap: n.Ledger.CurrentPayoutCap(),
		LockedTWAP:      n.Ledger.CurrentTWAP(),
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		n.blockCreateMu.Unlock()
		log.Printf("Failed to sign lease_accept: %v", err)
		n.teardownVM(&core.Lease{LeaseHash: leaseBlock.Hash})
		return
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		n.blockCreateMu.Unlock()
		log.Printf("Failed to add lease_accept: %v", err)
		if shouldTeardownOnAcceptFailure(n.GetLease(leaseBlock.Hash), myAddr) {
			n.teardownVM(&core.Lease{LeaseHash: leaseBlock.Hash})
		} else {
			log.Printf("Lease %s: our accept already stands on-chain, keeping VM (#598)", shortHash(leaseBlock.Hash))
		}
		return
	}
	n.blockCreateMu.Unlock()

	if err := n.Gossip.Publish(n.ctx, b); err != nil {
		log.Printf("Failed to publish lease_accept: %v", err)
		return
	}
	n.syncTracker.MarkDirty()
	log.Printf("Auto-accepted lease %s (stake=%d XUSD)", shortHash(leaseBlock.Hash), stake)
}

// leaseWatchLoop periodically scans for unaccepted lease blocks addressed to this
// provider. This catches leases that arrived via sync rather than gossip, where
// the autoAcceptLease callback wouldn't fire.
func (n *Node) leaseWatchLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	accepted := make(map[string]bool) // track leases we've already tried to accept
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			myAddr := n.KeyPair.Address()
			pending := n.Ledger.GetPendingForAccount(myAddr)
			for _, p := range pending {
				if accepted[p.SendHash] {
					continue
				}
				leaseBlock := n.Ledger.GetBlock(p.SendHash)
				if leaseBlock == nil || leaseBlock.Type != core.BlockLease {
					continue
				}
				if leaseBlock.Destination != myAddr {
					continue
				}
				// Skip only if the lease has moved past the created state. A
				// bare created-state record exists from creation/sync, so a
				// nil-only check here re-introduces #503 (#570/H6).
				if leaseAlreadyAccepted(n.GetLease(leaseBlock.Hash)) {
					accepted[leaseBlock.Hash] = true
					continue
				}
				accepted[leaseBlock.Hash] = true
				log.Printf("Lease watch: found unaccepted lease %s, auto-accepting", shortHash(leaseBlock.Hash))
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					n.autoAcceptLease(leaseBlock)
				}()
			}
		}
	}
}

func (n *Node) settleLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.trySettleExpiredLeases()
			n.tryForceSettleStaleLeases()
			n.tryArchiveExpiredLeases()
			n.cleanupOrphanedVMs()
		}
	}
}

// cleanupOrphanedVMs tears down VMs whose leases reached a terminal state
// but whose teardown failed or was interrupted. Only cleans up VMs that have
// a corresponding terminal lease — VMs without a lease record are in-flight
// provisions and must not be touched. Gates on LeaseState.Terminal(), not the
// legacy Settled bool, which stays false for cancelled leases (#762).
func (n *Node) cleanupOrphanedVMs() {
	if n.VMManager == nil {
		return
	}
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return
	}
	for _, info := range n.VMManager.List() {
		lease, err := ls.GetLease(info.LeaseHash)
		if err != nil || lease == nil {
			// No lease record — this VM is being provisioned (in-flight). Skip.
			continue
		}
		if lease.State.Terminal() {
			log.Printf("Cleaning up orphaned VM for terminal lease %s", shortHash(info.LeaseHash))
			if err := n.VMManager.Teardown(info.LeaseHash); err != nil {
				log.Printf("Orphan cleanup failed for %s: %v", shortHash(info.LeaseHash), err)
			}
		}
	}
}

func (n *Node) trySettleExpiredLeases() {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return
	}
	myAddr := n.KeyPair.Address()
	leases, err := ls.GetLeasesByProvider(myAddr)
	if err != nil {
		return
	}
	now := core.Now().UnixNano()
	for _, lease := range leases {
		// Only accepted leases are the provider's to settle. A cancelled lease
		// has Settled=false forever; today it is skipped by the expiry guard
		// only because cancel leaves StartTime==0 — make the gate explicit,
		// matching the sibling sweeps (#762).
		if lease.Settled || lease.State != core.LeaseAccepted {
			continue
		}
		expiry := lease.StartTime + int64(lease.Duration)*1e9
		if now < expiry {
			continue
		}
		// #487 (FM5): once past the grace window the chain rejects the settle, so
		// stop retrying — the lease is now the consumer's to force-settle (#488).
		if now > expiry+core.LeaseSettleGrace {
			continue
		}
		n.settleLease(lease)
	}
}

// consumerShouldForceSettle reports whether the consumer node should force-settle
// `lease`: it must be this node's own accepted-and-unsettled lease whose
// force-settle window (expiry + grace + gap) has opened. Pure for testability.
func consumerShouldForceSettle(lease *core.Lease, myAddr string, now int64) bool {
	if lease == nil || lease.Consumer != myAddr {
		return false
	}
	if lease.Settled || lease.State != core.LeaseAccepted {
		return false
	}
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	return now >= expiry+core.LeaseSettleGrace+core.LeaseForceSettleGap
}

// tryForceSettleStaleLeases recovers leases this node consumed that the provider
// accepted but never settled (#489, FM4). Runs on the same 10s tick as
// trySettleExpiredLeases; the disjoint force-settle window keeps it from racing
// the provider's settle.
func (n *Node) tryForceSettleStaleLeases() {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return
	}
	myAddr := n.KeyPair.Address()
	leases, err := ls.GetLeasesByState(core.LeaseAccepted)
	if err != nil {
		return
	}
	now := core.Now().UnixNano()
	for _, lease := range leases {
		if !consumerShouldForceSettle(lease, myAddr, now) {
			continue
		}
		n.forceSettleLease(lease)
	}
}

// shouldArchiveExpiredLease reports whether `lease` is a both-offline abandoned
// lease (#493, outcome #4) whose escrow refund window has not only closed
// (expiry+LeaseEscrowExpiry, the consensus deadline) but is also far enough past
// it (+LeaseArchiveGap) that no late-synced-yet-valid force-settle could still
// need the escrow on any node. Pure for testability. Party-agnostic: every node
// archives its own derived copy independently — there is no submitter and no
// block.
func shouldArchiveExpiredLease(lease *core.Lease, now int64) bool {
	if lease == nil || lease.Settled || lease.State != core.LeaseAccepted {
		return false
	}
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	return now >= expiry+core.LeaseEscrowExpiry+core.LeaseArchiveGap
}

// tryArchiveExpiredLeases garbage-collects leases abandoned by BOTH parties
// (#493, outcome #4). On the same 10s tick as settle/force-settle, it burns the
// escrow and marks the lease LeaseExpired. This is a local, blockless derived-
// state op: it touches no account balances and emits no block, so the immutable
// lattice is untouched and only the (eventually-converging) pending/lease caches
// change. Reputation is deliberately not touched — see #506.
func (n *Node) tryArchiveExpiredLeases() {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return
	}
	leases, err := ls.GetLeasesByState(core.LeaseAccepted)
	if err != nil {
		return
	}
	now := core.Now().UnixNano()
	for _, lease := range leases {
		if !shouldArchiveExpiredLease(lease, now) {
			continue
		}
		n.archiveExpiredLease(lease)
	}
}

// archiveExpiredLease burns the escrow of an abandoned lease and marks it
// expired. Deleting the escrow PendingSend changes no account balance — the
// consumer was debited at lease creation — so total supply simply drops by the
// burnt escrow. Delete-then-put is crash-idempotent: a restart that finds the
// escrow gone but the lease still LeaseAccepted simply re-runs (DeletePendingSend
// is a no-op on an absent id) and re-marks it.
func (n *Node) archiveExpiredLease(lease *core.Lease) {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return
	}
	if err := n.store.DeletePendingSend(lease.LeaseHash); err != nil {
		log.Printf("archive: DeletePendingSend %s: %v", shortHash(lease.LeaseHash), err)
		return
	}
	updated := *lease
	updated.State = core.LeaseExpired
	updated.Settled = true
	if err := ls.PutLease(&updated); err != nil {
		log.Printf("archive: PutLease %s: %v", shortHash(lease.LeaseHash), err)
		return
	}
	log.Printf("Archived expired lease %s: burned %d µXUSD escrow (both parties offline, #493)",
		shortHash(lease.LeaseHash), lease.Cost+lease.Stake)
}

// forceSettleLease submits a lease_force_settle on the consumer's own chain to
// recover an accepted lease the provider never settled. Mirrors settleLease, but
// refunds the consumer's cost in XUSD (the chain burns the provider's stake)
// rather than minting XE, and tears down no VM (the consumer never ran one).
func (n *Node) forceSettleLease(lease *core.Lease) {
	myAddr := n.KeyPair.Address()

	if lease.Cost == 0 {
		log.Printf("lease_force_settle: stored lease.Cost is zero for %s", shortHash(lease.LeaseHash))
		return
	}

	// Gather timekeeper attestations BEFORE acquiring the mutex (can take ~15s).
	var attestations []core.TimekeeperAttestation
	if tkConfig := n.getTimekeeperConfig(); tkConfig != nil {
		var err error
		attestations, err = n.gatherAttestations(lease.LeaseHash, tkConfig)
		if err != nil {
			log.Printf("Failed to gather attestations for lease_force_settle %s: %v", shortHash(lease.LeaseHash), err)
			return
		}
		log.Printf("Gathered %d attestations for lease_force_settle %s", len(attestations), shortHash(lease.LeaseHash))
	}

	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()

	chain := n.Ledger.GetChain(myAddr)
	if len(chain) == 0 {
		return
	}
	prev := chain[len(chain)-1].Hash
	oldXUSD := n.Ledger.GetAssetBalances(myAddr)["XUSD"]

	b := &core.Block{
		Type:         core.BlockLeaseForceSettle,
		Account:      myAddr,
		Previous:     prev,
		Balance:      oldXUSD + lease.Cost,
		Timestamp:    core.Now().UnixNano(),
		Asset:        "XUSD",
		Source:       lease.LeaseHash,
		Amount:       lease.Cost,
		Attestations: attestations,
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		log.Printf("Failed to sign lease_force_settle: %v", err)
		return
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		log.Printf("Failed to add lease_force_settle for %s: %v", shortHash(lease.LeaseHash), err)
		return
	}
	if err := n.Gossip.Publish(n.ctx, b); err != nil {
		log.Printf("Failed to publish lease_force_settle: %v", err)
		return
	}
	log.Printf("Force-settled stale lease %s (refunded %d XUSD; provider stake burned)", shortHash(lease.LeaseHash), lease.Cost)
}

// leaseSettleAmount returns the XE emission the chain validator expects for a
// lease_settle of `lease`. Mirrors core/ledger.go:validateAndAddLeaseSettle:
// the emission is computed purely from the LockedR/LockedPayoutCap/LockedTWAP
// snapshotted onto the lease at accept time (#401). #514 removed the live-ledger
// fallback — validateAndAddLeaseAccept rejects accepts with LockedR==0, so an
// accepted lease always carries non-zero locked params. Reading live state
// would produce a wrong Amount the validator rejects (the #434/#501 divergence
// when the cap-binding regime caused LockedR != CurrentR mid-lease).
func (n *Node) leaseSettleAmount(lease *core.Lease) uint64 {
	return core.LeaseEmission(lease.Cost, core.CapR(lease.LockedR, lease.LockedPayoutCap, lease.LockedTWAP))
}

func (n *Node) settleLease(lease *core.Lease) {
	myAddr := n.KeyPair.Address()

	if lease.Cost == 0 {
		log.Printf("lease_settle: stored lease.Cost is zero for %s", shortHash(lease.LeaseHash))
		return
	}
	xeAmount := n.leaseSettleAmount(lease)

	// Gather timekeeper attestations BEFORE acquiring the mutex,
	// since this can take up to 15 seconds.
	var attestations []core.TimekeeperAttestation
	if tkConfig := n.getTimekeeperConfig(); tkConfig != nil {
		var err error
		attestations, err = n.gatherAttestations(lease.LeaseHash, tkConfig)
		if err != nil {
			log.Printf("Failed to gather attestations for lease_settle %s: %v", shortHash(lease.LeaseHash), err)
			return
		}
		log.Printf("Gathered %d attestations for lease_settle %s", len(attestations), shortHash(lease.LeaseHash))
	}

	// Acquire mutex and read fresh chain state. #570/H7: hold blockCreateMu ONLY
	// across the block build+add — releasing it BEFORE the gossip/tunnel/VM
	// teardown below. teardownVM → LimaManager.Teardown contends with Provision,
	// which can hold the VM-manager lock for minutes; holding blockCreateMu
	// across it would freeze ALL block creation (sends, receives, accepts, other
	// settles) and could push the settle past LeaseSettleGrace.
	n.blockCreateMu.Lock()

	chain := n.Ledger.GetChain(myAddr)
	if len(chain) == 0 {
		n.blockCreateMu.Unlock()
		return
	}
	prev := chain[len(chain)-1].Hash
	oldXE := n.Ledger.GetAssetBalances(myAddr)["XE"]

	b := &core.Block{
		Type:         core.BlockLeaseSettle,
		Account:      myAddr,
		Previous:     prev,
		Balance:      oldXE + xeAmount,
		Timestamp:    core.Now().UnixNano(),
		Asset:        "XE",
		Source:       lease.LeaseHash,
		Amount:       xeAmount,
		Attestations: attestations,
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		n.blockCreateMu.Unlock()
		log.Printf("Failed to sign lease_settle: %v", err)
		return
	}
	n.solvePoW(b)

	addErr := n.Ledger.AddBlock(b)
	n.blockCreateMu.Unlock()
	if addErr != nil {
		log.Printf("Failed to add lease_settle for %s: %v", shortHash(lease.LeaseHash), addErr)
		return
	}

	// Post-commit work runs WITHOUT blockCreateMu (gossip, tunnel close, and the
	// potentially multi-minute VM teardown).
	n.finishSettle(b, lease)
}

// finishSettle performs the post-commit work for a settled lease — gossip,
// tunnel close, and synchronous VM teardown. It MUST NOT hold blockCreateMu:
// teardown can block for minutes on the VM manager and would otherwise freeze
// all block creation (#570/H7).
func (n *Node) finishSettle(b *core.Block, lease *core.Lease) {
	if n.Gossip != nil {
		if err := n.Gossip.Publish(n.ctx, b); err != nil {
			log.Printf("Failed to publish lease_settle: %v", err)
			return
		}
	}
	log.Printf("Settled lease %s (earned %d XE)", shortHash(lease.LeaseHash), b.Amount)

	if n.tunnelRegistry != nil {
		n.tunnelRegistry.CloseTunnelsForLease(lease.LeaseHash)
	}

	// Teardown synchronously — don't leave orphaned VMs.
	n.teardownVM(lease)
}

// RequestLease publishes a resource request and waits for the first offer.
func (n *Node) RequestLease(vcpus, memoryMB, diskGB, durationSecs uint64) (*xenet.ResourceOffer, error) {
	requestID := fmt.Sprintf("%s-%d", n.KeyPair.Address()[:16], core.Now().UnixNano())
	req := &xenet.ResourceRequest{
		Consumer:  n.KeyPair.Address(),
		RequestID: requestID,
		VCPUs:     vcpus,
		MemoryMB:  memoryMB,
		DiskGB:    diskGB,
		Duration:  durationSecs,
		Timestamp: core.Now().UnixNano(),
	}
	xenet.SignRequest(req, n.KeyPair.Private)
	msg := &xenet.MarketplaceMsg{
		Type:    "request",
		Request: req,
	}
	if err := n.MarketGossip.Publish(n.ctx, msg); err != nil {
		return nil, fmt.Errorf("publish request: %w", err)
	}
	log.Printf("Published resource request %s: %d vCPUs, %d MB, %d GB for %ds", shortHash(requestID), vcpus, memoryMB, diskGB, durationSecs)

	// Wait for offer (up to 30s).
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			return nil, fmt.Errorf("no offer received within 30s")
		case <-ticker.C:
			n.pendingOffersMu.Lock()
			offer, ok := n.pendingOffers[requestID]
			if ok {
				delete(n.pendingOffers, requestID)
			}
			n.pendingOffersMu.Unlock()
			if ok {
				return offer, nil
			}
		case <-n.ctx.Done():
			return nil, n.ctx.Err()
		}
	}
}

// CreateLeaseBlock creates and submits a lease block for the given offer.
// certHash is the provider's performance certificate hash at the time of
// the offer — locked in on the lease block so the price multiplier cannot
// be changed by a later cert reissue (#297).
func (n *Node) CreateLeaseBlock(provider string, vcpus, memoryMB, diskGB, durationSecs, cost uint64, accessPubKey, certHash string) error {
	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()
	myAddr := n.KeyPair.Address()
	chain := n.Ledger.GetChain(myAddr)
	if len(chain) == 0 {
		return fmt.Errorf("account not open")
	}
	prev := chain[len(chain)-1].Hash
	xusdBal := n.Ledger.GetAssetBalances(myAddr)["XUSD"]
	if cost > xusdBal {
		return fmt.Errorf("insufficient XUSD: have %d, need %d", xusdBal, cost)
	}

	b := &core.Block{
		Type:            core.BlockLease,
		Account:         myAddr,
		Previous:        prev,
		Balance:         xusdBal - cost,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     provider,
		Amount:          cost,
		VCPUs:           vcpus,
		MemoryMB:        memoryMB,
		DiskGB:          diskGB,
		Duration:        durationSecs,
		AccessPubKey:    accessPubKey,
		CertificateHash: certHash,
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		return fmt.Errorf("sign lease block: %w", err)
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		return err
	}
	return n.Gossip.Publish(n.ctx, b)
}

// GetLeases returns all leases from the store.
func (n *Node) GetLeases() []*core.Lease {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return []*core.Lease{}
	}
	leases, err := ls.GetAllLeases()
	if err != nil {
		return []*core.Lease{}
	}
	for _, l := range leases {
		l.BackfillState()
	}
	return leases
}

// GetLeasesByState returns leases filtered by state.
func (n *Node) GetLeasesByState(state core.LeaseState) []*core.Lease {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return []*core.Lease{}
	}
	leases, err := ls.GetLeasesByState(state)
	if err != nil {
		return []*core.Lease{}
	}
	for _, l := range leases {
		l.BackfillState()
	}
	return leases
}

// GetLease returns a single lease by its hash.
func (n *Node) GetLease(leaseHash string) *core.Lease {
	ls, ok := n.store.(core.LeaseStore)
	if !ok {
		return nil
	}
	lease, err := ls.GetLease(leaseHash)
	if err != nil {
		return nil
	}
	if lease != nil {
		lease.BackfillState()
	}
	return lease
}

// ManualSettle settles a lease manually.
func (n *Node) ManualSettle(lease *core.Lease) {
	n.settleLease(lease)
}

// ValidateTunnelLease implements net.TunnelValidator — checks lease is valid
// for this provider. The SSH gateway authenticates the consumer via their
// lease key before opening the tunnel, so we don't restrict by peer ID here.
// This allows bootstrap nodes to relay tunnels on behalf of consumers.
func (n *Node) ValidateTunnelLease(leaseHash string, peerID peer.ID) error {
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return fmt.Errorf("lease not found")
	}
	// Access requires a live lease — accepted is the only state with a running
	// VM. The legacy Settled bool stays false for cancelled leases (#761).
	if lease.State != core.LeaseAccepted {
		return fmt.Errorf("lease not active")
	}
	if lease.Provider != n.KeyPair.Address() {
		return fmt.Errorf("not the provider for this lease")
	}
	return nil
}

// DialSSH implements net.TunnelValidator — dials the container's sshd via VMManager.
func (n *Node) DialSSH(leaseHash string) (net.Conn, error) {
	if n.VMManager == nil {
		return nil, fmt.Errorf("not a provider")
	}
	return n.VMManager.DialSSH(leaseHash)
}

// OpenTunnel opens a tunnel to a provider peer via the libp2p tunnel protocol.
func (n *Node) OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	return xenet.OpenTunnel(ctx, n.Host, n.DHT, providerPeer, leaseHash)
}

// OpenTunnelForLease looks up a lease and opens a tunnel to its provider.
func (n *Node) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return nil, fmt.Errorf("lease not found")
	}
	// Access requires a live lease — accepted is the only state with a running
	// VM. The legacy Settled bool stays false for cancelled leases (#761).
	if lease.State != core.LeaseAccepted {
		return nil, fmt.Errorf("lease not active")
	}
	providerPeer := n.PeerForAccount(lease.Provider)
	if providerPeer == "" {
		return nil, fmt.Errorf("provider peer not found")
	}
	return xenet.OpenTunnel(ctx, n.Host, n.DHT, providerPeer, leaseHash)
}

func (n *Node) RequestAttestation(identifier string) (*core.TimekeeperAttestation, error) {
	// Identifiers are 64-char hex: lease hashes (for lease accept/settle) or
	// provider addresses (for performance certificates) — and must be bound
	// to a live lease or registered provider (#570/H8).
	if len(identifier) != 64 {
		return nil, fmt.Errorf("invalid attestation identifier length: %d", len(identifier))
	}
	if err := n.canAttest(identifier); err != nil {
		return nil, err
	}
	ts := core.Now().UnixNano()
	return core.SignAttestation(identifier, ts, n.KeyPair)
}

func (n *Node) handleStateChain(blocks <-chan *statechain.Block) {
	for b := range blocks {
		if err := n.StateChain.AddBlock(b); err != nil {
			logging.Warnf("statechain: rejected block %d: %v", b.Index, err)
			// A gap means we are behind and the missing range exists on a
			// peer — pull it now instead of waiting for a reconnect that a
			// stable mesh never delivers (#656).
			if errors.Is(err, statechain.ErrGap) {
				statechain.ResyncOnGap(n.Host, n.StateChain)
			}
		} else {
			logging.Debugf("statechain: accepted block %d", b.Index)
		}
	}
}

func (n *Node) GetStateChainTip() *statechain.Block {
	return n.StateChain.Tip()
}

func (n *Node) GetStateChainBlock(index uint64) *statechain.Block {
	b, _ := n.StateChain.GetBlock(index)
	return b
}

func (n *Node) GetStateChainBlocks(start, limit uint64) []*statechain.Block {
	blocks, err := n.StateChain.GetBlocks(start, limit)
	if err != nil {
		return []*statechain.Block{}
	}
	return blocks
}

func (n *Node) GetStateChainBlockCount() uint64 {
	count, _ := n.StateChain.BlockCount()
	return count
}

func (n *Node) GetStateKV(key string) (json.RawMessage, bool) {
	return n.StateChain.GetKV(key)
}

func (n *Node) GetStateKVByPrefix(prefix string) map[string]json.RawMessage {
	return n.StateChain.GetKVByPrefix(prefix)
}

func (n *Node) GetAllStateKV() map[string]json.RawMessage {
	return n.StateChain.GetAllKV()
}

func (n *Node) GetDAOKeyset() *statechain.DAOKeyset {
	return n.StateChain.DAOKeyset()
}

func (n *Node) SubmitStateChainBlock(b *statechain.Block) error {
	if err := n.StateChain.AddBlock(b); err != nil {
		return err
	}
	return n.StateChainGossip.Publish(n.ctx, b)
}

const keyFileName = "node.key"

// loadOrCreateKeyPair loads a node keypair from dataDir/node.key, or generates
// a new one and persists the 32-byte seed for identity across restarts.
func loadOrCreateKeyPair(dataDir string) (*core.KeyPair, error) {
	keyPath := filepath.Join(dataDir, keyFileName)

	seed, err := os.ReadFile(keyPath)
	if err == nil {
		if len(seed) != 32 {
			return nil, fmt.Errorf("corrupt key file %s: expected 32 bytes, got %d", keyPath, len(seed))
		}
		log.Printf("Loaded node identity from %s", keyPath)
		return core.KeyPairFromSeed(seed), nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	kp, err := core.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(keyPath, kp.Private.Seed(), 0o600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	log.Printf("Generated new node identity, saved to %s", keyPath)
	return kp, nil
}

func (n *Node) solvePoW(b *core.Block) {
	if n.difficulty == 0 {
		return
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, n.difficulty, runtime.NumCPU())
}

// satSub returns a-b, saturating at zero rather than wrapping (#808).
func satSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

// exceedsCapacity reports whether used+req would exceed capacity, without the
// unguarded used+req addition it replaces (#808). Ordering matters: the
// used > capacity test runs first, so capacity-used can never underflow.
func exceedsCapacity(used, req, capacity uint64) bool {
	return used > capacity || req > capacity-used
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

func shortAddr(a string) string {
	return shortHash(a)
}

func (n *Node) selfRegister() {
	nodePeer := n.Host.ID().String()
	ts := core.Now().UnixNano()
	// #829: a registration now carries BOTH the account address and the
	// verifying key, because the address no longer is the key. Build it through
	// directory.NewRegistration — the one path that cannot forget to declare
	// PubKey or declare one that doesn't match the account it signs for.
	reg := directory.NewRegistration(nodePeer, ts, n.KeyPair)
	account := reg.Account
	if err := n.Directory.Register(reg); err != nil {
		logging.Warnf("directory: self-register failed: %v", err)
	} else {
		logging.Debugf("directory: registered own account %s", shortAddr(account))
	}
	// Gossip immediately so other nodes learn about us right away.
	if err := n.DirGossip.Publish(n.ctx, reg); err != nil {
		logging.Warnf("directory: gossip self-registration failed: %v", err)
	}
}

func (n *Node) handleDirectoryGossip(regs <-chan *directory.Registration) {
	for reg := range regs {
		if err := n.Directory.Register(reg); err != nil {
			logging.Warnf("directory: rejected registration for %s: %v", shortAddr(reg.Account), err)
		} else {
			logging.Debugf("directory: accepted registration for %s on %s", shortAddr(reg.Account), reg.NodePeer[:12])
		}
	}
}

func (n *Node) directoryPruneLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			if pruned := n.Directory.Prune(); pruned > 0 {
				logging.Debugf("directory: pruned %d expired registrations", pruned)
			}
		}
	}
}

func (n *Node) directoryReRegisterLoop() {
	interval := n.Directory.TTL() / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.selfRegister()
			// Gossip own registration
			reg, ok := n.Directory.Lookup(n.KeyPair.Address())
			if ok {
				if err := n.DirGossip.Publish(n.ctx, reg); err != nil {
					logging.Warnf("directory: gossip self-registration failed: %v", err)
				}
			}
		}
	}
}

// RegisterAccount registers an external account (e.g. from a wallet) and gossips it.
func (n *Node) RegisterAccount(reg *directory.Registration) error {
	if err := n.Directory.Register(reg); err != nil {
		return err
	}
	if err := n.DirGossip.Publish(n.ctx, reg); err != nil {
		logging.Warnf("directory: gossip registration failed: %v", err)
	}
	return nil
}

// ListDirectory returns all active registrations.
func (n *Node) ListDirectory() []*directory.Registration {
	return n.Directory.List()
}

// LookupDirectory finds the registration for an account.
func (n *Node) LookupDirectory(account string) *directory.Registration {
	reg, ok := n.Directory.Lookup(account)
	if !ok {
		return nil
	}
	return reg
}

// validateChatEnvelope is the shared acceptance gate for chat: every ingress
// (p2p account_chat and API SendChat) runs the same full check — signature,
// canonical ID, freshness, and anti-spam PoW at the node's chat difficulty.
// Enforcing at only one door leaves the other as a free flood path (#729).
func (n *Node) validateChatEnvelope(env *chat.Envelope) error {
	return env.VerifyFull(n.chatDifficulty)
}

// ChatPoWDifficulty returns the PoW threshold inbound chat envelopes must
// satisfy. 0 = chat PoW disabled.
func (n *Node) ChatPoWDifficulty() uint64 {
	return n.chatDifficulty
}

func (n *Node) registerChatHandler() {
	n.Msg.Handle("account_chat", func(from peer.ID, payload json.RawMessage) (json.RawMessage, error) {
		var env chat.Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return nil, fmt.Errorf("invalid chat envelope: %w", err)
		}
		if err := n.validateChatEnvelope(&env); err != nil {
			return nil, fmt.Errorf("envelope verification failed: %w", err)
		}
		if !n.ChatStore.Store(&env) {
			return nil, fmt.Errorf("duplicate envelope")
		}
		log.Printf("Chat received: %s → %s (%d bytes)", shortAddr(env.From), shortAddr(env.To), len(env.Message))
		return json.Marshal(map[string]bool{"ok": true})
	})
}

func (n *Node) SendChatMessage(ctx context.Context, to, message string) error {
	env, err := chat.NewEnvelope(n.KeyPair.Address(), to, message, n.KeyPair, n.chatDifficulty)
	if err != nil {
		return fmt.Errorf("create envelope: %w", err)
	}
	return n.SendChat(ctx, env)
}

// ErrRecipientUnreachable is returned by SendChat when the recipient account
// resolves to no node in the directory. It is a typed sentinel so the API can
// map it to 404 (recipient not registered) and distinguish it from a malformed
// request or a delivery failure, which stay 400/502 (#746).
var ErrRecipientUnreachable = errors.New("recipient not found in directory")

func (n *Node) SendChat(ctx context.Context, env *chat.Envelope) error {
	if err := n.validateChatEnvelope(env); err != nil {
		return fmt.Errorf("invalid envelope: %w", err)
	}

	// Look up recipient's node via directory
	recipientPeer := n.PeerForAccount(env.To)
	if recipientPeer == "" {
		return ErrRecipientUnreachable
	}

	// Co-located recipient: the recipient's node IS this node, so there is no
	// peer to dial (dialing self errors, #742). Store + broadcast locally and
	// return success. ChatStore.Store dedupes, so an API-door replay is caught.
	if recipientPeer == n.Host.ID() {
		if !n.ChatStore.Store(env) {
			return fmt.Errorf("duplicate envelope")
		}
		return nil
	}

	// Cross-node: send first, store only after the peer accepts. Storing
	// before the request left a phantom on send failure that looked delivered
	// and survived reload (#742).
	if _, err := n.Msg.Request(ctx, recipientPeer, "account_chat", env); err != nil {
		return fmt.Errorf("send chat: %w", err)
	}
	if !n.ChatStore.Store(env) {
		return fmt.Errorf("duplicate envelope")
	}
	return nil
}

func (n *Node) GetChatMessages(account string, since int64) []*chat.Envelope {
	return n.ChatStore.Messages(account, since)
}

func (n *Node) GetChatAccounts() []string {
	return n.ChatStore.Accounts()
}

func (n *Node) SubscribeChat() (chan *chat.Envelope, func()) {
	return n.ChatStore.Subscribe()
}
