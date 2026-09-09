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
	providerPriceMultMilli uint64
	acceptPolicy           LeaseAcceptPolicy
	VMManager              vm.Manager
	perfCert               atomic.Pointer[perf.Certificate]
	CertGossip             *xenet.CertificateGossip
	certCache              *certSet
	certsOnce              sync.Once

	attRateMu        sync.Mutex
	attRateMap       map[string]time.Time
	consumerVMs      sync.Map
	pendingOffersMu  sync.Mutex
	pendingOffers    map[string]*xenet.ResourceOffer
	providerAds      sync.Map
	blockCreateMu    sync.Mutex
	reservedRes      vm.Resources
	reservedResMu    sync.Mutex
	syncTracker      *xenet.SyncTracker
	syncWait         func()
	gater            *xenet.NetworkGater
	activationLog    *activationReporter
	tunnelRegistry   *xenet.TunnelRegistry
	acceptInFlight   map[string]struct{}
	acceptInFlightMu sync.Mutex
	pullSem          chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

const maxInFlightVotePulls = 32

type Config struct {
	Port       int
	DialAddrs  []string
	DataDir    string
	Difficulty uint64

	ChatDifficulty uint64
	DisableMDNS    bool
	Store          core.Store
	Version        string
	Provide        bool
	VCPUs          uint64
	MemoryMB       uint64
	DiskGB         uint64

	PriceMultiplierMilli uint64

	AcceptPolicy  LeaseAcceptPolicy
	GenesisBlock  *statechain.Block
	MsgTTL        time.Duration
	LimactlPath   string
	MaxConnsPerIP int

	MaxInboundConns int

	DisableDiscovery bool

	DiscoveryTarget int
}

func New(ctx context.Context, cfg Config) (*Node, error) {
	ctx, cancel := context.WithCancel(ctx)

	gater := xenet.NewNetworkGater()
	if cfg.MaxInboundConns != 0 {
		gater.SetMaxInboundConns(cfg.MaxInboundConns)
	}

	gater.StartBanMaintenance(ctx, cfg.DataDir)

	scGenesis := cfg.GenesisBlock
	if scGenesis == nil {
		var gerr error
		scGenesis, gerr = statechain.LoadGenesis()
		if gerr != nil {
			cancel()
			return nil, fmt.Errorf("statechain genesis: %w", gerr)
		}
	}

	gater.SetGenesisHash(scGenesis.Hash)
	if id := statechain.NetworkIDFromGenesis(scGenesis); id != "" {
		core.SetNetworkID(id)
		gater.SetNetworkID(id)
		log.Printf("Network ID (from genesis): %s", id)
		log.Printf("Statechain genesis: %s", scGenesis.Hash)
	} else {
		log.Printf("WARNING: genesis sets no sys.network_id — this node will be banned by every peer that completes a handshake with it")
	}

	h, err := xenet.NewHost(ctx, cfg.Port, cfg.DataDir, cfg.Version, true, gater, cfg.MaxConnsPerIP)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("host: %w", err)
	}

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

	if err := preflightDataDirGenesis(s, cfg.DataDir); err != nil {
		cancel()
		return nil, err
	}

	var timekeeperConfigFn func() *core.TimekeeperConfig

	var minterConfigFn func() *core.MinterConfig

	var repConfigFn func() *core.RepresentativeConfig

	var epochRFn func() uint64
	var epochPayoutCapFn func() uint64
	var epochTWAPFn func() uint64
	var epochAtFn func(ns int64) []core.EpochParams

	var featureActiveFn func(feature string) bool

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

	vs := s.(core.VoteStore)
	cs := s.(core.ConflictStore)
	qs := s.(core.QuorumStore)
	voteMgr := core.NewVoteManager(vs, kp, ledger)
	quorumMgr := core.NewQuorumManager(qs, cs, vs, ledger)
	voteMgr.SetQuorumManager(quorumMgr)
	quorumMgr.StartStaleConflictSweep(ctx.Done())
	quorumMgr.RevoteFn = func(account, previous string) { voteMgr.CastVote(account, previous) }
	quorumMgr.OnFinalized = voteMgr.SweepFrontiers
	ledger.SetConflictCallback(voteMgr.OnConflict)
	ledger.SetBlockAddedCallback(voteMgr.OnBlockAdded)

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

	voteMgr.VoteEmitter = func(v *core.Vote) {
		if err := voteGossip.Publish(ctx, v); err != nil {
			log.Printf("vote broadcast failed: %v", err)
		}
	}

	syncTracker, syncWait := xenet.SetupSync(ctx, h, ledger)

	dhtInst, err := xenet.SetupDHT(ctx, h)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dht: %w", err)
	}

	if !cfg.DisableDiscovery {
		xenet.StartAmbientDiscovery(ctx, h, dhtInst, statechain.NetworkIDFromGenesis(scGenesis), cfg.DiscoveryTarget)
	}

	msg := xenet.NewMessenger(h, dhtInst)

	chatStore := chat.NewChatStore(1000)

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

	featureActiveFn = func(feature string) bool {
		return sc.FeatureActive(feature)
	}

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
			log.Printf("WARN: sys.representatives is not valid JSON (%v) — treating the quorum denominator as unrestricted", err)
			repCfgRaw, repCfgVal = string(raw), nil
			return nil
		}
		repCfgRaw, repCfgVal = string(raw), &rc
		return repCfgVal
	}
	ledger.SetRepresentativeConfigFn(func() *core.RepresentativeConfig { return repConfigFn() })

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

	epochAtFn = func(ns int64) []core.EpochParams {
		epochs := sc.GetKVByPrefix("epoch.")
		var active []statechain.EpochValue
		for _, raw := range epochs {
			var ev statechain.EpochValue
			if err := json.Unmarshal(raw, &ev); err != nil {
				continue
			}
			if ev.StartNS > ns {
				continue
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
		pullSem:                make(chan struct{}, maxInFlightVotePulls),
		ctx:                    ctx,
		cancel:                 cancel,
	}

	n.syncActivationPolicy()

	sc.SetOnBlock(func(*statechain.Block) { go n.syncActivationPolicy() })

	n.registerAttestationHandler()

	certLookupFn = n.certificateInfoByHash

	n.registerVMHandlers()
	n.registerChatHandler()

	if n.isProvider {

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

		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if !n.waitForAttestationPeers() {
				return
			}
			certGenerationLoop(n.ctx, n.generatePerformanceCertificate, certRetryInitialDelay, certRetryMaxDelay)
		}()

		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.certRebroadcastLoop()
		}()
	}

	n.selfRegister()

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

	n.loadPersistedCertificates()
	xenet.SetupCertSync(ctx, n.Host, n.Msg, n.collectCertificates, n.ingestCertificate)

	xenet.SetupBlockSync(n.Msg, n.Ledger.GetBlockOrStaged)
	n.QuorumMgr.PhantomPullFn = n.pullPhantomBlocks

	xenet.SetupVoteSync(n.Msg, n.VoteMgr.VotesForPosition)
	n.QuorumMgr.VotePullFn = n.pullConflictVotes

	n.VoteMgr.VotePullFn = n.pullFrontierVotes

	if len(cfg.DialAddrs) > 0 {
		n.bootstrapWithRetry(cfg.DialAddrs)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.joinDiagnosticLoop()
		}()
	}

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

		if b.Account == n.KeyPair.Address() {
			continue
		}
		err := n.Ledger.AddBlock(b)
		if err != nil {

			metrics.BlocksAdded.WithLabelValues("gossip_rejected").Inc()
			logging.Debugf("Rejected block %s: %v", shortHash(b.Hash), err)
		} else {
			metrics.BlocksAdded.WithLabelValues("gossip").Inc()
			logging.Debugf("Accepted block %s (%s on %s)", shortHash(b.Hash), b.Type, shortAddr(b.Account))
			n.syncTracker.MarkDirty()

			if b.Type == core.BlockLease && b.Destination == n.KeyPair.Address() && n.isProvider {
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					n.autoAcceptLease(b)
				}()
			}

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

		metrics.RecordVote(v.RepAccount())
	}
}

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
			asset = "XE"
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

func (n *Node) Address() string {
	return n.KeyPair.Address()
}

func (n *Node) GetBalance(account string) uint64 {
	return n.Ledger.GetBalance(account)
}

func (n *Node) GetAssetBalances(account string) map[string]uint64 {
	return n.Ledger.GetAssetBalances(account)
}

func (n *Node) GetSpendableBalances(account string) map[string]uint64 {
	return n.Ledger.SpendableBalances(account)
}

func (n *Node) IsBlockFinalized(account, hash string) bool {
	return n.Ledger.IsFinalized(account, hash)
}

func (n *Node) FinalHeight(account string) uint64 {
	return n.Ledger.FinalHeight(account)
}

func (n *Node) GetKeyset(account string) *core.Keyset {
	return n.Ledger.GetKeyset(account)
}

func (n *Node) GetReputation(account string) *core.ReputationAggregate {
	return n.Ledger.GetReputation(account)
}

func (n *Node) GetAllReputations() map[string]*core.ReputationAggregate {
	return n.Ledger.AllReputations()
}

func (n *Node) GetChain(account string) []*core.Block {
	return n.Ledger.GetChain(account)
}

func (n *Node) GetBlock(hash string) *core.Block {
	return n.Ledger.GetBlock(hash)
}

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

func (n *Node) pullFrontierVotes(account, previous string) bool {
	select {
	case <-n.ctx.Done():
		return false
	default:
	}
	select {
	case n.pullSem <- struct{}{}:
	default:
		return false
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() { <-n.pullSem }()
		peers := n.Host.Network().Peers()
		if len(peers) == 0 {
			return
		}
		xenet.PullVotes(n.ctx, n.Msg, peers, account, previous, n.VoteMgr.ReceiveVote)
		n.QuorumMgr.Retally(account, previous)
	}()
	return true
}

func (n *Node) GetPending(account string) []*core.PendingSend {
	return n.Ledger.GetPendingForAccount(account)
}

func (n *Node) GetFrontiers() map[string]string {
	return n.Ledger.Frontiers()
}

type FrontierInfo struct {
	Account        string `json:"account"`
	Frontier       string `json:"frontier"`
	BlockType      string `json:"block_type"`
	Timestamp      int64  `json:"timestamp"`
	BlockCount     int    `json:"block_count"`
	Representative string `json:"representative,omitempty"`
}

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

type AccountSummary struct {
	Address            string            `json:"address"`
	Balance            uint64            `json:"balance"`
	Balances           map[string]uint64 `json:"balances"`
	BlockCount         int               `json:"block_count"`
	Frontier           string            `json:"frontier"`
	LastBlockTimestamp int64             `json:"last_block_timestamp"`
}

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

func (n *Node) GetAllPending() []*core.PendingSend {
	return n.Ledger.GetAllPending()
}

func (n *Node) GetSupply() *core.SupplyReport {
	n.supplyOnce.Do(func() { n.supplyAuditor = core.NewSupplyAuditor(n.Ledger) })
	return n.supplyAuditor.Report()
}

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

	xenet.SignAdvertisement(ad, n.KeyPair.Private)
	msg := &xenet.MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	}
	if err := n.MarketGossip.Publish(n.ctx, msg); err != nil {
		log.Printf("Failed to publish resource advertisement: %v", err)
	}

	n.providerAds.Store(ad.Provider, ad)
}

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

func leaseHoldsCapacity(lease *core.Lease) bool {
	return !lease.State.Terminal() && lease.State != core.LeaseCreated
}

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
				if leaseHoldsCapacity(l) {
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

func (n *Node) GetConflicts(account string) []*core.Conflict {
	return n.Ledger.GetConflictsForAccount(account)
}

func (n *Node) GetAllConflicts() []*core.Conflict {
	return n.Ledger.GetAllConflicts()
}

type DelegationInfo struct {
	Weights map[string]uint64 `json:"weights"`

	TotalWeight uint64 `json:"total_weight"`

	IneligibleWeights map[string]uint64 `json:"ineligible_weights,omitempty"`
	IneligibleWeight  uint64            `json:"ineligible_weight"`

	EligibilityRestricted bool `json:"eligibility_restricted"`
	EligibilityFailedOpen bool `json:"eligibility_failed_open"`
}

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

type PeerInfo struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	Version     string `json:"version"`
	ConnectedAt int64  `json:"connected_at"`
}

type NodeInfo struct {
	ID string `json:"id"`

	Address    string     `json:"address"`
	PublicKey  string     `json:"public_key"`
	Version    string     `json:"version"`
	NetworkID  string     `json:"network_id,omitempty"`
	Peers      []PeerInfo `json:"peers"`
	PeerCount  int        `json:"peer_count"`
	Accounts   int        `json:"accounts"`
	BlockCount int        `json:"block_count"`

	DroppedBlocks uint64 `json:"dropped_blocks"`

	DelegationUnderflows uint64 `json:"delegation_underflows"`

	TotalDelegatedWeight uint64 `json:"total_delegated_weight"`
	Representatives      int    `json:"representatives"`
	FinalityAdvances     uint64 `json:"finality_advances"`
	LastFinalityNs       int64  `json:"last_finality_ns"`

	PoWDifficulty     string `json:"pow_difficulty"`
	ChatPoWDifficulty string `json:"chat_pow_difficulty"`

	LeaseTiming LeaseTimingInfo `json:"lease_timing"`

	Certificate CertificateStatus `json:"certificate"`
}

type CertificateStatus struct {
	Valid     bool   `json:"valid"`
	Hash      string `json:"hash,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type LeaseTimingInfo struct {
	MinDurationSecs  uint64 `json:"min_duration_secs"`
	SettleGraceNs    int64  `json:"settle_grace_ns"`
	ForceSettleGapNs int64  `json:"force_settle_gap_ns"`
	EscrowExpiryNs   int64  `json:"escrow_expiry_ns"`
	ArchiveGapNs     int64  `json:"archive_gap_ns"`
	MaxAttestSkewNs  int64  `json:"max_attestation_skew_ns"`
}

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

func (n *Node) Multiaddr() string {
	addrs := n.Host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	return fmt.Sprintf("%s/p2p/%s", addrs[0], n.Host.ID())
}

func (n *Node) Stop() {
	n.cancel()
	n.wg.Wait()

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

			if err := xenet.VerifyRequest(msg.Request); err != nil {
				logging.Warnf("Rejecting resource request: %v", err)
				continue
			}
			req := msg.Request

			if err := core.ValidateLeaseDimensions(req.VCPUs, req.MemoryMB, req.DiskGB, req.Duration); err != nil {
				log.Printf("Skipping request %s: %v", shortHash(req.RequestID), err)
				continue
			}

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

			if err := xenet.VerifyAdvertisement(msg.Ad); err != nil {
				logging.Warnf("Rejecting resource advertisement: %v", err)
				continue
			}
			n.providerAds.Store(msg.Ad.Provider, msg.Ad)

		case "offer":
			if msg.Offer == nil {
				continue
			}

			if err := xenet.VerifyOffer(msg.Offer); err != nil {
				logging.Warnf("Rejecting resource offer: %v", err)
				continue
			}

			n.pendingOffersMu.Lock()

			cutoff := time.Now().Add(-60 * time.Second).UnixNano()
			for id, o := range n.pendingOffers {
				if o.Timestamp < cutoff {
					delete(n.pendingOffers, id)
				}
			}

			if len(n.pendingOffers) < 1000 {
				n.pendingOffers[msg.Offer.RequestID] = msg.Offer
			}
			n.pendingOffersMu.Unlock()
			log.Printf("Received offer from %s for request %s", shortAddr(msg.Offer.Provider), shortHash(msg.Offer.RequestID))
		}
	}
}

func (n *Node) activeLeaseCount() uint64 {
	if n.VMManager == nil {
		return 0
	}
	return uint64(len(n.VMManager.List()))
}

func leaseAlreadyAccepted(lease *core.Lease) bool {
	return lease != nil && lease.State != core.LeaseCreated
}

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

	if n.VMManager != nil {
		if _, err := n.VMManager.Get(leaseBlock.Hash); err == nil {
			return
		}
	}

	if err := n.acceptPolicy.Allow(leaseBlock, n.activeLeaseCount()); err != nil {
		log.Printf("Auto-accept policy rejected lease %s: %v", shortHash(leaseBlock.Hash), err)
		return
	}

	myAddr := n.KeyPair.Address()
	stake := core.LeaseStake(leaseBlock.Amount)

	if stake > n.Ledger.GetAssetBalances(myAddr)["XUSD"] {
		log.Printf("Cannot auto-accept lease %s: insufficient XUSD for stake", shortHash(leaseBlock.Hash))
		return
	}

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

	n.blockCreateMu.Lock()

	xusdBal := n.Ledger.GetAssetBalances(myAddr)["XUSD"]
	if stake > xusdBal {
		n.blockCreateMu.Unlock()
		log.Printf("Cannot auto-accept lease %s: insufficient XUSD for stake (have %d, need %d)", shortHash(leaseBlock.Hash), xusdBal, stake)
		return
	}

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

		n.reservedResMu.Lock()
		n.reservedRes.VCPUs += leaseBlock.VCPUs
		n.reservedRes.MemoryMB += leaseBlock.MemoryMB
		n.reservedRes.DiskGB += leaseBlock.DiskGB
		n.reservedResMu.Unlock()
	}

	n.blockCreateMu.Unlock()

	n.provisionVM(leaseBlock)

	if n.VMManager != nil {
		n.reservedResMu.Lock()
		n.reservedRes.VCPUs -= leaseBlock.VCPUs
		n.reservedRes.MemoryMB -= leaseBlock.MemoryMB
		n.reservedRes.DiskGB -= leaseBlock.DiskGB
		n.reservedResMu.Unlock()
	}

	if n.VMManager != nil {
		if _, err := n.VMManager.Get(leaseBlock.Hash); err != nil {
			log.Printf("Lease %s: VM provision failed, not accepting", shortHash(leaseBlock.Hash))
			return
		}
	}

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
			log.Printf("Lease %s: our accept already stands on-chain, keeping VM", shortHash(leaseBlock.Hash))
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

func (n *Node) leaseWatchLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	accepted := make(map[string]bool)
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

		if lease.Settled || lease.State != core.LeaseAccepted {
			continue
		}
		expiry := lease.StartTime + int64(lease.Duration)*1e9
		if now < expiry {
			continue
		}

		if now > expiry+core.LeaseSettleGrace {
			continue
		}
		n.settleLease(lease)
	}
}

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

func shouldArchiveExpiredLease(lease *core.Lease, now int64) bool {
	if lease == nil || lease.Settled || lease.State != core.LeaseAccepted {
		return false
	}
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	return now >= expiry+core.LeaseEscrowExpiry+core.LeaseArchiveGap
}

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
	log.Printf("Archived expired lease %s: burned %d µXUSD escrow (both parties offline)",
		shortHash(lease.LeaseHash), lease.Cost+lease.Stake)
}

func (n *Node) forceSettleLease(lease *core.Lease) {
	myAddr := n.KeyPair.Address()

	if lease.Cost == 0 {
		log.Printf("lease_force_settle: stored lease.Cost is zero for %s", shortHash(lease.LeaseHash))
		return
	}

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

	n.finishSettle(b, lease)
}

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

	n.teardownVM(lease)
}

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

func (n *Node) ManualSettle(lease *core.Lease) {
	n.settleLease(lease)
}

func (n *Node) ValidateTunnelLease(leaseHash string, peerID peer.ID) error {
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return fmt.Errorf("lease not found")
	}

	if lease.State != core.LeaseAccepted {
		return fmt.Errorf("lease not active")
	}
	if lease.Provider != n.KeyPair.Address() {
		return fmt.Errorf("not the provider for this lease")
	}
	return nil
}

func (n *Node) DialSSH(leaseHash string) (net.Conn, error) {
	if n.VMManager == nil {
		return nil, fmt.Errorf("not a provider")
	}
	return n.VMManager.DialSSH(leaseHash)
}

func (n *Node) OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	return xenet.OpenTunnel(ctx, n.Host, n.DHT, providerPeer, leaseHash)
}

func (n *Node) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return nil, fmt.Errorf("lease not found")
	}

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

func satSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

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

	reg := directory.NewRegistration(nodePeer, ts, n.KeyPair)
	account := reg.Account
	if err := n.Directory.Register(reg); err != nil {
		logging.Warnf("directory: self-register failed: %v", err)
	} else {
		logging.Debugf("directory: registered own account %s", shortAddr(account))
	}

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

			reg, ok := n.Directory.Lookup(n.KeyPair.Address())
			if ok {
				if err := n.DirGossip.Publish(n.ctx, reg); err != nil {
					logging.Warnf("directory: gossip self-registration failed: %v", err)
				}
			}
		}
	}
}

func (n *Node) RegisterAccount(reg *directory.Registration) error {
	if err := n.Directory.Register(reg); err != nil {
		return err
	}
	if err := n.DirGossip.Publish(n.ctx, reg); err != nil {
		logging.Warnf("directory: gossip registration failed: %v", err)
	}
	return nil
}

func (n *Node) ListDirectory() []*directory.Registration {
	return n.Directory.List()
}

func (n *Node) LookupDirectory(account string) *directory.Registration {
	reg, ok := n.Directory.Lookup(account)
	if !ok {
		return nil
	}
	return reg
}

func (n *Node) validateChatEnvelope(env *chat.Envelope) error {
	return env.VerifyFull(n.chatDifficulty)
}

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

var ErrRecipientUnreachable = errors.New("recipient not found in directory")

func (n *Node) SendChat(ctx context.Context, env *chat.Envelope) error {
	if err := n.validateChatEnvelope(env); err != nil {
		return fmt.Errorf("invalid envelope: %w", err)
	}

	recipientPeer := n.PeerForAccount(env.To)
	if recipientPeer == "" {
		return ErrRecipientUnreachable
	}

	if recipientPeer == n.Host.ID() {
		if !n.ChatStore.Store(env) {
			return fmt.Errorf("duplicate envelope")
		}
		return nil
	}

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

func (n *Node) GetChatContacts(account string) []string {
	return n.ChatStore.Contacts(account)
}

func (n *Node) SubscribeChat() (chan *chat.Envelope, func()) {
	return n.ChatStore.Subscribe()
}
