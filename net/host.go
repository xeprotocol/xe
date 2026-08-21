package net

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	connmgrImpl "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/x/rate"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/xeprotocol/xe/logging"
)

const mdnsServiceTag = "xe-poc"

// NewHost creates a libp2p host listening on the given port.
// If dataDir is non-empty, the host identity key is persisted to dataDir/host.key
// so the peer ID survives restarts.
// If gater is non-nil it is installed as the ConnectionGater, allowing the
// caller to reject banned peers before stream negotiation.
func NewHost(ctx context.Context, port int, dataDir string, version string, enableRelay bool, gater connmgr.ConnectionGater, maxConnsPerIP int) (host.Host, error) {
	addr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	cm, err := connmgrImpl.NewConnManager(100, 400, connmgrImpl.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("connmgr: %w", err)
	}

	if maxConnsPerIP <= 0 {
		maxConnsPerIP = 8
	}

	rm, err := newResourceManager(maxConnsPerIP)
	if err != nil {
		return nil, fmt.Errorf("rcmgr: %w", err)
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(addr),
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		libp2p.UserAgent("xe/" + version),
	}
	if gater != nil {
		opts = append(opts, libp2p.ConnectionGater(gater))
	}
	if dataDir != "" {
		privKey, err := loadOrCreateHostKey(dataDir)
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		opts = append(opts, libp2p.Identity(privKey))
	}
	if enableRelay {
		opts = append(opts,
			libp2p.EnableRelay(),
			libp2p.EnableRelayService(),
			libp2p.EnableHolePunching(),
		)
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("libp2p.New: %w", err)
	}

	log.Printf("Host ID: %s", h.ID())
	for _, a := range h.Addrs() {
		log.Printf("Listening on: %s/p2p/%s", a, h.ID())
	}

	return h, nil
}

func newResourceManager(maxConnsPerIP int) (network.ResourceManager, error) {
	limits := rcmgr.DefaultLimits.AutoScale()
	v6Broader := 4 * maxConnsPerIP
	rm, err := rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(limits),
		rcmgr.WithLimitPerSubnet(
			[]rcmgr.ConnLimitPerSubnet{
				{PrefixLength: 32, ConnCount: maxConnsPerIP},
			},
			[]rcmgr.ConnLimitPerSubnet{
				{PrefixLength: 56, ConnCount: maxConnsPerIP},
				{PrefixLength: 48, ConnCount: v6Broader},
			},
		),
		rcmgr.WithNetworkPrefixLimit(
			[]rcmgr.NetworkPrefixLimit{
				{Network: netip.MustParsePrefix("127.0.0.0/8"), ConnCount: math.MaxInt},
			},
			nil,
		),
		rcmgr.WithConnRateLimiters(&rate.Limiter{
			NetworkPrefixLimits: []rate.PrefixLimit{
				{Prefix: netip.MustParsePrefix("127.0.0.0/8")},
				{Prefix: netip.MustParsePrefix("::1/128")},
			},
			SubnetRateLimiter: rate.SubnetLimiter{
				IPv4SubnetLimits: []rate.SubnetLimit{
					{PrefixLength: 32, Limit: rate.Limit{RPS: 1, Burst: 2 * maxConnsPerIP}},
				},
				IPv6SubnetLimits: []rate.SubnetLimit{
					{PrefixLength: 56, Limit: rate.Limit{RPS: 1, Burst: 2 * maxConnsPerIP}},
					{PrefixLength: 48, Limit: rate.Limit{RPS: 2, Burst: 2 * v6Broader}},
				},
				GracePeriod: time.Minute,
			},
		}),
	)
	if err != nil {
		return nil, err
	}
	return rm, nil
}

func loadOrCreateHostKey(dataDir string) (crypto.PrivKey, error) {
	keyPath := filepath.Join(dataDir, "host.key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		key, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal host key: %w", err)
		}
		log.Printf("Loaded libp2p host identity from %s", keyPath)
		return key, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read host key: %w", err)
	}

	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	raw, err := crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	log.Printf("Generated new libp2p host identity, saved to %s", keyPath)
	return key, nil
}

// SetupDiscovery starts mDNS discovery and connects to found peers.
func SetupDiscovery(ctx context.Context, h host.Host) error {
	n := &discoveryNotifee{ctx: ctx, h: h}
	svc := mdns.NewMdnsService(h, mdnsServiceTag, n)
	return svc.Start()
}

// ParsePeerAddr parses a multiaddr string into a peer.AddrInfo.
func ParsePeerAddr(addr string) (*peer.AddrInfo, error) {
	maddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse multiaddr: %w", err)
	}
	pi, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, fmt.Errorf("addr info: %w", err)
	}
	return pi, nil
}

// DialPeer connects to a peer at the given multiaddr string (e.g. "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...").
func DialPeer(ctx context.Context, h host.Host, addr string) error {
	pi, err := ParsePeerAddr(addr)
	if err != nil {
		return err
	}
	if err := h.Connect(ctx, *pi); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	logging.Debugf("Connected to bootstrap peer: %s", pi.ID.ShortString())
	return nil
}

type discoveryNotifee struct {
	ctx context.Context
	h   host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return
	}
	logging.Debugf("Discovered peer: %s", pi.ID.ShortString())
	if err := n.h.Connect(n.ctx, pi); err != nil {
		logging.Warnf("Failed to connect to %s: %v", pi.ID.ShortString(), err)
	}
}
