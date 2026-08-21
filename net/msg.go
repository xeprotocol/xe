package net

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/logging"
)

const (
	MsgProtocol        = "/xe/msg/1.0.0"
	MsgStreamDeadline  = 30 * time.Second
	MsgMaxRequestSize  = 65536
	MsgMaxResponseSize = 65536

	// Messenger ingress rate limits (#840). MsgProtocol is unauthenticated
	// beyond the netcheck handshake and its handlers do real work — store
	// lookups per requested hash, vote-store scans, chat PoW verification —
	// so before this a single peer could pin CPU and disk with a request
	// loop.
	//
	// The per-peer allowance is deliberately generous. Honest traffic here is
	// bursty, not steady: a node catching up pulls certificates, conflict
	// sibling bodies and votes from one peer in a clump, and throttling that
	// slows exactly the recovery paths that exist to unwedge a stuck account.
	// 200 in a burst then 50/s sustained is far above any observed honest
	// clump while still being a hard ceiling where there was none.
	msgPerPeerRPS   = 50
	msgPerPeerBurst = 200
	// The global bucket is what actually bounds total work, because peer IDs
	// cost one keygen and a per-peer limit alone is evaded by rotating them.
	// With block_request now capped at MaxBlockRequestHashes, 200 rps bounds
	// the worst case at ~12.8k store lookups/second. Tightening either number
	// wants measurements from a network of realistic size (#450).
	msgGlobalRPS    = 200
	msgGlobalBurst  = 400
	msgLimiterPeers = 2048

	// msgDenyLogInterval throttles rate-limit logging. Logging every refusal
	// turns a request flood into a disk-fill, which is a worse outcome than
	// the flood.
	msgDenyLogInterval = time.Minute
)

type MsgRequest struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type MsgResponse struct {
	Type    string          `json:"type"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

type MsgHandler func(from peer.ID, payload json.RawMessage) (json.RawMessage, error)

type Messenger struct {
	host     host.Host
	dht      *dht.IpfsDHT
	handlers map[string]MsgHandler
	mu       sync.RWMutex

	limiter    *peerRateLimiter
	lastDenyNs atomic.Int64
}

func NewMessenger(h host.Host, d *dht.IpfsDHT) *Messenger {
	m := &Messenger{
		host:     h,
		dht:      d,
		handlers: make(map[string]MsgHandler),
		limiter: newPeerRateLimiter(msgPerPeerRPS, msgPerPeerBurst,
			msgGlobalRPS, msgGlobalBurst, msgLimiterPeers),
	}

	h.SetStreamHandler(MsgProtocol, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("msg: handler panic: %v", r)
			}
		}()
		// Refuse before reading the request body: an over-budget peer must
		// cost us a stream reset, not a decode plus a handler.
		if !m.limiter.allow(s.Conn().RemotePeer()) {
			m.noteRateLimited(s.Conn().RemotePeer())
			_ = s.Reset()
			return
		}
		_ = s.SetDeadline(time.Now().Add(MsgStreamDeadline))

		var req MsgRequest
		if err := json.NewDecoder(io.LimitReader(s, MsgMaxRequestSize)).Decode(&req); err != nil {
			logging.Warnf("msg: decode request: %v", err)
			return
		}

		m.mu.RLock()
		handler, ok := m.handlers[req.Type]
		m.mu.RUnlock()

		enc := json.NewEncoder(s)
		if !ok {
			_ = enc.Encode(&MsgResponse{Type: req.Type, Error: "unknown message type: " + req.Type})
			return
		}

		result, err := handler(s.Conn().RemotePeer(), req.Payload)
		if err != nil {
			_ = enc.Encode(&MsgResponse{Type: req.Type, Error: err.Error()})
			return
		}

		_ = enc.Encode(&MsgResponse{Type: req.Type, Payload: result})
	})

	return m
}

// noteRateLimited logs at most once per msgDenyLogInterval, with the running
// totals, so a sustained flood produces a bounded log volume.
func (m *Messenger) noteRateLimited(p peer.ID) {
	now := time.Now().UnixNano()
	last := m.lastDenyNs.Load()
	if now-last < int64(msgDenyLogInterval) {
		return
	}
	if !m.lastDenyNs.CompareAndSwap(last, now) {
		return
	}
	allowed, denied, buckets := m.limiter.stats()
	logging.Warnf("msg: rate limited peer %s (allowed=%d denied=%d tracked-peers=%d)",
		p.ShortString(), allowed, denied, buckets)
}

// RateLimitStats reports allowed and denied Messenger requests.
func (m *Messenger) RateLimitStats() (allowed, denied uint64) {
	a, d, _ := m.limiter.stats()
	return a, d
}

func (m *Messenger) Handle(msgType string, h MsgHandler) {
	m.mu.Lock()
	m.handlers[msgType] = h
	m.mu.Unlock()
}

func (m *Messenger) Request(ctx context.Context, target peer.ID, msgType string, payload any) (json.RawMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("msg: marshal payload: %w", err)
	}

	if len(m.host.Peerstore().Addrs(target)) == 0 && m.dht != nil {
		pi, err := m.dht.FindPeer(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("msg: find peer %s: %w", target.ShortString(), err)
		}
		if err := m.host.Connect(ctx, pi); err != nil {
			return nil, fmt.Errorf("msg: connect to %s: %w", target.ShortString(), err)
		}
	}

	s, err := m.host.NewStream(ctx, target, MsgProtocol)
	if err != nil {
		return nil, fmt.Errorf("msg: open stream to %s: %w", target.ShortString(), err)
	}
	defer func() { _ = s.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(MsgStreamDeadline)
	}
	_ = s.SetDeadline(deadline)

	if err := json.NewEncoder(s).Encode(&MsgRequest{Type: msgType, Payload: raw}); err != nil {
		return nil, fmt.Errorf("msg: encode request: %w", err)
	}
	if err := s.CloseWrite(); err != nil {
		return nil, fmt.Errorf("msg: close write: %w", err)
	}

	var resp MsgResponse
	if err := json.NewDecoder(io.LimitReader(s, MsgMaxResponseSize)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("msg: decode response: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("msg %s: %s", msgType, resp.Error)
	}

	return resp.Payload, nil
}
