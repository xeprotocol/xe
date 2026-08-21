package statechain

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/logging"
)

const (
	SyncProtocol = "/xe/statechain-sync/1.0.0"

	syncPageSize        = 64
	syncMaxBlocks       = 10000
	syncCooldown        = 30 * time.Second
	syncStreamDeadline  = 60 * time.Second
	syncMaxRequestSize  = 1024     // sync requests are tiny
	syncMaxResponseSize = 10 << 20 // 10 MiB per page
)

type syncRateLimiter struct {
	mu   sync.Mutex
	last map[peer.ID]time.Time
}

func newSyncRateLimiter() *syncRateLimiter {
	return &syncRateLimiter{last: make(map[peer.ID]time.Time)}
}

func (rl *syncRateLimiter) allow(pid peer.ID) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for id, t := range rl.last {
		if now.Sub(t) >= syncCooldown {
			delete(rl.last, id)
		}
	}
	if t, ok := rl.last[pid]; ok && now.Sub(t) < syncCooldown {
		return false
	}
	rl.last[pid] = now
	return true
}

type syncRequest struct {
	TipIndex int64 `json:"tip_index"`
}

type syncResponse struct {
	Blocks  []*Block `json:"blocks"`
	HasMore bool     `json:"has_more"`
}

// SetupSync registers the state chain sync stream handler and triggers
// outbound sync on new peer connections.
func SetupSync(h host.Host, chain *Chain) {
	inboundRL := newSyncRateLimiter()
	outboundRL := newSyncRateLimiter()

	h.SetStreamHandler(SyncProtocol, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		_ = s.SetDeadline(time.Now().Add(syncStreamDeadline))
		if !inboundRL.allow(s.Conn().RemotePeer()) {
			return
		}
		handleSyncStream(s, chain)
	})

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			go func() {
				pid := conn.RemotePeer()
				if !outboundRL.allow(pid) {
					return
				}
				if err := requestSync(h, pid, chain); err != nil {
					logging.Warnf("statechain sync with %s failed: %v", pid.ShortString(), err)
				}
			}()
		},
	})
}

func handleSyncStream(s network.Stream, chain *Chain) {
	var req syncRequest
	dec := json.NewDecoder(io.LimitReader(s, syncMaxRequestSize))
	if err := dec.Decode(&req); err != nil {
		return
	}

	tip := chain.Tip()
	if tip == nil {
		return
	}

	// Validate TipIndex before arithmetic to prevent integer overflow.
	// Valid range: -1 (empty chain) to tip.Index.
	if req.TipIndex < -1 || (req.TipIndex >= 0 && uint64(req.TipIndex) > tip.Index) {
		_ = json.NewEncoder(s).Encode(syncResponse{HasMore: false})
		return
	}

	startIndex := uint64(req.TipIndex + 1)
	if startIndex == 0 {
		startIndex = 1 // never send genesis
	}
	if startIndex > tip.Index {
		// Client is up to date
		_ = json.NewEncoder(s).Encode(syncResponse{HasMore: false})
		return
	}

	enc := json.NewEncoder(s)
	totalSent := 0

	for idx := startIndex; idx <= tip.Index && totalSent < syncMaxBlocks; {
		remaining := tip.Index - idx + 1
		pageCount := uint64(syncPageSize)
		if remaining < pageCount {
			pageCount = remaining
		}

		blocks, err := chain.GetBlocks(idx, pageCount)
		if err != nil {
			logging.Warnf("statechain sync: read blocks: %v", err)
			return
		}

		totalSent += len(blocks)
		hasMore := idx+uint64(len(blocks)) <= tip.Index && totalSent < syncMaxBlocks

		if err := enc.Encode(syncResponse{Blocks: blocks, HasMore: hasMore}); err != nil {
			return
		}

		idx += uint64(len(blocks))
	}
}

func requestSync(h host.Host, pid peer.ID, chain *Chain) error {
	ctx, cancel := context.WithTimeout(context.Background(), syncStreamDeadline)
	defer cancel()

	s, err := h.NewStream(ctx, pid, SyncProtocol)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(syncStreamDeadline))

	tip := chain.Tip()
	tipIndex := int64(-1)
	if tip != nil {
		tipIndex = int64(tip.Index)
	}

	if err := json.NewEncoder(s).Encode(syncRequest{TipIndex: tipIndex}); err != nil {
		return err
	}
	if err := s.CloseWrite(); err != nil {
		return err
	}

	dec := json.NewDecoder(io.LimitReader(s, syncMaxResponseSize))
	added := 0
	for {
		var resp syncResponse
		if err := dec.Decode(&resp); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		for _, b := range resp.Blocks {
			if err := chain.AddBlock(b); err != nil {
				logging.Warnf("statechain sync: block %d: %v", b.Index, err)
			} else {
				added++
			}
		}
		if !resp.HasMore {
			break
		}
		if added >= syncMaxBlocks {
			break
		}
	}

	if added > 0 {
		logging.Debugf("statechain sync: synced %d block(s) from %s", added, pid.ShortString())
	}
	return nil
}

const gapSyncBackoff = 30 * time.Second

// gapSyncAllowed reports whether a gap-triggered resync may fire now,
// consuming the backoff window when it does.
func (c *Chain) gapSyncAllowed() bool {
	c.gapSyncMu.Lock()
	defer c.gapSyncMu.Unlock()
	if time.Since(c.lastGapSync) < gapSyncBackoff {
		return false
	}
	c.lastGapSync = time.Now()
	return true
}

// ResyncOnGap pulls missing statechain blocks from connected peers after a
// gossiped block was rejected as a gap (#656). Sync otherwise runs only from
// the connect-time notifier — one-shot. When that attempt fails (the peer was
// mid-replay during a rolling deploy), a stable mesh never retries it: before
// #649/#652 the gater's bans cycled every connection within minutes, and each
// reconnect re-fired the sync, masking this; with connections now long-lived
// the node sat behind forever, gap-rejecting every later epoch (ffm, 40+ min,
// 2026-06-12). The gap rejection itself is the demand signal that we are
// behind and that the missing range exists on some peer. Throttled to one
// attempt per backoff window, tries up to three peers, runs async (called
// from the gossip ingest loop).
func ResyncOnGap(h host.Host, chain *Chain) {
	if !chain.gapSyncAllowed() {
		return
	}
	go func() {
		for i, pid := range h.Network().Peers() {
			if i >= 3 {
				return
			}
			if err := requestSync(h, pid, chain); err != nil {
				logging.Warnf("statechain gap-resync with %s failed: %v", pid.ShortString(), err)
				continue
			}
			logging.Debugf("statechain gap-resync: tip now %d", chain.Tip().Index)
			return
		}
	}()
}
