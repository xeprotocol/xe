package statechain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
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
	syncMaxRequestSize  = 1024
	syncMaxResponseSize = 10 << 20

	syncMaxRoundBlocks = syncMaxBlocks - 1 + syncPageSize
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

type syncPage struct {
	Blocks  syncPageBlocks `json:"blocks"`
	HasMore bool           `json:"has_more"`
}

type syncPageBlocks []*Block

func (p *syncPageBlocks) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("sync page: blocks is not an array")
	}
	for dec.More() {
		if len(*p) == syncPageSize {
			return fmt.Errorf("sync page: more than %d blocks", syncPageSize)
		}
		var b *Block
		if err := dec.Decode(&b); err != nil {
			return err
		}
		*p = append(*p, b)
	}
	return nil
}

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
				if err := runSyncRound(pid, func() error { return requestSync(h, pid, chain) }); err != nil {
					logging.Warnf("statechain sync with %s failed: %v", pid.ShortString(), err)
				}
			}()
		},
	})
}

func runSyncRound(pid peer.ID, round func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("statechain sync: round with %s panicked: %v\n%s", pid.ShortString(), r, debug.Stack())
			err = fmt.Errorf("round panicked: %v", r)
		}
	}()
	return round()
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

	if req.TipIndex < -1 || (req.TipIndex >= 0 && uint64(req.TipIndex) > tip.Index) {
		_ = json.NewEncoder(s).Encode(syncResponse{HasMore: false})
		return
	}

	startIndex := uint64(req.TipIndex + 1)
	if startIndex == 0 {
		startIndex = 1
	}
	if startIndex > tip.Index {

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
	received := 0
	nulls := 0
	for {
		var resp syncPage
		if err := dec.Decode(&resp); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		for _, b := range resp.Blocks {
			if received == syncMaxRoundBlocks {
				break
			}
			received++

			if b == nil {
				nulls++
				continue
			}
			if err := chain.AddBlock(b); err != nil {
				logging.Warnf("statechain sync: block %d: %v", b.Index, err)
			} else {
				added++
			}
		}
		if received >= syncMaxRoundBlocks {
			logging.Warnf("statechain sync: hit round block cap (%d) with %s, stopping", syncMaxRoundBlocks, pid.ShortString())
			break
		}
		if !resp.HasMore {
			break
		}
		if added >= syncMaxBlocks {
			break
		}
	}

	if nulls > 0 {
		logging.Warnf("statechain sync: dropped %d null block(s) from %s", nulls, pid.ShortString())
	}
	if added > 0 {
		logging.Debugf("statechain sync: synced %d block(s) from %s", added, pid.ShortString())
	}
	return nil
}

const gapSyncBackoff = 30 * time.Second

func (c *Chain) gapSyncAllowed() bool {
	c.gapSyncMu.Lock()
	defer c.gapSyncMu.Unlock()
	if time.Since(c.lastGapSync) < gapSyncBackoff {
		return false
	}
	c.lastGapSync = time.Now()
	return true
}

func ResyncOnGap(h host.Host, chain *Chain) {
	if !chain.gapSyncAllowed() {
		return
	}
	go func() {
		for i, pid := range h.Network().Peers() {
			if i >= 3 {
				return
			}
			if err := runSyncRound(pid, func() error { return requestSync(h, pid, chain) }); err != nil {
				logging.Warnf("statechain gap-resync with %s failed: %v", pid.ShortString(), err)
				continue
			}
			logging.Debugf("statechain gap-resync: tip now %d", chain.Tip().Index)
			return
		}
	}()
}
