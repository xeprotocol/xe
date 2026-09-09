package net

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	sync2 "sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/metrics"
)

const (
	syncProtocol    = "/xe/sync/1.0.0"
	defaultPageSize = 64
	maxPageSize     = 256

	maxTotalBlocks = 10000

	syncCooldown = 5 * time.Second

	periodicSyncInterval = 10 * time.Second

	maxSyncRequestBytes = 1 << 20

	maxSyncResponseBytes = 10 << 20

	maxFrontiers = 10000

	maxServerBlocks = 10000

	unrecognizedDropThreshold = 3

	syncReprobeInterval = 10 * time.Minute
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

type syncTracker struct {
	mu             sync.Mutex
	lastFrontiers  map[peer.ID]map[string]string
	dirty          int32
	lastFullResync time.Time

	rejections map[peer.ID]map[string]int

	syncIncapable map[peer.ID]time.Time
}

const fullResyncInterval = 60 * time.Second

func newSyncTracker() *syncTracker {
	return &syncTracker{
		lastFrontiers:  make(map[peer.ID]map[string]string),
		dirty:          1,
		lastFullResync: time.Time{},
		rejections:     make(map[peer.ID]map[string]int),
		syncIncapable:  make(map[peer.ID]time.Time),
	}
}

func (st *syncTracker) MarkDirty() {
	if st == nil {
		return
	}
	sync2.StoreInt32(&st.dirty, 1)
}

func (st *syncTracker) shouldSync(pid peer.ID, currentFrontiers map[string]string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	if since, ok := st.syncIncapable[pid]; ok {
		if time.Since(since) < syncReprobeInterval {
			return false
		}
		delete(st.syncIncapable, pid)
	}

	if time.Since(st.lastFullResync) >= fullResyncInterval {
		return true
	}

	if sync2.LoadInt32(&st.dirty) != 0 {
		return true
	}

	last, ok := st.lastFrontiers[pid]
	if !ok {
		return true
	}

	return !frontiersEqual(last, currentFrontiers)
}

func (st *syncTracker) recordSync(pid peer.ID, frontiers map[string]string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	cp := make(map[string]string, len(frontiers))
	for k, v := range frontiers {
		cp[k] = v
	}
	st.lastFrontiers[pid] = cp
}

func (st *syncTracker) clearDirty() {
	st.mu.Lock()
	st.lastFullResync = time.Now()
	st.mu.Unlock()
	sync2.StoreInt32(&st.dirty, 0)
}

func (st *syncTracker) removePeer(pid peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.lastFrontiers, pid)
	delete(st.rejections, pid)
	delete(st.syncIncapable, pid)
}

func (st *syncTracker) markSyncIncapable(pid peer.ID) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.syncIncapable == nil {
		st.syncIncapable = make(map[peer.ID]time.Time)
	}
	st.syncIncapable[pid] = time.Now()
}

func (st *syncTracker) isSyncIncapable(pid peer.ID) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	since, ok := st.syncIncapable[pid]
	return ok && time.Since(since) < syncReprobeInterval
}

func isProtocolNotSupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), "protocols not supported")
}

func (st *syncTracker) filterFrontiers(pid peer.ID, frontiers map[string]string) map[string]string {
	st.mu.Lock()
	defer st.mu.Unlock()
	counts := st.rejections[pid]
	dropAny := false
	for acc := range frontiers {
		if counts[acc] >= unrecognizedDropThreshold {
			dropAny = true
			break
		}
	}
	if !dropAny {
		return frontiers
	}
	out := make(map[string]string, len(frontiers))
	dropped := 0
	for acc, h := range frontiers {
		if counts[acc] >= unrecognizedDropThreshold {
			dropped++
			continue
		}
		out[acc] = h
	}
	logging.Warnf("sync: dropping %d account(s) from frontier map to %s (>= %d consecutive rejections) — recovery path",
		dropped, pid.ShortString(), unrecognizedDropThreshold)
	return out
}

func (st *syncTracker) recordRejections(pid peer.ID, rejected []string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rejections == nil {
		st.rejections = make(map[peer.ID]map[string]int)
	}
	cur := st.rejections[pid]
	if cur == nil {
		cur = make(map[string]int)
		st.rejections[pid] = cur
	}
	rejectedSet := make(map[string]struct{}, len(rejected))
	for _, a := range rejected {
		rejectedSet[a] = struct{}{}
	}

	for acc := range cur {
		if _, still := rejectedSet[acc]; !still {
			delete(cur, acc)
		}
	}

	for acc := range rejectedSet {
		cur[acc]++
	}

	if len(cur) == 0 {
		delete(st.rejections, pid)
	}
}

func (st *syncTracker) rejectionCount(pid peer.ID, account string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.rejections[pid][account]
}

func (st *syncTracker) isDirtyForTest() bool {
	return sync2.LoadInt32(&st.dirty) != 0
}

const maxQuarantineEntries = 8192

type blockQuarantine struct {
	mu     sync.RWMutex
	hashes map[string]struct{}
	order  []string
	max    int
}

func newBlockQuarantine() *blockQuarantine {
	return &blockQuarantine{hashes: make(map[string]struct{}), max: maxQuarantineEntries}
}

func (q *blockQuarantine) add(hash string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.hashes[hash]; ok {
		return
	}
	q.hashes[hash] = struct{}{}
	q.order = append(q.order, hash)
	for len(q.order) > q.max {
		oldest := q.order[0]
		q.order = q.order[1:]
		delete(q.hashes, oldest)
	}

	metrics.BlocksQuarantined.Inc()
	metrics.QuarantinedBlocks.Set(float64(len(q.hashes)))
}

func (q *blockQuarantine) contains(hash string) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	_, ok := q.hashes[hash]
	return ok
}

func (q *blockQuarantine) len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.hashes)
}

func frontiersEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

type SyncTracker = syncTracker

func SetupSync(ctx context.Context, h host.Host, ledger *core.Ledger) (*SyncTracker, func()) {
	inboundRL := newSyncRateLimiter()
	outboundRL := newSyncRateLimiter()
	tracker := newSyncTracker()
	quarantine := newBlockQuarantine()
	gate := &spawnGate{}

	h.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		_ = s.SetDeadline(time.Now().Add(60 * time.Second))
		if !inboundRL.allow(s.Conn().RemotePeer()) {
			return
		}
		handleSyncStream(s, ledger, tracker)
	})

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			gate.spawn(func() {
				pid := conn.RemotePeer()
				if !outboundRL.allow(pid) {
					return
				}
				if err := requestSync(h, pid, ledger, quarantine, tracker); err != nil {
					metrics.RecordSyncRound(false)
					if isProtocolNotSupported(err) {
						tracker.markSyncIncapable(pid)
						logging.Warnf("sync: peer %s does not support %s, skipping sync for %s", pid.ShortString(), syncProtocol, syncReprobeInterval)
					} else {
						logging.Warnf("sync: sync with %s failed: %v", pid.ShortString(), err)
					}
				} else {
					metrics.RecordSyncRound(true)
					tracker.recordSync(pid, ledger.Frontiers())
				}
			})
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			tracker.removePeer(conn.RemotePeer())
		},
	})

	gate.spawn(func() {
		ticker := time.NewTicker(periodicSyncInterval)
		defer ticker.Stop()
		runPeriodicResync(ctx, ticker.C, func() {
			currentFrontiers := ledger.Frontiers()
			synced := false
			for _, pid := range h.Network().Peers() {
				if !outboundRL.allow(pid) {
					continue
				}

				if !peerMaySupportSync(h, pid) {
					tracker.markSyncIncapable(pid)
					continue
				}
				if !tracker.shouldSync(pid, currentFrontiers) {
					continue
				}
				synced = true
				p := pid
				gate.spawn(func() {
					if err := requestSync(h, p, ledger, quarantine, tracker); err != nil {
						metrics.RecordSyncRound(false)
						if isProtocolNotSupported(err) {
							tracker.markSyncIncapable(p)
							logging.Warnf("sync: peer %s does not support %s, skipping periodic sync for %s", p.ShortString(), syncProtocol, syncReprobeInterval)
						} else {
							logging.Warnf("sync: periodic sync with %s failed: %v", p.ShortString(), err)
						}
					} else {
						metrics.RecordSyncRound(true)
						tracker.recordSync(p, ledger.Frontiers())
					}
				})
			}
			if synced {
				tracker.clearDirty()
			}
		})
	})

	return tracker, gate.wait
}

type spawnGate struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

func (g *spawnGate) spawn(f func()) bool {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return false
	}
	g.wg.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.wg.Done()
		f()
	}()
	return true
}

func (g *spawnGate) wait() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.wg.Wait()
}

func runPeriodicResync(ctx context.Context, tick <-chan time.Time, round func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			round()
		}
	}
}

func handleSyncStream(s network.Stream, ledger *core.Ledger, tracker *syncTracker) {
	var req SyncRequest
	dec := json.NewDecoder(io.LimitReader(s, maxSyncRequestBytes))
	if err := dec.Decode(&req); err != nil {
		if err != io.EOF {
			logging.Warnf("sync: decode request: %v", err)
		}
		return
	}

	if len(req.Frontiers) > maxFrontiers {
		trimmed := make(map[string]string, maxFrontiers)
		n := 0
		for k, v := range req.Frontiers {
			if n >= maxFrontiers {
				break
			}
			trimmed[k] = v
			n++
		}
		req.Frontiers = trimmed
	}

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	behind := frontiersWhereServerIsBehind(req.Frontiers, ledger)

	enc := json.NewEncoder(s)
	ch := findMissingBlocksPaginated(req.Frontiers, ledger, pageSize)
	totalBlocks, encErr := streamPages(enc, ch)
	if encErr != nil {
		logging.Warnf("sync: encode response: %v", encErr)
		return
	}
	if totalBlocks > 0 {
		logging.Debugf("sync: sent %d block(s) to %s", totalBlocks, s.Conn().RemotePeer().ShortString())
	}
	if tracker != nil && len(behind) > 0 {
		logging.Debugf("sync: peer %s is ahead on %d account(s) we hold — scheduling self-resync",
			s.Conn().RemotePeer().ShortString(), len(behind))
		tracker.MarkDirty()
	}
}

func frontiersWhereServerIsBehind(remoteFrontiers map[string]string, ledger *core.Ledger) map[string]struct{} {
	behind := make(map[string]struct{})
	for account, remoteFrontier := range remoteFrontiers {
		if remoteFrontier == "" {
			continue
		}
		chain := ledger.GetChain(account)
		if len(chain) == 0 {

			continue
		}
		ourFrontier := chain[len(chain)-1].Hash
		if remoteFrontier == ourFrontier {
			continue
		}

		ahead := false
		for _, b := range chain {
			if b.Hash == remoteFrontier {
				ahead = true
				break
			}
		}
		if ahead {
			continue
		}

		behind[account] = struct{}{}
	}
	return behind
}

type pageEncoder interface {
	Encode(v any) error
}

func streamPages(enc pageEncoder, ch <-chan SyncResponse) (int, error) {
	total := 0
	var encErr error
	for batch := range ch {
		if encErr != nil {
			continue
		}
		total += len(batch.Blocks)
		if err := enc.Encode(&batch); err != nil {
			encErr = err
		}
	}
	return total, encErr
}

func requestSync(h host.Host, pid peer.ID, ledger *core.Ledger, quarantine *blockQuarantine, tracker *syncTracker) error {

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := h.NewStream(ctx, pid, syncProtocol)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(60 * time.Second))

	frontiers := ledger.Frontiers()
	if tracker != nil {
		frontiers = tracker.filterFrontiers(pid, frontiers)
	}
	req := SyncRequest{
		Frontiers: frontiers,
		PageSize:  defaultPageSize,
	}
	if err := json.NewEncoder(s).Encode(&req); err != nil {
		return err
	}

	if err := s.CloseWrite(); err != nil {
		return err
	}

	lr := &io.LimitedReader{R: s, N: maxSyncResponseBytes}
	dec := json.NewDecoder(lr)
	var allBlocks []*core.Block
	var rejectedAccounts []string
	gotTerminal := false

	for {
		lr.N = maxSyncResponseBytes
		var resp SyncResponse
		if err := dec.Decode(&resp); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		allBlocks = append(allBlocks, resp.Blocks...)
		logging.Debugf("sync: received page from %s: %d blocks (total: %d, hasMore: %v)", pid.ShortString(), len(resp.Blocks), len(allBlocks), resp.HasMore)
		if !resp.HasMore {
			rejectedAccounts = resp.Rejected
			gotTerminal = true
		}
		if len(allBlocks) >= maxTotalBlocks {
			logging.Warnf("sync: hit maxTotalBlocks cap (%d), stopping", maxTotalBlocks)
			break
		}
		if !resp.HasMore {
			break
		}
	}
	if tracker != nil && gotTerminal {
		tracker.recordRejections(pid, rejectedAccounts)
	}

	filtered := allBlocks[:0]
	skipped := 0
	for _, b := range allBlocks {
		if quarantine.contains(b.Hash) {
			skipped++
		} else {
			filtered = append(filtered, b)
		}
	}

	added := 0
	pending := filtered

	const maxRetries = 10
	rejected := 0
	for retry := 0; retry < maxRetries && len(pending) > 0; retry++ {
		var retryable []*core.Block
		for _, b := range pending {
			err := ledger.AddSyncedBlock(b)
			if err != nil {
				if isRetryableError(err) {
					retryable = append(retryable, b)
				} else {
					rejected++
					quarantine.add(b.Hash)
					if rejected <= 3 {
						logging.Warnf("sync: block %s rejected (quarantined): %v", shortHash(b.Hash), err)
					}
				}
			} else {
				added++
				metrics.BlocksAdded.WithLabelValues("sync").Inc()
			}
		}
		if len(retryable) == len(pending) {
			break
		}
		pending = retryable
	}
	if len(pending) > 0 {

		reasons := map[string]int{}
		for _, b := range pending {
			err := ledger.AddSyncedBlock(b)
			if err == nil {
				added++
				continue
			}
			msg := err.Error()
			if len(msg) > 60 {
				msg = msg[:60]
			}
			reasons[msg]++
		}
		logging.Warnf("sync: %d block(s) could not be added after retries; reasons: %v", len(pending), reasons)
	}
	if added > 0 {
		logging.Debugf("sync: synced %d block(s) from %s", added, pid.ShortString())
	}
	return nil
}

func findMissingBlocksPaginated(remoteFrontiers map[string]string, ledger *core.Ledger, pageSize int) <-chan SyncResponse {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	ch := make(chan SyncResponse)
	go func() {
		defer close(ch)

		ourFrontiers := ledger.Frontiers()
		var pending []*core.Block
		var rejected []string
		totalSent := 0

		flushIntermediate := func() {
			if len(pending) == 0 {
				return
			}
			cursor := pending[len(pending)-1].Hash
			ch <- SyncResponse{
				Blocks:  pending,
				HasMore: true,
				Cursor:  cursor,
			}
			totalSent += len(pending)
			pending = nil
		}

		accounts := make([]string, 0, len(ourFrontiers))
		for acc := range ourFrontiers {
			accounts = append(accounts, acc)
		}

		capHit := false
		for _, account := range accounts {
			if totalSent+len(pending) >= maxServerBlocks {
				capHit = true
				break
			}

			remoteFrontier, exists := remoteFrontiers[account]
			var toSend []*core.Block

			if !exists {

				toSend = ledger.GetChain(account)
			} else if remoteFrontier == ourFrontiers[account] {

				continue
			} else {

				chain := ledger.GetChain(account)
				sending := false
				for _, b := range chain {
					if sending {
						toSend = append(toSend, b)
					} else if b.Hash == remoteFrontier {
						sending = true
					}
				}
				if !sending {

					logging.Debugf("sync: ignoring unrecognized frontier %s for account %s",
						shortHash(remoteFrontier), shortHash(account))
					rejected = append(rejected, account)
					continue
				}
			}

			for _, b := range toSend {
				if totalSent+len(pending) >= maxServerBlocks {
					capHit = true
					break
				}
				pending = append(pending, b)
				if len(pending) == pageSize {
					flushIntermediate()
				}
			}
			if capHit {
				break
			}
		}

		if len(pending) > 0 || len(rejected) > 0 {
			cursor := ""
			if len(pending) > 0 {
				cursor = pending[len(pending)-1].Hash
			}
			ch <- SyncResponse{
				Blocks:   pending,
				HasMore:  false,
				Cursor:   cursor,
				Rejected: rejected,
			}
		}
		_ = capHit
	}()
	return ch
}

func isRetryableError(err error) bool {
	return core.IsRetryableError(err)
}

func peerMaySupportSync(h host.Host, pid peer.ID) bool {
	ps := h.Peerstore()
	if ps == nil {
		return true
	}
	protos, err := ps.GetProtocols(pid)
	if err != nil || len(protos) == 0 {

		return true
	}
	for _, p := range protos {
		if string(p) == syncProtocol {
			return true
		}
	}
	return false
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
