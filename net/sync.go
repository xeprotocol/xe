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

	// maxTotalBlocks caps the number of blocks a client will accept during a
	// single sync session, preventing a malicious peer from causing OOM.
	maxTotalBlocks = 10000

	// syncCooldown is the minimum interval between sync requests from the same peer.
	syncCooldown = 5 * time.Second

	// periodicSyncInterval is how often each node triggers a re-sync with all
	// connected peers to recover from any missed gossip messages.
	periodicSyncInterval = 10 * time.Second

	// maxSyncRequestBytes limits the size of an incoming SyncRequest to prevent
	// a malicious peer from sending a huge frontier map and causing OOM.
	maxSyncRequestBytes = 1 << 20 // 1 MiB

	// maxSyncResponseBytes limits the size of each incoming SyncResponse page.
	maxSyncResponseBytes = 10 << 20 // 10 MiB

	// maxFrontiers caps the number of frontier entries a peer can claim in a
	// SyncRequest. Beyond this, the excess entries are silently ignored.
	maxFrontiers = 10000

	// maxServerBlocks caps the total number of blocks the server will send per
	// sync session, preventing CPU/memory exhaustion from chain walking.
	maxServerBlocks = 10000

	// unrecognizedDropThreshold is the number of consecutive sync rounds an
	// account must be reported as Rejected by a peer before the client drops
	// it from the outgoing frontier map. Dropping triggers the server's
	// !exists branch which dumps the full chain, recovering a node whose
	// local frontier has diverged from the canonical chain (#406).
	//
	// Tuning: too low risks false positives if a single round is dropped on
	// the wire; too high prolongs recovery. With periodicSyncInterval=10s
	// and steady-state fullResyncInterval=60s, a value of 3 means worst-case
	// recovery in ~3 minutes after a wedge is first observable.
	unrecognizedDropThreshold = 3

	// syncReprobeInterval is how long a peer that has advertised it does not
	// speak syncProtocol stays on the skip list before we try it again. Such
	// peers (e.g. cert-gossipers that speak gossip/netcheck but not sync)
	// otherwise get re-selected every periodicSyncInterval and fail protocol
	// negotiation forever — wasted work, log spam, and a minor amplification
	// vector where a peer advertises partial protocols to burn sync attempts
	// indefinitely (#542). The interval is long enough to eliminate the spam
	// but short enough that a peer which later upgrades to a full node is
	// re-probed and picked back up.
	syncReprobeInterval = 10 * time.Minute
)

// syncRateLimiter tracks the last sync request time per peer.
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
	// Evict expired entries to prevent unbounded growth.
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

// syncTracker tracks per-peer sync state to avoid redundant sync rounds
// when nothing has changed. Each peer records the local frontier snapshot
// that was last sent. On tick, if our frontiers haven't changed since the
// last successful sync with a peer, we skip that peer.
//
// An atomic dirty flag is set whenever a block is added locally (gossip,
// API, or sync). When dirty, all peers are synced on the next tick and
// the flag is cleared. When clean, peers are skipped (no streams opened).
// A full resync is forced every fullResyncInterval regardless of dirty state
// to catch any edge cases.
type syncTracker struct {
	mu             sync.Mutex
	lastFrontiers  map[peer.ID]map[string]string // per-peer: frontiers we last sent
	dirty          int32                         // atomic: set when local state changes
	lastFullResync time.Time
	// rejections counts consecutive sync rounds where a peer reported an
	// account as Rejected (unrecognized frontier). Per-(peer, account).
	// Reset to zero whenever a round completes without that account in the
	// Rejected list. Drives filterFrontiers — see #406.
	rejections map[peer.ID]map[string]int
	// syncIncapable records peers that have advertised they do not speak
	// syncProtocol. The value is the time we last observed this so the peer
	// can be re-probed after syncReprobeInterval (it may have upgraded to a
	// full node). See shouldSync / markSyncIncapable — #542.
	syncIncapable map[peer.ID]time.Time
}

const fullResyncInterval = 60 * time.Second

func newSyncTracker() *syncTracker {
	return &syncTracker{
		lastFrontiers:  make(map[peer.ID]map[string]string),
		dirty:          1, // start dirty to force initial sync
		lastFullResync: time.Time{},
		rejections:     make(map[peer.ID]map[string]int),
		syncIncapable:  make(map[peer.ID]time.Time),
	}
}

// MarkDirty signals that local state has changed and all peers need resync.
func (st *syncTracker) MarkDirty() {
	if st == nil {
		return
	}
	sync2.StoreInt32(&st.dirty, 1)
}

// shouldSync returns true if we need to sync with this peer on this tick.
func (st *syncTracker) shouldSync(pid peer.ID, currentFrontiers map[string]string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Skip peers that have advertised they do not speak syncProtocol, until
	// the re-probe window elapses. This check precedes the dirty/full-resync
	// short-circuits below so a sync-incapable peer is never re-selected just
	// because local state changed — it would only fail negotiation again
	// (#542). After syncReprobeInterval the entry is dropped and the peer is
	// retried once, in case it has since upgraded to a full node.
	if since, ok := st.syncIncapable[pid]; ok {
		if time.Since(since) < syncReprobeInterval {
			return false
		}
		delete(st.syncIncapable, pid)
	}

	// Force full resync periodically as safety net.
	if time.Since(st.lastFullResync) >= fullResyncInterval {
		return true
	}

	// If local state changed, sync everyone.
	if sync2.LoadInt32(&st.dirty) != 0 {
		return true
	}

	// If we haven't synced this peer before, sync.
	last, ok := st.lastFrontiers[pid]
	if !ok {
		return true
	}

	// If our frontiers changed since last sync with this peer, sync.
	return !frontiersEqual(last, currentFrontiers)
}

// recordSync records that a successful sync was completed with this peer.
func (st *syncTracker) recordSync(pid peer.ID, frontiers map[string]string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	// Copy the map so it doesn't mutate.
	cp := make(map[string]string, len(frontiers))
	for k, v := range frontiers {
		cp[k] = v
	}
	st.lastFrontiers[pid] = cp
}

// clearDirty resets the dirty flag after a full sync round completes.
func (st *syncTracker) clearDirty() {
	st.mu.Lock()
	st.lastFullResync = time.Now()
	st.mu.Unlock()
	sync2.StoreInt32(&st.dirty, 0)
}

// removePeer cleans up state for a disconnected peer.
func (st *syncTracker) removePeer(pid peer.ID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.lastFrontiers, pid)
	delete(st.rejections, pid)
	delete(st.syncIncapable, pid)
}

// markSyncIncapable records that a peer does not speak syncProtocol so it is
// skipped by shouldSync for syncReprobeInterval. Idempotent re-marks refresh
// the timestamp, extending the skip window for a peer that is still incapable
// (#542).
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

// isSyncIncapable reports whether the peer is currently on the skip list and
// within its re-probe window. Test helper; production code goes through
// shouldSync.
func (st *syncTracker) isSyncIncapable(pid peer.ID) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	since, ok := st.syncIncapable[pid]
	return ok && time.Since(since) < syncReprobeInterval
}

// isProtocolNotSupported reports whether err is a libp2p stream-negotiation
// failure caused by the remote not speaking the requested protocol. The
// underlying go-multistream error renders as "protocols not supported: [...]"
// (wrapped by libp2p as "failed to negotiate protocol: ..."); we match on the
// stable substring rather than the generic ErrNotSupported[protocol.ID] type
// because the error is flattened to a string as it crosses the swarm boundary.
func isProtocolNotSupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), "protocols not supported")
}

// filterFrontiers returns a copy of frontiers with any account omitted that
// the given peer has reported as Rejected for unrecognizedDropThreshold or
// more consecutive sync rounds. Omitting an account triggers the server's
// !exists branch in findMissingBlocksPaginated, which sends the full chain
// for that account — the recovery path documented in the sync.go comment
// block and required by #406.
//
// Returns the input map unmodified if no accounts are over threshold for
// this peer (fast path on the common case).
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
	logging.Warnf("sync: dropping %d account(s) from frontier map to %s (>= %d consecutive rejections) — recovery path #406",
		dropped, pid.ShortString(), unrecognizedDropThreshold)
	return out
}

// recordRejections updates the per-(peer, account) rejection counter based
// on the Rejected list a peer returned in its terminal SyncResponse.
//
// Semantics: any account in rejected has its count bumped by 1; any account
// previously tracked for this peer that is NOT in rejected has its count
// cleared, since a single non-rejection breaks the "consecutive" chain.
// Once an account is dropped via filterFrontiers and the server sends a full
// chain in response, the next round will see no rejection for it, the count
// clears, and steady-state resumes.
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
	// Clear counts for accounts no longer rejected.
	for acc := range cur {
		if _, still := rejectedSet[acc]; !still {
			delete(cur, acc)
		}
	}
	// Bump counts for currently rejected accounts.
	for acc := range rejectedSet {
		cur[acc]++
	}
	// If the peer never rejected anything, drop the per-peer map entirely
	// so the rejections map doesn't accumulate empty submaps.
	if len(cur) == 0 {
		delete(st.rejections, pid)
	}
}

// rejectionCount returns the current consecutive-rejection count for an
// (account, peer) pair. Test-only helper; production code uses
// filterFrontiers to make decisions.
func (st *syncTracker) rejectionCount(pid peer.ID, account string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.rejections[pid][account]
}

// isDirtyForTest reports whether the dirty flag is set. Test-only helper;
// production code reads it via shouldSync.
func (st *syncTracker) isDirtyForTest() bool {
	return sync2.LoadInt32(&st.dirty) != 0
}

// maxQuarantineEntries caps the number of rejected block hashes retained by a
// blockQuarantine. The keys are attacker-supplied block hashes, so without a
// bound a flood of distinct rejected hashes (up to 10000/round, with rotating
// peer IDs defeating the per-peer limiter) would grow the map without limit
// (#570/M6). When the cap is exceeded the oldest entries are evicted FIFO; the
// only cost of evicting a still-bad hash is re-validating (and re-rejecting) it
// on a later round.
const maxQuarantineEntries = 8192

// blockQuarantine tracks block hashes that have been permanently rejected
// during sync. These blocks are skipped on subsequent sync rounds to avoid
// wasting CPU and log noise retrying blocks that will never pass validation.
type blockQuarantine struct {
	mu     sync.RWMutex
	hashes map[string]struct{}
	order  []string // insertion order for FIFO eviction
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
	// There is no fork machinery: an unknown block type hard-rejects and is
	// non-retryable, so a chain split first shows up as this counter climbing
	// on some nodes and not others. Worth alerting on (#841).
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

// SyncTracker is returned by SetupSync so the node can signal when local
// state changes (block added via gossip or API). Call MarkDirty() after
// adding a block to trigger resync on the next tick.
type SyncTracker = syncTracker

// SetupSync registers the sync stream handler, triggers sync on new peer
// connections, and starts a periodic re-sync to recover from missed gossip.
// Returns a SyncTracker that the caller should use to signal state changes.
// The periodic re-sync goroutine stops when ctx is cancelled (#570/L8) — before
// that it would run forever, calling into the ledger even after Node.Stop closed
// the underlying store.
//
// The returned wait func blocks until every sync goroutine (periodic loop,
// per-peer workers, connect-triggered syncs) has finished and prevents new
// ones from starting; Node.Stop must call it before closing the store (#602).
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
						logging.Warnf("sync: peer %s does not support %s, skipping sync for %s (#542)", pid.ShortString(), syncProtocol, syncReprobeInterval)
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

	// Periodic re-sync. Only opens streams to peers when state has changed
	// or fullResyncInterval has elapsed (safety net). Stops on ctx cancel.
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
				// Prefer peers whose libp2p-advertised protocol set is known
				// not to include syncProtocol — skip them outright before
				// wasting a stream on a negotiation that will fail (#542). An
				// empty/error result (identify not yet complete) is treated as
				// "unknown", so we still attempt sync and let the on-failure
				// path mark genuine non-supporters.
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
							logging.Warnf("sync: peer %s does not support %s, skipping periodic sync for %s (#542)", p.ShortString(), syncProtocol, syncReprobeInterval)
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

// spawnGate tracks goroutines spawned by the sync subsystem so shutdown can
// wait for in-flight work before the store closes (#602). Once wait begins,
// spawn refuses new work — avoiding the WaitGroup Add-after-Wait race that a
// bare wg.Add in libp2p notify callbacks would have.
type spawnGate struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

// spawn runs f on a tracked goroutine, or reports false if wait has begun.
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

// wait blocks new spawns, then blocks until all tracked goroutines finish.
func (g *spawnGate) wait() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.wg.Wait()
}

// runPeriodicResync invokes round on each tick until ctx is cancelled, then
// returns. Extracted so the lifecycle (stop on ctx cancel) is testable without
// a libp2p host. (#570/L8)
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

// handleSyncStream is the server-side handler for sync streams.
// It reads the client's frontiers, then streams pages of missing blocks.
//
// tracker may be nil in tests that don't exercise self-recovery; in production
// it's the node's sync tracker. When non-nil, after serving the request the
// server checks whether the requester advertised a tip that DISAGREES with an
// account the server itself holds (i.e. the server may be the behind party —
// see frontiersWhereServerIsBehind). If so it marks itself dirty so its own
// periodic resync re-pulls those accounts (#685). The sync stream is pull-only
// (blocks only flow server->client), so without this a node that fell behind on
// some accounts during a partition could serve its peers forever while never
// catching up itself — a pure liveness wedge.
//
// SECURITY NOTE: The sync protocol reveals the full frontier set to the
// responding peer. A malicious peer learns which accounts exist and at what
// block height. Future improvement: use a bloom filter or frontier hash
// instead of sending the full frontier map, and cross-verify with multiple
// peers to detect selective withholding.
func handleSyncStream(s network.Stream, ledger *core.Ledger, tracker *syncTracker) {
	var req SyncRequest
	dec := json.NewDecoder(io.LimitReader(s, maxSyncRequestBytes))
	if err := dec.Decode(&req); err != nil {
		if err != io.EOF {
			logging.Warnf("sync: decode request: %v", err)
		}
		return
	}
	// Only log inbound sync requests that have a frontier mismatch (will transfer blocks).
	// Steady-state "0 blocks" exchanges are suppressed.

	// Cap frontier entries to prevent amplification from huge maps.
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

	// Clamp page size.
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	// Before serving, detect accounts where the requester advertised a tip we
	// disagree with for an account we hold — we may be behind on them. Compute
	// it up front so the request map is the one the client actually sent (the
	// channel producer doesn't mutate it, but ordering keeps this obviously
	// correct). The actual self-trigger happens after the response is drained.
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
		logging.Debugf("sync: peer %s is ahead on %d account(s) we hold — scheduling self-resync (#685)",
			s.Conn().RemotePeer().ShortString(), len(behind))
		tracker.MarkDirty()
	}
}

// frontiersWhereServerIsBehind returns the set of accounts for which the
// requester advertised a frontier that DISAGREES with a chain the server holds,
// and where the server is NOT ahead of the requester. These are the accounts on
// which the server may itself be behind (the requester's tip is a descendant we
// haven't seen, or a divergent sibling) and so should trigger its own catch-up
// pull rather than silently doing nothing.
//
// It deliberately ignores:
//   - accounts the server does not hold at all (empty chain) — chasing a
//     phantom account is the amplification vector the anti-amplification guard
//     exists to prevent (#406); a forged hash for a non-existent account never
//     trips this;
//   - accounts where the advertised frontier equals the server's frontier
//     (already in sync);
//   - accounts where the advertised frontier appears earlier in the server's
//     chain (the requester is BEHIND us — we forward-fill it the normal way and
//     have nothing to catch up on).
func frontiersWhereServerIsBehind(remoteFrontiers map[string]string, ledger *core.Ledger) map[string]struct{} {
	behind := make(map[string]struct{})
	for account, remoteFrontier := range remoteFrontiers {
		if remoteFrontier == "" {
			continue
		}
		chain := ledger.GetChain(account)
		if len(chain) == 0 {
			// We don't hold this account — not our gap to fill.
			continue
		}
		ourFrontier := chain[len(chain)-1].Hash
		if remoteFrontier == ourFrontier {
			continue // already in sync
		}
		// If the advertised frontier is somewhere in our chain, the requester is
		// behind us (an ancestor of our tip) — we serve them, we're not behind.
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
		// We hold this account, disagree on the tip, and are not ahead: we may
		// be behind. Schedule our own pull.
		behind[account] = struct{}{}
	}
	return behind
}

// pageEncoder is the subset of *json.Encoder that streamPages needs.
type pageEncoder interface {
	Encode(v any) error
}

// streamPages encodes each page from ch to enc and returns the total block
// count and the first encode error. On an encode error it MUST keep draining ch
// to completion: findMissingBlocksPaginated's producer sends on an unbuffered
// channel, so abandoning ch mid-stream (e.g. the peer disconnected and Encode
// fails) would park the producer goroutine forever, holding block slices —
// a goroutine/memory leak remotely repeatable via rotating peer IDs (#570/M8).
func streamPages(enc pageEncoder, ch <-chan SyncResponse) (int, error) {
	total := 0
	var encErr error
	for batch := range ch {
		if encErr != nil {
			continue // keep draining so the producer can finish and close ch
		}
		total += len(batch.Blocks)
		if err := enc.Encode(&batch); err != nil {
			encErr = err
		}
	}
	return total, encErr
}

// requestSync opens a sync stream to a peer, sends our frontiers, and applies
// the pages of missing blocks we receive.
//
// tracker may be nil in tests that bypass recovery; in production it's the
// per-peer rejection counter used to detect and recover from unrecognized-
// frontier wedges (#406). When non-nil:
//   - the outgoing frontier map is filtered through tracker.filterFrontiers
//     so accounts past the rejection threshold are omitted (triggering the
//     server's !exists full-chain dump)
//   - the Rejected list on the terminal SyncResponse is fed back into
//     tracker.recordRejections so consecutive-rejection state advances.
func requestSync(h host.Host, pid peer.ID, ledger *core.Ledger, quarantine *blockQuarantine, tracker *syncTracker) error {
	// Only log sync requests at debug level — these are frequent during idle.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := h.NewStream(ctx, pid, syncProtocol)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(60 * time.Second))

	// Build the outgoing frontier map. If we have an active rejection
	// tracker, omit any account that has been Rejected by this peer for
	// enough consecutive rounds to trip the recovery threshold.
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

	// Signal we're done writing so the peer can respond.
	if err := s.CloseWrite(); err != nil {
		return err
	}

	// Read pages of missing blocks until HasMore is false.
	// Collect all blocks first, then add with retry to handle cross-account
	// dependencies (e.g., receive blocks that depend on send blocks from
	// other accounts which may appear later in the stream).
	lr := &io.LimitedReader{R: s, N: maxSyncResponseBytes}
	dec := json.NewDecoder(lr)
	var allBlocks []*core.Block
	var rejectedAccounts []string
	gotTerminal := false
	// Read pages of missing blocks.
	for {
		lr.N = maxSyncResponseBytes // reset per-page byte limit
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

	// Filter out quarantined blocks (previously rejected with non-retryable errors).
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
	// 10 retries handles cross-account dependency chains that exceed the
	// previous 3-retry cap (#409). Each retry is in-memory and cheap; the
	// loop exits early when no progress is made in a pass.
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
			break // no progress, stop retrying
		}
		pending = retryable
	}
	if len(pending) > 0 {
		// Summarize WHY the leftovers are stuck, not just how many — a cold
		// node that never converges is undiagnosable from a bare count (#630).
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

// findMissingBlocksPaginated computes which blocks the remote is missing and
// yields them in pages of at most pageSize blocks. pageSize is clamped to
// maxPageSize. It walks account by account, using the same logic as
// findMissingBlocks but without loading everything at once.
// The returned channel is closed after all pages have been sent.
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

		// flushIntermediate emits a full mid-stream page (HasMore=true).
		// All terminating emission goes through the explicit final block
		// after the loop so a single page carries HasMore=false + the
		// Rejected list. This makes the protocol unambiguous for the
		// client: exactly one terminal page per stream.
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
				// Remote doesn't have this account — send the entire chain.
				toSend = ledger.GetChain(account)
			} else if remoteFrontier == ourFrontiers[account] {
				// Already in sync for this account.
				continue
			} else {
				// Remote is behind — find the blocks after their frontier.
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
					// Their frontier not found in our chain — skip this account.
					// Sending the entire chain on an unrecognized frontier is a
					// bandwidth amplification vector: a malicious peer sends fake
					// frontier hashes for every account and gets the full ledger.
					// The peer can re-sync and will get the full chain when they
					// omit the account from their frontier map. The Rejected list
					// on the final SyncResponse page signals which accounts the
					// client should drop to trigger recovery (#406).
					logging.Debugf("sync: ignoring unrecognized frontier %s for account %s",
						shortHash(remoteFrontier), shortHash(account))
					rejected = append(rejected, account)
					continue
				}
			}

			// Emit toSend in pages, respecting server cap.
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

		// One terminal page closes the stream and carries any leftover
		// blocks plus the full Rejected list. Suppressed when there's
		// genuinely nothing to communicate (idle sync, both peers fully
		// in sync) — the channel just closes, the client reads EOF, the
		// wire behavior matches the pre-#406 protocol for that case.
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
		_ = capHit // for future structured logging if we want to surface partial-sync state
	}()
	return ch
}

// isRetryableError reports whether a block add may succeed on a later attempt
// (missing dependency or transient race) rather than being permanently invalid.
// The canonical allowlist now lives in core.IsRetryableError so the sync path
// and conflict promotion (#673) share ONE classifier and can't drift; this thin
// wrapper keeps the sync-local call sites and their regression tests intact.
func isRetryableError(err error) bool {
	return core.IsRetryableError(err)
}

// peerMaySupportSync reports whether it is worth attempting a sync stream to a
// peer based on its libp2p-advertised protocols. It returns false only when the
// peerstore positively knows the peer's protocol set and syncProtocol is absent
// from it; in every "unknown" case (identify not yet complete, peerstore error,
// or empty protocol list) it returns true so real full nodes are never starved
// of sync — the on-failure markSyncIncapable path is the backstop for peers
// whose protocols we couldn't read up front (#542).
func peerMaySupportSync(h host.Host, pid peer.ID) bool {
	ps := h.Peerstore()
	if ps == nil {
		return true
	}
	protos, err := ps.GetProtocols(pid)
	if err != nil || len(protos) == 0 {
		// Protocols not known yet — don't skip; attempt and learn from the result.
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
