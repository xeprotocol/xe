package net

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// maxBannedPeers caps the number of live ban entries held in memory.
	//
	// Peer IDs cost one keygen, so an attacker can deliberately fail the
	// netcheck handshake from an unbounded stream of fresh identities. Before
	// this cap the ban map grew one entry per identity and was pruned only
	// lazily, for the single peer being looked up — an identity that never
	// returns is never looked up again and its entry was therefore never
	// freed. That is a straightforward memory DoS (#840).
	//
	// 4096 entries is ~200 KiB and comfortably exceeds any plausible honest
	// ban set (a public network bans a handful of wrong-network_id or
	// wrong-version peers, not thousands). Bans of rotating identities have
	// close to zero defensive value anyway — the identity is single-use — so
	// evicting them under pressure loses nothing. The per-IP connection cap
	// and connection rate limiter (net/host.go) are the defences that
	// actually bound a rotating-identity flood; this cap bounds our memory.
	maxBannedPeers = 4096

	// banSweepInterval is how often expired entries are swept wholesale.
	// Lazy per-lookup pruning cannot reclaim an entry whose peer never comes
	// back, which is exactly the flood case.
	banSweepInterval = 60 * time.Second

	// banFileName is the on-disk ban snapshot inside the node data dir.
	banFileName = "bans.json"

	// banSnapshotVersion guards the on-disk format. An unrecognised version
	// is ignored rather than failing startup: bans are soft state and losing
	// them must never stop a node from booting.
	banSnapshotVersion = 1
)

// banStore is a bounded, sweepable set of peer bans with expiry.
//
// Eviction policy, in order:
//  1. entries whose ban has expired (they carry no information),
//  2. failing that, the oldest-inserted entry (FIFO).
//
// FIFO rather than least-recently-used or longest-remaining is deliberate:
// under a rotating-identity flood every entry is a single-use identity, so
// any policy sheds the flood equally, and FIFO is O(1) with no per-lookup
// bookkeeping to contend on. The only entries a flood can push out are ones
// the attacker just created plus, at worst, a bounded tail of older bans that
// re-ban on the offender's next handshake.
type banStore struct {
	mu      sync.RWMutex
	entries map[peer.ID]time.Time
	// order records insertion order for FIFO eviction. It may contain ids no
	// longer present in entries (expired or already evicted); those are
	// skipped when popping and removed by compaction.
	order []peer.ID
	max   int

	// lastSweep throttles the inline sweep. Sweeping is O(n) over the map, so
	// doing it on every insert once the map is full turns a ban flood into a
	// CPU denial of service — the attacker pays one keygen and we pay 4096
	// map operations. The inline sweep is only an optimisation (it prefers
	// evicting entries that carry no information); the periodic sweeper is
	// what actually reclaims expired entries.
	lastSweep time.Time

	evicted atomic.Uint64
	swept   atomic.Uint64
	dirty   atomic.Bool
}

// inlineSweepInterval is the minimum gap between inline sweeps during ban().
const inlineSweepInterval = time.Second

func newBanStore(max int) *banStore {
	if max <= 0 {
		max = maxBannedPeers
	}
	return &banStore{
		entries: make(map[peer.ID]time.Time),
		max:     max,
	}
}

// ban records or extends a ban on p until the given instant.
func (s *banStore) ban(p peer.ID, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[p]; !exists {
		if now := time.Now(); len(s.entries) >= s.max && now.Sub(s.lastSweep) >= inlineSweepInterval {
			s.lastSweep = now
			s.sweepLocked(now)
		}
		for len(s.entries) >= s.max {
			if !s.evictOldestLocked() {
				break
			}
		}
		s.order = append(s.order, p)
		s.compactLocked()
	}
	s.entries[p] = until
	s.dirty.Store(true)
}

// clear removes any ban on p.
func (s *banStore) clear(p peer.ID) {
	s.mu.Lock()
	if _, ok := s.entries[p]; ok {
		delete(s.entries, p)
		s.dirty.Store(true)
	}
	s.mu.Unlock()
}

// banned reports whether p is currently banned, dropping the entry if its ban
// has expired.
func (s *banStore) banned(p peer.ID) bool {
	s.mu.RLock()
	exp, ok := s.entries[p]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		s.mu.Lock()
		// Re-check under the write lock: a concurrent ban may have extended it.
		if exp, ok := s.entries[p]; ok && time.Now().After(exp) {
			delete(s.entries, p)
			s.dirty.Store(true)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

// size returns the number of live ban entries.
func (s *banStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// sweep removes every expired entry and returns how many were removed.
func (s *banStore) sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(time.Now())
}

func (s *banStore) sweepLocked(now time.Time) int {
	removed := 0
	for p, exp := range s.entries {
		if now.After(exp) {
			delete(s.entries, p)
			removed++
		}
	}
	if removed > 0 {
		s.swept.Add(uint64(removed))
		s.dirty.Store(true)
		s.compactLocked()
	}
	return removed
}

// evictOldestLocked drops the oldest still-live entry. Returns false when the
// FIFO is exhausted (nothing left to evict).
func (s *banStore) evictOldestLocked() bool {
	for len(s.order) > 0 {
		p := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.entries[p]; ok {
			delete(s.entries, p)
			s.evicted.Add(1)
			s.dirty.Store(true)
			return true
		}
	}
	return false
}

// compactLocked rebuilds the FIFO when it has accumulated too many stale ids,
// so the slice cannot grow without bound while the map stays capped.
func (s *banStore) compactLocked() {
	if len(s.order) <= 2*s.max {
		return
	}
	compacted := make([]peer.ID, 0, len(s.entries))
	for _, p := range s.order {
		if _, ok := s.entries[p]; ok {
			compacted = append(compacted, p)
		}
	}
	s.order = compacted
}

// stats reports the store's bounded-ness for observability and tests.
func (s *banStore) stats() (live int, evictions, sweeps uint64) {
	return s.size(), s.evicted.Load(), s.swept.Load()
}

// banSnapshot is the on-disk representation of the ban set.
type banSnapshot struct {
	Version int              `json:"version"`
	Entries []banSnapshotItm `json:"entries"`
}

type banSnapshotItm struct {
	Peer     string `json:"peer"`
	ExpiryNs int64  `json:"expiry_ns"`
}

// save writes the live (unexpired) ban entries to path atomically. Bans are
// soft state: a write failure is reported but is never fatal to the node.
func (s *banStore) save(path string) error {
	s.mu.RLock()
	now := time.Now()
	snap := banSnapshot{Version: banSnapshotVersion, Entries: make([]banSnapshotItm, 0, len(s.entries))}
	for p, exp := range s.entries {
		if now.After(exp) {
			continue
		}
		snap.Entries = append(snap.Entries, banSnapshotItm{Peer: p.String(), ExpiryNs: exp.UnixNano()})
	}
	s.mu.RUnlock()

	data, err := json.Marshal(&snap)
	if err != nil {
		return fmt.Errorf("marshal bans: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ban dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write bans: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename bans: %w", err)
	}
	s.dirty.Store(false)
	return nil
}

// load restores bans from path, dropping entries that have already expired and
// respecting the size cap. A missing or unreadable file is not an error: the
// node simply starts with an empty ban set.
func (s *banStore) load(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read bans: %w", err)
	}
	var snap banSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return 0, fmt.Errorf("decode bans: %w", err)
	}
	if snap.Version != banSnapshotVersion {
		return 0, fmt.Errorf("unsupported ban snapshot version %d", snap.Version)
	}

	now := time.Now()
	restored := 0
	for _, e := range snap.Entries {
		exp := time.Unix(0, e.ExpiryNs)
		if now.After(exp) {
			continue
		}
		pid, err := peer.Decode(e.Peer)
		if err != nil {
			continue
		}
		s.ban(pid, exp)
		restored++
		if restored >= s.max {
			break
		}
	}
	s.dirty.Store(false)
	return restored, nil
}
