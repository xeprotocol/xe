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
	maxBannedPeers = 4096

	banSweepInterval = 60 * time.Second

	banFileName = "bans.json"

	banSnapshotVersion = 1
)

type banStore struct {
	mu      sync.RWMutex
	entries map[peer.ID]time.Time

	order []peer.ID
	max   int

	lastSweep time.Time

	evicted atomic.Uint64
	swept   atomic.Uint64
	dirty   atomic.Bool
}

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

func (s *banStore) clear(p peer.ID) {
	s.mu.Lock()
	if _, ok := s.entries[p]; ok {
		delete(s.entries, p)
		s.dirty.Store(true)
	}
	s.mu.Unlock()
}

func (s *banStore) banned(p peer.ID) bool {
	s.mu.RLock()
	exp, ok := s.entries[p]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		s.mu.Lock()

		if exp, ok := s.entries[p]; ok && time.Now().After(exp) {
			delete(s.entries, p)
			s.dirty.Store(true)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

func (s *banStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

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

func (s *banStore) stats() (live int, evictions, sweeps uint64) {
	return s.size(), s.evicted.Load(), s.swept.Load()
}

type banSnapshot struct {
	Version int              `json:"version"`
	Entries []banSnapshotItm `json:"entries"`
}

type banSnapshotItm struct {
	Peer     string `json:"peer"`
	ExpiryNs int64  `json:"expiry_ns"`
}

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
