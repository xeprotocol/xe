package net

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestBanStore_FlushImmunityForRealOffender(t *testing.T) {
	// Replicates the scenario in Issue #202:
	// A 24-hour ban on a real offender must NOT be evicted by churning
	// 4,200 short throwaway bans through a 4096-entry table.
	s := newBanStore(4096)
	now := time.Now()

	realOffender := peer.ID("real-offender-peer-id-12345")
	s.ban(realOffender, now.Add(24*time.Hour))

	if !s.banned(realOffender) {
		t.Fatal("expected real offender to be banned immediately")
	}

	// Churn 4,200 throwaway peer bans
	for i := 0; i < 4200; i++ {
		throwaway := peer.ID(fmt.Sprintf("throwaway-peer-%05d", i))
		s.ban(throwaway, now.Add(10*time.Minute))
	}

	// Verify real offender remains banned
	if !s.banned(realOffender) {
		t.Fatalf("vulnerability reproduced: real offender was evicted from banStore after churning 4,200 identities")
	}

	live, evictions, _ := s.stats()
	if live > 4096 {
		t.Fatalf("live count exceeded capacity: %d", live)
	}
	if evictions == 0 {
		t.Fatalf("expected evictions to occur, got %d", evictions)
	}
}

func TestBanStore_EvictsShortestRemainingFirst(t *testing.T) {
	s := newBanStore(3)
	now := time.Now()

	p1 := peer.ID("peer-long-24h")
	p2 := peer.ID("peer-med-30m")
	p3 := peer.ID("peer-short-10m")

	s.ban(p1, now.Add(24*time.Hour))
	s.ban(p2, now.Add(30*time.Minute))
	s.ban(p3, now.Add(10*time.Minute))

	// Table is full (3/3). Adding a 4th ban should evict the shortest non-security ban (p3)
	p4 := peer.ID("peer-new-20m")
	s.ban(p4, now.Add(20*time.Minute))

	if !s.banned(p1) {
		t.Fatal("expected p1 (24h ban) to remain protected")
	}
	if !s.banned(p2) {
		t.Fatal("expected p2 (30m ban) to remain protected over shorter ban")
	}
	if s.banned(p3) {
		t.Fatal("expected p3 (10m ban) to be evicted first")
	}
	if !s.banned(p4) {
		t.Fatal("expected p4 to be admitted")
	}
}

func TestBanStore_SnapshotPreservesLongLivedBans(t *testing.T) {
	s := newBanStore(10)
	now := time.Now()

	pLong := peer.ID("peer-security-24h")
	s.ban(pLong, now.Add(24*time.Hour))

	for i := 0; i < 9; i++ {
		p := peer.ID(fmt.Sprintf("throwaway-%d", i))
		s.ban(p, now.Add(time.Duration(i+1)*time.Minute))
	}

	tmpDir := t.TempDir()
	snapPath := filepath.Join(tmpDir, "bans.json")

	if err := s.save(snapPath); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Restore into a smaller store with capacity 3
	s2 := newBanStore(3)
	restored, err := s2.load(snapPath)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if restored != 3 {
		t.Fatalf("expected 3 restored entries, got %d", restored)
	}

	// Ensure the 24h ban was prioritized and restored
	if !s2.banned(pLong) {
		t.Fatal("expected security ban to be restored into limited capacity store")
	}
}
