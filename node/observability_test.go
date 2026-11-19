package node

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/metrics"
)

func parseScrapedMetrics(t *testing.T, body string) (ready float64, checks map[string]float64) {
	t.Helper()
	checks = make(map[string]float64)
	readyFound := false

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "xe_ready ") {
			val, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, "xe_ready ")), 64)
			if err != nil {
				t.Fatalf("parse xe_ready %q: %v", line, err)
			}
			ready = val
			readyFound = true
			continue
		}
		if strings.HasPrefix(line, `xe_ready_check{check="`) {
			rest := strings.TrimPrefix(line, `xe_ready_check{check="`)
			idx := strings.Index(rest, `"} `)
			if idx < 0 {
				continue
			}
			name := rest[:idx]
			val, err := strconv.ParseFloat(strings.TrimSpace(rest[idx+3:]), 64)
			if err != nil {
				t.Fatalf("parse xe_ready_check %q: %v", line, err)
			}
			checks[name] = val
		}
	}
	if !readyFound {
		t.Fatalf("xe_ready missing from scrape output")
	}
	return ready, checks
}

func TestMetricsScrapeNeverTornAndEvaluatesPeersOnce(t *testing.T) {
	defer metrics.SetPreScrape(nil)

	now := core.Now()
	cfg := ObsConfig{
		SampleInterval:         15 * time.Second,
		MinPeers:               1,
		FinalityStallThreshold: 90 * time.Second,
		VoteWindow:             10 * time.Minute,
		SyncStaleThreshold:     180 * time.Second,
	}.Defaults()

	readySnap := &Snapshot{
		At:                    now,
		Accounts:              10,
		Blocks:                20,
		UnfinalizedPositions:  1,
		LastFinalityAdvance:   now.Add(-5 * time.Second),
		DelegatedWeight:       1_000_000,
		ActiveWeight:          900_000,
		Representatives:       3,
		ActiveRepresentatives: 3,
		QuorumMargin:          0.90 - metrics.QuorumRatio,
		Supply:                map[string]uint64{"XE": 1_000_000},
		SupplyConserved:       map[string]bool{"XE": true},
		SupplyDiscrepancy:     map[string]int64{"XE": 0},
	}

	stalledSnap := &Snapshot{
		At:                    now,
		Accounts:              10,
		Blocks:                20,
		UnfinalizedPositions:  4,
		LastFinalityAdvance:   now.Add(-10 * time.Minute),
		DelegatedWeight:       1_000_000,
		ActiveWeight:          100_000,
		Representatives:       3,
		ActiveRepresentatives: 1,
		QuorumMargin:          0.10 - metrics.QuorumRatio,
		Supply:                map[string]uint64{"XE": 1_000_000},
		SupplyConserved:       map[string]bool{"XE": true},
		SupplyDiscrepancy:     map[string]int64{"XE": 0},
	}

	var peerCalls atomic.Int32
	obs := NewFixedObserver(cfg, readySnap, 3, now.Add(-5*time.Second))
	obs.o.peersFn = func() int {
		peerCalls.Add(1)
		return 3
	}

	handler := metrics.Handler()

	// Single scrape must invoke peersFn once (not twice).
	peerCalls.Store(0)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("single scrape status = %d, want 200", rec.Code)
	}
	if got := peerCalls.Load(); got != 1 {
		t.Fatalf("peersFn called %d times during single scrape, want 1", got)
	}

	// Hammer concurrent publish() transitions between readySnap and stalledSnap while scraping.
	stopPub := make(chan struct{})
	var pubWG sync.WaitGroup
	pubWG.Add(1)
	go func() {
		defer pubWG.Done()
		toggle := false
		for {
			select {
			case <-stopPub:
				return
			default:
				toggle = !toggle
				s := readySnap
				if toggle {
					s = stalledSnap
				}
				obs.o.snap.Store(s)
				obs.o.publish(s)
			}
		}
	}()

	var scrapeWG sync.WaitGroup
	for g := 0; g < 4; g++ {
		scrapeWG.Add(1)
		go func() {
			defer scrapeWG.Done()
			for i := 0; i < 60; i++ {
				r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code == http.StatusServiceUnavailable {
					continue
				}
				if w.Code != http.StatusOK {
					t.Errorf("unexpected status %d", w.Code)
					return
				}
				readyVal, checks := parseScrapedMetrics(t, w.Body.String())
				allPass := len(checks) == len(ReadyCheckNames)
				for _, name := range ReadyCheckNames {
					if checks[name] != 1 {
						allPass = false
					}
				}
				if (readyVal == 1) != allPass {
					t.Errorf("torn scrape snapshot: xe_ready=%v while checks=%v", readyVal, checks)
					return
				}
			}
		}()
	}

	scrapeWG.Wait()
	close(stopPub)
	pubWG.Wait()
}
