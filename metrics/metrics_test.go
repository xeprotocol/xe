package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestHandlerShedsExcessRequestsBeforePreScrape(t *testing.T) {
	defer SetPreScrape(nil)

	entered := make(chan struct{}, maxMetricsInFlight)
	release := make(chan struct{})
	var preScrapeCalls atomic.Int32

	SetPreScrape(func() {
		n := preScrapeCalls.Add(1)
		if int(n) <= maxMetricsInFlight {
			entered <- struct{}{}
			<-release
		}
	})

	h := Handler()

	var admittedWG sync.WaitGroup
	admittedCodes := make([]int, maxMetricsInFlight)
	readyToFire := make(chan struct{})
	var launched atomic.Int32

	for i := 0; i < maxMetricsInFlight; i++ {
		idx := i
		admittedWG.Add(1)
		go func() {
			defer admittedWG.Done()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			if launched.Add(1) == maxMetricsInFlight {
				close(readyToFire)
			}
			h.ServeHTTP(rec, req)
			admittedCodes[idx] = rec.Code
		}()
	}

	<-entered
	<-readyToFire
	time.Sleep(25 * time.Millisecond)

	const burst = 40
	var shedWG sync.WaitGroup
	var shedCount atomic.Int32
	for i := 0; i < burst; i++ {
		shedWG.Add(1)
		go func() {
			defer shedWG.Done()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusServiceUnavailable {
				shedCount.Add(1)
			}
		}()
	}
	shedWG.Wait()

	if got := shedCount.Load(); got != burst {
		t.Fatalf("expected all %d excess scrapes to be shed with 503, got %d", burst, got)
	}
	if calls := preScrapeCalls.Load(); calls != 1 {
		t.Fatalf("expected shed requests to never invoke preScrape while 1st holds lock; got %d calls", calls)
	}

	close(release)
	admittedWG.Wait()

	for i, code := range admittedCodes {
		if code != http.StatusOK {
			t.Fatalf("admitted scrape %d returned status %d, want 200", i, code)
		}
	}
	if calls := preScrapeCalls.Load(); calls != maxMetricsInFlight {
		t.Fatalf("total preScrape calls = %d, want %d (shed requests must execute 0 preScrapes)", calls, maxMetricsInFlight)
	}
}

func TestHandlerPreScrapePanicReleasesPublishLock(t *testing.T) {
	defer SetPreScrape(nil)

	h := Handler()
	SetPreScrape(func() {
		panic("synthetic preScrape panic")
	})

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic from preScrape to propagate to HTTP server recovery")
			}
		}()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}()

	// Subsequent scrapes and WithPublishLock callers must not deadlock.
	SetPreScrape(func() {})
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("follow-up scrape status = %d, want 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publishMu deadlocked after preScrape panic")
	}
}

func TestHandlerCanceledRequestDoesNotReleasePublishLockEarly(t *testing.T) {
	defer SetPreScrape(nil)

	var hookActive atomic.Bool
	gatherEntered := make(chan struct{}, 1)
	allowFinish := make(chan struct{})

	c := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "xe_test_cancel_lock_hold_total",
		Help: "Test collector verifying Gather stays inside WithPublishLock on context cancel.",
	}, func() float64 {
		if hookActive.CompareAndSwap(true, false) {
			gatherEntered <- struct{}{}
			<-allowFinish
		}
		return 1
	})
	if err := Registry.Register(c); err != nil {
		t.Fatalf("Register test collector: %v", err)
	}
	defer Registry.Unregister(c)

	h := Handler()
	ctx, cancel := context.WithCancel(context.Background())
	hookActive.Store(true)

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}()

	<-gatherEntered
	// Cancel client request context while Registry.Gather() is mid-flight.
	cancel()

	lockAcquiredEarly := make(chan struct{})
	go func() {
		WithPublishLock(func() {
			close(lockAcquiredEarly)
		})
	}()

	select {
	case <-lockAcquiredEarly:
		close(allowFinish)
		t.Fatal("publishMu was released while Registry.Gather() was still running after context cancellation")
	case <-time.After(40 * time.Millisecond):
	}

	close(allowFinish)
	<-serveDone
	<-lockAcquiredEarly
}
