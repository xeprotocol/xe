package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatSSEConcurrencyCap(t *testing.T) {
	h := &Handler{}
	testIP := "198.51.100.1"

	// Should allow up to maxSSEPerIP
	for i := 0; i < maxSSEPerIP; i++ {
		if !h.acquireSSESlot(testIP) {
			t.Fatalf("acquireSSESlot failed at iteration %d (under max %d)", i, maxSSEPerIP)
		}
	}

	// 17th attempt must be rejected
	if h.acquireSSESlot(testIP) {
		t.Fatalf("acquireSSESlot should have failed beyond cap %d", maxSSEPerIP)
	}

	// Different IP should still have its own quota
	otherIP := "198.51.100.2"
	if !h.acquireSSESlot(otherIP) {
		t.Fatalf("acquireSSESlot should succeed for distinct IP %s", otherIP)
	}
	h.releaseSSESlot(otherIP)

	// Releasing one slot allows another acquisition
	h.releaseSSESlot(testIP)
	if !h.acquireSSESlot(testIP) {
		t.Fatalf("acquireSSESlot should succeed after releasing a slot")
	}

	// Clean up
	for i := 0; i < maxSSEPerIP; i++ {
		h.releaseSSESlot(testIP)
	}

	// Internal map should be empty for that IP
	h.sseMu.Lock()
	if count, exists := h.sseByIP[testIP]; exists && count > 0 {
		t.Fatalf("expected count 0 or cleaned up for %s, got %d", testIP, count)
	}
	h.sseMu.Unlock()
}

func TestChatSSEExhaustionHTTPResponse(t *testing.T) {
	h := &Handler{}
	testIP := "203.0.113.5:12345"

	// Pre-fill the quota for this IP
	ipKey := "203.0.113.5"
	for i := 0; i < maxSSEPerIP; i++ {
		if !h.acquireSSESlot(ipKey) {
			t.Fatalf("failed to pre-fill slot %d", i)
		}
	}
	defer func() {
		for i := 0; i < maxSSEPerIP; i++ {
			h.releaseSSESlot(ipKey)
		}
	}()

	req := httptest.NewRequest("GET", "/chat/events", nil)
	req.RemoteAddr = testIP
	rr := httptest.NewRecorder()

	h.handleChatEvents(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected HTTP 429 Too Many Requests, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "too many concurrent chat SSE streams") {
		t.Errorf("expected error message in body, got: %s", rr.Body.String())
	}
}
