package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/xeprotocol/xe/node"
)

type mockFrontiersBackend struct {
	nodeBackend
	callCount int
	frontiers []node.FrontierInfo
}

func (m *mockFrontiersBackend) GetFrontiersDetailedPaged(offset, limit int) []node.FrontierInfo {
	m.callCount++
	if offset >= len(m.frontiers) {
		return []node.FrontierInfo{}
	}
	end := len(m.frontiers)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return m.frontiers[offset:end]
}

func TestHandleGetFrontiers_PaginationAndCache(t *testing.T) {
	mock := &mockFrontiersBackend{
		frontiers: make([]node.FrontierInfo, 100),
	}
	for i := 0; i < 100; i++ {
		mock.frontiers[i] = node.FrontierInfo{
			Account:    "account_" + strconv.Itoa(i),
			Frontier:   "hash_" + strconv.Itoa(i),
			BlockType:  "send",
			Timestamp:  int64(1000 + i),
			BlockCount: i + 1,
		}
	}

	h := &Handler{node: mock}

	// 1. Request page 1: offset=0, limit=10
	req := httptest.NewRequest("GET", "/frontiers?offset=0&limit=10", nil)
	rr := httptest.NewRecorder()
	h.handleGetFrontiers(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	var res1 []node.FrontierInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res1) != 10 {
		t.Fatalf("expected 10 items, got %d", len(res1))
	}
	if res1[0].Account != "account_0" || res1[9].Account != "account_9" {
		t.Fatalf("unexpected items in page 1: %+v", res1)
	}
	if mock.callCount != 1 {
		t.Fatalf("expected 1 backend call, got %d", mock.callCount)
	}

	// 2. Request page 1 again immediately (should be served from 1s TTL cache)
	req2 := httptest.NewRequest("GET", "/frontiers?offset=0&limit=10", nil)
	rr2 := httptest.NewRecorder()
	h.handleGetFrontiers(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr2.Code)
	}
	var res2 []node.FrontierInfo
	if err := json.Unmarshal(rr2.Body.Bytes(), &res2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res2) != 10 {
		t.Fatalf("expected 10 items, got %d", len(res2))
	}
	if mock.callCount != 1 {
		t.Fatalf("expected cache hit (1 backend call), got %d calls", mock.callCount)
	}

	// 3. Request page 2: offset=10, limit=10
	req3 := httptest.NewRequest("GET", "/frontiers?offset=10&limit=10", nil)
	rr3 := httptest.NewRecorder()
	h.handleGetFrontiers(rr3, req3)

	var res3 []node.FrontierInfo
	if err := json.Unmarshal(rr3.Body.Bytes(), &res3); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res3) != 10 || res3[0].Account != "account_10" {
		t.Fatalf("unexpected items in page 2: %+v", res3)
	}
	if mock.callCount != 2 {
		t.Fatalf("expected 2 backend calls, got %d", mock.callCount)
	}

	// 4. Request past end: offset=150
	req4 := httptest.NewRequest("GET", "/frontiers?offset=150&limit=10", nil)
	rr4 := httptest.NewRecorder()
	h.handleGetFrontiers(rr4, req4)

	var res4 []node.FrontierInfo
	if err := json.Unmarshal(rr4.Body.Bytes(), &res4); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res4) != 0 {
		t.Fatalf("expected 0 items, got %d", len(res4))
	}

	// 5. Test Cache Expiry after 1s
	time.Sleep(1100 * time.Millisecond)
	req5 := httptest.NewRequest("GET", "/frontiers?offset=0&limit=10", nil)
	rr5 := httptest.NewRecorder()
	h.handleGetFrontiers(rr5, req5)

	if mock.callCount != 4 {
		t.Fatalf("expected cache expiry to trigger backend call (4 calls total), got %d", mock.callCount)
	}
}
