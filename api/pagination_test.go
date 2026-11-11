package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/core"
)

type mockPaginationBackend struct {
	nodeBackend
	blocks  []*core.Block
	pending map[string][]*core.PendingSend
}

func (m *mockPaginationBackend) GetRecentBlocks(limit int) []*core.Block {
	if len(m.blocks) > limit {
		return m.blocks[:limit]
	}
	return m.blocks
}

func (m *mockPaginationBackend) GetPending(account string) []*core.PendingSend {
	return m.pending[account]
}

func (m *mockPaginationBackend) GetBlock(hash string) *core.Block {
	for _, b := range m.blocks {
		if b.Hash == hash {
			return b
		}
	}
	return nil
}

func TestGetRecentBlocks_PaginationOffset(t *testing.T) {
	mock := &mockPaginationBackend{}
	for i := 0; i < 10; i++ {
		mock.blocks = append(mock.blocks, &core.Block{
			Hash:      fmt.Sprintf("block%02d", i),
			Timestamp: int64(1000 + i),
		})
	}

	h := &Handler{node: mock}
	mux := h.Mux()

	// 1. First page: offset=0, limit=2 -> block00, block01
	req := httptest.NewRequest(http.MethodGet, "/blocks/recent?limit=2&offset=0", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var page1 []*core.Block
	if err := json.NewDecoder(rec.Body).Decode(&page1); err != nil {
		t.Fatalf("decode page1: %v", err)
	}
	if len(page1) != 2 || page1[0].Hash != "block00" || page1[1].Hash != "block01" {
		t.Fatalf("page 1 mismatch: got %+v", page1)
	}

	// 2. Second page: offset=2, limit=2 -> block02, block03
	req2 := httptest.NewRequest(http.MethodGet, "/blocks/recent?limit=2&offset=2", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var page2 []*core.Block
	if err := json.NewDecoder(rec2.Body).Decode(&page2); err != nil {
		t.Fatalf("decode page2: %v", err)
	}
	if len(page2) != 2 || page2[0].Hash != "block02" || page2[1].Hash != "block03" {
		t.Fatalf("page 2 mismatch: got %+v", page2)
	}

	// 3. Tail page: offset=9, limit=2 -> block09 (only 1 item)
	req3 := httptest.NewRequest(http.MethodGet, "/blocks/recent?limit=2&offset=9", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var page3 []*core.Block
	if err := json.NewDecoder(rec3.Body).Decode(&page3); err != nil {
		t.Fatalf("decode page3: %v", err)
	}
	if len(page3) != 1 || page3[0].Hash != "block09" {
		t.Fatalf("page 3 mismatch: got %+v", page3)
	}

	// 4. Past end: offset=15, limit=2 -> empty array
	req4 := httptest.NewRequest(http.MethodGet, "/blocks/recent?limit=2&offset=15", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)

	var page4 []*core.Block
	if err := json.NewDecoder(rec4.Body).Decode(&page4); err != nil {
		t.Fatalf("decode page4: %v", err)
	}
	if len(page4) != 0 {
		t.Fatalf("page 4 mismatch: expected empty, got %+v", page4)
	}
}

func TestGetPendingAddress_Pagination(t *testing.T) {
	victim := "victim0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	mock := &mockPaginationBackend{
		pending: make(map[string][]*core.PendingSend),
	}
	for i := 0; i < 5; i++ {
		mock.pending[victim] = append(mock.pending[victim], &core.PendingSend{
			SendHash:    fmt.Sprintf("send%02d", i),
			Destination: victim,
			Amount:      uint64(100 + i),
			Asset:       "XE",
		})
	}

	h := &Handler{node: mock}
	mux := h.Mux()

	type pendingResp struct {
		Address string         `json:"address"`
		Pending []pendingEntry `json:"pending"`
	}

	// 1. Page 1: limit=2, offset=0
	req := httptest.NewRequest(http.MethodGet, "/pending/"+victim+"?limit=2&offset=0", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var res1 pendingResp
	if err := json.NewDecoder(rec.Body).Decode(&res1); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res1.Pending) != 2 || res1.Pending[0].SendHash != "send00" || res1.Pending[1].SendHash != "send01" {
		t.Fatalf("unexpected page 1: %+v", res1.Pending)
	}

	// 2. Page 2: limit=2, offset=2
	req2 := httptest.NewRequest(http.MethodGet, "/pending/"+victim+"?limit=2&offset=2", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var res2 pendingResp
	if err := json.NewDecoder(rec2.Body).Decode(&res2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res2.Pending) != 2 || res2.Pending[0].SendHash != "send02" || res2.Pending[1].SendHash != "send03" {
		t.Fatalf("unexpected page 2: %+v", res2.Pending)
	}

	// 3. Page 3: limit=2, offset=4
	req3 := httptest.NewRequest(http.MethodGet, "/pending/"+victim+"?limit=2&offset=4", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var res3 pendingResp
	if err := json.NewDecoder(rec3.Body).Decode(&res3); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res3.Pending) != 1 || res3.Pending[0].SendHash != "send04" {
		t.Fatalf("unexpected page 3: %+v", res3.Pending)
	}

	// 4. Page 4: past end: offset=10
	req4 := httptest.NewRequest(http.MethodGet, "/pending/"+victim+"?limit=2&offset=10", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)

	var res4 pendingResp
	if err := json.NewDecoder(rec4.Body).Decode(&res4); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res4.Pending) != 0 {
		t.Fatalf("unexpected page 4: expected empty, got %+v", res4.Pending)
	}
}
