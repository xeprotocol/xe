package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/client"
	"github.com/xeprotocol/xe/core"
)

type mockPendingNode struct {
	nodeBackend
	pendingMap    map[string][]*core.PendingSend
	blocksMap     map[string]*core.Block
	getBlockCalls int
}

func (m *mockPendingNode) GetPending(account string) []*core.PendingSend {
	if m.pendingMap != nil {
		return m.pendingMap[account]
	}
	return nil
}

func (m *mockPendingNode) GetBlock(hash string) *core.Block {
	m.getBlockCalls++
	if m.blocksMap != nil {
		return m.blocksMap[hash]
	}
	return nil
}

func TestGetPendingAddress_Pagination(t *testing.T) {
	victim := "victim_address_1234567890abcdef"
	sender := "sender_address_abcdef1234567890"

	// Create 10 pending sends for victim
	pendingSends := make([]*core.PendingSend, 10)
	blocks := make(map[string]*core.Block)
	for i := 0; i < 10; i++ {
		hash := fmt.Sprintf("send_hash_%02d", i)
		pendingSends[i] = &core.PendingSend{
			SendHash:    hash,
			Source:      sender,
			Destination: victim,
			Amount:      uint64(1000 * (i + 1)),
			Asset:       "XE",
		}
		blocks[hash] = &core.Block{
			Hash:      hash,
			Timestamp: int64(1700000000 + i*10),
		}
	}

	mock := &mockPendingNode{
		pendingMap: map[string][]*core.PendingSend{victim: pendingSends},
		blocksMap:  blocks,
	}

	h := &Handler{node: mock}

	// Helper to make request
	getPending := func(query string) []pendingEntry {
		req := httptest.NewRequest("GET", "/pending/"+victim+query, nil)
		req.SetPathValue("address", victim)
		rec := httptest.NewRecorder()
		h.handleGetPending(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp struct {
			Address string         `json:"address"`
			Pending []pendingEntry `json:"pending"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Address != victim {
			t.Fatalf("expected address %s, got %s", victim, resp.Address)
		}
		return resp.Pending
	}

	// 1. ?limit=1 returns only the first item
	{
		res := getPending("?limit=1")
		if len(res) != 1 {
			t.Fatalf("expected 1 item, got %d", len(res))
		}
		if res[0].SendHash != "send_hash_00" {
			t.Fatalf("expected send_hash_00, got %s", res[0].SendHash)
		}
		if res[0].Amount != 1000 {
			t.Fatalf("expected amount 1000, got %d", res[0].Amount)
		}
		if res[0].Timestamp != 1700000000 {
			t.Fatalf("expected timestamp 1700000000, got %d", res[0].Timestamp)
		}
	}

	// 2. ?limit=2&offset=1 returns items [1, 2]
	{
		res := getPending("?limit=2&offset=1")
		if len(res) != 2 {
			t.Fatalf("expected 2 items, got %d", len(res))
		}
		if res[0].SendHash != "send_hash_01" || res[1].SendHash != "send_hash_02" {
			t.Fatalf("unexpected items: %+v", res)
		}
	}

	// 3. ?limit=5&offset=8 returns items [8, 9] (end truncated at slice len)
	{
		res := getPending("?limit=5&offset=8")
		if len(res) != 2 {
			t.Fatalf("expected 2 items, got %d", len(res))
		}
		if res[0].SendHash != "send_hash_08" || res[1].SendHash != "send_hash_09" {
			t.Fatalf("unexpected items: %+v", res)
		}
	}

	// 4. ?offset=20 returns empty list (offset beyond slice len)
	{
		res := getPending("?offset=20")
		if len(res) != 0 {
			t.Fatalf("expected 0 items, got %d", len(res))
		}
	}

	// 5. Unspecified limit/offset returns all 10 items (default limit is 100)
	{
		res := getPending("")
		if len(res) != 10 {
			t.Fatalf("expected 10 items, got %d", len(res))
		}
		if res[0].SendHash != "send_hash_00" || res[9].SendHash != "send_hash_09" {
			t.Fatalf("unexpected items: %+v", res)
		}
	}
}

func TestGetPendingAddress_EnrichmentBounded(t *testing.T) {
	victim := "victim_address_large"
	sender := "sender_address_large"

	// Create 200 pending sends
	pendingSends := make([]*core.PendingSend, 200)
	for i := 0; i < 200; i++ {
		hash := fmt.Sprintf("large_send_%03d", i)
		pendingSends[i] = &core.PendingSend{
			SendHash:    hash,
			Source:      sender,
			Destination: victim,
			Amount:      100,
			Asset:       "XE",
		}
	}

	mock := &mockPendingNode{
		pendingMap: map[string][]*core.PendingSend{victim: pendingSends},
	}
	h := &Handler{node: mock}

	req := httptest.NewRequest("GET", "/pending/"+victim+"?limit=5", nil)
	req.SetPathValue("address", victim)
	rec := httptest.NewRecorder()
	h.handleGetPending(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// GetBlock must only have been called 5 times (for the paginated items), NOT 200 times!
	if mock.getBlockCalls != 5 {
		t.Fatalf("expected exactly 5 GetBlock calls for limit=5, got %d", mock.getBlockCalls)
	}
}

func TestGetPendingAddress_DefaultAndMaxLimit(t *testing.T) {
	victim := "victim_limit_test"
	sender := "sender_limit_test"

	// Create 1500 pending sends
	pendingSends := make([]*core.PendingSend, 1500)
	for i := 0; i < 1500; i++ {
		pendingSends[i] = &core.PendingSend{
			SendHash:    fmt.Sprintf("h_%04d", i),
			Source:      sender,
			Destination: victim,
			Amount:      10,
			Asset:       "XE",
		}
	}

	mock := &mockPendingNode{
		pendingMap: map[string][]*core.PendingSend{victim: pendingSends},
	}
	h := &Handler{node: mock}

	// Default limit: 100
	{
		req := httptest.NewRequest("GET", "/pending/"+victim, nil)
		req.SetPathValue("address", victim)
		rec := httptest.NewRecorder()
		h.handleGetPending(rec, req)

		var resp struct {
			Pending []pendingEntry `json:"pending"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if len(resp.Pending) != defaultPageLimit {
			t.Fatalf("expected default %d items, got %d", defaultPageLimit, len(resp.Pending))
		}
	}

	// Max limit cap: requesting 5000 is capped at maxPageLimit (1000)
	{
		req := httptest.NewRequest("GET", "/pending/"+victim+"?limit=5000", nil)
		req.SetPathValue("address", victim)
		rec := httptest.NewRecorder()
		h.handleGetPending(rec, req)

		var resp struct {
			Pending []pendingEntry `json:"pending"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if len(resp.Pending) != maxPageLimit {
			t.Fatalf("expected max cap %d items, got %d", maxPageLimit, len(resp.Pending))
		}
	}
}

func TestClient_GetPendingPage(t *testing.T) {
	victim := "victim_client_test"
	sender := "sender_client_test"

	pendingSends := make([]*core.PendingSend, 10)
	for i := 0; i < 10; i++ {
		pendingSends[i] = &core.PendingSend{
			SendHash:    fmt.Sprintf("chash_%02d", i),
			Source:      sender,
			Destination: victim,
			Amount:      uint64(500 * (i + 1)),
			Asset:       "XE",
		}
	}

	mock := &mockPendingNode{
		pendingMap: map[string][]*core.PendingSend{victim: pendingSends},
	}

	mux := http.NewServeMux()
	h := &Handler{node: mock}
	mux.HandleFunc("GET /pending/{address}", h.handleGetPending)

	server := httptest.NewServer(mux)
	defer server.Close()

	c := &client.Client{BaseURL: server.URL}

	// Request page with limit 3, offset 2
	page, err := c.GetPendingPage(victim, 2, 3)
	if err != nil {
		t.Fatalf("GetPendingPage failed: %v", err)
	}

	if len(page) != 3 {
		t.Fatalf("expected 3 items, got %d", len(page))
	}
	if page[0].SendHash != "chash_02" || page[1].SendHash != "chash_03" || page[2].SendHash != "chash_04" {
		t.Fatalf("unexpected items: %+v", page)
	}
}
