package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/node"
)

type testNodeBackend struct {
	nodeBackend
	accounts []node.AccountSummary
	pending  []*core.PendingSend
}

func (t *testNodeBackend) GetAllAccounts() []node.AccountSummary {
	return t.accounts
}

func (t *testNodeBackend) GetAllPending() []*core.PendingSend {
	return t.pending
}

func (t *testNodeBackend) GetBlock(hash string) *core.Block {
	return nil
}

func TestHandleGetAllAccounts_Pagination(t *testing.T) {
	// Create 5 accounts
	accounts := []node.AccountSummary{
		{Address: "addr1", Balances: map[string]uint64{"XE": 500}},
		{Address: "addr2", Balances: map[string]uint64{"XE": 400}},
		{Address: "addr3", Balances: map[string]uint64{"XE": 300}},
		{Address: "addr4", Balances: map[string]uint64{"XE": 200}},
		{Address: "addr5", Balances: map[string]uint64{"XE": 100}},
	}
	backend := &testNodeBackend{accounts: accounts}
	h := &Handler{node: backend}

	// Test 1: limit=2, offset=0
	req := httptest.NewRequest("GET", "/accounts?limit=2&offset=0", nil)
	rec := httptest.NewRecorder()
	h.handleGetAllAccounts(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	var res1 []node.AccountSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &res1); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(res1) != 2 {
		t.Fatalf("expected 2 items, got %d", len(res1))
	}
	if res1[0].Address != "addr1" || res1[1].Address != "addr2" {
		t.Fatalf("unexpected order: %+v", res1)
	}

	// Test 2: limit=2, offset=2
	req = httptest.NewRequest("GET", "/accounts?limit=2&offset=2", nil)
	rec = httptest.NewRecorder()
	h.handleGetAllAccounts(rec, req)

	var res2 []node.AccountSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &res2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(res2) != 2 {
		t.Fatalf("expected 2 items, got %d", len(res2))
	}
	if res2[0].Address != "addr3" || res2[1].Address != "addr4" {
		t.Fatalf("unexpected items: %+v", res2)
	}

	// Test 3: offset >= len
	req = httptest.NewRequest("GET", "/accounts?offset=10", nil)
	rec = httptest.NewRecorder()
	h.handleGetAllAccounts(rec, req)

	var res3 []node.AccountSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &res3); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(res3) != 0 {
		t.Fatalf("expected empty array, got %d items", len(res3))
	}
}

func TestHandleGetAllAccounts_Caching(t *testing.T) {
	callCount := 0
	accounts := []node.AccountSummary{
		{Address: "addr1", Balances: map[string]uint64{"XE": 100}},
	}
	backend := &countingBackend{
		testNodeBackend: testNodeBackend{accounts: accounts},
		onGetAll: func() {
			callCount++
		},
	}
	h := &Handler{node: backend}

	// First request: should call GetAllAccounts
	req1 := httptest.NewRequest("GET", "/accounts", nil)
	rec1 := httptest.NewRecorder()
	h.handleGetAllAccounts(rec1, req1)
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	// Immediate second request: should hit cache
	req2 := httptest.NewRequest("GET", "/accounts", nil)
	rec2 := httptest.NewRecorder()
	h.handleGetAllAccounts(rec2, req2)
	if callCount != 1 {
		t.Fatalf("expected cache hit (still 1 call), got %d", callCount)
	}
}

type countingBackend struct {
	testNodeBackend
	onGetAll func()
}

func (c *countingBackend) GetAllAccounts() []node.AccountSummary {
	if c.onGetAll != nil {
		c.onGetAll()
	}
	return c.accounts
}

func TestHandleGetAllPending_Pagination(t *testing.T) {
	pending := []*core.PendingSend{
		{SendHash: "s1", Source: "src1", Destination: "dst1", Amount: 10, Asset: "XE"},
		{SendHash: "s2", Source: "src2", Destination: "dst2", Amount: 20, Asset: "XE"},
		{SendHash: "s3", Source: "src3", Destination: "dst3", Amount: 30, Asset: "XE"},
	}
	backend := &testNodeBackend{pending: pending}
	h := &Handler{node: backend}

	req := httptest.NewRequest("GET", "/pending?limit=2&offset=1", nil)
	rec := httptest.NewRecorder()
	h.handleGetAllPending(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	var res []pendingEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 items, got %d", len(res))
	}
	if res[0].SendHash != "s2" || res[1].SendHash != "s3" {
		t.Fatalf("unexpected items: %+v", res)
	}
}
