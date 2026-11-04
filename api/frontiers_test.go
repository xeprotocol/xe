package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/store"
)

func TestHandleGetFrontiers_Pagination(t *testing.T) {
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{
		TimestampWindow: core.DefaultTimestampWindow,
	})

	n := &node.Node{
		Ledger: l,
	}

	const numAccounts = 20
	now := time.Now().UnixNano()
	for i := 0; i < numAccounts; i++ {
		addr := "user_" + strconv.Itoa(100+i)
		b := &core.Block{
			Type:           core.BlockSend,
			Hash:           "hash_" + addr,
			Account:        addr,
			Representative: "rep_node",
			Timestamp:      now + int64(i),
			Asset:          "XE",
			Amount:         500,
		}
		s.CommitBlock(&core.BlockCommit{
			Block:        b,
			Account:      addr,
			Chain:        &core.AccountChain{Blocks: []*core.Block{b}},
			FrontierHash: b.Hash,
		})
	}

	h := NewHandler(n)

	// 1. Test limit=1
	req := httptest.NewRequest(http.MethodGet, "/frontiers?limit=1", nil)
	rec := httptest.NewRecorder()
	h.handleGetFrontiers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var res1 []node.FrontierInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res1) != 1 {
		t.Fatalf("expected exactly 1 item for limit=1, got %d", len(res1))
	}

	// 2. Test limit=5&offset=2
	req = httptest.NewRequest(http.MethodGet, "/frontiers?limit=5&offset=2", nil)
	rec = httptest.NewRecorder()
	h.handleGetFrontiers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var res2 []node.FrontierInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &res2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res2) != 5 {
		t.Fatalf("expected exactly 5 items for limit=5, got %d", len(res2))
	}

	// 3. Test out of range offset returns empty list
	req = httptest.NewRequest(http.MethodGet, "/frontiers?limit=10&offset=1000", nil)
	rec = httptest.NewRecorder()
	h.handleGetFrontiers(rec, req)

	var resEmpty []node.FrontierInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &resEmpty); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resEmpty) != 0 {
		t.Fatalf("expected empty list for large offset, got %d", len(resEmpty))
	}
}
