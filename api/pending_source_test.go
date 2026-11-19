package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/core"
)

type mockSourcePendingNode struct {
	nodeBackend
	destPending []*core.PendingSend
	srcPending  []*core.PendingSend
}

func (m *mockSourcePendingNode) GetPending(account string) []*core.PendingSend {
	return m.destPending
}

func (m *mockSourcePendingNode) GetPendingBySource(account string) []*core.PendingSend {
	return m.srcPending
}

func (m *mockSourcePendingNode) GetBlock(hash string) *core.Block {
	return nil
}

func TestHandler_GetPending_RoleParam(t *testing.T) {
	alice := "alice_addr_00000001"
	bob := "bob_addr_00000002"

	psIncoming := &core.PendingSend{
		SendHash:    "incoming_hash_01",
		Source:      bob,
		Destination: alice,
		Amount:      500,
		Asset:       "XE",
		Timestamp:   1700000000,
	}
	psOutgoing := &core.PendingSend{
		SendHash:    "outgoing_hash_02",
		Source:      alice,
		Destination: bob,
		Amount:      1500,
		Asset:       "XE",
		Timestamp:   1700000001,
	}

	mock := &mockSourcePendingNode{
		destPending: []*core.PendingSend{psIncoming},
		srcPending:  []*core.PendingSend{psOutgoing},
	}
	h := &Handler{node: mock}

	// 1. Default (destination) query
	reqDest := httptest.NewRequest(http.MethodGet, "/pending/"+alice, nil)
	reqDest.SetPathValue("address", alice)
	wDest := httptest.NewRecorder()
	h.handleGetPending(wDest, reqDest)

	if wDest.Code != http.StatusOK {
		t.Fatalf("destination pending status: got %d, want 200", wDest.Code)
	}
	var respDest struct {
		Address string         `json:"address"`
		Pending []pendingEntry `json:"pending"`
	}
	if err := json.NewDecoder(wDest.Body).Decode(&respDest); err != nil {
		t.Fatalf("decode respDest: %v", err)
	}
	if len(respDest.Pending) != 1 || respDest.Pending[0].SendHash != "incoming_hash_01" {
		t.Fatalf("expected incoming send, got %+v", respDest.Pending)
	}
	if respDest.Pending[0].Timestamp != 1700000000 {
		t.Fatalf("expected timestamp 1700000000, got %d", respDest.Pending[0].Timestamp)
	}

	// 2. Role=source query
	reqSrc := httptest.NewRequest(http.MethodGet, "/pending/"+alice+"?role=source", nil)
	reqSrc.SetPathValue("address", alice)
	wSrc := httptest.NewRecorder()
	h.handleGetPending(wSrc, reqSrc)

	if wSrc.Code != http.StatusOK {
		t.Fatalf("source pending status: got %d, want 200", wSrc.Code)
	}
	var respSrc struct {
		Address string         `json:"address"`
		Pending []pendingEntry `json:"pending"`
	}
	if err := json.NewDecoder(wSrc.Body).Decode(&respSrc); err != nil {
		t.Fatalf("decode respSrc: %v", err)
	}
	if len(respSrc.Pending) != 1 || respSrc.Pending[0].SendHash != "outgoing_hash_02" {
		t.Fatalf("expected outgoing send, got %+v", respSrc.Pending)
	}
	if respSrc.Pending[0].Timestamp != 1700000001 {
		t.Fatalf("expected timestamp 1700000001, got %d", respSrc.Pending[0].Timestamp)
	}
}
