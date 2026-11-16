package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

type mockAccountBackend struct {
	nodeBackend
	balances  map[string]map[string]uint64
	spendable map[string]map[string]uint64
	chains    map[string][]*core.Block
	heights   map[string]uint64
}

func (m *mockAccountBackend) GetAssetBalances(account string) map[string]uint64 {
	if m.balances != nil {
		if b, ok := m.balances[account]; ok {
			return b
		}
	}
	return map[string]uint64{}
}

func (m *mockAccountBackend) GetSpendableBalances(account string) map[string]uint64 {
	if m.spendable != nil {
		if s, ok := m.spendable[account]; ok {
			return s
		}
	}
	return map[string]uint64{}
}

func (m *mockAccountBackend) FinalHeight(account string) uint64 {
	if m.heights != nil {
		return m.heights[account]
	}
	return 0
}

func (m *mockAccountBackend) GetChain(account string) []*core.Block {
	if m.chains != nil {
		return m.chains[account]
	}
	return nil
}

func (m *mockAccountBackend) IsBlockFinalized(account, hash string) bool {
	return true
}

func (m *mockAccountBackend) GetPending(account string) []*core.PendingSend {
	return nil
}

func (m *mockAccountBackend) GetKeyset(account string) *core.Keyset {
	return nil
}

func (m *mockAccountBackend) GetReputation(account string) *core.ReputationAggregate {
	return nil
}

func (m *mockAccountBackend) GetConflicts(account string) []*core.Conflict {
	return nil
}

func TestAccountAddressValidationAndNormalization(t *testing.T) {
	testAddrLower := "a2673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	testAddrUpper := "A2673B1CB92518FBCD2C578EF297CE79E90BD1E6E0FCA13A50AF1485B86F435D"

	mockBackend := &mockAccountBackend{
		balances: map[string]map[string]uint64{
			testAddrLower: {"XE": 147898100},
		},
		spendable: map[string]map[string]uint64{
			testAddrLower: {"XE": 147898100},
		},
		heights: map[string]uint64{
			testAddrLower: 182,
		},
	}
	h := &Handler{node: mockBackend}

	// 1. Lowercase query succeeds and returns balance
	{
		req := httptest.NewRequest("GET", "/accounts/"+testAddrLower+"/balance", nil)
		req.SetPathValue("address", testAddrLower)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for lowercase address, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp struct {
			Address     string            `json:"address"`
			Balances    map[string]uint64 `json:"balances"`
			FinalHeight uint64            `json:"final_height"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Address != testAddrLower {
			t.Fatalf("expected address %s, got %s", testAddrLower, resp.Address)
		}
		if resp.Balances["XE"] != 147898100 {
			t.Fatalf("expected XE balance 147898100, got %d", resp.Balances["XE"])
		}
		if resp.FinalHeight != 182 {
			t.Fatalf("expected FinalHeight 182, got %d", resp.FinalHeight)
		}
	}

	// 2. Uppercase query succeeds, normalizes address, and returns real balance (Fix for Issue #69)
	{
		req := httptest.NewRequest("GET", "/accounts/"+testAddrUpper+"/balance", nil)
		req.SetPathValue("address", testAddrUpper)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for uppercase address, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp struct {
			Address     string            `json:"address"`
			Balances    map[string]uint64 `json:"balances"`
			FinalHeight uint64            `json:"final_height"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Address != testAddrLower {
			t.Fatalf("expected response address to be normalized to lowercase %s, got %s", testAddrLower, resp.Address)
		}
		if resp.Balances["XE"] != 147898100 {
			t.Fatalf("expected XE balance 147898100 for uppercase query, got %d", resp.Balances["XE"])
		}
		if resp.FinalHeight != 182 {
			t.Fatalf("expected FinalHeight 182, got %d", resp.FinalHeight)
		}
	}

	// 3. Non-hex address returns HTTP 400
	{
		nonHex := "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
		req := httptest.NewRequest("GET", "/accounts/"+nonHex+"/balance", nil)
		req.SetPathValue("address", nonHex)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for non-hex address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 4. Overly long address returns HTTP 400
	{
		longAddr := strings.Repeat("f", 4000)
		req := httptest.NewRequest("GET", "/accounts/"+longAddr+"/balance", nil)
		req.SetPathValue("address", longAddr)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for long address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 5. Short address returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/accounts/abc/balance", nil)
		req.SetPathValue("address", "abc")
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for short address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 6. Chain endpoint with uppercase address succeeds and normalizes
	{
		req := httptest.NewRequest("GET", "/accounts/"+testAddrUpper+"/chain", nil)
		req.SetPathValue("address", testAddrUpper)
		rec := httptest.NewRecorder()
		h.handleGetChain(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for chain with uppercase address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 7. Chain endpoint with invalid address returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/accounts/invalid-address/chain", nil)
		req.SetPathValue("address", "invalid-address")
		rec := httptest.NewRecorder()
		h.handleGetChain(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for invalid chain address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 8. Pending endpoint with invalid address returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/pending/invalid-address", nil)
		req.SetPathValue("address", "invalid-address")
		rec := httptest.NewRecorder()
		h.handleGetPending(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for invalid pending address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 9. Keyset endpoint with invalid address returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/accounts/invalid-address/keyset", nil)
		req.SetPathValue("address", "invalid-address")
		rec := httptest.NewRecorder()
		h.handleGetKeyset(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for invalid keyset address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 10. Reputation endpoint with invalid address returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/accounts/invalid-address/reputation", nil)
		req.SetPathValue("address", "invalid-address")
		rec := httptest.NewRecorder()
		h.handleGetReputation(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for invalid reputation address, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 11. Conflicts endpoint with invalid account returns HTTP 400
	{
		req := httptest.NewRequest("GET", "/conflicts/invalid-address", nil)
		req.SetPathValue("account", "invalid-address")
		rec := httptest.NewRecorder()
		h.handleGetAccountConflicts(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for invalid conflicts account, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}
