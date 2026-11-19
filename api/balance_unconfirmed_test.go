package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/client"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/statechain"
)

type mockBalanceNode struct {
	nodeBackend
	balances       map[string]map[string]uint64
	spendable      map[string]map[string]uint64
	finalSpendable map[string]map[string]uint64
	finalHeights   map[string]uint64
	chainTotals    map[string]int
}

func (m *mockBalanceNode) GetBalance(account string) uint64 {
	return 0
}

func (m *mockBalanceNode) GetAssetBalances(account string) map[string]uint64 {
	if m.balances != nil && m.balances[account] != nil {
		return m.balances[account]
	}
	return map[string]uint64{}
}

func (m *mockBalanceNode) GetSpendableBalances(account string) map[string]uint64 {
	if m.spendable != nil && m.spendable[account] != nil {
		return m.spendable[account]
	}
	return map[string]uint64{}
}

func (m *mockBalanceNode) GetFinalSpendableBalances(account string) map[string]uint64 {
	if m.finalSpendable != nil && m.finalSpendable[account] != nil {
		return m.finalSpendable[account]
	}
	return map[string]uint64{}
}

func (m *mockBalanceNode) IsBlockFinalized(account, hash string) bool {
	return true
}

func (m *mockBalanceNode) FinalHeight(account string) uint64 {
	if m.finalHeights != nil {
		return m.finalHeights[account]
	}
	return 0
}

func (m *mockBalanceNode) GetChainRange(account string, from, to int) ([]*core.Block, int) {
	if m.chainTotals != nil {
		return nil, m.chainTotals[account]
	}
	return nil, 0
}

func (m *mockBalanceNode) GetKeyset(account string) *core.Keyset                       { return nil }
func (m *mockBalanceNode) GetReputation(account string) *core.ReputationAggregate     { return nil }
func (m *mockBalanceNode) GetAllReputations() map[string]*core.ReputationAggregate    { return nil }
func (m *mockBalanceNode) GetBlock(hash string) *core.Block                           { return nil }
func (m *mockBalanceNode) GetPending(account string) []*core.PendingSend              { return nil }
func (m *mockBalanceNode) GetPendingPage(ctx context.Context, offset, limit int) ([]*core.PendingSend, error) {
	return nil, nil
}
func (m *mockBalanceNode) GetFrontiers() map[string]string                            { return nil }
func (m *mockBalanceNode) GetFrontiersPage(offset, limit int) []node.FrontierInfo     { return nil }
func (m *mockBalanceNode) GetAccountsPage(offset, limit int) []node.AccountSummary    { return nil }
func (m *mockBalanceNode) GetSupply() *core.SupplyReport                              { return nil }
func (m *mockBalanceNode) GetRecentBlocks(ctx context.Context, limit int) ([]*core.Block, error) {
	return nil, nil
}
func (m *mockBalanceNode) SubmitBlock(b *core.Block) error                            { return nil }
func (m *mockBalanceNode) GetConflicts(account string) []*core.Conflict               { return nil }
func (m *mockBalanceNode) GetAllConflicts() []*core.Conflict                          { return nil }
func (m *mockBalanceNode) GetDelegation() *node.DelegationInfo                        { return nil }
func (m *mockBalanceNode) GetNodeInfo() *node.NodeInfo                                { return nil }
func (m *mockBalanceNode) GetActivations() *node.ActivationsInfo                      { return nil }
func (m *mockBalanceNode) GetReadiness() *node.ReadinessInfo                          { return nil }
func (m *mockBalanceNode) GetLeases() []*core.Lease                                  { return nil }
func (m *mockBalanceNode) GetLeasesByState(state core.LeaseState) []*core.Lease       { return nil }
func (m *mockBalanceNode) GetLease(leaseHash string) *core.Lease                      { return nil }
func (m *mockBalanceNode) GetStateChainTip() *statechain.Block                        { return nil }
func (m *mockBalanceNode) GetStateChainBlock(index uint64) *statechain.Block         { return nil }

func TestHandleGetBalance_UnconfirmedFrontierFlagAndFinalSpendable(t *testing.T) {
	w1 := "2dda1e8cead608801ed02791123da1e11bfc2b90862d68b2954e2995b7f57b18"
	wConfirmed := "11112222333344445555666677778888aaaabbbbccccddddeeeeffff00001111"
	wEmpty := "9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff"

	mockBackend := &mockBalanceNode{
		balances: map[string]map[string]uint64{
			w1:         {"XE": 600000},
			wConfirmed: {"XE": 800000},
		},
		spendable: map[string]map[string]uint64{
			w1:         {"XE": 600000},
			wConfirmed: {"XE": 800000},
		},
		finalSpendable: map[string]map[string]uint64{
			w1:         {"XE": 900000}, // Finalized spendable before unconfirmed 300k send
			wConfirmed: {"XE": 800000},
		},
		finalHeights: map[string]uint64{
			w1:         2,
			wConfirmed: 3,
			wEmpty:     0,
		},
		chainTotals: map[string]int{
			w1:         3, // total 3 > finalHeight 2 -> has_unconfirmed_frontier: true
			wConfirmed: 3, // total 3 == finalHeight 3 -> has_unconfirmed_frontier: false
			wEmpty:     0, // total 0 == finalHeight 0 -> has_unconfirmed_frontier: false
		},
	}

	h := &Handler{node: mockBackend}

	// 1. Test w1: Partitioned/lagging node case (unconfirmed frontier)
	{
		req := httptest.NewRequest("GET", "/accounts/"+w1+"/balance", nil)
		req.SetPathValue("address", w1)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var resp struct {
			Address                string            `json:"address"`
			Balances               map[string]uint64 `json:"balances"`
			Spendable              map[string]uint64 `json:"spendable"`
			FinalSpendable         map[string]uint64 `json:"final_spendable"`
			FinalHeight            uint64            `json:"final_height"`
			HasUnconfirmedFrontier bool              `json:"has_unconfirmed_frontier"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}

		if resp.Address != w1 {
			t.Fatalf("expected address %s, got %s", w1, resp.Address)
		}
		if !resp.HasUnconfirmedFrontier {
			t.Fatalf("expected has_unconfirmed_frontier: true for unconfirmed frontier")
		}
		if resp.FinalHeight != 2 {
			t.Fatalf("expected final_height: 2, got %d", resp.FinalHeight)
		}
		if resp.Spendable["XE"] != 600000 {
			t.Fatalf("expected spendable 600000, got %d", resp.Spendable["XE"])
		}
		if resp.FinalSpendable["XE"] != 900000 {
			t.Fatalf("expected final_spendable 900000, got %d", resp.FinalSpendable["XE"])
		}
	}

	// 2. Test wConfirmed: Fully confirmed frontier
	{
		req := httptest.NewRequest("GET", "/accounts/"+wConfirmed+"/balance", nil)
		req.SetPathValue("address", wConfirmed)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var resp struct {
			Address                string            `json:"address"`
			Balances               map[string]uint64 `json:"balances"`
			Spendable              map[string]uint64 `json:"spendable"`
			FinalSpendable         map[string]uint64 `json:"final_spendable"`
			FinalHeight            uint64            `json:"final_height"`
			HasUnconfirmedFrontier bool              `json:"has_unconfirmed_frontier"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}

		if resp.HasUnconfirmedFrontier {
			t.Fatalf("expected has_unconfirmed_frontier: false for fully confirmed frontier")
		}
		if resp.FinalHeight != 3 {
			t.Fatalf("expected final_height: 3, got %d", resp.FinalHeight)
		}
		if resp.Spendable["XE"] != 800000 {
			t.Fatalf("expected spendable 800000, got %d", resp.Spendable["XE"])
		}
		if resp.FinalSpendable["XE"] != 800000 {
			t.Fatalf("expected final_spendable 800000, got %d", resp.FinalSpendable["XE"])
		}
	}

	// 3. Test wEmpty: Unopened/empty account
	{
		req := httptest.NewRequest("GET", "/accounts/"+wEmpty+"/balance", nil)
		req.SetPathValue("address", wEmpty)
		rec := httptest.NewRecorder()
		h.handleGetBalance(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var resp struct {
			Address                string            `json:"address"`
			Balances               map[string]uint64 `json:"balances"`
			Spendable              map[string]uint64 `json:"spendable"`
			FinalSpendable         map[string]uint64 `json:"final_spendable"`
			FinalHeight            uint64            `json:"final_height"`
			HasUnconfirmedFrontier bool              `json:"has_unconfirmed_frontier"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}

		if resp.HasUnconfirmedFrontier {
			t.Fatalf("expected has_unconfirmed_frontier: false for empty account")
		}
		if resp.FinalHeight != 0 {
			t.Fatalf("expected final_height: 0, got %d", resp.FinalHeight)
		}
		if len(resp.Balances) != 0 || len(resp.Spendable) != 0 || len(resp.FinalSpendable) != 0 {
			t.Fatalf("expected empty balance maps, got balances=%+v spendable=%+v final_spendable=%+v",
				resp.Balances, resp.Spendable, resp.FinalSpendable)
		}
	}
}

func TestClient_GetBalanceInfo(t *testing.T) {
	w := "2dda1e8cead608801ed02791123da1e11bfc2b90862d68b2954e2995b7f57b18"
	mockBackend := &mockBalanceNode{
		balances:       map[string]map[string]uint64{w: {"XE": 600000}},
		spendable:      map[string]map[string]uint64{w: {"XE": 600000}},
		finalSpendable: map[string]map[string]uint64{w: {"XE": 900000}},
		finalHeights:   map[string]uint64{w: 2},
		chainTotals:    map[string]int{w: 3},
	}

	mux := http.NewServeMux()
	h := &Handler{node: mockBackend}
	mux.HandleFunc("GET /accounts/{address}/balance", h.handleGetBalance)

	server := httptest.NewServer(mux)
	defer server.Close()

	c := &client.Client{BaseURL: server.URL}
	info, err := c.GetBalanceInfo(w)
	if err != nil {
		t.Fatalf("GetBalanceInfo failed: %v", err)
	}

	if info.Address != w {
		t.Fatalf("expected address %s, got %s", w, info.Address)
	}
	if !info.HasUnconfirmedFrontier {
		t.Fatalf("expected has_unconfirmed_frontier: true")
	}
	if info.FinalHeight != 2 {
		t.Fatalf("expected final_height 2, got %d", info.FinalHeight)
	}
	if info.Spendable["XE"] != 600000 {
		t.Fatalf("expected spendable 600000, got %d", info.Spendable["XE"])
	}
	if info.FinalSpendable["XE"] != 900000 {
		t.Fatalf("expected final_spendable 900000, got %d", info.FinalSpendable["XE"])
	}
}
