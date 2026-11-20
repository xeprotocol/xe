package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/core"
)

type testSearchBackend struct {
	nodeBackend
	committedBlocks map[string]*core.Block
	stagedBlocks    map[string]*core.Block
	chains          map[string][]*core.Block
	balances        map[string]map[string]uint64
}

func (m *testSearchBackend) GetBlock(hash string) *core.Block {
	return m.committedBlocks[hash]
}

func (m *testSearchBackend) GetBlockOrStaged(hash string) *core.Block {
	if b := m.committedBlocks[hash]; b != nil {
		return b
	}
	return m.stagedBlocks[hash]
}

func (m *testSearchBackend) IsBlockFinalized(account, hash string) bool {
	return m.committedBlocks[hash] != nil
}

func (m *testSearchBackend) GetChain(account string) []*core.Block {
	return m.chains[account]
}

func (m *testSearchBackend) FinalHeight(account string) uint64 {
	return uint64(len(m.chains[account]))
}

func (m *testSearchBackend) GetAssetBalances(account string) map[string]uint64 {
	if b := m.balances[account]; b != nil {
		return b
	}
	return map[string]uint64{}
}

func (m *testSearchBackend) GetSpendableBalances(account string) map[string]uint64 {
	return m.GetAssetBalances(account)
}

func TestCleanHex(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"0x1234abcd", "1234abcd"},
		{"0X1234ABCD", "1234abcd"},
		{"  0xabcdef  ", "abcdef"},
		{"abcdef", "abcdef"},
		{"", ""},
	}
	for _, tc := range cases {
		got := cleanHex(tc.input)
		if got != tc.expected {
			t.Errorf("cleanHex(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestHandleGetBlock_CommittedAndStaged(t *testing.T) {
	committed := &core.Block{
		Type:    core.BlockSend,
		Account: "1111111111111111111111111111111111111111111111111111111111111111",
		Hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Amount:  100,
	}
	staged := &core.Block{
		Type:    core.BlockSend,
		Account: "2222222222222222222222222222222222222222222222222222222222222222",
		Hash:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Amount:  200,
	}

	backend := &testSearchBackend{
		committedBlocks: map[string]*core.Block{
			committed.Hash: committed,
		},
		stagedBlocks: map[string]*core.Block{
			staged.Hash: staged,
		},
	}
	h := &Handler{node: backend}

	// 1. Committed block lookup by hash
	req := httptest.NewRequest("GET", "/api/blocks/"+committed.Hash, nil)
	req.SetPathValue("hash", committed.Hash)
	rec := httptest.NewRecorder()
	h.handleGetBlock(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for committed block, got %d", rec.Code)
	}
	var view blockView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if view.Hash != committed.Hash || !view.Finalized {
		t.Fatalf("unexpected block view: %+v", view)
	}

	// 2. Committed block lookup with 0x prefix and uppercase
	req0x := httptest.NewRequest("GET", "/api/blocks/0x"+committed.Hash, nil)
	req0x.SetPathValue("hash", "0X"+committed.Hash)
	rec0x := httptest.NewRecorder()
	h.handleGetBlock(rec0x, req0x)
	if rec0x.Code != http.StatusOK {
		t.Fatalf("expected 200 for 0x prefixed committed block, got %d", rec0x.Code)
	}

	// 3. Staged block lookup (not in committed store)
	reqStaged := httptest.NewRequest("GET", "/api/blocks/"+staged.Hash, nil)
	reqStaged.SetPathValue("hash", staged.Hash)
	recStaged := httptest.NewRecorder()
	h.handleGetBlock(recStaged, reqStaged)
	if recStaged.Code != http.StatusOK {
		t.Fatalf("expected 200 for staged block, got %d", recStaged.Code)
	}
	var stagedView blockView
	if err := json.Unmarshal(recStaged.Body.Bytes(), &stagedView); err != nil {
		t.Fatalf("unmarshal staged error: %v", err)
	}
	if stagedView.Hash != staged.Hash || stagedView.Finalized {
		t.Fatalf("expected staged block unfinalized, got %+v", stagedView)
	}

	// 4. Missing block
	reqMissing := httptest.NewRequest("GET", "/api/blocks/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", nil)
	reqMissing.SetPathValue("hash", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	recMissing := httptest.NewRecorder()
	h.handleGetBlock(recMissing, reqMissing)
	if recMissing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing block, got %d", recMissing.Code)
	}
}

func TestHandleGetChainAndBalance_Normalization(t *testing.T) {
	addr := "040d2665b6244d198f3c6c1f44ede6c9b9a546afc73dc33387a10ec09751e4a8"
	backend := &testSearchBackend{
		chains: map[string][]*core.Block{
			addr: {},
		},
		balances: map[string]map[string]uint64{
			addr: {"XE": 5000000},
		},
	}
	h := &Handler{node: backend}

	// Chain with 0x prefix
	reqChain := httptest.NewRequest("GET", "/api/accounts/0x"+addr+"/chain", nil)
	reqChain.SetPathValue("address", "0x"+addr)
	recChain := httptest.NewRecorder()
	h.handleGetChain(recChain, reqChain)
	if recChain.Code != http.StatusOK {
		t.Fatalf("expected 200 for chain with 0x, got %d", recChain.Code)
	}

	// Balance with 0x prefix
	reqBal := httptest.NewRequest("GET", "/api/accounts/0X"+addr+"/balance", nil)
	reqBal.SetPathValue("address", "0X"+addr)
	recBal := httptest.NewRecorder()
	h.handleGetBalance(recBal, reqBal)
	if recBal.Code != http.StatusOK {
		t.Fatalf("expected 200 for balance with 0x, got %d", recBal.Code)
	}
}
