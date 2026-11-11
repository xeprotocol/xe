package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/vm"
)

type mockNodeBackend struct {
	pendingMap map[string][]*core.PendingSend
	blocksMap  map[string]*core.Block
}

func (m *mockNodeBackend) GetBalance(account string) uint64                       { return 0 }
func (m *mockNodeBackend) GetAssetBalances(account string) map[string]uint64      { return nil }
func (m *mockNodeBackend) GetSpendableBalances(account string) map[string]uint64  { return nil }
func (m *mockNodeBackend) IsBlockFinalized(account, hash string) bool             { return true }
func (m *mockNodeBackend) FinalHeight(account string) uint64                      { return 0 }
func (m *mockNodeBackend) GetKeyset(account string) *core.Keyset                  { return nil }
func (m *mockNodeBackend) GetReputation(account string) *core.ReputationAggregate { return nil }
func (m *mockNodeBackend) GetAllReputations() map[string]*core.ReputationAggregate {
	return nil
}
func (m *mockNodeBackend) GetChain(account string) []*core.Block { return nil }
func (m *mockNodeBackend) GetBlock(hash string) *core.Block {
	if m.blocksMap != nil {
		return m.blocksMap[hash]
	}
	return nil
}
func (m *mockNodeBackend) GetPending(account string) []*core.PendingSend {
	if m.pendingMap != nil {
		return m.pendingMap[account]
	}
	return nil
}
func (m *mockNodeBackend) GetAllPending() []*core.PendingSend                 { return nil }
func (m *mockNodeBackend) GetFrontiers() map[string]string                    { return nil }
func (m *mockNodeBackend) GetFrontiersDetailed() []node.FrontierInfo          { return nil }
func (m *mockNodeBackend) GetAllAccounts() []node.AccountSummary              { return nil }
func (m *mockNodeBackend) GetSupply() *core.SupplyReport                      { return nil }
func (m *mockNodeBackend) GetRecentBlocks(limit int) []*core.Block            { return nil }
func (m *mockNodeBackend) SubmitBlock(b *core.Block) error                    { return nil }
func (m *mockNodeBackend) GetConflicts(account string) []*core.Conflict       { return nil }
func (m *mockNodeBackend) GetAllConflicts() []*core.Conflict                  { return nil }
func (m *mockNodeBackend) GetDelegation() *node.DelegationInfo                { return nil }
func (m *mockNodeBackend) GetNodeInfo() *node.NodeInfo                        { return &node.NodeInfo{} }
func (m *mockNodeBackend) GetActivations() *node.ActivationsInfo              { return nil }
func (m *mockNodeBackend) GetReadiness() *node.ReadinessInfo                  { return nil }
func (m *mockNodeBackend) GetLeases() []*core.Lease                           { return nil }
func (m *mockNodeBackend) GetLeasesByState(state core.LeaseState) []*core.Lease { return nil }
func (m *mockNodeBackend) GetLease(leaseHash string) *core.Lease              { return nil }
func (m *mockNodeBackend) GetStateChainTip() *statechain.Block                { return nil }
func (m *mockNodeBackend) GetStateChainBlock(index uint64) *statechain.Block  { return nil }
func (m *mockNodeBackend) GetStateChainBlocks(start, limit uint64) []*statechain.Block {
	return nil
}
func (m *mockNodeBackend) GetStateChainBlockCount() uint64                      { return 0 }
func (m *mockNodeBackend) GetStateKV(key string) (json.RawMessage, bool)        { return nil, false }
func (m *mockNodeBackend) GetStateKVByPrefix(prefix string) map[string]json.RawMessage {
	return nil
}
func (m *mockNodeBackend) GetAllStateKV() map[string]json.RawMessage { return nil }
func (m *mockNodeBackend) GetDAOKeyset() *statechain.DAOKeyset        { return nil }
func (m *mockNodeBackend) SubmitStateChainBlock(b *statechain.Block) error {
	return nil
}
func (m *mockNodeBackend) SendChat(ctx context.Context, env *chat.Envelope) error { return nil }
func (m *mockNodeBackend) SendChatMessage(ctx context.Context, to, message string) error {
	return nil
}
func (m *mockNodeBackend) GetChatMessages(account string, since int64) []*chat.Envelope {
	return nil
}
func (m *mockNodeBackend) GetChatAccounts() []string                      { return nil }
func (m *mockNodeBackend) GetChatContacts(account string) []string        { return nil }
func (m *mockNodeBackend) SubscribeChat() (chan *chat.Envelope, func())   { return nil, func() {} }
func (m *mockNodeBackend) RequestAttestation(source, identifier string) (*core.TimekeeperAttestation, error) {
	return nil, nil
}
func (m *mockNodeBackend) RegisterAccount(reg *directory.Registration) error   { return nil }
func (m *mockNodeBackend) ListDirectory() []*directory.Registration            { return nil }
func (m *mockNodeBackend) LookupDirectory(account string) *directory.Registration {
	return nil
}
func (m *mockNodeBackend) GetVMs() []*vm.Info             { return nil }
func (m *mockNodeBackend) GetVM(leaseHash string) *vm.Info { return nil }
func (m *mockNodeBackend) RequestAndCreateLease(ctx context.Context, vcpus, memoryMB, diskGB, duration uint64, accessPubKey string) (string, error) {
	return "", nil
}
func (m *mockNodeBackend) RenewLease(leaseHash string, additionalSecs uint64) (*core.Block, error) {
	return nil, nil
}
func (m *mockNodeBackend) GetProviders() []*node.ProviderInfo                  { return nil }
func (m *mockNodeBackend) GetPerformanceCertificate() *perf.Certificate        { return nil }
func (m *mockNodeBackend) GetCertificateByProvider(provider string) *perf.Certificate {
	return nil
}
func (m *mockNodeBackend) GetCertificateByHash(hash string) *perf.Certificate { return nil }
func (m *mockNodeBackend) CertificateNonces(hash string) []uint64             { return nil }
func (m *mockNodeBackend) CertificateAttestations(hash string) *node.CertificateAttestations {
	return nil
}
func (m *mockNodeBackend) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestPaginateSlice(t *testing.T) {
	items := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	tests := []struct {
		name     string
		offset   int
		limit    int
		expected []int
	}{
		{"offset 0, limit 3", 0, 3, []int{0, 1, 2}},
		{"offset 3, limit 4", 3, 4, []int{3, 4, 5, 6}},
		{"offset 8, limit 5", 8, 5, []int{8, 9}},
		{"offset out of bounds", 15, 5, []int{}},
		{"empty slice", 0, 5, []int{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := items
			if tc.name == "empty slice" {
				input = []int{}
			}
			got := paginateSlice(input, tc.offset, tc.limit)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected len %d, got %d", len(tc.expected), len(got))
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Errorf("at index %d: expected %d, got %d", i, tc.expected[i], got[i])
				}
			}
		})
	}
}

func TestHandleGetPendingPagination(t *testing.T) {
	const testAddr = "xe_test_victim_account"
	pendingList := make([]*core.PendingSend, 10)
	blocksList := make(map[string]*core.Block)

	for i := 0; i < 10; i++ {
		hash := fmt.Sprintf("send_hash_%02d", i)
		pendingList[i] = &core.PendingSend{
			SendHash:    hash,
			Source:      "xe_test_source",
			Destination: testAddr,
			Amount:      uint64(1000 + i),
			Asset:       "XE",
		}
		blocksList[hash] = &core.Block{
			Hash:      hash,
			Timestamp: int64(1700000000 + i),
		}
	}

	mock := &mockNodeBackend{
		pendingMap: map[string][]*core.PendingSend{
			testAddr: pendingList,
		},
		blocksMap: blocksList,
	}

	h := &Handler{node: mock}
	handler := h.Mux()

	type pendingResponse struct {
		Address string         `json:"address"`
		Pending []pendingEntry `json:"pending"`
	}

	// 1. Default pagination (should return all 10 entries since default limit is 100)
	req := httptest.NewRequest("GET", "/pending/"+testAddr, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp pendingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Address != testAddr {
		t.Errorf("expected address %s, got %s", testAddr, resp.Address)
	}
	if len(resp.Pending) != 10 {
		t.Fatalf("expected 10 pending entries, got %d", len(resp.Pending))
	}

	// 2. Limit 2, Offset 0
	req = httptest.NewRequest("GET", "/pending/"+testAddr+"?limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	resp = pendingResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Pending) != 2 {
		t.Fatalf("expected 2 pending entries, got %d", len(resp.Pending))
	}
	if resp.Pending[0].SendHash != "send_hash_00" || resp.Pending[1].SendHash != "send_hash_01" {
		t.Errorf("unexpected hashes: %v, %v", resp.Pending[0].SendHash, resp.Pending[1].SendHash)
	}

	// 3. Limit 3, Offset 4
	req = httptest.NewRequest("GET", "/pending/"+testAddr+"?limit=3&offset=4", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	resp = pendingResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Pending) != 3 {
		t.Fatalf("expected 3 pending entries, got %d", len(resp.Pending))
	}
	if resp.Pending[0].SendHash != "send_hash_04" || resp.Pending[2].SendHash != "send_hash_06" {
		t.Errorf("unexpected hashes: %v, %v", resp.Pending[0].SendHash, resp.Pending[2].SendHash)
	}

	// 4. Offset beyond bounds (Offset 20)
	req = httptest.NewRequest("GET", "/pending/"+testAddr+"?offset=20", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	resp = pendingResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Pending) != 0 {
		t.Fatalf("expected 0 pending entries, got %d", len(resp.Pending))
	}
}
