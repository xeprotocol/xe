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

type mockRecentBlocksBackend struct {
	blocks []*core.Block
}

func (m *mockRecentBlocksBackend) GetBalance(account string) uint64                       { return 0 }
func (m *mockRecentBlocksBackend) GetAssetBalances(account string) map[string]uint64      { return nil }
func (m *mockRecentBlocksBackend) GetSpendableBalances(account string) map[string]uint64  { return nil }
func (m *mockRecentBlocksBackend) IsBlockFinalized(account, hash string) bool             { return true }
func (m *mockRecentBlocksBackend) FinalHeight(account string) uint64                      { return 0 }
func (m *mockRecentBlocksBackend) GetKeyset(account string) *core.Keyset                  { return nil }
func (m *mockRecentBlocksBackend) GetReputation(account string) *core.ReputationAggregate { return nil }
func (m *mockRecentBlocksBackend) GetAllReputations() map[string]*core.ReputationAggregate {
	return nil
}
func (m *mockRecentBlocksBackend) GetChain(account string) []*core.Block       { return nil }
func (m *mockRecentBlocksBackend) GetBlock(hash string) *core.Block            { return nil }
func (m *mockRecentBlocksBackend) GetPending(account string) []*core.PendingSend { return nil }
func (m *mockRecentBlocksBackend) GetAllPending() []*core.PendingSend           { return nil }
func (m *mockRecentBlocksBackend) GetFrontiers() map[string]string              { return nil }
func (m *mockRecentBlocksBackend) GetFrontiersDetailed() []node.FrontierInfo    { return nil }
func (m *mockRecentBlocksBackend) GetAllAccounts() []node.AccountSummary        { return nil }
func (m *mockRecentBlocksBackend) GetSupply() *core.SupplyReport                { return nil }
func (m *mockRecentBlocksBackend) GetRecentBlocks(limit int) []*core.Block {
	if len(m.blocks) > limit {
		return m.blocks[:limit]
	}
	return m.blocks
}
func (m *mockRecentBlocksBackend) SubmitBlock(b *core.Block) error              { return nil }
func (m *mockRecentBlocksBackend) GetConflicts(account string) []*core.Conflict { return nil }
func (m *mockRecentBlocksBackend) GetAllConflicts() []*core.Conflict            { return nil }
func (m *mockRecentBlocksBackend) GetDelegation() *node.DelegationInfo          { return nil }
func (m *mockRecentBlocksBackend) GetNodeInfo() *node.NodeInfo                  { return &node.NodeInfo{} }
func (m *mockRecentBlocksBackend) GetActivations() *node.ActivationsInfo        { return nil }
func (m *mockRecentBlocksBackend) GetReadiness() *node.ReadinessInfo            { return nil }
func (m *mockRecentBlocksBackend) GetLeases() []*core.Lease                     { return nil }
func (m *mockRecentBlocksBackend) GetLeasesByState(state core.LeaseState) []*core.Lease {
	return nil
}
func (m *mockRecentBlocksBackend) GetLease(leaseHash string) *core.Lease              { return nil }
func (m *mockRecentBlocksBackend) GetStateChainTip() *statechain.Block                { return nil }
func (m *mockRecentBlocksBackend) GetStateChainBlock(index uint64) *statechain.Block  { return nil }
func (m *mockRecentBlocksBackend) GetStateChainBlocks(start, limit uint64) []*statechain.Block {
	return nil
}
func (m *mockRecentBlocksBackend) GetStateChainBlockCount() uint64                      { return 0 }
func (m *mockRecentBlocksBackend) GetStateKV(key string) (json.RawMessage, bool)        { return nil, false }
func (m *mockRecentBlocksBackend) GetStateKVByPrefix(prefix string) map[string]json.RawMessage {
	return nil
}
func (m *mockRecentBlocksBackend) GetAllStateKV() map[string]json.RawMessage { return nil }
func (m *mockRecentBlocksBackend) GetDAOKeyset() *statechain.DAOKeyset        { return nil }
func (m *mockRecentBlocksBackend) SubmitStateChainBlock(b *statechain.Block) error {
	return nil
}
func (m *mockRecentBlocksBackend) SendChat(ctx context.Context, env *chat.Envelope) error {
	return nil
}
func (m *mockRecentBlocksBackend) SendChatMessage(ctx context.Context, to, message string) error {
	return nil
}
func (m *mockRecentBlocksBackend) GetChatMessages(account string, since int64) []*chat.Envelope {
	return nil
}
func (m *mockRecentBlocksBackend) GetChatAccounts() []string                    { return nil }
func (m *mockRecentBlocksBackend) GetChatContacts(account string) []string      { return nil }
func (m *mockRecentBlocksBackend) SubscribeChat() (chan *chat.Envelope, func()) { return nil, func() {} }
func (m *mockRecentBlocksBackend) RequestAttestation(source, identifier string) (*core.TimekeeperAttestation, error) {
	return nil, nil
}
func (m *mockRecentBlocksBackend) RegisterAccount(reg *directory.Registration) error { return nil }
func (m *mockRecentBlocksBackend) ListDirectory() []*directory.Registration          { return nil }
func (m *mockRecentBlocksBackend) LookupDirectory(account string) *directory.Registration {
	return nil
}
func (m *mockRecentBlocksBackend) GetVMs() []*vm.Info             { return nil }
func (m *mockRecentBlocksBackend) GetVM(leaseHash string) *vm.Info { return nil }
func (m *mockRecentBlocksBackend) RequestAndCreateLease(ctx context.Context, vcpus, memoryMB, diskGB, duration uint64, accessPubKey string) (string, error) {
	return "", nil
}
func (m *mockRecentBlocksBackend) RenewLease(leaseHash string, additionalSecs uint64) (*core.Block, error) {
	return nil, nil
}
func (m *mockRecentBlocksBackend) GetProviders() []*node.ProviderInfo                  { return nil }
func (m *mockRecentBlocksBackend) GetPerformanceCertificate() *perf.Certificate        { return nil }
func (m *mockRecentBlocksBackend) GetCertificateByProvider(provider string) *perf.Certificate {
	return nil
}
func (m *mockRecentBlocksBackend) GetCertificateByHash(hash string) *perf.Certificate { return nil }
func (m *mockRecentBlocksBackend) CertificateNonces(hash string) []uint64             { return nil }
func (m *mockRecentBlocksBackend) CertificateAttestations(hash string) *node.CertificateAttestations {
	return nil
}
func (m *mockRecentBlocksBackend) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestHandleGetRecentBlocksPagination(t *testing.T) {
	sampleBlocks := make([]*core.Block, 10)
	for i := 0; i < 10; i++ {
		sampleBlocks[i] = &core.Block{
			Hash:      fmt.Sprintf("block_hash_%02d", i),
			Timestamp: int64(1700000000 + i*10),
		}
	}

	mock := &mockRecentBlocksBackend{blocks: sampleBlocks}
	h := &Handler{node: mock}
	handler := h.Mux()

	// 1. Default request without offset or limit
	req := httptest.NewRequest("GET", "/blocks/recent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var res []*core.Block
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling response: %v", err)
	}
	if len(res) != 10 {
		t.Fatalf("expected 10 blocks, got %d", len(res))
	}

	// 2. Limit 2, Offset 0
	req = httptest.NewRequest("GET", "/blocks/recent?limit=2&offset=0", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	res = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling response: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(res))
	}
	if res[0].Hash != "block_hash_00" || res[1].Hash != "block_hash_01" {
		t.Errorf("unexpected block hashes: %v, %v", res[0].Hash, res[1].Hash)
	}

	// 3. Limit 3, Offset 3
	req = httptest.NewRequest("GET", "/blocks/recent?limit=3&offset=3", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	res = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling response: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(res))
	}
	if res[0].Hash != "block_hash_03" || res[2].Hash != "block_hash_05" {
		t.Errorf("unexpected block hashes: %v, %v", res[0].Hash, res[2].Hash)
	}

	// 4. Offset beyond available blocks
	req = httptest.NewRequest("GET", "/blocks/recent?offset=50", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	res = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling response: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(res))
	}

	// 5. Since parameter combined with offset and limit
	// Blocks have timestamps 1700000000, 1700000010, 1700000020, ...
	// Since 1700000030 gives blocks 4..9 (6 blocks)
	// Offset 1, Limit 2 should give blocks 5 and 6
	req = httptest.NewRequest("GET", "/blocks/recent?since=1700000030&offset=1&limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	res = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling response: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(res))
	}
	if res[0].Hash != "block_hash_05" || res[1].Hash != "block_hash_06" {
		t.Errorf("unexpected block hashes: %v, %v", res[0].Hash, res[1].Hash)
	}
}
