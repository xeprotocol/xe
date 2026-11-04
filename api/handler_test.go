package api

import (
	"context"
	"encoding/json"
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

type dummyNodeBackend struct {
	leases []*core.Lease
}

func (d *dummyNodeBackend) GetBalance(account string) uint64                         { return 0 }
func (d *dummyNodeBackend) GetAssetBalances(account string) map[string]uint64        { return nil }
func (d *dummyNodeBackend) GetSpendableBalances(account string) map[string]uint64    { return nil }
func (d *dummyNodeBackend) IsBlockFinalized(account, hash string) bool               { return false }
func (d *dummyNodeBackend) FinalHeight(account string) uint64                        { return 0 }
func (d *dummyNodeBackend) GetKeyset(account string) *core.Keyset                    { return nil }
func (d *dummyNodeBackend) GetReputation(account string) *core.ReputationAggregate   { return nil }
func (d *dummyNodeBackend) GetAllReputations() map[string]*core.ReputationAggregate  { return nil }
func (d *dummyNodeBackend) GetChain(account string) []*core.Block                    { return nil }
func (d *dummyNodeBackend) GetBlock(hash string) *core.Block                         { return nil }
func (d *dummyNodeBackend) GetPending(account string) []*core.PendingSend            { return nil }
func (d *dummyNodeBackend) GetAllPending() []*core.PendingSend                       { return nil }
func (d *dummyNodeBackend) GetFrontiers() map[string]string                          { return nil }
func (d *dummyNodeBackend) GetFrontiersDetailed() []node.FrontierInfo                { return nil }
func (d *dummyNodeBackend) GetAllAccounts() []node.AccountSummary                    { return nil }
func (d *dummyNodeBackend) GetSupply() *core.SupplyReport                            { return nil }
func (d *dummyNodeBackend) GetRecentBlocks(limit int) []*core.Block                  { return nil }
func (d *dummyNodeBackend) SubmitBlock(b *core.Block) error                          { return nil }
func (d *dummyNodeBackend) GetConflicts(account string) []*core.Conflict             { return nil }
func (d *dummyNodeBackend) GetAllConflicts() []*core.Conflict                        { return nil }
func (d *dummyNodeBackend) GetDelegation() *node.DelegationInfo                      { return nil }
func (d *dummyNodeBackend) GetNodeInfo() *node.NodeInfo                              { return nil }
func (d *dummyNodeBackend) GetActivations() *node.ActivationsInfo                    { return nil }
func (d *dummyNodeBackend) GetReadiness() *node.ReadinessInfo                        { return nil }
func (d *dummyNodeBackend) GetLeases() []*core.Lease                                 { return d.leases }
func (d *dummyNodeBackend) GetLeasesByState(state core.LeaseState) []*core.Lease {
	var result []*core.Lease
	for _, l := range d.leases {
		if l.State == state {
			result = append(result, l)
		}
	}
	return result
}
func (d *dummyNodeBackend) GetLease(leaseHash string) *core.Lease                                                   { return nil }
func (d *dummyNodeBackend) GetStateChainTip() *statechain.Block                                                     { return nil }
func (d *dummyNodeBackend) GetStateChainBlock(index uint64) *statechain.Block                                       { return nil }
func (d *dummyNodeBackend) GetStateChainBlocks(start, limit uint64) []*statechain.Block                             { return nil }
func (d *dummyNodeBackend) GetStateChainBlockCount() uint64                                                         { return 0 }
func (d *dummyNodeBackend) GetStateKV(key string) (json.RawMessage, bool)                                           { return nil, false }
func (d *dummyNodeBackend) GetStateKVByPrefix(prefix string) map[string]json.RawMessage                             { return nil }
func (d *dummyNodeBackend) GetAllStateKV() map[string]json.RawMessage                                               { return nil }
func (d *dummyNodeBackend) GetDAOKeyset() *statechain.DAOKeyset                                                     { return nil }
func (d *dummyNodeBackend) SubmitStateChainBlock(b *statechain.Block) error                                         { return nil }
func (d *dummyNodeBackend) SendChat(ctx context.Context, env *chat.Envelope) error                                  { return nil }
func (d *dummyNodeBackend) SendChatMessage(ctx context.Context, to, message string) error                          { return nil }
func (d *dummyNodeBackend) GetChatMessages(account string, since int64) []*chat.Envelope                            { return nil }
func (d *dummyNodeBackend) GetChatAccounts() []string                                                               { return nil }
func (d *dummyNodeBackend) GetChatContacts(account string) []string                                                 { return nil }
func (d *dummyNodeBackend) SubscribeChat() (chan *chat.Envelope, func())                                            { return nil, func() {} }
func (d *dummyNodeBackend) RequestAttestation(source, identifier string) (*core.TimekeeperAttestation, error)       { return nil, nil }
func (d *dummyNodeBackend) RegisterAccount(reg *directory.Registration) error                                       { return nil }
func (d *dummyNodeBackend) ListDirectory() []*directory.Registration                                               { return nil }
func (d *dummyNodeBackend) LookupDirectory(account string) *directory.Registration                                 { return nil }
func (d *dummyNodeBackend) GetVMs() []*vm.Info                                                                      { return nil }
func (d *dummyNodeBackend) GetVM(leaseHash string) *vm.Info                                                        { return nil }
func (d *dummyNodeBackend) RequestAndCreateLease(ctx context.Context, vcpus, mem, disk, dur uint64, pub string) (string, error) {
	return "", nil
}
func (d *dummyNodeBackend) RenewLease(leaseHash string, additionalSecs uint64) (*core.Block, error) {
	return nil, nil
}
func (d *dummyNodeBackend) GetProviders() []*node.ProviderInfo                   { return nil }
func (d *dummyNodeBackend) GetPerformanceCertificate() *perf.Certificate         { return nil }
func (d *dummyNodeBackend) GetCertificateByProvider(provider string) *perf.Certificate { return nil }
func (d *dummyNodeBackend) GetCertificateByHash(hash string) *perf.Certificate   { return nil }
func (d *dummyNodeBackend) CertificateNonces(hash string) []uint64               { return nil }
func (d *dummyNodeBackend) CertificateAttestations(hash string) *node.CertificateAttestations {
	return nil
}
func (d *dummyNodeBackend) OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestHandleGetLeasesInvalidStateIncludesExpired(t *testing.T) {
	backend := &dummyNodeBackend{}
	h := &Handler{node: backend}

	req := httptest.NewRequest(http.MethodGet, "/leases?state=bogus", nil)
	rec := httptest.NewRecorder()

	h.handleGetLeases(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}

	expectedErr := "invalid state: must be one of created, accepted, settled, cancelled, unfulfilled, expired"
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp["error"] != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, resp["error"])
	}
}

func TestHandleGetLeasesExpiredStateFilter(t *testing.T) {
	backend := &dummyNodeBackend{
		leases: []*core.Lease{
			{LeaseHash: "1111", State: core.LeaseCreated},
			{LeaseHash: "2222", State: core.LeaseAccepted},
			{LeaseHash: "3333", State: core.LeaseExpired},
		},
	}
	h := &Handler{node: backend}

	req := httptest.NewRequest(http.MethodGet, "/leases?state=expired", nil)
	rec := httptest.NewRecorder()

	h.handleGetLeases(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp []*core.Lease
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if len(resp) != 1 || resp[0].LeaseHash != "3333" || resp[0].State != core.LeaseExpired {
		t.Errorf("expected 1 expired lease with hash 3333, got %+v", resp)
	}
}
