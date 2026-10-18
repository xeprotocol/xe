package api

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/vm"
)

type stubBackend struct {
	vms    []*vm.Info
	leases map[string]*core.Lease
}

func (s *stubBackend) GetBalance(string) uint64                              { return 0 }
func (s *stubBackend) GetAssetBalances(string) map[string]uint64             { return nil }
func (s *stubBackend) GetSpendableBalances(string) map[string]uint64         { return nil }
func (s *stubBackend) IsBlockFinalized(string, string) bool                  { return false }
func (s *stubBackend) FinalHeight(string) uint64                             { return 0 }
func (s *stubBackend) GetKeyset(string) *core.Keyset                         { return nil }
func (s *stubBackend) GetReputation(string) *core.ReputationAggregate        { return nil }
func (s *stubBackend) GetAllReputations() map[string]*core.ReputationAggregate { return nil }
func (s *stubBackend) GetChain(string) []*core.Block                         { return nil }
func (s *stubBackend) GetBlock(string) *core.Block                           { return nil }
func (s *stubBackend) GetPending(string) []*core.PendingSend                 { return nil }
func (s *stubBackend) GetAllPending() []*core.PendingSend                    { return nil }
func (s *stubBackend) GetFrontiers() map[string]string                       { return nil }
func (s *stubBackend) GetFrontiersDetailed() []node.FrontierInfo             { return nil }
func (s *stubBackend) GetAllAccounts() []node.AccountSummary                 { return nil }
func (s *stubBackend) GetSupply() *core.SupplyReport                         { return nil }
func (s *stubBackend) GetRecentBlocks(int) []*core.Block                     { return nil }
func (s *stubBackend) SubmitBlock(*core.Block) error                         { return nil }
func (s *stubBackend) GetConflicts(string) []*core.Conflict                  { return nil }
func (s *stubBackend) GetAllConflicts() []*core.Conflict                     { return nil }
func (s *stubBackend) GetDelegation() *node.DelegationInfo                   { return nil }
func (s *stubBackend) GetNodeInfo() *node.NodeInfo                           { return nil }
func (s *stubBackend) GetActivations() *node.ActivationsInfo                 { return nil }
func (s *stubBackend) GetReadiness() *node.ReadinessInfo                     { return nil }
func (s *stubBackend) GetLeases() []*core.Lease                              { return nil }
func (s *stubBackend) GetLeasesByState(core.LeaseState) []*core.Lease        { return nil }
func (s *stubBackend) GetLease(h string) *core.Lease                         { return s.leases[h] }
func (s *stubBackend) GetStateChainTip() *statechain.Block                   { return nil }
func (s *stubBackend) GetStateChainBlock(uint64) *statechain.Block           { return nil }
func (s *stubBackend) GetStateChainBlocks(uint64, uint64) []*statechain.Block { return nil }
func (s *stubBackend) GetStateChainBlockCount() uint64                       { return 0 }
func (s *stubBackend) GetStateKV(string) (json.RawMessage, bool)             { return nil, false }
func (s *stubBackend) GetStateKVByPrefix(string) map[string]json.RawMessage  { return nil }
func (s *stubBackend) GetAllStateKV() map[string]json.RawMessage             { return nil }
func (s *stubBackend) GetDAOKeyset() *statechain.DAOKeyset                   { return nil }
func (s *stubBackend) SubmitStateChainBlock(*statechain.Block) error         { return nil }
func (s *stubBackend) SendChat(context.Context, *chat.Envelope) error        { return nil }
func (s *stubBackend) SendChatMessage(context.Context, string, string) error { return nil }
func (s *stubBackend) GetChatMessages(string, int64) []*chat.Envelope        { return nil }
func (s *stubBackend) GetChatAccounts() []string                             { return nil }
func (s *stubBackend) GetChatContacts(string) []string                       { return nil }
func (s *stubBackend) SubscribeChat() (chan *chat.Envelope, func())          { return nil, func() {} }
func (s *stubBackend) RequestAttestation(string, string) (*core.TimekeeperAttestation, error) {
	return nil, nil
}
func (s *stubBackend) RegisterAccount(*directory.Registration) error { return nil }
func (s *stubBackend) ListDirectory() []*directory.Registration      { return nil }
func (s *stubBackend) LookupDirectory(string) *directory.Registration { return nil }
func (s *stubBackend) GetVMs() []*vm.Info                            { return s.vms }
func (s *stubBackend) GetVM(h string) *vm.Info {
	for _, v := range s.vms {
		if v.LeaseHash == h {
			return v
		}
	}
	return nil
}
func (s *stubBackend) RequestAndCreateLease(context.Context, uint64, uint64, uint64, uint64, string) (string, error) {
	return "", nil
}
func (s *stubBackend) RenewLease(string, uint64) (*core.Block, error)     { return nil, nil }
func (s *stubBackend) GetProviders() []*node.ProviderInfo                 { return nil }
func (s *stubBackend) GetPerformanceCertificate() *perf.Certificate       { return nil }
func (s *stubBackend) GetCertificateByProvider(string) *perf.Certificate  { return nil }
func (s *stubBackend) GetCertificateByHash(string) *perf.Certificate      { return nil }
func (s *stubBackend) CertificateNonces(string) []uint64                  { return nil }
func (s *stubBackend) CertificateAttestations(string) *node.CertificateAttestations {
	return nil
}
func (s *stubBackend) OpenTunnelForLease(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, nil
}

func TestVMEndpointsRequireAdminAuth(t *testing.T) {
	leaseHash := strings.Repeat("a", 64)
	backend := &stubBackend{
		vms: []*vm.Info{
			{
				LeaseHash: leaseHash,
				Status:    "running",
				Credentials: &vm.Credentials{
					Username: "xe-aaaaaa",
					Password: "super-secret-password",
				},
			},
		},
	}

	h := &Handler{
		node:       backend,
		adminToken: "secret-admin-token",
	}
	mux := h.Mux()

	// 1. Unauthenticated GET /vms and GET /vms/{lease} must return 401 Unauthorized
	for _, path := range []string{"/vms", "/vms/" + leaseHash} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated GET %s returned %d, want %d; body=%s", path, rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "super-secret-password") {
			t.Fatalf("unauthenticated GET %s leaked VM password", path)
		}
	}

	// 2. Authenticated GET /vms and GET /vms/{lease} with valid admin bearer token succeed
	for _, path := range []string{"/vms", "/vms/" + leaseHash} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer secret-admin-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("authenticated GET %s returned %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

func TestHandleTunnelTCPRejectsExpiredLease(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	leaseHash := strings.Repeat("b", 64)
	startTime := time.Now().Add(-2 * time.Hour).UnixNano()

	backend := &stubBackend{
		leases: map[string]*core.Lease{
			leaseHash: {
				LeaseHash:    leaseHash,
				State:        core.LeaseAccepted,
				Duration:     3600,
				StartTime:    startTime,
				AccessPubKey: kp.PubKeyHex(),
			},
		},
	}

	h := &Handler{node: backend}
	mux := h.Mux()

	hashBytes, _ := core.DecodeHash(leaseHash)
	sig := hex.EncodeToString(ed25519.Sign(kp.Private, hashBytes))

	req := httptest.NewRequest(http.MethodPost, "/tunnel/"+leaseHash+"/tcp", nil)
	req.Header.Set("X-Signature", sig)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("POST /tunnel/{lease}/tcp for expired lease returned %d, want 410 Gone; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "lease expired") {
		t.Fatalf("expected 'lease expired' error message, got: %s", rec.Body.String())
	}
}
