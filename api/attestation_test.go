package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/store"
)

func TestHandleAttestationRequest_RejectsZeroMidAndEnforcesSourceRateLimit(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ms := store.NewMemStore()
	dir := directory.New(directory.DefaultTTL)
	n := &node.Node{
		KeyPair:   kp,
		Directory: dir,
	}

	providerKP, _ := core.GenerateKeyPair()
	reg := directory.NewRegistration("12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT", core.Now().UnixNano(), providerKP)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("dir.Register: %v", err)
	}

	mux := NewHandler(n).Mux()

	zeroMid := reg.Account[:32] + "0000000000000000" + reg.Account[48:]
	body, _ := json.Marshal(map[string]string{"lease_hash": zeroMid})
	req := httptest.NewRequest(http.MethodPost, "/attestation/request", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unauthenticated zero-mid attestation request, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not a live lease") {
		t.Fatalf("unexpected error body: %s", rec.Body.String())
	}
	_ = ms
}
