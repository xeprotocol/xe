package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestGetChainHTTPErrorStatus(t *testing.T) {
	// Server returns 429 Too Many Requests with JSON error body
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limited"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	chain, err := c.GetChain("test_account")
	if err == nil {
		t.Fatalf("expected error for HTTP 429, got nil (blocks=%d)", len(chain))
	}
	if chain != nil {
		t.Fatalf("expected nil chain on error, got %v", chain)
	}
}

func TestGetChainServerError500(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal node error"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	chain, err := c.GetChain("test_account")
	if err == nil {
		t.Fatalf("expected error for HTTP 500, got nil")
	}
	if chain != nil {
		t.Fatalf("expected nil chain on error, got %v", chain)
	}
}

func TestGetBalancesHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limited"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	bals, err := c.GetBalances("test_account")
	if err == nil {
		t.Fatalf("expected error for HTTP 429, got nil (balances=%v)", bals)
	}
	if bals != nil {
		t.Fatalf("expected nil balances on error, got %v", bals)
	}
}

func TestGetPendingHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "service unavailable"})
	}))
	defer ts.Close()

	c := New(ts.URL)
	pending, err := c.GetPending("test_account")
	if err == nil {
		t.Fatalf("expected error for HTTP 503, got nil")
	}
	if pending != nil {
		t.Fatalf("expected nil pending on error, got %v", pending)
	}
}

func TestGetChainSuccess200(t *testing.T) {
	mockBlock := &core.Block{
		Hash:    "deadbeef",
		Account: "test_account",
		Type:    core.BlockSend,
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"blocks": []*core.Block{mockBlock},
			"total":  1,
		})
	}))
	defer ts.Close()

	c := New(ts.URL)
	chain, err := c.GetChain("test_account")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 || chain[0].Hash != "deadbeef" {
		t.Fatalf("unexpected chain: %v", chain)
	}
}
