package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetProvidersPropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintln(w, "internal server error")
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.GetProviders(); err == nil {
		t.Fatalf("expected error on HTTP 500 from /providers, got nil")
	}
	if _, err := c.GetVM("abcd"); err == nil {
		t.Fatalf("expected error on HTTP 500 from /vms/abcd, got nil")
	}
	if _, err := c.GetLease("abcd"); err == nil {
		t.Fatalf("expected error on HTTP 500 from /leases/abcd, got nil")
	}
}

func TestChatPoWDifficultyRejectsExcessiveDifficulty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"chat_pow_difficulty":"fffffffffffffff0"}`)
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.ChatPoWDifficulty(); err == nil {
		t.Fatalf("expected ChatPoWDifficulty to reject near-maximum difficulty fffffffffffffff0")
	}
}
