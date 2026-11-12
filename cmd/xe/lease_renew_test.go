package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func captureOutput(f func()) string {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()

	_ = w.Close()
	os.Stdout = oldStdout
	out := <-outC
	_ = r.Close()
	return out
}

func TestCmdLeaseRenewCostFormatting(t *testing.T) {
	testCases := []struct {
		name         string
		cost         uint64
		expectedCost string
	}{
		{
			name:         "micro XUSD formatted to decimal",
			cost:         40000,
			expectedCost: "0.04 XUSD",
		},
		{
			name:         "whole XUSD formatted without trailing zeros",
			cost:         1000000,
			expectedCost: "1 XUSD",
		},
		{
			name:         "fractional XUSD with mixed digits",
			cost:         1500000,
			expectedCost: "1.5 XUSD",
		},
		{
			name:         "zero cost",
			cost:         0,
			expectedCost: "0 XUSD",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if !strings.HasPrefix(r.URL.Path, "/lease/") || !strings.HasSuffix(r.URL.Path, "/renew") {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				if r.Header.Get("Authorization") != "Bearer test-operator-token" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				resp := map[string]any{
					"renew_hash": "renewblock0123456789abcdef",
					"lease_hash": "leaseblock0123456789abcdef",
					"cost":       tc.cost,
					"duration":   3600,
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			oldNode := os.Getenv("XE_NODE")
			oldToken := os.Getenv("XE_API_ADMIN_TOKEN")
			t.Cleanup(func() {
				_ = os.Setenv("XE_NODE", oldNode)
				_ = os.Setenv("XE_API_ADMIN_TOKEN", oldToken)
			})

			_ = os.Setenv("XE_NODE", server.URL)
			_ = os.Setenv("XE_API_ADMIN_TOKEN", "test-operator-token")

			out := captureOutput(func() {
				cmdLeaseRenew("leaseblock0123456789abcdef", "3600")
			})

			if !strings.Contains(out, tc.expectedCost) {
				t.Fatalf("expected output to contain %q, but got: %s", tc.expectedCost, out)
			}

			// Ensure raw micro amount (e.g. 40000 XUSD) is not printed when cost is 40000
			if tc.cost == 40000 && strings.Contains(out, "40000 XUSD") {
				t.Fatalf("output still contains unformatted micro amount '40000 XUSD': %s", out)
			}
		})
	}
}

func TestRenewCostFormatAmountDirect(t *testing.T) {
	// Directly verify core.FormatAmount with AssetXUSD matches expectations
	if got := core.FormatAmount(40000, core.AssetXUSD); got != "0.04" {
		t.Fatalf("FormatAmount(40000, AssetXUSD) = %q, want %q", got, "0.04")
	}
	if got := core.FormatAmount(1000000, core.AssetXUSD); got != "1" {
		t.Fatalf("FormatAmount(1000000, AssetXUSD) = %q, want %q", got, "1")
	}
	if got := core.FormatAmount(1, core.AssetXUSD); got != "0.000001" {
		t.Fatalf("FormatAmount(1, AssetXUSD) = %q, want %q", got, "0.000001")
	}
}
