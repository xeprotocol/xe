package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/chat"
)

func TestChatPoWDifficulty_Bounds(t *testing.T) {
	tests := []struct {
		name        string
		advertised  string
		expectErr   bool
		errContains string
		expectedVal uint64
	}{
		{
			name:        "valid default difficulty",
			advertised:  "ffffc00000000000",
			expectErr:   false,
			expectedVal: chat.DefaultPoWDifficulty,
		},
		{
			name:        "maximum allowed difficulty",
			advertised:  "ffffff0000000000",
			expectErr:   false,
			expectedVal: chat.MaxPoWDifficulty,
		},
		{
			name:        "difficulty exceeds max allowed",
			advertised:  "ffffffffffffffff",
			expectErr:   true,
			errContains: "exceeds maximum allowable",
		},
		{
			name:        "missing difficulty",
			advertised:  "",
			expectErr:   true,
			errContains: "node advertises no chat_pow_difficulty",
		},
		{
			name:        "malformed hex difficulty",
			advertised:  "not-hex-value",
			expectErr:   true,
			errContains: "invalid syntax",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/node" {
					http.NotFound(w, r)
					return
				}
				resp := map[string]any{}
				if tc.advertised != "" {
					resp["chat_pow_difficulty"] = tc.advertised
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()

			c := New(srv.URL)
			val, err := c.ChatPoWDifficulty()

			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if val != tc.expectedVal {
					t.Fatalf("expected 0x%016x, got 0x%016x", tc.expectedVal, val)
				}
			}
		})
	}
}
