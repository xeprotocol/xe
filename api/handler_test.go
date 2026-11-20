package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCleanBlockError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected string
	}{
		{
			name:     "statechain verify chain",
			input:    errors.New("VerifyBlockHash: HashBlock: MarshalCanonical: prev_hash must be 32 bytes, got 0"),
			expected: "prev_hash must be 32 bytes, got 0",
		},
		{
			name:     "ledger verify chain with double verify",
			input:    errors.New("verify: verify: HashBlock: MarshalBlock: previous must be 32 bytes, got 0"),
			expected: "previous must be 32 bytes, got 0",
		},
		{
			name:     "clean error untouched",
			input:    errors.New("insufficient balance for fee"),
			expected: "insufficient balance for fee",
		},
		{
			name:     "single prefix",
			input:    fmt.Errorf("verify: %w", errors.New("bad signature")),
			expected: "bad signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanBlockError(tt.input)
			if got != tt.expected {
				t.Errorf("cleanBlockError() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestWriteSubmitErrorSanitization(t *testing.T) {
	rec := httptest.NewRecorder()
	err := errors.New("VerifyBlockHash: HashBlock: MarshalCanonical: prev_hash must be 32 bytes, got 0")

	writeSubmitError(rec, err)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	expectedMsg := "block rejected: prev_hash must be 32 bytes, got 0"
	if resp["error"] != expectedMsg {
		t.Errorf("expected error %q, got %q", expectedMsg, resp["error"])
	}
	if resp["retryable"] != false {
		t.Errorf("expected retryable false, got %v", resp["retryable"])
	}
}
