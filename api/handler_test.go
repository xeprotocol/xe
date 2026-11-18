package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteSubmitError_DeterministicClassification(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedRetry  bool
		expectedErrSub string
	}{
		{
			name:           "Case 1: previous mismatch is HTTP 400 retryable:false",
			err:            fmt.Errorf("previous mismatch: block references 3f681f61... but account frontier is 967416ba..."),
			expectedStatus: http.StatusBadRequest,
			expectedRetry:  false,
			expectedErrSub: "previous mismatch",
		},
		{
			name:           "Case 2: source send not pending is HTTP 400 retryable:false",
			err:            fmt.Errorf("source send not pending: abababababab..."),
			expectedStatus: http.StatusBadRequest,
			expectedRetry:  false,
			expectedErrSub: "source send not pending",
		},
		{
			name:           "Case 3: conflict with finalized block is HTTP 400 retryable:false",
			err:            fmt.Errorf("block conflicts with finalized block deadbeef — rejected"),
			expectedStatus: http.StatusBadRequest,
			expectedRetry:  false,
			expectedErrSub: "block conflicts with finalized block",
		},
		{
			name:           "Case 4: invalid PoW is HTTP 400 retryable:false",
			err:            errors.New("invalid proof of work"),
			expectedStatus: http.StatusBadRequest,
			expectedRetry:  false,
			expectedErrSub: "invalid proof of work",
		},
		{
			name:           "Case 5: feature not yet activated is HTTP 503 retryable:true",
			err:            fmt.Errorf("block type \"burn\" requires feature \"burn\": not yet activated (retry after statechain syncs)"),
			expectedStatus: http.StatusServiceUnavailable,
			expectedRetry:  true,
			expectedErrSub: "not yet activated",
		},
		{
			name:           "Case 6: unresolved conflict pending vote is HTTP 503 retryable:true",
			err:            fmt.Errorf("account has unresolved conflict — block rejected pending resolution"),
			expectedStatus: http.StatusServiceUnavailable,
			expectedRetry:  true,
			expectedErrSub: "unresolved conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeSubmitError(rec, tt.err)

			if rec.Code != tt.expectedStatus {
				t.Fatalf("writeSubmitError status = %d, want %d", rec.Code, tt.expectedStatus)
			}

			var body struct {
				Error     string `json:"error"`
				Retryable bool   `json:"retryable"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode response JSON: %v", err)
			}

			if body.Retryable != tt.expectedRetry {
				t.Errorf("body.Retryable = %v, want %v", body.Retryable, tt.expectedRetry)
			}
			if !strings.Contains(body.Error, tt.expectedErrSub) {
				t.Errorf("body.Error %q does not contain %q", body.Error, tt.expectedErrSub)
			}
			if !strings.Contains(body.Error, "block rejected: ") {
				t.Errorf("body.Error %q missing 'block rejected: ' prefix", body.Error)
			}
		})
	}
}
