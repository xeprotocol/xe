package core

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "previous mismatch against frontier (send)",
			err:       fmt.Errorf("previous mismatch: block references 3f681f61... but account frontier is 967416ba..."),
			retryable: false,
		},
		{
			name:      "previous mismatch got/want format",
			err:       fmt.Errorf("previous mismatch: got 3f681f61, want 967416ba"),
			retryable: false,
		},
		{
			name:      "source send not pending (receive replay or nonexistent)",
			err:       fmt.Errorf("source send not pending: abababababab..."),
			retryable: false,
		},
		{
			name:      "staged receive source send not pending",
			err:       fmt.Errorf("staged receive: source send not pending: %s", "deadbeef"),
			retryable: false,
		},
		{
			name:      "conflicts with finalized block",
			err:       fmt.Errorf("block conflicts with finalized block %s — rejected", "c0ffee"),
			retryable: false,
		},
		{
			name:      "frontier mismatch",
			err:       fmt.Errorf("frontier mismatch: chain head changed"),
			retryable: false,
		},
		{
			name:      "unopened account send",
			err:       fmt.Errorf("send from unopened account: 1234"),
			retryable: false,
		},
		{
			name:      "unopened account burn",
			err:       fmt.Errorf("burn from unopened account: 1234"),
			retryable: false,
		},
		{
			name:      "unknown block type",
			err:       fmt.Errorf("unknown block type: foo"),
			retryable: false,
		},
		{
			name:      "certificate not found",
			err:       fmt.Errorf("certificate 1234 not found"),
			retryable: false,
		},
		{
			name:      "lease not found",
			err:       fmt.Errorf("lease not found: 1234"),
			retryable: false,
		},
		{
			name:      "bad signature",
			err:       fmt.Errorf("bad signature: ed25519 verification failed"),
			retryable: false,
		},
		{
			name:      "invalid proof of work",
			err:       errors.New("invalid proof of work"),
			retryable: false,
		},
		{
			name:      "insufficient balance",
			err:       fmt.Errorf("insufficient balance: have 100, sending 200"),
			retryable: false,
		},
		{
			name:      "balance mismatch",
			err:       fmt.Errorf("balance mismatch: expected 90, got 100"),
			retryable: false,
		},
		// Transient conditions that MUST return retryable: true
		{
			name:      "retry after statechain syncs (feature activation)",
			err:       fmt.Errorf("block type \"burn\" requires feature \"burn\": not yet activated (retry after statechain syncs)"),
			retryable: true,
		},
		{
			name:      "cancel-wins provider accept not found locally: retry after sync",
			err:       fmt.Errorf("cancel-wins: provider accept not found locally: retry after sync"),
			retryable: true,
		},
		{
			name:      "lease not yet accepted for settle (state created): retry after accept",
			err:       fmt.Errorf("lease not yet accepted for settle (state created): retry after accept"),
			retryable: true,
		},
		{
			name:      "lease not yet accepted for force-settle: retry after accept",
			err:       fmt.Errorf("lease not yet accepted for force-settle (state created): retry after accept"),
			retryable: true,
		},
		{
			name:      "lease not yet accepted for renewal: retry after accept",
			err:       fmt.Errorf("lease not yet accepted for renewal (state created): retry after accept"),
			retryable: true,
		},
		{
			name:      "epoch not yet available: retry after statechain syncs",
			err:       fmt.Errorf("lease_renew epoch not yet available for time 1000: retry after statechain syncs"),
			retryable: true,
		},
		{
			name:      "account has unresolved conflict",
			err:       fmt.Errorf("account has unresolved conflict — block rejected pending resolution"),
			retryable: true,
		},
		{
			name:      "source send is contested by unresolved conflict",
			err:       fmt.Errorf("source send 1234 is contested by an unresolved conflict — receive deferred pending resolution"),
			retryable: true,
		},
		{
			name:      "storage GetAccountChain transient error",
			err:       fmt.Errorf("GetAccountChain: leveldb: closed"),
			retryable: true,
		},
		{
			name:      "storage GetBlock transient error",
			err:       fmt.Errorf("GetBlock: io timeout"),
			retryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRetryableError(tt.err)
			if got != tt.retryable {
				t.Errorf("IsRetryableError(%v) = %v, want %v", tt.err, got, tt.retryable)
			}
		})
	}
}
