package core

import "strings"

// IsRetryableError reports whether an error represents a transient condition
// that may succeed if the same block is resubmitted later (e.g. pending sync,
// unactivated feature awaiting statechain epoch, or unresolved vote conflict).
// Deterministic validation failures (previous mismatch against frontier,
// source send not pending, conflicts with finalized blocks, signature or balance
// failures) are permanent and are never retryable.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()

	// Deterministic validation failures are permanent: resubmitting the identical
	// block will never succeed and must return HTTP 400 Bad Request (retryable: false).
	deterministicPatterns := []string{
		"previous mismatch",
		"frontier mismatch",
		"source send not pending",
		"conflicts with finalized block",
		"unopened account",
		"unknown block type",
		"invalid proof of work",
		"bad signature",
		"signature verification failed",
		"insufficient balance",
		"cannot send to self",
		"balance mismatch",
	}
	for _, p := range deterministicPatterns {
		if strings.Contains(msg, p) {
			return false
		}
	}

	// Genuinely transient conditions where retrying the block once dependencies
	// land or epochs advance is valid.
	retryablePatterns := []string{
		"retry after statechain syncs",
		"retry after sync",
		"retry after accept",
		"lease not yet accepted",
		"epoch not yet available",
		"not yet activated",
		"unresolved conflict",
		"Transaction Conflict",
		"GetAccountChain",
		"GetBlock",
	}
	for _, p := range retryablePatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
