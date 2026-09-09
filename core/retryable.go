package core

import "strings"

func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	retryablePatterns := []string{
		"previous block not found",
		"source send not pending",
		"not found",
		"frontier mismatch",
		"previous mismatch",
		"GetAccountChain",
		"GetBlock",
		"unresolved conflict",
		"Transaction Conflict",
		"lease not yet accepted",
		"epoch not yet available",
		"retry after statechain syncs",
		"retry after sync",
		"unopened account",

		"unknown block type",
		"not yet activated",
	}
	for _, p := range retryablePatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
