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
		"lease already settled",
		"lease not yet expired",
		"lease settle past grace",
		"renew-wins: provider built on",
		"settle-wins: consumer built on",
		"cannot force-settle lease in",
		"lease not renewable in",
		"lease_settle XE mismatch",
	}
	for _, p := range retryablePatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
