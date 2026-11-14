package core

import "strings"

func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	nonRetryablePatterns := []string{
		"unopened account",
		"has no declared public key",
		"previous cannot be 0",
		"cannot open an account",
		"open block must declare pub_key",
		"non-open block must not declare pub_key",
		"multisig block must not declare pub_key",
		"first block must have previous=0",
		"first block on account must have previous=0",
		"multisig_open must have previous=0",
		"multisig_open: account already exists",
		"multisig_update: account not found",
		"account is not multisig",
		"previous mismatch: got 0,",
		"previous mismatch: got 000000000000",
	}
	for _, p := range nonRetryablePatterns {
		if strings.Contains(msg, p) {
			return false
		}
	}
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
