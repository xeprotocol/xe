package core

import "strings"

// IsRetryableError reports whether err may resolve on a subsequent attempt —
// either because of a missing dependency (e.g. a receive arriving before its
// source send) or a transient race (e.g. parallel sync delivering the same
// chain). It uses an allowlist so a permanently invalid block (bad signature,
// PoW, structural/value validation) is never retried.
//
// This is the single source of truth for the "transient/dependency vs
// deterministic-terminal" distinction. The sync path uses it to decide
// quarantine-vs-retry, and conflict promotion uses it to decide whether a
// winner that failed full validation may be quarantined (#673): only a
// DETERMINISTIC failure (IsRetryableError==false) is identical on every node
// that holds the dependencies, so only those are safe to quarantine without
// risking divergent winner substitution across nodes. Keeping one classifier
// (rather than a second, hand-synced copy) is deliberate — drifting copies are
// exactly the footgun that produced #673.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	retryablePatterns := []string{
		"previous block not found",     // block's Previous not yet in chain
		"source send not pending",      // receive arrived before send
		"not found",                    // generic dependency missing
		"frontier mismatch",            // chain tip changed between attempts
		"previous mismatch",            // cross-peer race: another goroutine advanced the frontier
		"GetAccountChain",              // transient store error
		"GetBlock",                     // transient store error
		"unresolved conflict",          // account locked during conflict resolution
		"Transaction Conflict",         // badger txn conflict — explicitly self-describes as retryable
		"lease not yet accepted",       // #497: settle/force-settle arrived before its lease_accept on OOO sync
		"epoch not yet available",      // #570/M1: accept arrived before the epoch@accept synced on this node
		"retry after statechain syncs", // #601: synced accept's locked params can't be verified yet (epoch history behind)
		"retry after sync",             // #570/C3b: cancel-wins deferred (provider accept not yet present / chain busy)
		"unopened account",             // #630/#846: a block arrived before the opening block that declares its credential (single-key pub_key, or multisig keyset) on OOO sync

		// #830 — version skew, not invalidity. Both of these say "this BINARY,
		// at this state-chain height, cannot judge the block", which is exactly
		// what C7 forbids quarantining on: the verdict is not identical on
		// every node holding the dependencies, so quarantining it would let a
		// stale node permanently blocklist a block the network accepted and
		// freeze the account chain behind it (#501's "never permanently
		// quarantine a majority-accepted block"). Cost, stated plainly: junk
		// with an invented type is retried each sync round instead of being
		// quarantined after the first. It is bounded — such a block still has
		// to carry a valid hash and proof of work to reach the ledger, the
		// retry loop breaks on the first no-progress pass (#846), and it
		// never enters state.
		"unknown block type", // a type introduced by a LATER binary than this one
		"not yet activated",  // a type this binary knows, gated by sys.activations
	}
	for _, p := range retryablePatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
