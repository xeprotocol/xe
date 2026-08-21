package core

import (
	"fmt"
	"strings"
)

// MinterConfig is the set of accounts authorized to mint XUSD. It is published
// on the state chain under sys.minter (like sys.timekeepers / sys.oracle) and
// read by the ledger at block-apply time via LedgerConfig.MinterConfigFn.
//
// Each entry is an ACCOUNT ADDRESS, and this is the one sys.* set for which that
// is true (#829). isMinter compares an entry against a block's Account field, so
// the set names *who may mint*, an identity — whereas sys.dao_keyset,
// sys.timekeepers and sys.oracle name *verifying keys*, because their entries
// are matched against signatures. Before #829 the two forms were the same 64-hex
// string and the distinction was invisible; now an address is
// sha256("xe/account/v1" || pubkey) and putting a raw public key here would
// authorize nobody. The minter account may itself be a multisig account, in
// which case its keyset's threshold is enforced by the normal multisig path
// (mint is a spending op — see IsSpendingOp).
type MinterConfig struct {
	Keys []string `json:"keys"` // account addresses authorized to mint XUSD
}

// isMinter reports whether account is an authorized XUSD minter per the current
// sys.minter config. Returns false when no minter is configured (e.g. a genesis
// without sys.minter), which makes every mint unauthorized — the safe default.
func (l *Ledger) isMinter(account string) bool {
	if l.minterConfigFn == nil {
		return false
	}
	cfg := l.minterConfigFn()
	if cfg == nil {
		return false
	}
	for _, k := range cfg.Keys {
		if strings.EqualFold(k, account) {
			return true
		}
	}
	return false
}

// validateAndAddMint validates an authorized XUSD mint block and applies it.
//
// Mint is the value-creation counterpart to burn: it credits newly created XUSD
// to a sys-registered minter account, with no counterparty, no destination, and
// no pending entry. The minter then distributes XUSD via ordinary send → receive
// (the faucet and, later, the bridge both work this way).
//
// Unlike the removed permissionless faucet claim (#519/#557), mint is reached
// through the normal AddBlock path — signature/PoW/timestamp/duplicate checks and
// conflict detection all run before this function, and on success fireBlockAdded
// drives finalization. There is no addBlockLocked shortcut. A cross-node mint race
// off the same (account, previous) is therefore detected and resolved like any
// other equivocation, which is the defect that made the claim block exploitable
// (#554/#556).
//
// XUSD-only by design: XE supply is fixed at genesis plus lease emission and must
// not be mintable by any wallet.
func (l *Ledger) validateAndAddMint(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("mint: restricted to XUSD")
	}
	if !l.isMinter(b.Account) {
		return fmt.Errorf("mint: account %s is not an authorized minter", shortAddr(b.Account))
	}
	if b.Destination != "" || b.Source != "" {
		return fmt.Errorf("mint: must not have source or destination")
	}
	if b.Memo != "" {
		return fmt.Errorf("mint: memo not allowed")
	}
	if b.Amount == 0 {
		return fmt.Errorf("mint: amount must be > 0")
	}

	// Overlay-aware reads (#622/#643): when a conflict promotion is re-applying
	// a MINT winner, the account's chain and balance are the not-yet-committed
	// post-undo overlay values — the live store still has the loser as the
	// frontier. Reading the store directly here (the pre-#643 bug; mint.go was
	// missed by the #639 sweep over ledger.go) made every mint-winner promotion
	// fail `previous mismatch` and retry forever, freezing the account behind
	// the unresolved-conflict guard.
	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		// First block on the minter's chain opens it with previous=0.
		if b.Previous != "0" {
			return fmt.Errorf("mint: first block must have previous=0")
		}
		if b.Balance != b.Amount {
			return fmt.Errorf("mint: balance mismatch: expected %d, got %d", b.Amount, b.Balance)
		}
	} else {
		if b.Previous != chain.Frontier() {
			return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
		}
		if len(chain.Blocks) > 0 {
			lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
			if b.Timestamp < lastTs {
				return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
			}
		}
		oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
		expected := oldBal + b.Amount
		if expected < oldBal {
			return fmt.Errorf("mint: balance would overflow uint64")
		}
		if b.Balance != expected {
			return fmt.Errorf("mint: balance mismatch: expected %d, got %d", expected, b.Balance)
		}
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	return l.commitBlockWrite(commit, prevBalance)
}
