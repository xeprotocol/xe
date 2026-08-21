package core

// spendable.go — settlement surfaces honor finalization (#528), epic #529.
//
// "Money is real" ⇔ finalized. Spendable balance counts only finalized inflows,
// so consumers (wallets, services) never treat funds that could still be reorged
// away as available. This is the read-side contract that makes the finalization
// machinery (#525–#527) actually protect settlement.

// FinalizedFrontier returns the hash of the account's highest finalized block, or
// "" if nothing on the account is finalized yet. (#528)
func (l *Ledger) FinalizedFrontier(account string) string {
	fh := l.FinalHeight(account)
	if fh == 0 {
		return ""
	}
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil || int(fh) > len(chain.Blocks) {
		return ""
	}
	return chain.Blocks[fh-1].Hash // 1-based watermark
}

// SpendableBalances returns per-asset balances as of the account's highest
// finalized block — funds that are irreversible and safe to spend. Unfinalized
// inflows are excluded; an account with nothing finalized has no spendable
// balance. (#528)
func (l *Ledger) SpendableBalances(account string) map[string]uint64 {
	out := make(map[string]uint64)
	fh := l.FinalHeight(account)
	if fh == 0 {
		return out
	}
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return out
	}
	limit := int(fh)
	if limit > len(chain.Blocks) {
		limit = len(chain.Blocks)
	}
	// Per asset, spendable starts at the balance recorded at the final-height
	// watermark (the finalized snapshot). Blocks above the watermark are not yet
	// irreversible, but they are not symmetric: an unfinalized INFLOW could still
	// be reorged away, so it is excluded (it sits above the snapshot and is never
	// added). An unfinalized OUTFLOW, by contrast, is already committed on the
	// account's own chain and has debited the live balance — so it must reduce
	// spendable too. Otherwise spendable reports the stale, higher pre-send
	// snapshot and can exceed the live balance, overstating funds in the unsafe
	// direction (#551). Equivalent to: live balance minus unfinalized inflows.
	prev := make(map[string]uint64)
	for i := 0; i < len(chain.Blocks); i++ {
		b := chain.Blocks[i]
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if i < limit {
			out[a] = b.Balance // finalized snapshot
		} else if b.Balance < prev[a] {
			// committed but unfinalized outflow — subtract it from spendable
			outflow := prev[a] - b.Balance
			if out[a] >= outflow {
				out[a] -= outflow
			} else {
				out[a] = 0
			}
		}
		prev[a] = b.Balance
	}
	return out
}
