package core

func (l *Ledger) FinalizedFrontier(account string) string {
	fh := l.FinalHeight(account)
	if fh == 0 {
		return ""
	}
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil || int(fh) > len(chain.Blocks) {
		return ""
	}
	return chain.Blocks[fh-1].Hash
}

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

	prev := make(map[string]uint64)
	for i := 0; i < len(chain.Blocks); i++ {
		b := chain.Blocks[i]
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if i < limit {
			out[a] = b.Balance
		} else if b.Balance < prev[a] {

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
