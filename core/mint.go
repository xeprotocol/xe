package core

import (
	"fmt"
	"strings"
)

type MinterConfig struct {
	Keys []string `json:"keys"`
}

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

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {

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
