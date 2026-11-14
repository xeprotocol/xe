package core_test

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestStructurallyImpossibleBlocksAreNotRetryable(t *testing.T) {
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	unopenedKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	destKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	fakePrev := strings.Repeat("a", 64)
	zeroHash64 := strings.Repeat("0", 64)

	// 1. Non-open block (send, burn, lease) for an unopened account without declared pub_key.
	for _, tc := range []struct {
		name  string
		block *core.Block
	}{
		{
			name: "send from unopened account without pub_key",
			block: &core.Block{
				Type:           core.BlockSend,
				Asset:          "XE",
				Account:        unopenedKP.Address(),
				Previous:       fakePrev,
				Balance:        0,
				Destination:    destKP.Address(),
				Amount:         100,
				Representative: unopenedKP.Address(),
				Timestamp:      core.Now().UnixNano(),
			},
		},
		{
			name: "burn from unopened account without pub_key",
			block: &core.Block{
				Type:           core.BlockBurn,
				Asset:          "XE",
				Account:        unopenedKP.Address(),
				Previous:       fakePrev,
				Balance:        0,
				Amount:         100,
				Representative: unopenedKP.Address(),
				Timestamp:      core.Now().UnixNano(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := core.SignBlock(tc.block, unopenedKP); err != nil {
				t.Fatalf("SignBlock: %v", err)
			}
			err := ledger.AddBlock(tc.block)
			if err == nil {
				t.Fatalf("expected AddBlock to reject %s, got nil", tc.name)
			}
			if core.IsRetryableError(err) {
				t.Fatalf("expected non-retryable error for %s, but IsRetryableError(%q) = true", tc.name, err)
			}
		})
	}

	// Seed an opened account with an initial chain.
	openedKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	seedMint := &core.Block{
		Type:           core.BlockMint,
		Asset:          "XE",
		Account:        openedKP.Address(),
		Previous:       "0",
		Balance:        10_000,
		Amount:         10_000,
		Representative: openedKP.Address(),
		Timestamp:      core.Now().UnixNano(),
		PubKey:         openedKP.PubKeyHex(),
	}
	if err := core.SignBlock(seedMint, openedKP); err != nil {
		t.Fatalf("SignBlock seedMint: %v", err)
	}
	if err := ledger.SeedAssetForTesting(seedMint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	// 2. Any block with previous = "0" or 64-zero hex when the account already has a chain.
	for _, tc := range []struct {
		name  string
		block *core.Block
	}{
		{
			name: "send with previous=0 on existing account",
			block: &core.Block{
				Type:           core.BlockSend,
				Asset:          "XE",
				Account:        openedKP.Address(),
				Previous:       "0",
				Balance:        9_000,
				Destination:    destKP.Address(),
				Amount:         1_000,
				Representative: openedKP.Address(),
				Timestamp:      core.Now().UnixNano() + 1,
			},
		},
		{
			name: "send with previous=0000...0000 and no pub_key on existing account",
			block: &core.Block{
				Type:           core.BlockSend,
				Asset:          "XE",
				Account:        openedKP.Address(),
				Previous:       zeroHash64,
				Balance:        9_000,
				Destination:    destKP.Address(),
				Amount:         1_000,
				Representative: openedKP.Address(),
				Timestamp:      core.Now().UnixNano() + 2,
			},
		},
		{
			name: "receive with previous=0 and declared pub_key on existing account",
			block: &core.Block{
				Type:           core.BlockReceive,
				Asset:          "XE",
				Account:        openedKP.Address(),
				Previous:       "0",
				Balance:        11_000,
				Source:         fakePrev,
				Representative: openedKP.Address(),
				Timestamp:      core.Now().UnixNano() + 3,
				PubKey:         openedKP.PubKeyHex(),
			},
		},
		{
			name: "receive with previous=0000...0000 and declared pub_key on existing account",
			block: &core.Block{
				Type:           core.BlockReceive,
				Asset:          "XE",
				Account:        openedKP.Address(),
				Previous:       zeroHash64,
				Balance:        11_000,
				Source:         fakePrev,
				Representative: openedKP.Address(),
				Timestamp:      core.Now().UnixNano() + 4,
				PubKey:         openedKP.PubKeyHex(),
			},
		},
		{
			name: "receive with previous=0000...0000 and no pub_key on existing account",
			block: &core.Block{
				Type:           core.BlockReceive,
				Asset:          "XE",
				Account:        openedKP.Address(),
				Previous:       zeroHash64,
				Balance:        11_000,
				Source:         fakePrev,
				Representative: openedKP.Address(),
				Timestamp:      core.Now().UnixNano() + 5,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := core.SignBlock(tc.block, openedKP); err != nil {
				t.Fatalf("SignBlock: %v", err)
			}
			err := ledger.AddBlock(tc.block)
			if err == nil {
				t.Fatalf("expected AddBlock to reject %s, got nil", tc.name)
			}
			if core.IsRetryableError(err) {
				t.Fatalf("expected non-retryable error for %s, but IsRetryableError(%q) = true", tc.name, err)
			}
		})
	}

	// 3. Genuine transient sync gaps remain retryable (503 / retryable: true).
	t.Run("opened account referencing unsynced non-zero previous is retryable", func(t *testing.T) {
		futureSend := &core.Block{
			Type:           core.BlockSend,
			Asset:          "XE",
			Account:        openedKP.Address(),
			Previous:       fakePrev,
			Balance:        9_000,
			Destination:    destKP.Address(),
			Amount:         1_000,
			Representative: openedKP.Address(),
			Timestamp:      core.Now().UnixNano() + 10,
		}
		if err := core.SignBlock(futureSend, openedKP); err != nil {
			t.Fatalf("SignBlock: %v", err)
		}
		err := ledger.AddBlock(futureSend)
		if err == nil {
			t.Fatal("expected AddBlock to reject block with unsynced previous, got nil")
		}
		if !core.IsRetryableError(err) {
			t.Fatalf("expected retryable error for unsynced non-zero previous on opened account, got IsRetryableError(%q) = false", err)
		}
	})

	t.Run("open receive referencing unsynced source send is retryable", func(t *testing.T) {
		openRecv := &core.Block{
			Type:           core.BlockReceive,
			Asset:          "XE",
			Account:        unopenedKP.Address(),
			Previous:       "0",
			Balance:        1_000,
			Source:         fakePrev,
			Representative: unopenedKP.Address(),
			Timestamp:      core.Now().UnixNano() + 11,
			PubKey:         unopenedKP.PubKeyHex(),
		}
		if err := core.SignBlock(openRecv, unopenedKP); err != nil {
			t.Fatalf("SignBlock: %v", err)
		}
		err := ledger.AddBlock(openRecv)
		if err == nil {
			t.Fatal("expected AddBlock to reject open receive with missing source send, got nil")
		}
		if !core.IsRetryableError(err) {
			t.Fatalf("expected retryable error for missing source send on open receive, got IsRetryableError(%q) = false", err)
		}
	})
}
