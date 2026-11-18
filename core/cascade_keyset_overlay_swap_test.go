package core_test

// Full-flow promotion tests for XE-17471 (companion to the overlay unit
// tests in cascade_keyset_overlay_test.go).
//
// These drive the real SwapBlock path: open a 2-of-2 multisig account,
// rotate its keyset, then promote a winner that rotates back. They pin
// two facts the XE-17471 report's consequence analysis gets wrong:
//   - an honest winner signed under the RESTORED (old) keyset is
//     accepted, because verifyBlockCredential resolves the keyset at the
//     winner's Previous from the store chain via keysetAtPrevious;
//   - a winner signed under the ROTATED (new) keyset is rejected for
//     the same reason.
// The overlay gap itself is pinned by the unit tests; these tests prove
// the fix does not change promotion outcomes on the reachable paths.

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// signMultisig17471 hashes the block and attaches threshold signatures
// (same pattern as the XE-17229 fix tests).
func signMultisig17471(t *testing.T, b *core.Block, kps ...*core.KeyPair) {
	t.Helper()
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h
	hb, err := core.DecodeHash(h)
	if err != nil {
		t.Fatalf("DecodeHash: %v", err)
	}
	b.Signatures = nil
	for _, kp := range kps {
		sig := ed25519.Sign(kp.Private, hb)
		b.Signatures = append(b.Signatures, core.BlockSignature{
			PublicKey: kp.PubKeyHex(),
			Sig:       hex.EncodeToString(sig),
		})
	}
}

func setupRotatedMultisig17471(t *testing.T) (*core.Ledger, string, *core.Keyset, []*core.KeyPair, *core.Keyset, []*core.KeyPair, *core.Block, *core.Block) {
	t.Helper()
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	ks0, kps0 := keypairKeyset17471(t, 2)
	ks1, kps1 := keypairKeyset17471(t, 2)
	msAddr, err := core.DeriveMultisigAddress(ks0)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}
	rep, _ := core.GenerateKeyPair()
	now := core.Now().UnixNano()

	open := &core.Block{
		Type:           core.BlockMultisigOpen,
		Account:        msAddr,
		Previous:       "0",
		Balance:        0,
		Representative: rep.Address(),
		MSKeyset:       ks0,
		Asset:          "XE",
		Timestamp:      now,
	}
	signMultisig17471(t, open, kps0...)
	if err := ledger.AddBlock(open); err != nil {
		t.Fatalf("AddBlock open: %v", err)
	}

	upd := &core.Block{
		Type:      core.BlockMultisigUpdate,
		Account:   msAddr,
		Previous:  open.Hash,
		Balance:   0,
		MSKeyset:  ks1,
		Asset:     "XE",
		Timestamp: now + 1,
	}
	signMultisig17471(t, upd, kps0...)
	if err := ledger.AddBlock(upd); err != nil {
		t.Fatalf("AddBlock update: %v", err)
	}
	return ledger, msAddr, ks0, kps0, ks1, kps1, open, upd
}

func keypairKeyset17471(t *testing.T, n int) (*core.Keyset, []*core.KeyPair) {
	t.Helper()
	var kps []*core.KeyPair
	var keys []string
	for i := 0; i < n; i++ {
		kp, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		kps = append(kps, kp)
		keys = append(keys, kp.PubKeyHex())
	}
	return &core.Keyset{Keys: keys, Threshold: n}, kps
}

// TestCascadeSwapPromotesHonestWinner: a winner rotating the keyset back
// to K0, signed 2-of-2 under the restored keyset K0, must be promoted.
func TestCascadeSwapPromotesHonestWinner(t *testing.T) {
	ledger, msAddr, ks0, kps0, _, _, open, upd := setupRotatedMultisig17471(t)
	now := core.Now().UnixNano()

	winner := &core.Block{
		Type:      core.BlockMultisigUpdate,
		Account:   msAddr,
		Previous:  open.Hash,
		Balance:   0,
		MSKeyset:  ks0,
		Asset:     "XE",
		Timestamp: now + 2,
	}
	signMultisig17471(t, winner, kps0...)
	if err := ledger.SwapBlock(msAddr, upd.Hash, winner.Hash, winner); err != nil {
		t.Fatalf("SwapBlock honest winner (signed under restored K0): %v", err)
	}
	got := ledger.GetKeyset(msAddr)
	if got == nil || got.Threshold != ks0.Threshold || !reflect.DeepEqual(got.Keys, ks0.Keys) {
		t.Fatalf("after promotion keyset = %+v, want %+v", got, ks0)
	}
}

// TestCascadeSwapRejectsRotatedKeysetWinner: a winner signed 2-of-2 under
// the rotated keyset K1 must be rejected — credential verification
// resolves the keyset at the winner's Previous (K0), not the live one.
func TestCascadeSwapRejectsRotatedKeysetWinner(t *testing.T) {
	ledger, msAddr, _, _, ks1, kps1, open, upd := setupRotatedMultisig17471(t)
	now := core.Now().UnixNano()

	winner := &core.Block{
		Type:      core.BlockMultisigUpdate,
		Account:   msAddr,
		Previous:  open.Hash,
		Balance:   0,
		MSKeyset:  ks1,
		Asset:     "XE",
		Timestamp: now + 2,
	}
	signMultisig17471(t, winner, kps1...)
	if err := ledger.SwapBlock(msAddr, upd.Hash, winner.Hash, winner); err == nil {
		t.Fatalf("expected SwapBlock to reject winner signed under rotated K1, but it succeeded")
	}
}
