package core

// Regression tests for XE-17471: the cascade keyset overlay ignored
// BlockUndo.RestoreKeyset.
//
// Before the fix, addUndo() never recorded a restored keyset, so
// getKeysetOverlay() returned the live keyset (the loser's rotated
// keyset) during conflict promotion, while CommitCascade and the
// in-memory apply closure both honored the restore. These tests pin
// the overlay logic directly (bare Ledger, hand-built undos — no store
// needed, so no import cycle with the store package).
//
// Note on scope: the overlay's only consumer is
// validateAndAddMultisigUpdate, where it feeds the "account is not
// multisig" nil check. Signature verification during promotion
// resolves the keyset at the winner's Previous from the store chain
// via keysetAtPrevious, which already yields the restored keyset — so
// the gap's reachable impact is the nil-check answer in the edge cases
// below, and the full-flow SwapBlock test in
// cascade_keyset_overlay_swap_test.go pins that promotion still works.

import (
	"reflect"
	"testing"
)

func keyset17471(keys ...string) *Keyset {
	return &Keyset{Keys: append([]string(nil), keys...), Threshold: len(keys)}
}

func assertKeyset17471(t *testing.T, what string, got, want *Keyset) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("%s: got keyset %+v, want nil", what, got)
		}
		return
	}
	if got == nil {
		t.Fatalf("%s: got nil keyset, want %+v", what, want)
	}
	if got.Threshold != want.Threshold || !reflect.DeepEqual(got.Keys, want.Keys) {
		t.Fatalf("%s: got %+v, want %+v", what, got, want)
	}
}

func ledgerWithLiveKeyset17471(t *testing.T, account string, live *Keyset) *Ledger {
	t.Helper()
	return &Ledger{keysets: map[string]*Keyset{account: live}}
}

func activateCascade17471(t *testing.T, l *Ledger, cb *cascadeBuild) {
	t.Helper()
	if err := l.activateCascade(cb); err != nil {
		t.Fatalf("activateCascade: %v", err)
	}
}

// TestCascadeKeysetOverlayRestoresKeyset pins the XE-17471 fix: rolling
// back a BlockMultisigUpdate (key rotation) must make the overlay return
// the pre-rotation keyset, not the live (rotated) one.
func TestCascadeKeysetOverlayRestoresKeyset(t *testing.T) {
	const acct = "acct"
	l := ledgerWithLiveKeyset17471(t, acct, keyset17471("k1a", "k1b"))

	// Sanity: without a cascade the overlay is the live keyset.
	assertKeyset17471(t, "overlay without cascade", l.getKeysetOverlay(acct), keyset17471("k1a", "k1b"))

	cb := newCascadeBuild("winner")
	cb.addUndo(&BlockUndo{
		Account:       acct,
		RestoreKeyset: keyset17471("k0a", "k0b"),
		Chain:         &AccountChain{},
	}, func() {})
	activateCascade17471(t, l, cb)
	defer l.deactivateCascade()

	assertKeyset17471(t, "overlay during promotion", l.getKeysetOverlay(acct), keyset17471("k0a", "k0b"))
	// The live map is untouched until commit.
	assertKeyset17471(t, "live keyset during promotion", l.GetKeyset(acct), keyset17471("k1a", "k1b"))
}

// TestCascadeKeysetOverlayLastUndoWins pins ordering: undos are applied
// newest-first, so the last undo recorded for an account determines the
// overlay — matching CommitCascade. A naive "restore always wins" fix
// would fail the second case by returning a keyset the commit is about
// to delete.
func TestCascadeKeysetOverlayLastUndoWins(t *testing.T) {
	const acct = "acct"

	// Two rotations undone (newest first): oldest restored keyset wins.
	l := ledgerWithLiveKeyset17471(t, acct, keyset17471("k2a", "k2b"))
	cb := newCascadeBuild("winner")
	cb.addUndo(&BlockUndo{Account: acct, RestoreKeyset: keyset17471("k1a", "k1b"), Chain: &AccountChain{}}, func() {})
	cb.addUndo(&BlockUndo{Account: acct, RestoreKeyset: keyset17471("k0a", "k0b"), Chain: &AccountChain{}}, func() {})
	activateCascade17471(t, l, cb)
	assertKeyset17471(t, "overlay after two restores", l.getKeysetOverlay(acct), keyset17471("k0a", "k0b"))
	l.deactivateCascade()

	// Rotation undone, then the open undone (oldest undo): the account
	// ends up non-multisig, so the overlay must be nil.
	l2 := ledgerWithLiveKeyset17471(t, acct, keyset17471("k1a", "k1b"))
	cb2 := newCascadeBuild("winner")
	cb2.addUndo(&BlockUndo{Account: acct, RestoreKeyset: keyset17471("k0a", "k0b"), Chain: &AccountChain{}}, func() {})
	cb2.addUndo(&BlockUndo{Account: acct, DeleteKeysetAccount: acct, Chain: &AccountChain{}}, func() {})
	activateCascade17471(t, l2, cb2)
	defer l2.deactivateCascade()
	assertKeyset17471(t, "overlay after restore then delete", l2.getKeysetOverlay(acct), nil)

	// Symmetric: a delete recorded first, then a restore, returns the
	// restored keyset (the last undo wins either way).
	l3 := ledgerWithLiveKeyset17471(t, acct, keyset17471("k1a", "k1b"))
	cb3 := newCascadeBuild("winner")
	cb3.addUndo(&BlockUndo{Account: acct, DeleteKeysetAccount: acct, Chain: &AccountChain{}}, func() {})
	cb3.addUndo(&BlockUndo{Account: acct, RestoreKeyset: keyset17471("k0a", "k0b"), Chain: &AccountChain{}}, func() {})
	activateCascade17471(t, l3, cb3)
	defer l3.deactivateCascade()
	assertKeyset17471(t, "overlay after delete then restore", l3.getKeysetOverlay(acct), keyset17471("k0a", "k0b"))
}
