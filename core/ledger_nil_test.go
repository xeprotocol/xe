package core

import (
	"testing"
)

func TestAddNilBlock(t *testing.T) {
	l := &Ledger{}
	if err := l.AddBlock(nil); err == nil {
		t.Fatal("expected error adding nil block to ledger, got nil")
	}
	if err := l.AddSyncedBlock(nil); err == nil {
		t.Fatal("expected error adding nil synced block to ledger, got nil")
	}
}
