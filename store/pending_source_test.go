package store_test

import (
	"os"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestMemStore_PendingBySource(t *testing.T) {
	mem := store.NewMemStore()
	alice := "alice_account_addr_0000000000001"
	bob := "bob_account_addr_000000000000002"
	carol := "carol_account_addr_0000000000003"

	ps1 := &core.PendingSend{
		SendHash:    "send_hash_01",
		Source:      alice,
		Destination: bob,
		Amount:      1000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}
	ps2 := &core.PendingSend{
		SendHash:    "send_hash_02",
		Source:      alice,
		Destination: carol,
		Amount:      2000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}
	ps3 := &core.PendingSend{
		SendHash:    "send_hash_03",
		Source:      bob,
		Destination: carol,
		Amount:      500,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}

	for _, ps := range []*core.PendingSend{ps1, ps2, ps3} {
		if err := mem.PutPendingSend(ps); err != nil {
			t.Fatalf("PutPendingSend failed: %v", err)
		}
	}

	// Verify alice's outgoing pending sends
	aliceSrc, err := mem.GetPendingBySource(alice)
	if err != nil {
		t.Fatalf("GetPendingBySource(alice): %v", err)
	}
	if len(aliceSrc) != 2 {
		t.Fatalf("expected 2 pending sends from alice, got %d", len(aliceSrc))
	}

	// Verify carol's incoming pending sends
	carolDst, err := mem.GetPendingByDest(carol)
	if err != nil {
		t.Fatalf("GetPendingByDest(carol): %v", err)
	}
	if len(carolDst) != 2 {
		t.Fatalf("expected 2 pending sends to carol, got %d", len(carolDst))
	}

	// Delete ps1 (carol receives or bob receives)
	if err := mem.DeletePendingSend(ps1.SendHash); err != nil {
		t.Fatalf("DeletePendingSend failed: %v", err)
	}

	aliceSrcAfter, err := mem.GetPendingBySource(alice)
	if err != nil {
		t.Fatalf("GetPendingBySource after delete: %v", err)
	}
	if len(aliceSrcAfter) != 1 || aliceSrcAfter[0].SendHash != ps2.SendHash {
		t.Fatalf("expected 1 remaining pending send for alice (ps2), got %+v", aliceSrcAfter)
	}

	bobDstAfter, err := mem.GetPendingByDest(bob)
	if err != nil {
		t.Fatalf("GetPendingByDest after delete: %v", err)
	}
	if len(bobDstAfter) != 0 {
		t.Fatalf("expected 0 pending sends to bob, got %d", len(bobDstAfter))
	}
}

func TestBadgerStore_PendingBySource(t *testing.T) {
	dir, err := os.MkdirTemp("", "badger_pending_src_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	bs, err := store.NewBadgerStore(dir)
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	defer bs.Close()

	alice := "alice_account_addr_0000000000001"
	bob := "bob_account_addr_000000000000002"
	carol := "carol_account_addr_0000000000003"

	ps1 := &core.PendingSend{
		SendHash:    "send_hash_b01",
		Source:      alice,
		Destination: bob,
		Amount:      1000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}
	ps2 := &core.PendingSend{
		SendHash:    "send_hash_b02",
		Source:      alice,
		Destination: carol,
		Amount:      2000,
		Asset:       "XE",
		Timestamp:   time.Now().UnixNano(),
	}

	if err := bs.PutPendingSend(ps1); err != nil {
		t.Fatalf("PutPendingSend(ps1): %v", err)
	}
	if err := bs.PutPendingSend(ps2); err != nil {
		t.Fatalf("PutPendingSend(ps2): %v", err)
	}

	aliceSrc, err := bs.GetPendingBySource(alice)
	if err != nil {
		t.Fatalf("GetPendingBySource(alice): %v", err)
	}
	if len(aliceSrc) != 2 {
		t.Fatalf("expected 2 pending sends from alice, got %d", len(aliceSrc))
	}

	if err := bs.DeletePendingSend(ps1.SendHash); err != nil {
		t.Fatalf("DeletePendingSend: %v", err)
	}

	aliceSrcAfter, err := bs.GetPendingBySource(alice)
	if err != nil {
		t.Fatalf("GetPendingBySource(alice) after delete: %v", err)
	}
	if len(aliceSrcAfter) != 1 || aliceSrcAfter[0].SendHash != ps2.SendHash {
		t.Fatalf("expected 1 remaining pending send for alice (ps2), got %+v", aliceSrcAfter)
	}
}
