package net

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestSyncResponseWithNullBlock(t *testing.T) {
	raw := `{"blocks":[null, null],"has_more":false}`
	var resp SyncResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(resp.Blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(resp.Blocks))
	}
	for i, b := range resp.Blocks {
		if b != nil {
			t.Fatalf("expected block %d to be nil, got %v", i, b)
		}
	}

	// Test that filtering nil blocks does not panic
	var allBlocks []*core.Block
	for _, b := range resp.Blocks {
		if b != nil {
			allBlocks = append(allBlocks, b)
		}
	}
	if len(allBlocks) != 0 {
		t.Fatalf("expected 0 non-nil blocks, got %d", len(allBlocks))
	}

	quarantine := newBlockQuarantine()
	filtered := allBlocks[:0]
	skipped := 0
	for _, b := range resp.Blocks {
		if b == nil {
			skipped++
			continue
		}
		if quarantine.contains(b.Hash) {
			skipped++
		} else {
			filtered = append(filtered, b)
		}
	}
	if skipped != 2 {
		t.Fatalf("expected 2 skipped blocks, got %d", skipped)
	}
	if len(filtered) != 0 {
		t.Fatalf("expected 0 filtered blocks, got %d", len(filtered))
	}
}

func TestSpawnGatePanicRecovery(t *testing.T) {
	gate := &spawnGate{}
	done := make(chan bool)
	spawned := gate.spawn(func() {
		defer func() {
			done <- true
		}()
		panic("simulated worker panic on sync path")
	})
	if !spawned {
		t.Fatal("expected spawn to succeed")
	}

	select {
	case <-done:
		// success: worker recovered cleanly without killing process
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not finish in time")
	}

	gate.wait()
}
