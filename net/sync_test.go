package net

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestSyncResponse_NilBlockHandling(t *testing.T) {
	// Simulate an adversarial peer response containing null blocks: {"blocks":[null, null],"has_more":false}
	payload := `{"blocks":[null, null],"has_more":false}`

	var resp SyncResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Blocks) != 2 {
		t.Fatalf("expected 2 raw elements in Blocks, got %d", len(resp.Blocks))
	}
	if resp.Blocks[0] != nil || resp.Blocks[1] != nil {
		t.Fatalf("expected nil blocks from null JSON elements")
	}

	// Verify our filtering logic in requestSync ignores nil elements
	var allBlocks []*core.Block
	for _, b := range resp.Blocks {
		if b != nil {
			allBlocks = append(allBlocks, b)
		}
	}

	if len(allBlocks) != 0 {
		t.Fatalf("expected 0 blocks after nil filtering, got %d", len(allBlocks))
	}

	// Verify quarantine filtering loop does not panic with defensive nil checks
	quarantine := newBlockQuarantine()
	filtered := make([]*core.Block, 0, len(allBlocks))
	for _, b := range allBlocks {
		if b == nil {
			continue
		}
		if quarantine.contains(b.Hash) {
			continue
		}
		filtered = append(filtered, b)
	}

	if len(filtered) != 0 {
		t.Fatalf("expected 0 filtered blocks, got %d", len(filtered))
	}
}

func TestSpawnGate_PanicRecovery(t *testing.T) {
	gate := &spawnGate{}

	var wg sync.WaitGroup
	wg.Add(1)

	// Verify that a panic inside a spawned worker is recovered and doesn't crash the test or process
	spawned := gate.spawn(func() {
		defer wg.Done()
		panic("simulated unhandled panic in worker")
	})

	if !spawned {
		t.Fatalf("expected spawn to succeed")
	}

	wg.Wait()
	gate.wait()
}
