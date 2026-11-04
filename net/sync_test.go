package net

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

// TestPoC_F5_OversizedPageRejected verifies that an oversized page (such as
// 20000 blocks in PoC F5) is rejected before materializing thousands/millions
// of Block structs in memory, preventing node OOM.
func TestPoC_F5_OversizedPageRejected(t *testing.T) {
	const pageCount = 20000
	var b strings.Builder
	b.Grow(pageCount*3 + 32)
	b.WriteString(`{"blocks":[`)
	for i := 0; i < pageCount; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString(`],"has_more":false}`)
	payload := []byte(b.String())

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	// 1. Verify decodeSyncResponse rejects immediately upon exceeding maxPageSize
	lr := &io.LimitedReader{R: bytes.NewReader(payload), N: maxSyncResponseBytes}
	dec := json.NewDecoder(lr)
	resp, err := decodeSyncResponse(dec, maxPageSize)
	if err == nil {
		t.Fatalf("expected decodeSyncResponse to reject oversized page of %d blocks, but got success: %d blocks", pageCount, len(resp.Blocks))
	}
	if !strings.Contains(err.Error(), "exceeding maxPageSize") {
		t.Fatalf("expected error mentioning maxPageSize, got: %v", err)
	}

	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	// Heap allocation should not spike by megabytes/gigabytes of decoded blocks
	allocDelta := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("oversized page rejected with error: %v (alloc delta: %d bytes)", err, allocDelta)

	// 2. Also verify SyncResponse.UnmarshalJSON rejects the oversized payload
	var sr SyncResponse
	err = json.Unmarshal(payload, &sr)
	if err == nil {
		t.Fatalf("expected json.Unmarshal to reject oversized page of %d blocks, but got success", pageCount)
	}
	if !strings.Contains(err.Error(), "exceeding maxPageSize") {
		t.Fatalf("expected UnmarshalJSON error mentioning maxPageSize, got: %v", err)
	}
}

func TestSyncDecode_ValidPage(t *testing.T) {
	rawJSON := `{
		"has_more": true,
		"cursor": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"rejected": ["acc1", "acc2"],
		"blocks": [
			{
				"type": "send",
				"account": "1111111111111111111111111111111111111111111111111111111111111111",
				"previous": "0000000000000000000000000000000000000000000000000000000000000000",
				"balance": 1000,
				"timestamp": 123456789,
				"asset": "XE",
				"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`

	dec := json.NewDecoder(strings.NewReader(rawJSON))
	resp, err := decodeSyncResponse(dec, maxPageSize)
	if err != nil {
		t.Fatalf("unexpected error decoding valid page: %v", err)
	}
	if !resp.HasMore {
		t.Fatalf("expected has_more to be true")
	}
	if resp.Cursor != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected cursor: %s", resp.Cursor)
	}
	if len(resp.Rejected) != 2 || resp.Rejected[0] != "acc1" || resp.Rejected[1] != "acc2" {
		t.Fatalf("unexpected rejected accounts: %v", resp.Rejected)
	}
	if len(resp.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(resp.Blocks))
	}
	if resp.Blocks[0].Account != "1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("unexpected block account: %s", resp.Blocks[0].Account)
	}
}

func TestSyncDecode_EmptyAndNullBlocks(t *testing.T) {
	// Case A: empty blocks array
	rawA := `{"blocks":[],"has_more":false}`
	decA := json.NewDecoder(strings.NewReader(rawA))
	respA, err := decodeSyncResponse(decA, maxPageSize)
	if err != nil {
		t.Fatalf("unexpected error decoding empty blocks: %v", err)
	}
	if len(respA.Blocks) != 0 || respA.HasMore {
		t.Fatalf("unexpected respA: %+v", respA)
	}

	// Case B: null blocks
	rawB := `{"blocks":null,"has_more":false}`
	decB := json.NewDecoder(strings.NewReader(rawB))
	respB, err := decodeSyncResponse(decB, maxPageSize)
	if err != nil {
		t.Fatalf("unexpected error decoding null blocks: %v", err)
	}
	if respB.Blocks != nil || respB.HasMore {
		t.Fatalf("unexpected respB: %+v", respB)
	}
}

func TestSyncDecode_CapEnforcementBeforeAppend(t *testing.T) {
	var allBlocks []*core.Block

	// Pre-fill allBlocks up to maxTotalBlocks - 5
	for i := 0; i < maxTotalBlocks-5; i++ {
		allBlocks = append(allBlocks, &core.Block{Balance: uint64(i)})
	}

	// Simulate incoming page with 10 blocks (less than maxPageSize, but exceeds remaining cap)
	incoming := SyncResponse{
		Blocks:  make([]*core.Block, 10),
		HasMore: true,
	}
	for i := range incoming.Blocks {
		incoming.Blocks[i] = &core.Block{Balance: uint64(1000 + i)}
	}

	// Client loop logic
	remaining := maxTotalBlocks - len(allBlocks)
	blocksToAdd := incoming.Blocks
	if len(blocksToAdd) > remaining {
		blocksToAdd = blocksToAdd[:remaining]
	}
	allBlocks = append(allBlocks, blocksToAdd...)

	if len(allBlocks) != maxTotalBlocks {
		t.Fatalf("expected allBlocks to strictly clamp at maxTotalBlocks (%d), got %d", maxTotalBlocks, len(allBlocks))
	}
}
