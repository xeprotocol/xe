package statechain

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestSyncConstantsConsistency(t *testing.T) {
	// Assert that a full page of maximum legal sized blocks does not exceed the client's decode cap
	maxLegalPageBytes := syncPageSize * MaxBlockSize
	if maxLegalPageBytes > syncMaxResponseSize {
		t.Fatalf("syncPageSize * MaxBlockSize (%d bytes) exceeds syncMaxResponseSize (%d bytes)",
			maxLegalPageBytes, syncMaxResponseSize)
	}
}

func TestSyncResponseByteBudgeting(t *testing.T) {
	// Construct a block near MaxBlockSize
	largeData := bytes.Repeat([]byte("a"), MaxBlockSize-1024)
	mockBlock := &Block{
		Index:     1,
		Key:       "test_key",
		StateData: largeData,
		Action:    ActionSet,
	}

	resp := syncResponse{
		Blocks:  []*Block{mockBlock},
		HasMore: false,
	}

	payload, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if len(payload) > syncMaxResponseSize {
		t.Fatalf("single block response size (%d bytes) exceeds syncMaxResponseSize (%d bytes)",
			len(payload), syncMaxResponseSize)
	}

	// Verify that LimitReader on syncMaxResponseSize decodes cleanly
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(payload), syncMaxResponseSize))
	var decoded syncResponse
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("dec.Decode failed: %v", err)
	}
	if len(decoded.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(decoded.Blocks))
	}
}

func TestSyncRequestBackwardCompatibility(t *testing.T) {
	// Test decoding old request without max_blocks
	oldReqJSON := []byte(`{"tip_index": 42}`)
	var req syncRequest
	if err := json.Unmarshal(oldReqJSON, &req); err != nil {
		t.Fatalf("unmarshal old req failed: %v", err)
	}
	if req.TipIndex != 42 || req.MaxBlocks != 0 {
		t.Fatalf("unexpected req fields: %+v", req)
	}

	// Test decoding new request with max_blocks
	newReqJSON := []byte(`{"tip_index": 42, "max_blocks": 16}`)
	if err := json.Unmarshal(newReqJSON, &req); err != nil {
		t.Fatalf("unmarshal new req failed: %v", err)
	}
	if req.TipIndex != 42 || req.MaxBlocks != 16 {
		t.Fatalf("unexpected req fields: %+v", req)
	}
}
