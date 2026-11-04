package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type submitTestBackend struct {
	nodeBackend
	ledger *core.Ledger
}

func (s *submitTestBackend) SubmitBlock(b *core.Block) error {
	return s.ledger.AddBlock(b)
}

func TestSubmitBlockHTTPStatusAndRetryableFlag(t *testing.T) {
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})
	h := &Handler{node: &submitTestBackend{ledger: ledger}}
	mux := h.Mux()

	unopenedKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	openedKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	destKP, err := core.GenerateKeyPair()
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
		t.Fatalf("SignBlock: %v", err)
	}
	if err := ledger.SeedAssetForTesting(seedMint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	postBlock := func(t *testing.T, path string, b *core.Block) (int, bool, string) {
		t.Helper()
		body, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp struct {
			Error     string `json:"error"`
			Retryable bool   `json:"retryable"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json.Unmarshal response (%s): %v", rec.Body.String(), err)
		}
		return rec.Code, resp.Retryable, resp.Error
	}

	fakePrev := strings.Repeat("b", 64)
	zeroHash64 := strings.Repeat("0", 64)

	// 1. Non-open send for unopened account without pub_key -> 400 {retryable: false}
	unopenedSend := &core.Block{
		Type:           core.BlockSend,
		Asset:          "XE",
		Account:        unopenedKP.Address(),
		Previous:       fakePrev,
		Balance:        0,
		Destination:    destKP.Address(),
		Amount:         100,
		Representative: unopenedKP.Address(),
		Timestamp:      core.Now().UnixNano(),
	}
	if err := core.SignBlock(unopenedSend, unopenedKP); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	status, retryable, errMsg := postBlock(t, "/blocks/send", unopenedSend)
	if status != http.StatusBadRequest || retryable {
		t.Fatalf("unopened send: got status=%d retryable=%v err=%q, want 400 retryable=false", status, retryable, errMsg)
	}

	// 2. Block with previous = 0 (64-zero hex or "0") on account with existing chain -> 400 {retryable: false}
	zeroPrevSend := &core.Block{
		Type:           core.BlockSend,
		Asset:          "XE",
		Account:        openedKP.Address(),
		Previous:       zeroHash64,
		Balance:        9_000,
		Destination:    destKP.Address(),
		Amount:         1_000,
		Representative: openedKP.Address(),
		Timestamp:      core.Now().UnixNano() + 1,
	}
	if err := core.SignBlock(zeroPrevSend, openedKP); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	status, retryable, errMsg = postBlock(t, "/blocks/send", zeroPrevSend)
	if status != http.StatusBadRequest || retryable {
		t.Fatalf("zero-previous send on existing account: got status=%d retryable=%v err=%q, want 400 retryable=false", status, retryable, errMsg)
	}

	zeroPrevRecv := &core.Block{
		Type:           core.BlockReceive,
		Asset:          "XE",
		Account:        openedKP.Address(),
		Previous:       "0",
		Balance:        11_000,
		Source:         fakePrev,
		Representative: openedKP.Address(),
		Timestamp:      core.Now().UnixNano() + 2,
		PubKey:         openedKP.PubKeyHex(),
	}
	if err := core.SignBlock(zeroPrevRecv, openedKP); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	status, retryable, errMsg = postBlock(t, "/blocks/receive", zeroPrevRecv)
	if status != http.StatusBadRequest || retryable {
		t.Fatalf("zero-previous receive on existing account: got status=%d retryable=%v err=%q, want 400 retryable=false", status, retryable, errMsg)
	}

	// 3. Opened account with unsynced non-zero previous -> 503 {retryable: true}
	unsyncedPrevSend := &core.Block{
		Type:           core.BlockSend,
		Asset:          "XE",
		Account:        openedKP.Address(),
		Previous:       fakePrev,
		Balance:        9_000,
		Destination:    destKP.Address(),
		Amount:         1_000,
		Representative: openedKP.Address(),
		Timestamp:      core.Now().UnixNano() + 3,
	}
	if err := core.SignBlock(unsyncedPrevSend, openedKP); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	status, retryable, errMsg = postBlock(t, "/blocks/send", unsyncedPrevSend)
	if status != http.StatusServiceUnavailable || !retryable {
		t.Fatalf("unsynced non-zero previous on opened account: got status=%d retryable=%v err=%q, want 503 retryable=true", status, retryable, errMsg)
	}
}
