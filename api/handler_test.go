package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestCORSMiddlewareHeaders(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	origin := "https://wallet.xe.network"
	middleware := corsMiddleware(dummyHandler, origin)

	// 1. Test preflight OPTIONS request
	req := httptest.NewRequest(http.MethodOptions, "/tunnel/test/tcp", nil)
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 for OPTIONS, got %d", rec.Code)
	}

	headers := rec.Header()
	if got := headers.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}

	allowHeaders := headers.Get("Access-Control-Allow-Headers")
	if !strings.Contains(allowHeaders, "X-Signature") {
		t.Errorf("expected Access-Control-Allow-Headers to contain X-Signature, got %q", allowHeaders)
	}
	if !strings.Contains(allowHeaders, "Content-Type") {
		t.Errorf("expected Access-Control-Allow-Headers to contain Content-Type, got %q", allowHeaders)
	}
	if !strings.Contains(allowHeaders, "Authorization") {
		t.Errorf("expected Access-Control-Allow-Headers to contain Authorization, got %q", allowHeaders)
	}

	// 2. Test regular GET request passes through and keeps headers
	reqGet := httptest.NewRequest(http.MethodGet, "/network/info", nil)
	recGet := httptest.NewRecorder()
	middleware.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("expected status 200 for GET, got %d", recGet.Code)
	}
	if got := recGet.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("expected Access-Control-Allow-Origin %q, got %q", origin, got)
	}
}

func TestChatAuthStateReplayAndCapacity(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	st := &chatAuthState{key: key, seen: map[string]int64{}}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	account, err := core.DeriveAddress(pubHex)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}

	now := time.Now().UnixNano()
	challenge, _, err := st.issueChallenge(now)
	if err != nil {
		t.Fatalf("issueChallenge: %v", err)
	}

	tokenBytes, err := hex.DecodeString(challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sigBytes := ed25519.Sign(priv, chatSignTarget(tokenBytes))
	sigHex := hex.EncodeToString(sigBytes)

	// First verification must succeed
	if err := st.verifyProof(account, pubHex, challenge, sigHex, now); err != nil {
		t.Fatalf("first verifyProof failed: %v", err)
	}

	// Second verification of same challenge must be rejected (replay prevention)
	if err := st.verifyProof(account, pubHex, challenge, sigHex, now); err == nil {
		t.Fatalf("expected challenge replay error, got nil")
	}

	// Verify capacity bound
	for i := 0; i < maxChatSeenNonces; i++ {
		st.seen[fmt.Sprintf("mock-nonce-%d", i)] = now + chatChallengeTTLNs
	}

	// Issuing new challenge and verifying when seen map is saturated
	ch2, _, err := st.issueChallenge(now)
	if err != nil {
		t.Fatalf("issueChallenge: %v", err)
	}
	tb2, _ := hex.DecodeString(ch2)
	sig2 := hex.EncodeToString(ed25519.Sign(priv, chatSignTarget(tb2)))

	err = st.verifyProof(account, pubHex, ch2, sig2, now)
	if err == nil || !strings.Contains(err.Error(), "too many active authentication challenges") {
		t.Fatalf("expected capacity bound error, got: %v", err)
	}

	// Advance time past expiry and issue a valid fresh challenge at future time
	future := now + chatChallengeTTLNs + 1
	ch3, _, err := st.issueChallenge(future)
	if err != nil {
		t.Fatalf("issueChallenge at future: %v", err)
	}
	tb3, _ := hex.DecodeString(ch3)
	sig3 := hex.EncodeToString(ed25519.Sign(priv, chatSignTarget(tb3)))

	// Verifying fresh challenge at future time prunes all previously expired nonces
	if err := st.verifyProof(account, pubHex, ch3, sig3, future); err != nil {
		t.Fatalf("verifyProof at future failed: %v", err)
	}

	st.mu.Lock()
	count := len(st.seen)
	st.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected all expired nonces to be pruned leaving only 1 active, got %d", count)
	}
}
