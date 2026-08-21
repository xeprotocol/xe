package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/xeprotocol/xe/core"
)

// Chat read endpoints (#745) expose an account's private history and a live
// event stream, so they must prove the caller owns the account they read. The
// embedded UI holds no bearer token (requireAdmin would lock it out), so we use
// a signed-challenge ownership proof instead: the node issues a short-lived
// HMAC-bound challenge, the wallet signs it with the account key, and the node
// verifies the signature against the requested account.

// chatAuthDomain domain-separates the ownership-proof signature from every
// other thing an account key signs (blocks, envelopes, directory regs) so a
// signature made elsewhere can never be replayed as a chat-read proof.
const chatAuthDomain = "xe/chat-read-auth/v1\x00"

// chatChallengeTTL bounds how long an issued challenge stays valid. Short
// enough to keep the replay window tiny, long enough for a wallet unlock +
// sign round-trip.
const chatChallengeTTLNs = int64(120) * 1_000_000_000 // 120s

// challenge wire layout (hex-encoded): expiryNs(8 BE) || nonce(16) || HMAC(32).
const (
	chatChExpiryLen = 8
	chatChNonceLen  = 16
	chatChMACLen    = 32
	chatChPayload   = chatChExpiryLen + chatChNonceLen
	chatChTotal     = chatChPayload + chatChMACLen
)

// chatAuthState holds the per-process HMAC key that binds challenges to this
// node and a used-nonce set that makes each challenge single-use (closing the
// in-window replay a purely stateless scheme would leave open). Chat reads are
// node-local and the same node issues the challenge, so node-local state is
// sufficient.
type chatAuthState struct {
	key  []byte
	mu   sync.Mutex
	seen map[string]int64 // nonce hex -> expiry ns
}

// chatAuth lazily initializes the ownership-proof state. Handler is built
// bare (NewHandler and tests both assign fields directly), so there is no
// constructor to seed this in.
func (h *Handler) chatAuth() (*chatAuthState, error) {
	h.chatAuthMu.Lock()
	defer h.chatAuthMu.Unlock()
	if h.chatAuthState == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("chat auth key: %w", err)
		}
		h.chatAuthState = &chatAuthState{key: key, seen: map[string]int64{}}
	}
	return h.chatAuthState, nil
}

func (s *chatAuthState) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(payload)
	return m.Sum(nil)
}

// issueChallenge mints a fresh HMAC-bound challenge and its expiry (ns).
func (s *chatAuthState) issueChallenge(now int64) (string, int64, error) {
	expiry := now + chatChallengeTTLNs
	payload := make([]byte, chatChPayload)
	binary.BigEndian.PutUint64(payload[:chatChExpiryLen], uint64(expiry))
	if _, err := rand.Read(payload[chatChExpiryLen:]); err != nil {
		return "", 0, fmt.Errorf("challenge nonce: %w", err)
	}
	token := append(payload, s.mac(payload)...)
	return hex.EncodeToString(token), expiry, nil
}

// signTarget is the 32-byte message the wallet signs: sha256(domain || token).
func chatSignTarget(tokenBytes []byte) []byte {
	h := sha256.New()
	h.Write([]byte(chatAuthDomain))
	h.Write(tokenBytes)
	sum := h.Sum(nil)
	return sum
}

// verifyProof checks that (account, pubKey, challenge, sig) is a valid,
// unexpired, unused ownership proof for account. now is unix-nanos.
//
// #829: account is an ADDRESS — sha256("xe/account/v1" || pubkey) — so it can
// no longer verify its own signature. The caller supplies the verifying key and
// we check it derives the account before checking the signature. The key comes
// from the client rather than from ledger.GetAccountKey deliberately: the proof
// stays stateless, and a chat-only account that has never opened a chain (so
// has declared no key on-chain) can still prove ownership. Nothing is lost by
// trusting the client for the key — the derivation is what binds it, exactly as
// it does for chat envelopes and directory registrations.
func (s *chatAuthState) verifyProof(account, pubKey, challenge, sig string, now int64) error {
	tokenBytes, err := hex.DecodeString(challenge)
	if err != nil || len(tokenBytes) != chatChTotal {
		return fmt.Errorf("malformed challenge")
	}
	payload := tokenBytes[:chatChPayload]
	gotMAC := tokenBytes[chatChPayload:]
	if subtle.ConstantTimeCompare(gotMAC, s.mac(payload)) != 1 {
		return fmt.Errorf("challenge not issued by this node")
	}
	expiry := int64(binary.BigEndian.Uint64(payload[:chatChExpiryLen]))
	if now > expiry {
		return fmt.Errorf("challenge expired")
	}
	if err := core.VerifyPayloadKey(pubKey, account); err != nil {
		return fmt.Errorf("ownership proof key: %w", err)
	}
	if err := core.VerifyHexSignature(pubKey, sig, chatSignTarget(tokenBytes)); err != nil {
		return fmt.Errorf("ownership proof failed: %w", err)
	}
	// Single-use: reject a replayed challenge, and opportunistically purge
	// expired nonces so the set can't grow without bound.
	nonceKey := hex.EncodeToString(payload[chatChExpiryLen:])
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if now > exp {
			delete(s.seen, k)
		}
	}
	if _, used := s.seen[nonceKey]; used {
		return fmt.Errorf("challenge already used")
	}
	s.seen[nonceKey] = expiry
	return nil
}

// requireChatOwnership verifies the ownership proof for the account named in
// the request before serving it. Proof is carried in query params (account,
// pub_key, challenge, sig) so it works with EventSource, which cannot set
// headers. Returns the proven account and true on success; on failure it writes
// the error response and returns false.
func (h *Handler) requireChatOwnership(w http.ResponseWriter, r *http.Request, account string) bool {
	if account == "" {
		writeError(w, http.StatusBadRequest, "missing account parameter")
		return false
	}
	st, err := h.chatAuth()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chat auth unavailable")
		return false
	}
	challenge := r.URL.Query().Get("challenge")
	sig := r.URL.Query().Get("sig")
	// pub_key is the account's VERIFYING KEY; account is its ADDRESS (#829).
	pubKey := r.URL.Query().Get("pub_key")
	if challenge == "" || sig == "" || pubKey == "" {
		writeError(w, http.StatusUnauthorized, "chat read requires an ownership proof (pub_key + challenge + sig); GET /chat/auth/challenge first")
		return false
	}
	if err := st.verifyProof(account, pubKey, challenge, sig, core.Now().UnixNano()); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return false
	}
	return true
}

// GET /chat/auth/challenge — issue a short-lived challenge for the caller to
// sign with their account key. Unauthenticated by design: the challenge is
// worthless without the account's private key.
func (h *Handler) handleChatChallenge(w http.ResponseWriter, r *http.Request) {
	st, err := h.chatAuth()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chat auth unavailable")
		return
	}
	challenge, expiry, err := st.issueChallenge(core.Now().UnixNano())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  challenge,
		"expires_at": expiry,
	})
}
