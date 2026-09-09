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

const chatAuthDomain = "xe/chat-read-auth/v1\x00"

const chatChallengeTTLNs = int64(120) * 1_000_000_000

const (
	chatChExpiryLen = 8
	chatChNonceLen  = 16
	chatChMACLen    = 32
	chatChPayload   = chatChExpiryLen + chatChNonceLen
	chatChTotal     = chatChPayload + chatChMACLen
)

type chatAuthState struct {
	key  []byte
	mu   sync.Mutex
	seen map[string]int64
}

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

func chatSignTarget(tokenBytes []byte) []byte {
	h := sha256.New()
	h.Write([]byte(chatAuthDomain))
	h.Write(tokenBytes)
	sum := h.Sum(nil)
	return sum
}

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
