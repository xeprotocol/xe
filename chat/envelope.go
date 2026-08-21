package chat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"

	"github.com/xeprotocol/xe/core"
)

// MaxMessageBytes caps the length of a chat message body (env.Message). It is
// deliberately small (8 KiB) so a signer can't submit huge messages under the
// larger global request-body limit. Counted in bytes, not runes.
const MaxMessageBytes = 8192

// DefaultPoWDifficulty is the anti-spam proof-of-work threshold for chat
// envelopes: ~2^18 expected attempts (~0.1s native, well under 1s of browser
// JS per message). Deliberately its own constant — chat spam pricing and
// block-mining difficulty (core.DefaultDifficulty, ~2^21) are different cost
// targets and must be tunable independently.
//
// Mirrored in web/assets/pow.js (DEFAULT_CHAT_POW_DIFFICULTY) — keep in sync.
const DefaultPoWDifficulty uint64 = 0xffffc00000000000

// MaxEnvelopeSkew bounds how far an envelope timestamp may sit from the
// receiving node's clock, in either direction. Together with the seen-ID
// dedup in ChatStore it makes a solved PoW nonce spendable at most once:
// inside the window duplicates are rejected by ID, outside it by staleness.
const MaxEnvelopeSkew = 5 * time.Minute

type Envelope struct {
	ID   string `json:"id"`
	From string `json:"from"` // ADDRESS: sender's account address
	// PubKey is the sender's ed25519 public key — a VERIFYING KEY, not an
	// address. Since #829 From is sha256("xe/account/v1" || pubkey), so the
	// envelope no longer carries a key that can check its own signature. Chat
	// ingress is stateless (no ledger lookup: a chat-only account may have no
	// chain at all), so the envelope self-certifies — the key is bound into the
	// envelope ID, which is both the signed message and the PoW target, so it
	// cannot be swapped in transit.
	PubKey    string `json:"pub_key"`
	To        string `json:"to"` // ADDRESS: recipient's account address
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
	PoWNonce  uint64 `json:"pow_nonce"`
}

func envelopeCanonical(from, pubKey, to, message string, timestamp int64) []byte {
	// Length-prefixed encoding prevents delimiter-injection collisions.
	// Format: [4-byte len][from][4-byte len][pub_key][4-byte len][to]
	//         [4-byte len][message][8-byte timestamp]
	// pub_key sits next to the address it certifies (#829).
	size := 4 + len(from) + 4 + len(pubKey) + 4 + len(to) + 4 + len(message) + 8
	buf := make([]byte, 0, size)
	buf = appendField(buf, []byte(from))
	buf = appendField(buf, []byte(pubKey))
	buf = appendField(buf, []byte(to))
	buf = appendField(buf, []byte(message))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	buf = append(buf, ts[:]...)
	return buf
}

func appendField(buf, data []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf = append(buf, lenBuf[:]...)
	return append(buf, data...)
}

func ComputeEnvelopeID(from, pubKey, to, message string, timestamp int64) string {
	data := envelopeCanonical(from, pubKey, to, message, timestamp)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// NewEnvelope builds, signs, and — when difficulty > 0 — solves anti-spam
// proof-of-work for a chat envelope. PoW-solving lives inside construction so
// producers and verifiers can never disagree: any envelope built here passes
// VerifyFull at the same difficulty.
func NewEnvelope(from, to, message string, kp *core.KeyPair, difficulty uint64) (*Envelope, error) {
	ts := core.Now().UnixNano()
	// The key is taken from the signing key pair, never from the caller, so a
	// producer can't build an envelope whose declared key isn't the one that
	// signs it (#829).
	pubKey := kp.PubKeyHex()
	id := ComputeEnvelopeID(from, pubKey, to, message, ts)

	idBytes, _ := hex.DecodeString(id)
	sig := ed25519.Sign(kp.Private, idBytes)

	env := &Envelope{
		ID:        id,
		From:      from,
		PubKey:    pubKey,
		To:        to,
		Message:   message,
		Timestamp: ts,
		Signature: hex.EncodeToString(sig),
	}
	if difficulty > 0 {
		env.PoWNonce = core.ComputePoWConcurrent(idBytes, difficulty, runtime.NumCPU())
	}
	return env, nil
}

// VerifyFull is the single acceptance check for an inbound envelope, run at
// every ingress (API /chat/send and the p2p account_chat handler). Checks are
// ordered cheapest-first so garbage is shed before the expensive signature
// verify: fields → freshness → canonical ID → PoW (on the recomputed ID, so
// the work is bound to the identity it prices) → key derivation → signature.
// difficulty 0 disables the PoW check (PoW-disabled dev/test nodes).
//
// The derivation check (#829) is what makes PubKey trustworthy: the signature
// alone only proves the sender holds PubKey's private half, so without tying
// PubKey back to From anyone could sign as anyone. It runs before the
// signature verify because it is the cheaper of the two and because a
// signature under an unrelated key is meaningless.
func (e *Envelope) VerifyFull(difficulty uint64) error {
	if e.From == "" || e.PubKey == "" || e.To == "" || e.Message == "" || e.Timestamp == 0 || e.Signature == "" {
		return fmt.Errorf("missing required fields")
	}
	if len(e.Message) > MaxMessageBytes {
		return fmt.Errorf("message exceeds maximum length of %d bytes", MaxMessageBytes)
	}

	if skew := core.Now().UnixNano() - e.Timestamp; skew > int64(MaxEnvelopeSkew) || skew < -int64(MaxEnvelopeSkew) {
		return fmt.Errorf("envelope timestamp outside freshness window")
	}

	expectedID := ComputeEnvelopeID(e.From, e.PubKey, e.To, e.Message, e.Timestamp)
	if e.ID != expectedID {
		return fmt.Errorf("envelope ID mismatch")
	}

	idBytes, _ := hex.DecodeString(e.ID)
	if difficulty > 0 && !core.ValidatePoW(idBytes, e.PoWNonce, difficulty) {
		return fmt.Errorf("insufficient proof of work")
	}
	if err := core.VerifyPayloadKey(e.PubKey, e.From); err != nil {
		return fmt.Errorf("envelope key: %w", err)
	}
	return core.VerifyHexSignature(e.PubKey, e.Signature, idBytes)
}
