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

const MaxMessageBytes = 8192

const DefaultPoWDifficulty uint64 = 0xffffc00000000000

const MaxEnvelopeSkew = 5 * time.Minute

type Envelope struct {
	ID   string `json:"id"`
	From string `json:"from"`

	PubKey    string `json:"pub_key"`
	To        string `json:"to"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
	PoWNonce  uint64 `json:"pow_nonce"`
}

const chatEnvelopeDomainTag = "xe/chat-envelope/v1\x00"

func envelopeCanonical(from, pubKey, to, message string, timestamp int64) []byte {
	netID := core.GetNetworkID()
	size := len(chatEnvelopeDomainTag) + 4 + len(netID) + 4 + len(from) + 4 + len(pubKey) + 4 + len(to) + 4 + len(message) + 8
	buf := make([]byte, 0, size)
	buf = append(buf, chatEnvelopeDomainTag...)
	buf = appendField(buf, []byte(netID))
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

func NewEnvelope(from, to, message string, kp *core.KeyPair, difficulty uint64) (*Envelope, error) {
	if err := core.ValidateAddress(from); err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}
	if err := core.ValidateAddress(to); err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}
	ts := core.Now().UnixNano()

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

func (e *Envelope) VerifyFull(difficulty uint64) error {
	if e.From == "" || e.PubKey == "" || e.To == "" || e.Message == "" || e.Timestamp <= 0 || e.Signature == "" {
		return fmt.Errorf("missing required fields")
	}
	if err := core.ValidateAddress(e.From); err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	if err := core.ValidateAddress(e.To); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}
	if len(e.Message) > MaxMessageBytes {
		return fmt.Errorf("message exceeds maximum length of %d bytes", MaxMessageBytes)
	}

	now := core.Now().UnixNano()
	maxSkew := int64(MaxEnvelopeSkew)
	if (e.Timestamp > now && e.Timestamp-now > maxSkew) || (now > e.Timestamp && now-e.Timestamp > maxSkew) {
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
