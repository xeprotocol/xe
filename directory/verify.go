package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/xeprotocol/xe/core"
)

// registrationDomainTag domain-separates registration signatures; the
// networkID written after it scopes them to one network incarnation — the
// same pattern as the certificate hash (#594). (#605)
const registrationDomainTag = "xe/directory-registration/v1\x00"

// canonicalBytes frames each field with an 8-byte big-endian length prefix so
// the concatenation is unambiguous (#605 — the last remaining '|'-delimited
// signing payload after #595 fixed the marketplace ones).
//
// pubKey is framed in alongside the account it certifies (#829) so the key a
// verifier checks the signature against cannot be swapped in transit: change it
// and the signature no longer covers these bytes.
func canonicalBytes(account, pubKey, nodePeer string, timestamp int64) []byte {
	var b bytes.Buffer
	var lenBuf [8]byte
	b.WriteString(registrationDomainTag)
	for _, f := range []string{core.GetNetworkID(), account, pubKey, nodePeer, strconv.FormatInt(timestamp, 10)} {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(f)))
		b.Write(lenBuf[:])
		b.WriteString(f)
	}
	return b.Bytes()
}

func VerifyRegistration(reg *Registration) error {
	if reg.Account == "" {
		return fmt.Errorf("missing account")
	}
	if reg.PubKey == "" {
		return fmt.Errorf("missing pub_key")
	}
	if reg.NodePeer == "" {
		return fmt.Errorf("missing node_peer")
	}
	if reg.Timestamp == 0 {
		return fmt.Errorf("missing timestamp")
	}
	if reg.Signature == "" {
		return fmt.Errorf("missing signature")
	}

	// #829: tie the declared key to the claimed address BEFORE checking the
	// signature — otherwise an attacker signs a registration for any account
	// with a key they own and the signature verifies.
	if err := core.VerifyPayloadKey(reg.PubKey, reg.Account); err != nil {
		return fmt.Errorf("registration key: %w", err)
	}

	msg := canonicalBytes(reg.Account, reg.PubKey, reg.NodePeer, reg.Timestamp)
	hash := sha256.Sum256(msg)
	return core.VerifyHexSignature(reg.PubKey, reg.Signature, hash[:])
}

// SignRegistration returns the hex signature over a registration's canonical
// bytes. The public key bound into those bytes is derived from privKey, so the
// declared key is always the one that signed; the caller must copy it into the
// record's PubKey field (or use NewRegistration, which does both).
func SignRegistration(account, nodePeer string, timestamp int64, privKey ed25519.PrivateKey) string {
	pubKey := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	msg := canonicalBytes(account, pubKey, nodePeer, timestamp)
	hash := sha256.Sum256(msg)
	sig := ed25519.Sign(privKey, hash[:])
	return hex.EncodeToString(sig)
}

// NewRegistration builds a complete, signed registration for kp's account. It
// is the one construction path that cannot forget to declare PubKey (#829).
func NewRegistration(nodePeer string, timestamp int64, kp *core.KeyPair) *Registration {
	account := kp.Address()
	return &Registration{
		Account:   account,
		PubKey:    kp.PubKeyHex(),
		NodePeer:  nodePeer,
		Timestamp: timestamp,
		Signature: SignRegistration(account, nodePeer, timestamp, kp.Private),
	}
}
