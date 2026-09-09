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

const registrationDomainTag = "xe/directory-registration/v1\x00"

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

	if err := core.VerifyPayloadKey(reg.PubKey, reg.Account); err != nil {
		return fmt.Errorf("registration key: %w", err)
	}

	msg := canonicalBytes(reg.Account, reg.PubKey, reg.NodePeer, reg.Timestamp)
	hash := sha256.Sum256(msg)
	return core.VerifyHexSignature(reg.PubKey, reg.Signature, hash[:])
}

func SignRegistration(account, nodePeer string, timestamp int64, privKey ed25519.PrivateKey) string {
	pubKey := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	msg := canonicalBytes(account, pubKey, nodePeer, timestamp)
	hash := sha256.Sum256(msg)
	sig := ed25519.Sign(privKey, hash[:])
	return hex.EncodeToString(sig)
}

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
