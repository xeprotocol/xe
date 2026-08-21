package net

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

// Domain tags give each marketplace message type a distinct signing domain so
// no two types can ever produce identical signing bytes, and binding the
// networkID scopes signatures to one network incarnation
// (wipe-and-rebootstrap) — the same pattern as the certificate hash (#594).
// (#605)
const (
	advertisementDomainTag = "xe/marketplace-advertisement/v1\x00"
	requestDomainTag       = "xe/marketplace-request/v1\x00"
	offerDomainTag         = "xe/marketplace-offer/v1\x00"
)

// canonicalFields writes the fixed domain tag, then the networkID and each
// field framed with an 8-byte big-endian length prefix so the concatenation is
// unambiguous. #570/L6: the previous '|'-delimited form let an
// attacker-controlled variable-length field (e.g. RequestID) absorb a
// delimiter — Consumer="a|b"/RequestID="c" and Consumer="a"/RequestID="b|c"
// produced identical bytes, so one signature validated two different field
// splits. Length-prefixing removes the boundary ambiguity entirely.
func canonicalFields(domainTag string, fields ...string) []byte {
	var b bytes.Buffer
	var lenBuf [8]byte
	b.WriteString(domainTag)
	writeField := func(f string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(f)))
		b.Write(lenBuf[:])
		b.WriteString(f)
	}
	writeField(core.GetNetworkID())
	for _, f := range fields {
		writeField(f)
	}
	return b.Bytes()
}

// Each canonical form frames the signer's public key immediately after the
// account address it certifies (#829). Marketplace messages ride gossip and are
// validated with no ledger lookup, so they must be self-certifying: since an
// address is now sha256("xe/account/v1" || pubkey), the address alone cannot
// check a signature. Binding the key into the signed bytes is what stops it
// being swapped for an attacker's key in transit.
func advertisementCanonical(ad *ResourceAdvertisement) []byte {
	return canonicalFields(
		advertisementDomainTag,
		ad.Provider,
		ad.ProviderPubKey,
		strconv.FormatUint(ad.VCPUs, 10),
		strconv.FormatUint(ad.MemoryMB, 10),
		strconv.FormatUint(ad.DiskGB, 10),
		strconv.FormatUint(ad.MaxConcurrentLeases, 10),
		strconv.FormatInt(ad.Timestamp, 10),
	)
}

func requestCanonical(req *ResourceRequest) []byte {
	return canonicalFields(
		requestDomainTag,
		req.Consumer,
		req.ConsumerPubKey,
		req.RequestID,
		strconv.FormatUint(req.VCPUs, 10),
		strconv.FormatUint(req.MemoryMB, 10),
		strconv.FormatUint(req.DiskGB, 10),
		strconv.FormatUint(req.Duration, 10),
		strconv.FormatInt(req.Timestamp, 10),
	)
}

func offerCanonical(offer *ResourceOffer) []byte {
	return canonicalFields(
		offerDomainTag,
		offer.Provider,
		offer.ProviderPubKey,
		offer.RequestID,
		strconv.FormatUint(offer.VCPUs, 10),
		strconv.FormatUint(offer.MemoryMB, 10),
		strconv.FormatUint(offer.DiskGB, 10),
		strconv.FormatUint(offer.Duration, 10),
		strconv.FormatUint(offer.TotalCost, 10),
		offer.CertificateHash,
		strconv.FormatInt(offer.Timestamp, 10),
	)
}

func signPayload(payload []byte, privKey ed25519.PrivateKey) string {
	hash := sha256.Sum256(payload)
	sig := ed25519.Sign(privKey, hash[:])
	return hex.EncodeToString(sig)
}

// verifyPayload ties the declared key to the claimed account address, then
// verifies the signature under that key. The derivation check must come first:
// a signature that verifies under a key the sender chose says nothing about the
// account the message names (#829).
func verifyPayload(payload []byte, pubKeyHex, account, signatureHex string) error {
	if signatureHex == "" {
		return fmt.Errorf("missing signature")
	}
	if err := core.VerifyPayloadKey(pubKeyHex, account); err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	return core.VerifyHexSignature(pubKeyHex, signatureHex, hash[:])
}

// pubKeyHexOf returns the hex public key belonging to privKey. The signers
// declare the key themselves rather than trusting a caller-populated field, so
// the declared key is always the signing key (#829).
func pubKeyHexOf(privKey ed25519.PrivateKey) string {
	return hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
}

func SignAdvertisement(ad *ResourceAdvertisement, privKey ed25519.PrivateKey) {
	ad.ProviderPubKey = pubKeyHexOf(privKey)
	ad.Signature = signPayload(advertisementCanonical(ad), privKey)
}

func VerifyAdvertisement(ad *ResourceAdvertisement) error {
	if ad.Provider == "" {
		return fmt.Errorf("missing provider")
	}
	return verifyPayload(advertisementCanonical(ad), ad.ProviderPubKey, ad.Provider, ad.Signature)
}

func SignRequest(req *ResourceRequest, privKey ed25519.PrivateKey) {
	req.ConsumerPubKey = pubKeyHexOf(privKey)
	req.Signature = signPayload(requestCanonical(req), privKey)
}

func VerifyRequest(req *ResourceRequest) error {
	if req.Consumer == "" {
		return fmt.Errorf("missing consumer")
	}
	return verifyPayload(requestCanonical(req), req.ConsumerPubKey, req.Consumer, req.Signature)
}

func SignOffer(offer *ResourceOffer, privKey ed25519.PrivateKey) {
	offer.ProviderPubKey = pubKeyHexOf(privKey)
	offer.Signature = signPayload(offerCanonical(offer), privKey)
}

func VerifyOffer(offer *ResourceOffer) error {
	if offer.Provider == "" {
		return fmt.Errorf("missing provider")
	}
	return verifyPayload(offerCanonical(offer), offer.ProviderPubKey, offer.Provider, offer.Signature)
}
