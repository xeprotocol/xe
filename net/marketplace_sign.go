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

const (
	advertisementDomainTag = "xe/marketplace-advertisement/v1\x00"
	requestDomainTag       = "xe/marketplace-request/v1\x00"
	offerDomainTag         = "xe/marketplace-offer/v1\x00"
)

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
