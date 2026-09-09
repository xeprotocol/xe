package perf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/xeprotocol/xe/core"
)

const (
	CertificateValidity = 7 * 24 * time.Hour
)

type Certificate struct {
	Provider string `json:"provider"`

	ProviderPubKey  string  `json:"provider_pub_key"`
	Seed            string  `json:"seed"`
	WorkloadVersion uint64  `json:"workload_version"`
	Iterations      uint64  `json:"iterations"`
	WorkProof       string  `json:"work_proof"`
	Score           float64 `json:"score"`

	StartAttestationRoot string `json:"start_attestation_root"`
	EndAttestationRoot   string `json:"end_attestation_root"`
	StartMedian          int64  `json:"start_median"`
	EndMedian            int64  `json:"end_median"`

	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`

	PriceMultiplierMilli uint64 `json:"price_multiplier_milli"`

	Signature string `json:"signature"`
	Hash      string `json:"hash"`
}

const (
	PriceMultiplierMin     uint64 = 500
	PriceMultiplierMax     uint64 = 10000
	PriceMultiplierDefault uint64 = 1000
)

const (
	merkleLeafPrefix     byte = 0x00
	merkleInternalPrefix byte = 0x01
)

func AttestationMerkleRoot(attestations []core.TimekeeperAttestation) string {
	if len(attestations) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}

	sorted := make([]core.TimekeeperAttestation, len(attestations))
	copy(sorted, attestations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].PublicKey < sorted[j].PublicKey
	})

	hashes := make([][32]byte, len(sorted))
	for i, att := range sorted {
		h := sha256.New()
		h.Write([]byte{merkleLeafPrefix})
		h.Write([]byte(att.PublicKey))
		writeInt64(h, att.Timestamp)
		h.Write([]byte(att.Signature))
		copy(hashes[i][:], h.Sum(nil))
	}

	for len(hashes) > 1 {
		var next [][32]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				h := sha256.New()
				h.Write([]byte{merkleInternalPrefix})
				h.Write(hashes[i][:])
				h.Write(hashes[i+1][:])
				var parent [32]byte
				copy(parent[:], h.Sum(nil))
				next = append(next, parent)
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hex.EncodeToString(hashes[0][:])
}

func HashCertificate(c *Certificate) string {
	h := sha256.New()

	h.Write([]byte("xe/perf-certificate/v1\x00"))
	writeLenPrefixed(h, []byte(core.GetNetworkID()))

	writeLenPrefixed(h, []byte(c.Provider))

	writeLenPrefixed(h, []byte(c.ProviderPubKey))
	writeLenPrefixed(h, []byte(c.Seed))
	writeUint64(h, c.WorkloadVersion)
	writeUint64(h, c.Iterations)
	writeLenPrefixed(h, []byte(c.WorkProof))
	writeFloat64(h, c.Score)
	writeLenPrefixed(h, []byte(c.StartAttestationRoot))
	writeLenPrefixed(h, []byte(c.EndAttestationRoot))
	writeInt64(h, c.StartMedian)
	writeInt64(h, c.EndMedian)
	writeInt64(h, c.IssuedAt)
	writeInt64(h, c.ExpiresAt)
	writeUint64(h, c.PriceMultiplierMilli)
	return hex.EncodeToString(h.Sum(nil))
}

func SignCertificate(c *Certificate, kp *core.KeyPair) error {
	c.ProviderPubKey = kp.PubKeyHex()
	c.Hash = HashCertificate(c)
	hashBytes, err := hex.DecodeString(c.Hash)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(kp.Private, hashBytes)
	c.Signature = hex.EncodeToString(sig)
	return nil
}

func VerifyCertificate(c *Certificate, now int64) error {
	if err := VerifyCertificateContent(c); err != nil {
		return err
	}
	if now > c.ExpiresAt {
		return fmt.Errorf("certificate expired at %d, now %d", c.ExpiresAt, now)
	}
	return nil
}

func VerifyCertificateContent(c *Certificate) error {
	expected := HashCertificate(c)
	if c.Hash != expected {
		return fmt.Errorf("certificate hash mismatch")
	}

	hashBytes, err := hex.DecodeString(c.Hash)
	if err != nil {
		return fmt.Errorf("invalid certificate hash hex")
	}

	if err := core.VerifyPayloadKey(c.ProviderPubKey, c.Provider); err != nil {
		return fmt.Errorf("certificate key: %w", err)
	}
	if err := core.VerifyHexSignature(c.ProviderPubKey, c.Signature, hashBytes); err != nil {
		return fmt.Errorf("certificate signature: %w", err)
	}

	if c.Score <= 0 {
		return fmt.Errorf("certificate score must be positive, got %f", c.Score)
	}

	if c.WorkloadVersion != WorkloadVersion {
		return fmt.Errorf("workload version mismatch: got %d, want %d", c.WorkloadVersion, WorkloadVersion)
	}

	if c.Iterations != BenchmarkIterations {
		return fmt.Errorf("iterations mismatch: got %d, want %d", c.Iterations, BenchmarkIterations)
	}

	if c.PriceMultiplierMilli < PriceMultiplierMin || c.PriceMultiplierMilli > PriceMultiplierMax {
		return fmt.Errorf("price_multiplier_milli %d out of bounds [%d, %d]",
			c.PriceMultiplierMilli, PriceMultiplierMin, PriceMultiplierMax)
	}

	return nil
}

func writeUint64(h interface{ Write([]byte) (int, error) }, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = h.Write(b[:])
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	writeUint64(h, uint64(len(b)))
	_, _ = h.Write(b)
}

func writeInt64(h interface{ Write([]byte) (int, error) }, v int64) {
	writeUint64(h, uint64(v))
}

func writeFloat64(h interface{ Write([]byte) (int, error) }, v float64) {
	writeUint64(h, math.Float64bits(v))
}
