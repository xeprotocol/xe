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

var CertificateValidity = 7 * 24 * time.Hour

var AcceptedWorkloadVersions = []uint64{WorkloadVersion}

func IsAcceptedWorkloadVersion(v uint64) bool {
	for _, accepted := range AcceptedWorkloadVersions {
		if v == accepted {
			return true
		}
	}
	return false
}

type Certificate struct {
	Provider string `json:"provider"`

	ProviderPubKey  string `json:"provider_pub_key"`
	Seed            string `json:"seed"`
	WorkloadVersion uint64 `json:"workload_version"`
	Puzzles         uint64 `json:"puzzles"`
	WorkProof       string `json:"work_proof"`

	CPUHash string  `json:"cpu_hash"`
	Score   float64 `json:"score"`

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
	writeUint64(h, c.Puzzles)
	writeLenPrefixed(h, []byte(c.WorkProof))

	writeLenPrefixed(h, []byte(c.CPUHash))
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

const MaxCertificateClockSkew = int64(core.DefaultMaxAttestationSkew)

func VerifyCertificate(c *Certificate, now int64) error {
	if err := VerifyCertificateContent(c); err != nil {
		return err
	}
	if now > 0 {
		if c.IssuedAt > now+MaxCertificateClockSkew {
			return fmt.Errorf("certificate issued_at %d is too far in the future (now %d)", c.IssuedAt, now)
		}
		if now >= c.ExpiresAt {
			return fmt.Errorf("certificate expired at %d, now %d", c.ExpiresAt, now)
		}
	}
	return nil
}

const zeroRootHex = "0000000000000000000000000000000000000000000000000000000000000000"

func VerifyCertificateContent(c *Certificate) error {
	if c == nil {
		return fmt.Errorf("certificate is nil")
	}
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

	if math.IsNaN(c.Score) || math.IsInf(c.Score, 0) || c.Score <= 0 {
		return fmt.Errorf("certificate score must be a finite positive number, got %f", c.Score)
	}

	if !IsAcceptedWorkloadVersion(c.WorkloadVersion) {
		return fmt.Errorf("workload version %d not accepted, accepted set is %v",
			c.WorkloadVersion, AcceptedWorkloadVersions)
	}

	if c.Puzzles != PoWPuzzles {
		return fmt.Errorf("puzzles mismatch: got %d, want %d", c.Puzzles, PoWPuzzles)
	}

	if !isHex64(c.CPUHash) {
		return fmt.Errorf("cpu_hash must be 64 lowercase hex chars, got %q", c.CPUHash)
	}

	if !isHex64(c.WorkProof) || c.WorkProof == zeroRootHex {
		return fmt.Errorf("work_proof must be a non-zero 64 lowercase hex string, got %q", c.WorkProof)
	}

	if !isHex64(c.StartAttestationRoot) || c.StartAttestationRoot == zeroRootHex {
		return fmt.Errorf("start_attestation_root must be a non-zero 64 lowercase hex string")
	}
	if !isHex64(c.EndAttestationRoot) || c.EndAttestationRoot == zeroRootHex {
		return fmt.Errorf("end_attestation_root must be a non-zero 64 lowercase hex string")
	}

	if c.StartMedian <= 0 || c.EndMedian <= c.StartMedian {
		return fmt.Errorf("invalid benchmark median timestamps: start=%d end=%d", c.StartMedian, c.EndMedian)
	}

	pubBytes, err := hex.DecodeString(c.ProviderPubKey)
	if err != nil {
		return fmt.Errorf("invalid provider_pub_key hex: %w", err)
	}
	expectedSeed := SeedHex(DeriveSeed(c.StartMedian, pubBytes))
	if c.Seed != expectedSeed {
		return fmt.Errorf("certificate seed mismatch: got %s, want %s", c.Seed, expectedSeed)
	}

	elapsedSecs := float64(c.EndMedian-c.StartMedian) / 1e9
	expectedScore := 1.0 / elapsedSecs
	if math.IsNaN(expectedScore) || math.IsInf(expectedScore, 0) || math.Abs(c.Score-expectedScore) > 1e-6*(1+expectedScore) {
		return fmt.Errorf("certificate score %.6f does not match elapsed benchmark time %.6fs (expected %.6f)",
			c.Score, elapsedSecs, expectedScore)
	}

	if c.IssuedAt != c.StartMedian {
		return fmt.Errorf("certificate issued_at (%d) must equal start_median (%d)", c.IssuedAt, c.StartMedian)
	}
	if c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("certificate expires_at (%d) must be after issued_at (%d)", c.ExpiresAt, c.IssuedAt)
	}
	if c.ExpiresAt-c.IssuedAt > int64(CertificateValidity) {
		return fmt.Errorf("certificate lifetime %v exceeds maximum validity %v",
			time.Duration(c.ExpiresAt-c.IssuedAt), CertificateValidity)
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

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
