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
	// CertificateValidity is how long a certificate is valid after issuance.
	CertificateValidity = 7 * 24 * time.Hour // 7 days
)

// Certificate is a cryptographic proof that a provider's machine completed
// a known benchmark in a measured amount of time. Start and end times are
// attested by trusted timekeepers.
//
// Attestations are stored as merkle roots (64-byte hex each) instead of
// full arrays, keeping the certificate compact (~700 bytes vs ~2.6 KB).
// Full attestations are available from the provider via API.
type Certificate struct {
	Provider string `json:"provider"` // ADDRESS: the provider's account address
	// ProviderPubKey is the provider's ed25519 public key — a VERIFYING KEY,
	// not an address. Since #829 Provider is sha256("xe/account/v1" || pubkey),
	// so the certificate no longer carries a key that can check its own
	// signature. Certificates arrive over gossip and the on-connect pull and
	// must verify statelessly (a cold-syncing node has no ledger view of the
	// provider yet), so the certificate self-certifies: this key is hashed into
	// Hash — which is what the signature covers — and is checked to derive
	// Provider before the signature is verified. The ledger still compares
	// Provider against the lease block's Destination (core/ledger.go), so the
	// address remains the identity the chain binds to.
	ProviderPubKey  string  `json:"provider_pub_key"`
	Seed            string  `json:"seed"`             // hex, derived from start attestation + provider key
	WorkloadVersion uint64  `json:"workload_version"` // benchmark algorithm version
	Iterations      uint64  `json:"iterations"`       // hash chain length
	WorkProof       string  `json:"work_proof"`       // hex, final hash of chain
	Score           float64 `json:"score"`            // 1.0 / elapsed_seconds

	// Compact attestation proofs (merkle roots).
	StartAttestationRoot string `json:"start_attestation_root"` // merkle root of start attestations
	EndAttestationRoot   string `json:"end_attestation_root"`   // merkle root of end attestations
	StartMedian          int64  `json:"start_median"`           // median start timestamp (nanos)
	EndMedian            int64  `json:"end_median"`             // median end timestamp (nanos)

	IssuedAt  int64 `json:"issued_at"`  // == StartMedian
	ExpiresAt int64 `json:"expires_at"` // issued_at + validity period

	// PriceMultiplierMilli scales the baseline lease cost. Scaled ×1000
	// (1000 = 1.000×, 2500 = 2.500×). Must be within [PriceMultiplierMin,
	// PriceMultiplierMax]; issuers set PriceMultiplierDefault for baseline.
	PriceMultiplierMilli uint64 `json:"price_multiplier_milli"`

	Signature string `json:"signature"` // provider signs the certificate
	Hash      string `json:"hash"`      // sha256 of canonical content
}

// PriceMultiplierBounds — sanity guard only. Real bounds (relative to
// network ref_rate) will come from #265/#293.
const (
	PriceMultiplierMin     uint64 = 500   // 0.500×
	PriceMultiplierMax     uint64 = 10000 // 10.000×
	PriceMultiplierDefault uint64 = 1000  // 1.000×
)

// RFC 6962 domain separators distinguish leaf hashes from internal node
// hashes, blocking second-preimage attacks where an attacker substitutes a
// 32-byte leaf for an internal node (or vice versa) — see #427.
const (
	merkleLeafPrefix     byte = 0x00
	merkleInternalPrefix byte = 0x01
)

// AttestationMerkleRoot computes a merkle root over a set of attestations.
// Each attestation is hashed individually into a domain-separated leaf, then
// pairs are combined under the internal-node prefix until a single root
// remains. For odd counts, the last hash is promoted unchanged (it remains a
// leaf at its level — a known asymmetric design; see RFC 6962 §2.1 for
// alternatives if uniform tree depth is later required).
func AttestationMerkleRoot(attestations []core.TimekeeperAttestation) string {
	if len(attestations) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Sort by public key for deterministic ordering.
	sorted := make([]core.TimekeeperAttestation, len(attestations))
	copy(sorted, attestations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].PublicKey < sorted[j].PublicKey
	})

	// Hash each attestation into a domain-separated leaf.
	hashes := make([][32]byte, len(sorted))
	for i, att := range sorted {
		h := sha256.New()
		h.Write([]byte{merkleLeafPrefix})
		h.Write([]byte(att.PublicKey))
		writeInt64(h, att.Timestamp)
		h.Write([]byte(att.Signature))
		copy(hashes[i][:], h.Sum(nil))
	}

	// Build merkle tree. Internal nodes are prefixed with 0x01 so a 32-byte
	// leaf cannot be substituted for an internal node with the same content.
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
				next = append(next, hashes[i]) // promote odd leaf
			}
		}
		hashes = next
	}

	return hex.EncodeToString(hashes[0][:])
}

// HashCertificate computes the SHA-256 hash of the certificate's content
// (excluding signature and hash fields).
func HashCertificate(c *Certificate) string {
	h := sha256.New()
	// #570/L4: domain separation + network scoping. Block hashes are
	// networkID-prefixed; certificates were not, so a ≤7-day-old cert from a
	// prior testnet incarnation re-verified after a wipe and could back
	// lease_accepts on the new network. The fixed tag also separates this
	// pre-image from any other SHA-256 use.
	h.Write([]byte("xe/perf-certificate/v1\x00"))
	writeLenPrefixed(h, []byte(core.GetNetworkID()))
	// #570/L5: length-prefix every variable-length field so byte-shifting
	// between adjacent fields (Provider/Seed/WorkProof/roots) can't produce two
	// distinct certificates that share one hash (and thus one signature).
	writeLenPrefixed(h, []byte(c.Provider))
	// #829: the verifying key is hashed in next to the address it certifies,
	// so the signature covers it and it cannot be swapped in transit.
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

// SignCertificate declares the provider's verifying key, computes the hash and
// signs it with the provider's key. The key is taken from kp rather than from
// the caller-populated struct, so an issuer can never declare a key other than
// the one that signs (#829) — the same reason core.SignBlock populates a block's
// PubKey itself.
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

// VerifyCertificate checks the certificate's content and that it has not
// expired as of now. Use this wherever a certificate must be usable *right
// now*: quoting an offer, accepting a lease.
//
// To decide whether a certificate may be retained or served to a peer, use
// VerifyCertificateContent — expiry is a point-in-time property, but retention
// is about history (#816).
func VerifyCertificate(c *Certificate, now int64) error {
	if err := VerifyCertificateContent(c); err != nil {
		return err
	}
	if now > c.ExpiresAt {
		return fmt.Errorf("certificate expired at %d, now %d", c.ExpiresAt, now)
	}
	return nil
}

// VerifyCertificateContent checks everything about a certificate that holds
// for all time: hash integrity, the provider's signature over that hash, and
// the bounds on its self-declared fields. It deliberately does NOT check
// expiry.
//
// An expired certificate is still a valid signed statement about the past, and
// the lease blocks pinning its hash still need it in order to validate — the
// ledger compares certificate expiry against the *block's* timestamp, never
// against wall-clock time. A node cold-syncing old lease history is therefore
// expected to receive, verify and retain certificates that expired long ago.
//
// This does not verify that the benchmark was actually run: WorkProof and the
// attestation roots are never checked, so a certificate costs one signature.
// That gap is tracked as #817, and is why retention is bounded per provider.
func VerifyCertificateContent(c *Certificate) error {
	expected := HashCertificate(c)
	if c.Hash != expected {
		return fmt.Errorf("certificate hash mismatch")
	}

	hashBytes, err := hex.DecodeString(c.Hash)
	if err != nil {
		return fmt.Errorf("invalid certificate hash hex")
	}
	// #829: bind the declared key to the claimed provider address before
	// trusting a signature made under that key. Without this any key holder
	// could issue certificates naming any provider address.
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

// writeLenPrefixed writes an 8-byte big-endian length followed by b, so that
// concatenated variable-length fields are unambiguously framed (#570/L5).
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
