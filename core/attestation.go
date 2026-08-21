package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// AttestationPayload computes sha256(lease_hash_bytes || timestamp_big_endian_8_bytes).
func AttestationPayload(leaseHash string, timestamp int64) ([]byte, error) {
	hashBytes, err := DecodeHash(leaseHash)
	if err != nil {
		return nil, err
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	h := sha256.New()
	h.Write(hashBytes)
	h.Write(ts[:])
	return h.Sum(nil), nil
}

// SignAttestation creates a signed timekeeper attestation for a lease.
func SignAttestation(leaseHash string, timestamp int64, kp *KeyPair) (*TimekeeperAttestation, error) {
	payload, err := AttestationPayload(leaseHash, timestamp)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(kp.Private, payload)
	return &TimekeeperAttestation{
		PublicKey: kp.PubKeyHex(),
		Timestamp: timestamp,
		Signature: hex.EncodeToString(sig),
	}, nil
}

// VerifyAttestation checks that a single attestation's signature is valid.
func VerifyAttestation(a *TimekeeperAttestation, leaseHash string) error {
	payload, err := AttestationPayload(leaseHash, a.Timestamp)
	if err != nil {
		return err
	}
	return VerifyHexSignature(a.PublicKey, a.Signature, payload)
}

// DefaultMaxAttestationSkew is the production (mainnet) value for MaxAttestationSkew.
// It is the fallback used when a genesis block does not pin the skew explicitly, so
// the embedded canonical genesis and every existing network keep the production
// 10-minute window with no change.
const DefaultMaxAttestationSkew = int64(10 * time.Minute)

// MaxAttestationSkew is the maximum allowed difference between an attested
// timestamp and the current time. Attestations with timestamps beyond this
// window are rejected to prevent a malicious timekeeper from signing
// far-future timestamps that would allow instant lease settlement.
//
// It is read from the ledger genesis at load (ApplyGenesisLeaseTiming), defaulting
// to the production value above (#662). Consensus-critical: it gates
// ValidateAttestations, so it lives on the genesis block where every node agrees by
// construction — same reasoning as the #524 lease-timing fields. Pinning a small
// skew lets a compressed test network shrink the force-settle gap below the
// production 20-minute floor; ValidateGenesisBlock keeps enforcing
// LeaseForceSettleGap > 2×MaxAttestationSkew against the genesis-pinned value.
var MaxAttestationSkew = DefaultMaxAttestationSkew

// MaxAttestationsPerBlock is the hard cap on attestations a block may carry.
// This prevents DoS via oversized attestation arrays during gossip/validation.
const MaxAttestationsPerBlock = 20

// ValidateAttestations checks that enough valid attestations exist from
// distinct trusted timekeepers. Returns the median attested timestamp.
// skipSkew=true bypasses the MaxAttestationSkew bound: used by sync to
// accept historical attestations whose timestamp is far from Now(),
// mirroring the skipTimestamp flag in Ledger.addBlock.
func ValidateAttestations(attestations []TimekeeperAttestation, leaseHash string, config *TimekeeperConfig, skipSkew bool) (int64, error) {
	if config == nil {
		return 0, fmt.Errorf("no timekeeper config")
	}
	if config.Threshold == 0 {
		return 0, fmt.Errorf("timekeeper threshold is zero")
	}
	if len(attestations) > MaxAttestationsPerBlock {
		return 0, fmt.Errorf("too many attestations: %d exceeds max %d", len(attestations), MaxAttestationsPerBlock)
	}
	if len(attestations) < config.Threshold {
		return 0, fmt.Errorf("need %d attestations, got %d", config.Threshold, len(attestations))
	}

	trusted := make(map[string]bool, len(config.Keys))
	for _, k := range config.Keys {
		trusted[k] = true
	}

	now := Now().UnixNano()
	seen := make(map[string]bool)
	var validTimestamps []int64
	for _, a := range attestations {
		if !trusted[a.PublicKey] {
			continue
		}
		if seen[a.PublicKey] {
			continue
		}
		if err := VerifyAttestation(&a, leaseHash); err != nil {
			continue
		}
		// Reject timestamps too far from current time. Skipped during
		// sync replay so historical blocks can land — mirrors the
		// skipTimestamp escape in Ledger.addBlock.
		if !skipSkew {
			delta := a.Timestamp - now
			if delta < 0 {
				delta = -delta
			}
			if delta > MaxAttestationSkew {
				continue
			}
		}
		seen[a.PublicKey] = true
		validTimestamps = append(validTimestamps, a.Timestamp)
	}

	if len(validTimestamps) < config.Threshold {
		return 0, fmt.Errorf("only %d valid attestations from trusted timekeepers, need %d", len(validTimestamps), config.Threshold)
	}

	sort.Slice(validTimestamps, func(i, j int) bool { return validTimestamps[i] < validTimestamps[j] })
	// Use lower-middle for even counts: conservative (underestimates time).
	// This prevents a single compromised timekeeper from biasing the median
	// upward to make lease_settle pass earlier than it should.
	median := validTimestamps[(len(validTimestamps)-1)/2]
	return median, nil
}
