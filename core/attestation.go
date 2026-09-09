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

func VerifyAttestation(a *TimekeeperAttestation, leaseHash string) error {
	payload, err := AttestationPayload(leaseHash, a.Timestamp)
	if err != nil {
		return err
	}
	return VerifyHexSignature(a.PublicKey, a.Signature, payload)
}

const DefaultMaxAttestationSkew = int64(10 * time.Minute)

var MaxAttestationSkew = DefaultMaxAttestationSkew

const MaxAttestationsPerBlock = 20

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

	median := validTimestamps[(len(validTimestamps)-1)/2]
	return median, nil
}
