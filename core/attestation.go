package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
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

type TimekeeperEra struct {
	Since  int64
	Config *TimekeeperConfig
}

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
		if kb, err := hex.DecodeString(k); err == nil {
			trusted[string(kb)] = true
		}
	}

	now := Now().UnixNano()
	seen := make(map[string]bool)
	var validTimestamps []int64
	for _, a := range attestations {
		pk, err := hex.DecodeString(a.PublicKey)
		if err != nil {
			continue
		}
		if !trusted[string(pk)] {
			continue
		}
		if seen[string(pk)] {
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
		seen[string(pk)] = true
		validTimestamps = append(validTimestamps, a.Timestamp)
	}

	if len(validTimestamps) < config.Threshold {
		return 0, fmt.Errorf("only %d valid attestations from trusted timekeepers, need %d", len(validTimestamps), config.Threshold)
	}

	sort.Slice(validTimestamps, func(i, j int) bool { return validTimestamps[i] < validTimestamps[j] })

	median := validTimestamps[(len(validTimestamps)-1)/2]
	return median, nil
}

func ValidateAttestationsAt(attestations []TimekeeperAttestation, leaseHash string, eras []TimekeeperEra, skipSkew bool) (int64, error) {
	if len(eras) == 0 {
		return 0, fmt.Errorf("no timekeeper config")
	}
	if len(attestations) > MaxAttestationsPerBlock {
		return 0, fmt.Errorf("too many attestations: %d exceeds max %d", len(attestations), MaxAttestationsPerBlock)
	}
	byEra := make([][]TimekeeperAttestation, len(eras))
	for _, a := range attestations {
		i := max(sort.Search(len(eras), func(i int) bool { return eras[i].Since > a.Timestamp })-1, 0)
		byEra[i] = append(byEra[i], a)
	}

	last := len(eras) - 1
	var firstErr error
	for i := last; i >= 0; i-- {
		if i != last && len(byEra[i]) == 0 {
			continue
		}
		median, err := ValidateAttestations(byEra[i], leaseHash, eras[i].Config, skipSkew)
		if err == nil {
			return median, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, a := range byEra[last] {
		if !eraListsKey(eras, a.PublicKey) && VerifyAttestation(&a, leaseHash) == nil {
			return 0, fmt.Errorf("%w (signer %s is in no timekeeper set held here: retry after statechain syncs)", firstErr, shortHash(a.PublicKey))
		}
	}
	return 0, firstErr
}

func eraListsKey(eras []TimekeeperEra, key string) bool {
	for _, e := range eras {
		if e.Config != nil && slices.Contains(e.Config.Keys, key) {
			return true
		}
	}
	return false
}
