package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

func DeriveMultisigAddress(ks *Keyset) (string, error) {
	if err := ValidateKeyset(ks); err != nil {
		return "", err
	}
	sorted := make([]string, len(ks.Keys))
	copy(sorted, ks.Keys)
	sort.Strings(sorted)

	h := sha256.New()
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(ks.Threshold))
	h.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:], uint32(len(sorted)))
	h.Write(buf[:])
	for _, k := range sorted {
		kb, err := hex.DecodeString(k)
		if err != nil {
			return "", fmt.Errorf("invalid key hex: %w", err)
		}
		h.Write(kb)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ValidateKeyset(ks *Keyset) error {
	if ks == nil {
		return fmt.Errorf("keyset is nil")
	}
	if len(ks.Keys) == 0 {
		return fmt.Errorf("keyset has no keys")
	}
	if ks.Threshold < 1 {
		return fmt.Errorf("keyset threshold must be >= 1, got %d", ks.Threshold)
	}
	if ks.Threshold > len(ks.Keys) {
		return fmt.Errorf("keyset threshold %d exceeds key count %d", ks.Threshold, len(ks.Keys))
	}
	seen := make(map[string]bool, len(ks.Keys))
	for i, k := range ks.Keys {
		if len(k) != 64 {
			return fmt.Errorf("key %d: expected 64 hex chars, got %d", i, len(k))
		}
		if _, err := hex.DecodeString(k); err != nil {
			return fmt.Errorf("key %d: invalid hex: %w", i, err)
		}
		lower := hex.EncodeToString(mustDecodeHex(k))
		if seen[lower] {
			return fmt.Errorf("duplicate key: %s", k[:12])
		}
		seen[lower] = true
	}
	return nil
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustDecodeHex: " + err.Error())
	}
	return b
}

func VerifyMultisig(hash string, sigs []BlockSignature, ks *Keyset) error {
	if len(sigs) == 0 {
		return fmt.Errorf("no signatures")
	}

	keysetMap := make(map[string]bool, len(ks.Keys))
	for _, k := range ks.Keys {
		keysetMap[k] = true
	}

	hashBytes, err := DecodeHash(hash)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}

	seen := make(map[string]bool, len(sigs))
	validCount := 0

	for _, sig := range sigs {
		pk := sig.PublicKey
		if seen[pk] {
			return fmt.Errorf("duplicate signer: %s", pk[:12])
		}
		seen[pk] = true

		if !keysetMap[pk] {
			return fmt.Errorf("signer %s not in keyset", pk[:12])
		}

		if err := VerifyHexSignature(pk, sig.Sig, hashBytes); err != nil {
			return fmt.Errorf("sig from %s: %w", pk[:12], err)
		}
		validCount++
	}

	if validCount < ks.Threshold {
		return fmt.Errorf("insufficient signatures: got %d, need %d", validCount, ks.Threshold)
	}
	return nil
}

func VerifyMultisigAny(hash string, sigs []BlockSignature, ks *Keyset) error {
	if len(sigs) == 0 {
		return fmt.Errorf("no signatures")
	}

	keysetMap := make(map[string]bool, len(ks.Keys))
	for _, k := range ks.Keys {
		keysetMap[k] = true
	}

	hashBytes, err := DecodeHash(hash)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}

	for _, sig := range sigs {
		if !keysetMap[sig.PublicKey] {
			continue
		}
		if err := VerifyHexSignature(sig.PublicKey, sig.Sig, hashBytes); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no valid signature from any keyset member")
}

func IsSpendingOp(t BlockType) bool {
	switch t {
	case BlockSend, BlockBurn, BlockLease, BlockMultisigOpen, BlockMultisigUpdate, BlockMint:
		return true
	default:
		return false
	}
}
