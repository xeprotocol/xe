package statechain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/xeprotocol/xe/core"
)

// HashBlock computes the SHA-256 hash of a block's canonical encoding.
func HashBlock(b *Block) (string, error) {
	data, err := MarshalCanonical(b)
	if err != nil {
		return "", fmt.Errorf("HashBlock: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SignBlock signs the block hash with the given private key and returns a BlockSignature.
// The block's Hash field must already be set.
func SignBlock(b *Block, priv ed25519.PrivateKey) (BlockSignature, error) {
	hashBytes, err := core.DecodeHash(b.Hash)
	if err != nil {
		return BlockSignature{}, fmt.Errorf("SignBlock: %w", err)
	}
	sig := ed25519.Sign(priv, hashBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return BlockSignature{
		PublicKey: hex.EncodeToString(pub),
		Sig:       hex.EncodeToString(sig),
	}, nil
}

// VerifySignature checks that a single signature is valid for the given block hash.
func VerifySignature(hash string, sig BlockSignature) error {
	hashBytes, err := core.DecodeHash(hash)
	if err != nil {
		return err
	}
	return core.VerifyHexSignature(sig.PublicKey, sig.Sig, hashBytes)
}

// VerifyBlockHash recomputes the canonical hash and checks it matches block.Hash.
func VerifyBlockHash(b *Block) error {
	expected, err := HashBlock(b)
	if err != nil {
		return fmt.Errorf("VerifyBlockHash: %w", err)
	}
	if b.Hash != expected {
		return fmt.Errorf("hash mismatch: got %s, want %s", b.Hash, expected)
	}
	return nil
}
