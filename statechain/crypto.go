package statechain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/xeprotocol/xe/core"
)

func HashBlock(b *Block) (string, error) {
	data, err := MarshalCanonical(b)
	if err != nil {
		return "", fmt.Errorf("HashBlock: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

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

func VerifySignature(hash string, sig BlockSignature) error {
	hashBytes, err := core.DecodeHash(hash)
	if err != nil {
		return err
	}
	return core.VerifyHexSignature(sig.PublicKey, sig.Sig, hashBytes)
}

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
