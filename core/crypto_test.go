package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustGenKPForTest(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func TestVerifyBlock_OpenBlock_Valid(t *testing.T) {
	kp := mustGenKPForTest(t)
	addr := MustDeriveAddress(kp.PubKeyHex())

	b := &Block{
		Type:        BlockSend,
		Account:     addr,
		Previous:    "0",
		Destination: strings.Repeat("2", 64),
		Amount:      500,
	}
	if err := SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}

	if err := VerifyBlock(b); err != nil {
		t.Fatalf("expected VerifyBlock to succeed, got %v", err)
	}
}

func TestVerifyBlock_OpenBlock_InvalidSignature(t *testing.T) {
	kp := mustGenKPForTest(t)
	addr := MustDeriveAddress(kp.PubKeyHex())

	b := &Block{
		Type:        BlockSend,
		Account:     addr,
		Previous:    "0",
		PubKey:      kp.PubKeyHex(),
		Destination: strings.Repeat("2", 64),
		Signature:   strings.Repeat("a", 128),
		Amount:      500,
	}
	h, err := HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	if err := VerifyBlock(b); err == nil {
		t.Fatalf("expected VerifyBlock to fail on garbage signature, but succeeded")
	}
}

func TestVerifyBlock_HashMismatch(t *testing.T) {
	kp := mustGenKPForTest(t)
	addr := MustDeriveAddress(kp.PubKeyHex())

	b := &Block{
		Type:        BlockSend,
		Account:     addr,
		Previous:    "0",
		Destination: strings.Repeat("2", 64),
		Amount:      500,
	}
	if err := SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	b.Hash = strings.Repeat("0", 64)

	if err := VerifyBlock(b); err == nil {
		t.Fatalf("expected VerifyBlock to fail on hash mismatch, but succeeded")
	}
}

func TestVerifyBlock_MultisigOpen(t *testing.T) {
	kp1 := mustGenKPForTest(t)
	kp2 := mustGenKPForTest(t)
	ks := &Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	msAddr, err := DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	t.Run("valid multisig open", func(t *testing.T) {
		b := &Block{
			Type:     BlockMultisigOpen,
			Account:  msAddr,
			Previous: "0",
			MSKeyset: ks,
			Amount:   1000,
		}
		h, err := HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		b.Hash = h
		hashBytes, _ := hex.DecodeString(h)

		sig1 := ed25519.Sign(kp1.Private, hashBytes)
		sig2 := ed25519.Sign(kp2.Private, hashBytes)
		b.Signatures = []BlockSignature{
			{PublicKey: kp1.PubKeyHex(), Sig: hex.EncodeToString(sig1)},
			{PublicKey: kp2.PubKeyHex(), Sig: hex.EncodeToString(sig2)},
		}

		if err := VerifyBlock(b); err != nil {
			t.Fatalf("expected VerifyBlock to succeed for multisig open, got %v", err)
		}
	})

	t.Run("garbage multisig signatures", func(t *testing.T) {
		b := &Block{
			Type:     BlockMultisigOpen,
			Account:  msAddr,
			Previous: "0",
			MSKeyset: ks,
			Amount:   1000,
		}
		h, err := HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		b.Hash = h
		b.Signatures = []BlockSignature{
			{PublicKey: kp1.PubKeyHex(), Sig: strings.Repeat("1", 128)},
			{PublicKey: kp2.PubKeyHex(), Sig: strings.Repeat("2", 128)},
		}

		if err := VerifyBlock(b); err == nil {
			t.Fatalf("expected VerifyBlock to fail on garbage multisig signatures, but succeeded")
		}
	})

	t.Run("missing keyset on multisig open", func(t *testing.T) {
		b := &Block{
			Type:     BlockMultisigOpen,
			Account:  msAddr,
			Previous: "0",
			MSKeyset: nil,
			Hash:     strings.Repeat("0", 64),
			Amount:   1000,
			Signatures: []BlockSignature{
				{PublicKey: kp1.PubKeyHex(), Sig: strings.Repeat("1", 128)},
			},
		}

		if err := VerifyBlock(b); err == nil {
			t.Fatalf("expected VerifyBlock to fail on nil MSKeyset, but succeeded")
		}
	})
}

func TestErrUnopenedAccount_IsRetryable(t *testing.T) {
	err := fmt.Errorf("signature: %w for %s", ErrUnopenedAccount, "testaddr")
	if !errors.Is(err, ErrUnopenedAccount) {
		t.Fatalf("expected errors.Is(err, ErrUnopenedAccount) to be true")
	}
	if !IsRetryableError(err) {
		t.Fatalf("expected IsRetryableError(err) to be true for ErrUnopenedAccount")
	}
}
