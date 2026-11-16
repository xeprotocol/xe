package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func generateTestKeyPair() (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(pub), priv
}

func signHashHex(priv ed25519.PrivateKey, hash string) string {
	hb, err := hex.DecodeString(hash)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, hb)
	return hex.EncodeToString(sig)
}

func TestMultisigThreshold_LeaseOperationsAreSpendingOps(t *testing.T) {
	leaseOps := []BlockType{
		BlockLeaseAccept,
		BlockLeaseSettle,
		BlockLeaseCancel,
		BlockLeaseForceSettle,
	}

	for _, op := range leaseOps {
		if !IsSpendingOp(op) {
			t.Errorf("expected %s to be classified as spending/authorizing op", op)
		}
	}
}

func TestMultisigThreshold_EnforcesThresholdOnLeaseOperations(t *testing.T) {
	// Create a 2-of-3 keyset
	pub1, priv1 := generateTestKeyPair()
	pub2, priv2 := generateTestKeyPair()
	pub3, _ := generateTestKeyPair()

	ks := &Keyset{
		Keys:      []string{pub1, pub2, pub3},
		Threshold: 2,
	}

	testHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 1-of-3 signature attempt (rogue member)
	sig1 := BlockSignature{
		PublicKey: pub1,
		Sig:       signHashHex(priv1, testHash),
	}

	singleSigList := []BlockSignature{sig1}

	// VerifyMultisig must fail with insufficient signatures
	err := VerifyMultisig(testHash, singleSigList, ks)
	if err == nil {
		t.Fatal("expected 1-of-3 signatures to fail threshold-2 verification")
	}

	// 2-of-3 signature attempt (honest consensus)
	sig2 := BlockSignature{
		PublicKey: pub2,
		Sig:       signHashHex(priv2, testHash),
	}

	thresholdSigList := []BlockSignature{sig1, sig2}

	// VerifyMultisig must succeed
	if err := VerifyMultisig(testHash, thresholdSigList, ks); err != nil {
		t.Fatalf("expected 2-of-3 signatures to succeed, got: %v", err)
	}
}

func TestMultisig_ShortKeySafety(t *testing.T) {
	// Verify that short public keys do not cause slice out of bounds panic
	shortPK := "abc"
	if res := shortKey(shortPK); res != "abc" {
		t.Fatalf("expected 'abc', got %q", res)
	}

	longPK := "0123456789abcdef"
	if res := shortKey(longPK); res != "0123456789ab" {
		t.Fatalf("expected 12 char prefix, got %q", res)
	}
}
