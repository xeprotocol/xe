package core

import (
	"strings"
	"testing"
)

func TestVerifyMultisigRejectsShortAndNonHexPublicKeyWithoutPanic(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ks := &Keyset{
		Threshold: 1,
		Keys:      []string{kp1.PubKeyHex()},
	}
	hash := strings.Repeat("a", 64)
	dummySig := strings.Repeat("b", 128)

	for _, badPK := range []string{"", "a", "abcde", strings.Repeat("z", 64)} {
		sigs := []BlockSignature{{PublicKey: badPK, Sig: dummySig}}
		if err := VerifyMultisig(hash, sigs, ks); err == nil {
			t.Fatalf("expected VerifyMultisig to reject public_key %q, got nil", badPK)
		}
		if err := VerifyMultisigAny(hash, sigs, ks); err == nil {
			t.Fatalf("expected VerifyMultisigAny to reject public_key %q, got nil", badPK)
		}
	}

	if err := VerifyMultisig(hash, []BlockSignature{{PublicKey: kp1.PubKeyHex(), Sig: dummySig}}, nil); err == nil {
		t.Fatalf("expected VerifyMultisig to reject nil keyset")
	}
	if err := VerifyMultisigAny(hash, []BlockSignature{{PublicKey: kp1.PubKeyHex(), Sig: dummySig}}, nil); err == nil {
		t.Fatalf("expected VerifyMultisigAny to reject nil keyset")
	}
}
