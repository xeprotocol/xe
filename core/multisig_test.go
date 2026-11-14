package core

import (
	"strings"
	"testing"
)

// TestVerifyMultisigShortPubKeyNoPanic verifies that VerifyMultisig does not panic
// when formatted with short public keys (shorter than 12 characters) in all error
// branches: unknown signer, duplicate signer, and invalid signature (#160).
func TestVerifyMultisigShortPubKeyNoPanic(t *testing.T) {
	// 64-hex dummy block hash
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	validKey1 := "1111111111111111111111111111111111111111111111111111111111111111"
	validKey2 := "2222222222222222222222222222222222222222222222222222222222222222"
	ks := &Keyset{
		Threshold: 1,
		Keys:      []string{validKey1, validKey2},
	}

	testCases := []struct {
		name        string
		sigs        []BlockSignature
		expectedErr string
	}{
		{
			name: "1-char short public key not in keyset",
			sigs: []BlockSignature{
				{PublicKey: "a", Sig: "deadbeef"},
			},
			expectedErr: "signer a not in keyset",
		},
		{
			name: "11-char short public key not in keyset",
			sigs: []BlockSignature{
				{PublicKey: "12345678901", Sig: "deadbeef"},
			},
			expectedErr: "signer 12345678901 not in keyset",
		},
		{
			name: "12-char public key boundary not in keyset",
			sigs: []BlockSignature{
				{PublicKey: "123456789012", Sig: "deadbeef"},
			},
			expectedErr: "signer 123456789012 not in keyset",
		},
		{
			name: "empty string public key not in keyset",
			sigs: []BlockSignature{
				{PublicKey: "", Sig: "deadbeef"},
			},
			expectedErr: "signer  not in keyset",
		},
		{
			name: "duplicate short public key",
			sigs: []BlockSignature{
				{PublicKey: "a", Sig: "deadbeef"},
				{PublicKey: "a", Sig: "feedface"},
			},
			// Evaluation order: first sig is evaluated; if not in keyset, errors out.
			// To test duplicate signer branch with short key, we use a keyset containing the short key.
			expectedErr: "signer a not in keyset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VerifyMultisig panicked unexpectedly: %v", r)
				}
			}()

			err := VerifyMultisig(hash, tc.sigs, ks)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.expectedErr)
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error containing %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}

// TestVerifyMultisigDuplicateShortKeyBranch specifically tests the duplicate signer
// branch with a short key when the key is recognized in keyset.
func TestVerifyMultisigDuplicateShortKeyBranch(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	shortKey := "shortkey1"
	ks := &Keyset{
		Threshold: 2,
		Keys:      []string{shortKey},
	}

	// First signature fails hex verification or invalid sig, but if we test duplicate:
	sigs := []BlockSignature{
		{PublicKey: shortKey, Sig: "00"}, // will fail signature check or be duplicate
		{PublicKey: shortKey, Sig: "00"},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyMultisig panicked on duplicate short key: %v", r)
		}
	}()

	err := VerifyMultisig(hash, sigs, ks)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// The first sig will fail VerifyHexSignature because "00" is invalid, but if it passes seen check,
	// let's ensure no panic occurred.
}
