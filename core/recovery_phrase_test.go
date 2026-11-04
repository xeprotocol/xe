package core

import (
	"slices"
	"strings"
	"testing"
)

func TestBIP39WordlistAndRecoveryPhraseCRLFResilience(t *testing.T) {
	if len(phraseWords) != 2048 {
		t.Fatalf("len(phraseWords) = %d, want 2048", len(phraseWords))
	}
	if len(phraseIndex) != 2048 {
		t.Fatalf("len(phraseIndex) = %d, want 2048", len(phraseIndex))
	}
	for i, w := range phraseWords {
		if w == "" {
			t.Fatalf("empty word at index %d", i)
		}
		if strings.ContainsAny(w, "\r\n") {
			t.Fatalf("word at index %d contains CR/LF: %q", i, w)
		}
		if got, ok := phraseIndex[w]; !ok || got != i {
			t.Fatalf("phraseIndex[%q] = (%d, %v), want (%d, true)", w, got, ok, i)
		}
	}

	// Simulate a Windows git checkout where core.autocrlf=true rewrote LF to CRLF.
	lfNormalized := strings.ReplaceAll(wordlistEnglish, "\r\n", "\n")
	crlfRewritten := strings.ReplaceAll(lfNormalized, "\n", "\r\n")
	fromLF := parseWordlist(lfNormalized)
	fromCRLF := parseWordlist(crlfRewritten)
	if !slices.Equal(fromLF, fromCRLF) {
		t.Fatalf("parseWordlist(CRLF) != parseWordlist(LF)")
	}
	if len(fromCRLF) != 2048 {
		t.Fatalf("len(fromCRLF) = %d, want 2048", len(fromCRLF))
	}

	// Verify end-to-end phrase generation, validation, and wallet derivation.
	phrase, err := NewRecoveryPhrase()
	if err != nil {
		t.Fatalf("NewRecoveryPhrase: %v", err)
	}
	if err := ValidatePhrase(phrase); err != nil {
		t.Fatalf("ValidatePhrase on generated phrase failed: %v", err)
	}
	kp1, err := KeyPairFromPhrase(phrase, "", 0)
	if err != nil {
		t.Fatalf("KeyPairFromPhrase: %v", err)
	}
	// Also verify phrase input with CRLF / extra whitespace normalizes and restores identically.
	kp2, err := KeyPairFromPhrase("  "+strings.ReplaceAll(phrase, " ", "\r\n")+"\r\n", "", 0)
	if err != nil {
		t.Fatalf("KeyPairFromPhrase with CRLF whitespace: %v", err)
	}
	if kp1.Address() != kp2.Address() || kp1.PubKeyHex() != kp2.PubKeyHex() {
		t.Fatalf("restored keypair mismatch: %s vs %s", kp1.Address(), kp2.Address())
	}
}
