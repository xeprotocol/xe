package chat

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestParsePoWDifficulty_RejectsZeroAndBelowFloor(t *testing.T) {
	cases := []struct {
		name  string
		input string
		floor uint64
	}{
		{"empty", "", MinPoWDifficulty},
		{"zero_short", "0", 1},
		{"zero_padded", "0000000000000000", 1},
		{"below_floor", "0000000000000001", MinPoWDifficulty},
		{"just_below_default_floor", "ffffbfffffffffff", MinPoWDifficulty},
		{"malformed_hex", "not-hex", 1},
		{"too_long", "0123456789abcdef0", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePoWDifficulty(tc.input, tc.floor); err == nil {
				t.Fatalf("expected ParsePoWDifficulty(%q, 0x%x) to fail, got nil", tc.input, tc.floor)
			}
		})
	}
}

func TestParsePoWDifficulty_AcceptsAtOrAboveFloor(t *testing.T) {
	diff, err := ParsePoWDifficulty("ffffc00000000000", MinPoWDifficulty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff != DefaultPoWDifficulty {
		t.Fatalf("expected 0x%x, got 0x%x", DefaultPoWDifficulty, diff)
	}

	higher, err := ParsePoWDifficulty("ffffe00000000000", MinPoWDifficulty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if higher != 0xffffe00000000000 {
		t.Fatalf("expected 0xffffe00000000000, got 0x%x", higher)
	}
}

func TestClampPoWDifficulty_FallsBackOnZeroOrBelowFloor(t *testing.T) {
	for _, s := range []string{"0", "0000000000000000", "1", "ffffbfffffffffff", "", "bad"} {
		diff, ok := ClampPoWDifficulty(s, MinPoWDifficulty)
		if ok {
			t.Fatalf("expected ClampPoWDifficulty(%q) to report fallback (ok=false)", s)
		}
		if diff != DefaultPoWDifficulty {
			t.Fatalf("expected fallback 0x%x for %q, got 0x%x", DefaultPoWDifficulty, s, diff)
		}
	}

	diff, ok := ClampPoWDifficulty("ffffc00000000000", MinPoWDifficulty)
	if !ok || diff != DefaultPoWDifficulty {
		t.Fatalf("expected valid default difficulty to pass without clamping, got 0x%x (ok=%v)", diff, ok)
	}
}

func TestVerifyFull_RejectsZeroNonceUnderEnforcedFloor(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	recipient, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Simulate an attacker crafting an envelope with difficulty 0 (no work)
	env, err := NewEnvelope(kp.Address(), recipient.Address(), "spam without pow", kp, 0)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	env.PoWNonce = 0

	// When the verifier clamps a lying node's "0" advertisement to MinPoWDifficulty,
	// VerifyFull rejects the zero-work envelope.
	clampedDiff, ok := ClampPoWDifficulty("0", MinPoWDifficulty)
	if ok {
		t.Fatalf("expected lying node '0' difficulty to trigger floor fallback")
	}
	err = env.VerifyFull(clampedDiff)
	if err == nil || !strings.Contains(err.Error(), "insufficient proof of work") {
		t.Fatalf("expected insufficient proof of work error under clamped floor, got: %v", err)
	}
}
