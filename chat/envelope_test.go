package chat

import (
	"context"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestNewEnvelopeWithContext_DifficultyExceedsMax(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Attempt difficulty above MaxPoWDifficulty
	_, err = NewEnvelopeWithContext(context.Background(), kp.Address(), "recipient", "hello", kp, MaxPoWDifficulty+1)
	if err != ErrDifficultyTooHigh {
		t.Fatalf("expected ErrDifficultyTooHigh, got %v", err)
	}

	// Maximum uint64 difficulty should also fail immediately
	_, err = NewEnvelopeWithContext(context.Background(), kp.Address(), "recipient", "hello", kp, ^uint64(0))
	if err != ErrDifficultyTooHigh {
		t.Fatalf("expected ErrDifficultyTooHigh for max uint64, got %v", err)
	}
}

func TestNewEnvelopeWithContext_TimeoutCancellation(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Non-zero difficulty with pre-cancelled context should fail fast without hanging
	_, err = NewEnvelopeWithContext(ctx, kp.Address(), "recipient", "hello", kp, DefaultPoWDifficulty)
	if err == nil {
		t.Fatalf("expected error on cancelled context, got nil")
	}
}

func TestNewEnvelope_Valid(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Use minimal difficulty for fast test execution
	env, err := NewEnvelope(kp.Address(), kp.Address(), "ping", kp, 1)
	if err != nil {
		t.Fatalf("NewEnvelope failed: %v", err)
	}
	if env.ID == "" {
		t.Fatalf("expected non-empty envelope ID")
	}
	if err := env.VerifyFull(1); err != nil {
		t.Fatalf("VerifyFull failed: %v", err)
	}
}

func TestVerifyFull_DifficultyExceedsMax(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	env, err := NewEnvelope(kp.Address(), kp.Address(), "test", kp, 0)
	if err != nil {
		t.Fatalf("NewEnvelope failed: %v", err)
	}

	err = env.VerifyFull(MaxPoWDifficulty + 1)
	if err != ErrDifficultyTooHigh {
		t.Fatalf("expected ErrDifficultyTooHigh, got %v", err)
	}
}
