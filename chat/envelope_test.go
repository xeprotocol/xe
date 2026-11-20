package chat

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestNewEnvelopeWithContext_Success(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	recipient, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair recipient failed: %v", err)
	}

	ctx := context.Background()
	env, err := NewEnvelopeWithContext(ctx, kp.Address(), recipient.Address(), "hello world", kp, core.TestDifficulty)
	if err != nil {
		t.Fatalf("NewEnvelopeWithContext failed: %v", err)
	}

	if env.From != kp.Address() {
		t.Errorf("expected from %s, got %s", kp.Address(), env.From)
	}
	if env.To != recipient.Address() {
		t.Errorf("expected to %s, got %s", recipient.Address(), env.To)
	}
	if env.Message != "hello world" {
		t.Errorf("expected message 'hello world', got %s", env.Message)
	}
	if env.Signature == "" {
		t.Errorf("expected signature to be non-empty")
	}

	if err := env.VerifyFull(core.TestDifficulty); err != nil {
		t.Errorf("VerifyFull failed on generated envelope: %v", err)
	}
}

func TestNewEnvelopeWithContext_ExceedsMaxDifficulty(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ctx := context.Background()
	excessiveDiff := MaxPoWDifficulty + 1
	_, err = NewEnvelopeWithContext(ctx, kp.Address(), kp.Address(), "test", kp, excessiveDiff)
	if err == nil {
		t.Fatalf("expected error when difficulty exceeds MaxPoWDifficulty, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewEnvelopeWithContext_ContextTimeout(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	// MaxPoWDifficulty ensures it won't instantly solve before timeout check
	_, err = NewEnvelopeWithContext(ctx, kp.Address(), kp.Address(), "test", kp, MaxPoWDifficulty)
	if err == nil {
		t.Fatalf("expected error when context timed out, got nil")
	}

	if !errors.Is(err, core.ErrPoWCancelled) && !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("expected error to wrap ErrPoWCancelled, got: %v", err)
	}
}

func TestNewEnvelopeWithContext_ContextCancelled(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = NewEnvelopeWithContext(ctx, kp.Address(), kp.Address(), "test", kp, MaxPoWDifficulty)
	if err == nil {
		t.Fatalf("expected error when context cancelled, got nil")
	}

	if !errors.Is(err, core.ErrPoWCancelled) && !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("expected error to wrap ErrPoWCancelled, got: %v", err)
	}
}

func TestNewEnvelope_BackwardCompatibility(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	env, err := NewEnvelope(kp.Address(), kp.Address(), "compat test", kp, core.TestDifficulty)
	if err != nil {
		t.Fatalf("NewEnvelope failed: %v", err)
	}

	if err := env.VerifyFull(core.TestDifficulty); err != nil {
		t.Errorf("VerifyFull failed: %v", err)
	}
}
