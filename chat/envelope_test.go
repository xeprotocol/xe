package chat

import (
	"context"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestNewEnvelopeRejectsExcessiveDifficulty(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := NewEnvelope(kp.Address(), kp.Address(), "hello", kp, 0xfffffffffffffff0); err == nil {
		t.Fatalf("expected NewEnvelope to reject difficulty > MaxPoWDifficulty")
	}
}

func TestNewEnvelopeHonorsCancelledContext(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewEnvelopeWithContext(ctx, kp.Address(), kp.Address(), "hello", kp, DefaultPoWDifficulty); err == nil {
		t.Fatalf("expected cancelled context to abort PoW computation")
	}
}
