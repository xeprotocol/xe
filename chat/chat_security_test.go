package chat

import (
	"math"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestChatEnvelopeNetworkBindingValidationAndStoreAccountCap(t *testing.T) {
	sender, _ := core.GenerateKeyPair()
	recipient, _ := core.GenerateKeyPair()

	prevNet := core.GetNetworkID()
	defer core.SetNetworkID(prevNet)

	// 1. Cross-network replay must be rejected.
	core.SetNetworkID("xe-testnet-a")
	env, err := NewEnvelope(sender.Address(), recipient.Address(), "hello", sender, 0)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if err := env.VerifyFull(0); err != nil {
		t.Fatalf("VerifyFull on originating network failed: %v", err)
	}

	core.SetNetworkID("xe-mainnet")
	if err := env.VerifyFull(0); err == nil {
		t.Fatalf("expected chat envelope from xe-testnet-a to be rejected on xe-mainnet")
	}

	core.SetNetworkID("xe-testnet-a")

	// 2. Malformed recipient address must be rejected.
	if _, err := NewEnvelope(sender.Address(), "not-a-valid-hex-address", "hello", sender, 0); err == nil {
		t.Fatalf("expected NewEnvelope with invalid recipient address to fail")
	}
	badTo := *env
	badTo.To = "invalid_recipient"
	if err := badTo.VerifyFull(0); err == nil {
		t.Fatalf("expected VerifyFull with invalid recipient address to fail")
	}

	// 3. Negative timestamp (math.MinInt64) must be rejected without signed int64 overflow.
	negEnv := *env
	negEnv.Timestamp = math.MinInt64
	if err := negEnv.VerifyFull(0); err == nil {
		t.Fatalf("expected VerifyFull with negative timestamp (MinInt64) to fail")
	}

	// 4. ChatStore caps the number of distinct tracked accounts.
	cs := NewChatStore(10)
	cs.maxAccounts = 3

	now := core.Now().UnixNano()
	for i := 0; i < 4; i++ {
		sKP, _ := core.GenerateKeyPair()
		rKP, _ := core.GenerateKeyPair()
		e, err := NewEnvelope(sKP.Address(), rKP.Address(), "msg", sKP, 0)
		if err != nil {
			t.Fatalf("NewEnvelope %d: %v", i, err)
		}
		e.Timestamp = now + int64(i)*1_000_000
		cs.Store(e)
	}
	if got := len(cs.Accounts()); got > 3 {
		t.Fatalf("expected ChatStore distinct accounts capped at 3, got %d", got)
	}
}
