package statechain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMinterConfig_Validation(t *testing.T) {
	validKey1 := "1111111111111111111111111111111111111111111111111111111111111111"
	validKey2 := "2222222222222222222222222222222222222222222222222222222222222222"

	// 1. Valid config with keys
	cfgJSON, err := json.Marshal(map[string]any{
		"keys": []string{validKey1, validKey2},
	})
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: cfgJSON}); err != nil {
		t.Fatalf("expected valid sys.minter config to pass, got: %v", err)
	}

	// 2. Valid config with addresses
	cfgAddrJSON, err := json.Marshal(map[string]any{
		"addresses": []string{validKey1},
	})
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: cfgAddrJSON}); err != nil {
		t.Fatalf("expected valid sys.minter with addresses to pass, got: %v", err)
	}

	// 3. Invalid length
	badLenJSON, _ := json.Marshal(map[string]any{
		"keys": []string{"1234"},
	})
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: badLenJSON}); err == nil || !strings.Contains(err.Error(), "invalid length") {
		t.Fatalf("expected invalid length error, got: %v", err)
	}

	// 4. Invalid hex
	badHexJSON, _ := json.Marshal(map[string]any{
		"keys": []string{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	})
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: badHexJSON}); err == nil || !strings.Contains(err.Error(), "invalid hex") {
		t.Fatalf("expected invalid hex error, got: %v", err)
	}

	// 5. Duplicate keys (including case-insensitive)
	dupJSON, _ := json.Marshal(map[string]any{
		"keys": []string{validKey1, strings.ToUpper(validKey1)},
	})
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: dupJSON}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got: %v", err)
	}

	// 6. Empty config
	emptyJSON, _ := json.Marshal(map[string]any{
		"keys": []string{},
	})
	if err := ValidateOp(Op{Action: "set", Key: "sys.minter", Value: emptyJSON}); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("expected at least one key or address error, got: %v", err)
	}
}

func TestMinterConfig_LowercaseKeys(t *testing.T) {
	upperKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cfgJSON, err := json.Marshal(map[string]any{
		"keys": []string{upperKey},
	})
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	lowered := lowercaseKeys("sys.minter", cfgJSON)
	var result struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(lowered, &result); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(result.Keys) != 1 || result.Keys[0] != strings.ToLower(upperKey) {
		t.Fatalf("expected lowered key, got %v", result.Keys)
	}
}
