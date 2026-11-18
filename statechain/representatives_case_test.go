package statechain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepresentativesCaseNormalization(t *testing.T) {
	rep := "a2673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	upper := strings.ToUpper(rep)

	// 1. Validation accepts uppercase allowlist
	val, _ := json.Marshal(map[string]any{"mode": "allowlist", "addresses": []string{upper}})
	if err := validateSysKeyValue("sys.representatives", val); err != nil {
		t.Fatalf("expected uppercase allowlist to be valid, got: %v", err)
	}

	// 2. Validation rejects duplicate addresses differing only by case
	valDup, _ := json.Marshal(map[string]any{"mode": "allowlist", "addresses": []string{rep, upper}})
	if err := validateSysKeyValue("sys.representatives", valDup); err == nil {
		t.Fatalf("expected duplicate error for [lower, UPPER] address pair, got nil")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected 'duplicate' in error message, got: %v", err)
	}

	// 3. ApplyOps normalizes uppercase representatives addresses to lowercase via lowercaseKeys
	kv := NewKVStore()
	kv.ApplyOps([]Op{{Action: ActionSet, Key: "sys.representatives", Value: val}})
	rc, err := kv.Representatives()
	if err != nil {
		t.Fatalf("Representatives() returned error: %v", err)
	}
	if len(rc.Addresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(rc.Addresses))
	}
	if rc.Addresses[0] != strings.ToLower(rep) {
		t.Fatalf("expected normalized lowercase address %q, got %q", strings.ToLower(rep), rc.Addresses[0])
	}
}
