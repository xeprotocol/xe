package main

import (
	"strings"
	"testing"
)

func TestParseSendFlags_Default(t *testing.T) {
	asset, memo, err := parseSendFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset != "XUSD" {
		t.Errorf("expected default asset XUSD, got %q", asset)
	}
	if memo != "" {
		t.Errorf("expected empty memo, got %q", memo)
	}
}

func TestParseSendFlags_Valid(t *testing.T) {
	asset, memo, err := parseSendFlags([]string{"--asset", "XE", "--memo", "payment-42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset != "XE" {
		t.Errorf("expected asset XE, got %q", asset)
	}
	if memo != "payment-42" {
		t.Errorf("expected memo payment-42, got %q", memo)
	}
}

func TestParseSendFlags_MemoDoesNotHijackAsset(t *testing.T) {
	// Case 1: memo is "--asset"
	asset, memo, err := parseSendFlags([]string{"--memo", "--asset"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset != "XUSD" {
		t.Errorf("expected asset to remain default XUSD, got %q", asset)
	}
	if memo != "--asset" {
		t.Errorf("expected memo to be '--asset', got %q", memo)
	}

	// Case 2: memo is "--asset" followed by trailing non-flag argument "XE"
	_, _, err = parseSendFlags([]string{"--memo", "--asset", "XE"})
	if err == nil {
		t.Fatalf("expected error for trailing non-flag argument 'XE', got nil")
	}
	if !strings.Contains(err.Error(), "unknown flag \"XE\"") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseSendFlags_MissingValue(t *testing.T) {
	_, _, err := parseSendFlags([]string{"--asset"})
	if err == nil || !strings.Contains(err.Error(), "--asset requires a value") {
		t.Errorf("expected '--asset requires a value', got %v", err)
	}

	_, _, err = parseSendFlags([]string{"--memo"})
	if err == nil || !strings.Contains(err.Error(), "--memo requires a value") {
		t.Errorf("expected '--memo requires a value', got %v", err)
	}
}

func TestParseSendFlags_UnknownFlag(t *testing.T) {
	_, _, err := parseSendFlags([]string{"--unknown"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected unknown flag error, got %v", err)
	}
}

func TestParseBurnFlags_Default(t *testing.T) {
	skip, memo, err := parseBurnFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if skip {
		t.Errorf("expected skipConfirm false by default")
	}
	if memo != "" {
		t.Errorf("expected empty memo, got %q", memo)
	}
}

func TestParseBurnFlags_Yes(t *testing.T) {
	skip, memo, err := parseBurnFlags([]string{"--yes", "--memo", "burning"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !skip {
		t.Errorf("expected skipConfirm true with --yes")
	}
	if memo != "burning" {
		t.Errorf("expected memo burning, got %q", memo)
	}

	skipShort, _, err := parseBurnFlags([]string{"-y"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !skipShort {
		t.Errorf("expected skipConfirm true with -y")
	}
}

func TestParseBurnFlags_MemoDoesNotBypassConfirm(t *testing.T) {
	// "--memo --yes" should treat "--yes" purely as the memo value and NOT set skipConfirm
	skip, memo, err := parseBurnFlags([]string{"--memo", "--yes"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if skip {
		t.Errorf("VULNERABILITY: memo value '--yes' bypassed burn confirmation!")
	}
	if memo != "--yes" {
		t.Errorf("expected memo to be '--yes', got %q", memo)
	}
}

func TestParseBurnFlags_MissingValue(t *testing.T) {
	_, _, err := parseBurnFlags([]string{"--memo"})
	if err == nil || !strings.Contains(err.Error(), "--memo requires a value") {
		t.Errorf("expected '--memo requires a value', got %v", err)
	}
}

func TestParseBurnFlags_UnknownFlag(t *testing.T) {
	_, _, err := parseBurnFlags([]string{"--invalid"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected unknown flag error, got %v", err)
	}
}
