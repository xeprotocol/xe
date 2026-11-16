package main

import (
	"strings"
	"testing"
)

func TestParseSendArgs_DefaultAssetXE(t *testing.T) {
	dest, asset, memo, amountStr, err := parseSendArgs([]string{"378d0f5c20630000000000000000000000000000000000000000000000000000", "1.5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest != "378d0f5c20630000000000000000000000000000000000000000000000000000" {
		t.Errorf("expected dest matching input, got: %s", dest)
	}
	if amountStr != "1.5" {
		t.Errorf("expected amountStr '1.5', got: %s", amountStr)
	}
	if asset != "XE" {
		t.Errorf("expected default asset 'XE', got: %s", asset)
	}
	if memo != "" {
		t.Errorf("expected empty memo, got: %s", memo)
	}
}

func TestParseSendArgs_ExplicitAsset(t *testing.T) {
	dest, asset, memo, amountStr, err := parseSendArgs([]string{
		"378d0f5c20630000000000000000000000000000000000000000000000000000",
		"100",
		"--asset",
		"XUSD",
		"--memo",
		"payment for lease",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest != "378d0f5c20630000000000000000000000000000000000000000000000000000" {
		t.Errorf("expected dest matching input, got: %s", dest)
	}
	if amountStr != "100" {
		t.Errorf("expected amountStr '100', got: %s", amountStr)
	}
	if asset != "XUSD" {
		t.Errorf("expected explicit asset 'XUSD', got: %s", asset)
	}
	if memo != "payment for lease" {
		t.Errorf("expected memo 'payment for lease', got: %s", memo)
	}
}

func TestParseSendArgs_InsufficientArgs(t *testing.T) {
	_, _, _, _, err := parseSendArgs([]string{"only_one_arg"})
	if err == nil {
		t.Fatal("expected error on insufficient args, got nil")
	}
	if !strings.Contains(err.Error(), "usage: xe send") {
		t.Errorf("expected usage in error, got: %v", err)
	}
}
