package main

import "testing"

func TestParseSendArgsConsumesOptionValues(t *testing.T) {
	dest, amount, asset, memo, err := parseSendArgs([]string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"1",
		"--memo",
		"--asset",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" || amount != "1" {
		t.Fatalf("unexpected dest/amount: %q %q", dest, amount)
	}
	if asset != "XUSD" {
		t.Fatalf("expected default asset XUSD when --memo value is '--asset', got %q", asset)
	}
	if memo != "--asset" {
		t.Fatalf("expected memo '--asset', got %q", memo)
	}

	if _, _, _, _, err := parseSendArgs([]string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"1",
		"--memo",
		"--asset",
		"XE",
	}); err == nil {
		t.Fatalf("expected trailing positional/unknown argument after consumed --memo value to fail")
	}
}

func TestParseBurnArgsConsumesMemoValueWithoutSettingSkipConfirm(t *testing.T) {
	amount, skipConfirm, memo, err := parseBurnArgs([]string{"1", "--memo", "--yes"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amount != "1" {
		t.Fatalf("expected amount '1', got %q", amount)
	}
	if skipConfirm {
		t.Fatalf("expected skipConfirm=false when '--yes' is the value of --memo")
	}
	if memo != "--yes" {
		t.Fatalf("expected memo '--yes', got %q", memo)
	}
}
