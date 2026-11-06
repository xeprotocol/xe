package main

import (
	"testing"

	"github.com/xeprotocol/xe/core"
)

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
	if asset != core.AssetXCU.Symbol {
		t.Fatalf("expected default asset %s when --memo value is '--asset', got %q", core.AssetXCU.Symbol, asset)
	}
	if _, ok := core.AssetByName(asset); !ok {
		t.Fatalf("expected default asset %q to be registered in core.AssetByName", asset)
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

func TestParseSendArgsExplicitAssets(t *testing.T) {
	for _, sym := range []string{core.AssetXE.Symbol, core.AssetXCU.Symbol} {
		_, _, asset, _, err := parseSendArgs([]string{
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"2.5",
			"--asset",
			sym,
		})
		if err != nil {
			t.Fatalf("unexpected error for --asset %s: %v", sym, err)
		}
		if asset != sym {
			t.Fatalf("expected asset %s, got %q", sym, asset)
		}
		if _, ok := core.AssetByName(asset); !ok {
			t.Fatalf("expected %q to be valid in core.AssetByName", asset)
		}
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
