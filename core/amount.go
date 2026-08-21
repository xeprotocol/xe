package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AssetConfig declares the decimal precision for a single on-chain asset.
// All amount fields (Balance, Amount, lease Cost/Stake, pending sends) are
// stored as unsigned 64-bit integers in micro-units, where one whole token
// equals UnitsPerToken micro-units (= 10^Decimals).
//
// Per-asset configuration leaves room for future assets to use different
// precisions without a multi-file refactor. XE and XUSD share 6 decimals
// today; that's an operational fact, not an invariant.
type AssetConfig struct {
	Symbol        string
	Decimals      uint8
	UnitsPerToken uint64
}

// Predefined assets. Production code should reference these by name rather
// than constructing AssetConfig values inline.
var (
	AssetXE   = AssetConfig{Symbol: "XE", Decimals: 6, UnitsPerToken: 1_000_000}
	AssetXUSD = AssetConfig{Symbol: "XUSD", Decimals: 6, UnitsPerToken: 1_000_000}
)

// AssetByName returns the AssetConfig for a known asset symbol. The second
// return is false for unknown symbols; callers can fall back to AssetXE or
// surface an error as appropriate.
func AssetByName(symbol string) (AssetConfig, bool) {
	switch symbol {
	case AssetXE.Symbol:
		return AssetXE, true
	case AssetXUSD.Symbol:
		return AssetXUSD, true
	}
	return AssetConfig{}, false
}

// ErrAmountNegative is returned when ParseAmount sees a leading minus sign.
var ErrAmountNegative = errors.New("amount must be non-negative")

// ErrAmountFormat is returned for syntactically invalid amount strings
// (empty, non-digits, scientific notation, multiple decimal points).
var ErrAmountFormat = errors.New("amount must be a non-negative decimal")

// ErrAmountPrecision is returned when more fractional digits are supplied
// than the asset's decimal precision permits (no silent truncation).
var ErrAmountPrecision = errors.New("amount exceeds asset decimal precision")

// ErrAmountOverflow is returned when the parsed value would exceed uint64.
var ErrAmountOverflow = errors.New("amount overflows uint64 micro-units")

// ParseAmount converts a decimal token string (e.g. "1.234567", "0.5", "100")
// into micro-units using the asset's precision. The input may not contain a
// sign, whitespace, thousands separators, scientific notation, or more than
// asset.Decimals fractional digits.
//
// Examples (asset.Decimals = 6):
//
//	ParseAmount("1",        AssetXE) → 1_000_000
//	ParseAmount("1.234567", AssetXE) → 1_234_567
//	ParseAmount("0.000001", AssetXE) → 1
//	ParseAmount("0",        AssetXE) → 0
func ParseAmount(s string, asset AssetConfig) (uint64, error) {
	if s == "" {
		return 0, ErrAmountFormat
	}
	if s[0] == '-' {
		return 0, ErrAmountNegative
	}
	if s[0] == '+' {
		return 0, ErrAmountFormat
	}

	decimals := int(asset.Decimals)

	whole, frac, hasDot := s, "", false
	if i := strings.IndexByte(s, '.'); i >= 0 {
		whole, frac, hasDot = s[:i], s[i+1:], true
		if whole == "" {
			return 0, ErrAmountFormat
		}
	}
	if hasDot && frac == "" {
		return 0, ErrAmountFormat
	}
	if len(frac) > decimals {
		return 0, fmt.Errorf("%w: %s allows %d, got %d", ErrAmountPrecision, asset.Symbol, decimals, len(frac))
	}
	if !allDigits(whole) || !allDigits(frac) {
		return 0, ErrAmountFormat
	}

	wholeVal, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, ErrAmountOverflow
	}

	if len(frac) < decimals {
		frac = frac + strings.Repeat("0", decimals-len(frac))
	}
	var fracVal uint64
	if frac != "" {
		fracVal, err = strconv.ParseUint(frac, 10, 64)
		if err != nil {
			return 0, ErrAmountFormat
		}
	}

	hi, lo := mul64(wholeVal, asset.UnitsPerToken)
	if hi != 0 {
		return 0, ErrAmountOverflow
	}
	total, carry := addOverflow64(lo, fracVal)
	if carry {
		return 0, ErrAmountOverflow
	}
	return total, nil
}

// FormatAmount renders micro-units as a decimal token string for the given
// asset, with trailing zero fractional digits trimmed. The decimal point is
// omitted entirely for whole-token amounts. Inverse of ParseAmount.
//
// Examples (asset.Decimals = 6):
//
//	FormatAmount(1_234_567, AssetXE) → "1.234567"
//	FormatAmount(1_230_000, AssetXE) → "1.23"
//	FormatAmount(1_000_000, AssetXE) → "1"
//	FormatAmount(1,         AssetXE) → "0.000001"
//	FormatAmount(0,         AssetXE) → "0"
func FormatAmount(micro uint64, asset AssetConfig) string {
	decimals := int(asset.Decimals)
	whole := micro / asset.UnitsPerToken
	frac := micro % asset.UnitsPerToken
	if frac == 0 {
		return strconv.FormatUint(whole, 10)
	}
	fracStr := strconv.FormatUint(frac, 10)
	if len(fracStr) < decimals {
		fracStr = strings.Repeat("0", decimals-len(fracStr)) + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return strconv.FormatUint(whole, 10) + "." + fracStr
}

// FormatAmountFixed is FormatAmount but always emits exactly asset.Decimals
// fractional digits. Useful for fixed-width accounting displays.
func FormatAmountFixed(micro uint64, asset AssetConfig) string {
	decimals := int(asset.Decimals)
	whole := micro / asset.UnitsPerToken
	frac := micro % asset.UnitsPerToken
	fracStr := strconv.FormatUint(frac, 10)
	if len(fracStr) < decimals {
		fracStr = strings.Repeat("0", decimals-len(fracStr)) + fracStr
	}
	return strconv.FormatUint(whole, 10) + "." + fracStr
}

// MustParseAmount panics on a parse error. Reserved for tests and constants.
func MustParseAmount(s string, asset AssetConfig) uint64 {
	v, err := ParseAmount(s, asset)
	if err != nil {
		panic(fmt.Sprintf("MustParseAmount(%q, %s): %v", s, asset.Symbol, err))
	}
	return v
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// mul64 multiplies two uint64s and returns the 128-bit result as (hi, lo).
// Used to detect overflow when scaling whole-token values to micro-units.
func mul64(a, b uint64) (hi, lo uint64) {
	const mask32 = uint64(0xffffffff)
	aLo, aHi := a&mask32, a>>32
	bLo, bHi := b&mask32, b>>32

	w0 := aLo * bLo
	t := aHi*bLo + w0>>32
	w1 := t & mask32
	w2 := t >> 32

	w1 += aLo * bHi
	hi = aHi*bHi + w2 + w1>>32
	lo = a * b
	return hi, lo
}

func addOverflow64(a, b uint64) (sum uint64, carry bool) {
	sum = a + b
	return sum, sum < a
}
