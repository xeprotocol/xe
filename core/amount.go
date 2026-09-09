package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type AssetConfig struct {
	Symbol        string
	Decimals      uint8
	UnitsPerToken uint64
}

var (
	AssetXE   = AssetConfig{Symbol: "XE", Decimals: 6, UnitsPerToken: 1_000_000}
	AssetXUSD = AssetConfig{Symbol: "XUSD", Decimals: 6, UnitsPerToken: 1_000_000}
)

func AssetByName(symbol string) (AssetConfig, bool) {
	switch symbol {
	case AssetXE.Symbol:
		return AssetXE, true
	case AssetXUSD.Symbol:
		return AssetXUSD, true
	}
	return AssetConfig{}, false
}

var ErrAmountNegative = errors.New("amount must be non-negative")

var ErrAmountFormat = errors.New("amount must be a non-negative decimal")

var ErrAmountPrecision = errors.New("amount exceeds asset decimal precision")

var ErrAmountOverflow = errors.New("amount overflows uint64 micro-units")

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
