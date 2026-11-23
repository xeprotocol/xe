package core

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

const MaxMemoBytes = 64

func ValidateMemo(memo string) error {
	if memo == "" {
		return nil
	}
	if len(memo) > MaxMemoBytes {
		return fmt.Errorf("memo too long: %d bytes (max %d)", len(memo), MaxMemoBytes)
	}
	if !utf8.ValidString(memo) {
		return fmt.Errorf("memo is not valid UTF-8")
	}
	for offset, r := range memo {
		if r == '\t' || r == '\n' {
			continue
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("memo contains disallowed control character %U at offset %d", r, offset)
		}
		if unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("memo contains disallowed format character %U at offset %d", r, offset)
		}
	}
	return nil
}
