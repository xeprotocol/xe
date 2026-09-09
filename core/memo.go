package core

import (
	"fmt"
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
	for i := 0; i < len(memo); i++ {
		c := memo[i]
		if c == '\t' || c == '\n' {
			continue
		}
		if c < 0x20 || c == 0x7F {
			return fmt.Errorf("memo contains disallowed control byte 0x%02x at offset %d", c, i)
		}
	}
	return nil
}
