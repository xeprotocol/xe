package core

import (
	"fmt"
	"unicode/utf8"
)

// MaxMemoBytes bounds the on-chain memo size. Byte-counted (not rune-counted)
// so the storage and wire layout are predictable.
const MaxMemoBytes = 64

// ValidateMemo checks that a memo string is acceptable for inclusion in a
// transaction block. Empty memos are valid (the field is optional).
//
// Rules:
//   - length ≤ MaxMemoBytes (byte count)
//   - valid UTF-8
//   - no ASCII control characters (0x00-0x1F, 0x7F) except tab (0x09) and
//     newline (0x0A). Other Unicode control codepoints are allowed; the
//     restriction is just the C0/DEL ASCII range, which would otherwise
//     corrupt terminal output and explorer renderings.
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
