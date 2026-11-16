package chat

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidateMessage checks that msg is non-empty, within MaxMessageBytes,
// valid UTF-8, and contains no disallowed C0/C1 control codes or ANSI/OSC escape sequences.
func ValidateMessage(msg string) error {
	if msg == "" {
		return fmt.Errorf("message is empty")
	}
	if len(msg) > MaxMessageBytes {
		return fmt.Errorf("message exceeds maximum length of %d bytes", MaxMessageBytes)
	}
	if !utf8.ValidString(msg) {
		return fmt.Errorf("message is not valid UTF-8")
	}
	if ContainsControlEscapes(msg) {
		return fmt.Errorf("message contains disallowed control characters or escape sequences")
	}
	return nil
}

// ContainsControlEscapes returns true if s contains any ANSI/OSC escape sequences
// or disallowed control characters (anything other than '\t', '\n', and valid '\r\n').
func ContainsControlEscapes(s string) bool {
	runes := []rune(s)
	n := len(runes)
	for i := 0; i < n; i++ {
		r := runes[i]
		if r == '\t' || r == '\n' {
			continue
		}
		if r == '\r' && i+1 < n && runes[i+1] == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return true
		}
	}
	return false
}

// SanitizeTerminal strips ANSI/OSC/CSI control sequences, C0 control characters
// (except '\t' and '\n'), and C1 control characters from s, preventing screen clears,
// cursor manipulation, OSC-8 phishing links, and terminal exploits.
func SanitizeTerminal(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(s))

	runes := []rune(s)
	n := len(runes)

	for i := 0; i < n; {
		r := runes[i]

		// 1. ANSI Escape sequence starting with ESC (0x1B)
		if r == 0x1B {
			i++
			if i >= n {
				break
			}
			next := runes[i]
			switch next {
			case '[': // CSI sequence: ESC [ (params) (intermediates) (final)
				i++
				// Skip parameter bytes (0x30-0x3F) and intermediate bytes (0x20-0x2F)
				for i < n && runes[i] >= 0x20 && runes[i] <= 0x3F {
					i++
				}
				// Skip final byte (0x40-0x7E)
				if i < n && runes[i] >= 0x40 && runes[i] <= 0x7E {
					i++
				}
				continue
			case ']': // OSC sequence: ESC ] ... (BEL or ST [ESC \ or C1 ST])
				i++
				for i < n {
					if runes[i] == 0x07 { // BEL (\a)
						i++
						break
					}
					if runes[i] == 0x1B && i+1 < n && runes[i+1] == '\\' { // ST (ESC \)
						i += 2
						break
					}
					if runes[i] == 0x9C { // C1 ST
						i++
						break
					}
					i++
				}
				continue
			case 'P', '_', '^', 'X': // DCS (P), APC (_), PM (^), SOS (X)
				i++
				for i < n {
					if runes[i] == 0x07 || runes[i] == 0x9C {
						i++
						break
					}
					if runes[i] == 0x1B && i+1 < n && runes[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			default:
				if next >= 0x20 && next <= 0x2F { // Intermediate bytes followed by final byte
					i++
					for i < n && runes[i] >= 0x20 && runes[i] <= 0x2F {
						i++
					}
					if i < n && runes[i] >= 0x30 && runes[i] <= 0x7E {
						i++
					}
					continue
				} else if next >= 0x30 && next <= 0x7E { // 2-byte escape sequence (e.g. ESC c)
					i++
					continue
				}
				continue
			}
		}

		// 2. C1 CSI (0x9B)
		if r == 0x9B {
			i++
			for i < n && runes[i] >= 0x20 && runes[i] <= 0x3F {
				i++
			}
			if i < n && runes[i] >= 0x40 && runes[i] <= 0x7E {
				i++
			}
			continue
		}

		// 3. C1 OSC (0x9D)
		if r == 0x9D {
			i++
			for i < n {
				if runes[i] == 0x07 || runes[i] == 0x9C {
					i++
					break
				}
				if runes[i] == 0x1B && i+1 < n && runes[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		// 4. Allowed whitespace control characters
		if r == '\t' || r == '\n' {
			b.WriteRune(r)
			i++
			continue
		}

		// 5. Carriage return handling: normalize CRLF to LF, drop standalone CR
		if r == '\r' {
			if i+1 < n && runes[i+1] == '\n' {
				b.WriteRune('\n')
				i += 2
			} else {
				i++
			}
			continue
		}

		// 6. Strip all other C0 controls (0x00-0x1F), DEL (0x7F), and C1 controls (0x80-0x9F)
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			i++
			continue
		}

		// 7. Legitimate printable character
		b.WriteRune(r)
		i++
	}

	return b.String()
}
