package core

import (
	"strings"
	"testing"
)

func TestValidateMemo(t *testing.T) {
	tests := []struct {
		name    string
		memo    string
		wantErr bool
	}{
		{"empty memo is allowed", "", false},
		{"simple ascii", "Payment for compute services", false},
		{"with tab and newline", "line1\nline2\tcol2", false},
		{"unicode letters and accents", "Café München", false},
		{"max allowed length (64 bytes)", strings.Repeat("a", MaxMemoBytes), false},
		{"exceeds max length", strings.Repeat("a", MaxMemoBytes+1), true},
		{"invalid utf8 byte sequence", string([]byte{0xff, 0xfe}), true},
		{"c0 null control byte", "hello\x00world", true},
		{"c0 bell control byte", "ring\x07bell", true},
		{"c0 escape control byte", "esc\x1bsequence", true},
		{"ascii del byte", "del\x7fchar", true},
		{"c1 control character U+0085 NEL", "line1\u0085line2", true},
		{"c1 control character U+009B CSI", "ansi\u009b31mcolor", true},
		{"c1 control character U+009D OSC", "title\u009dpayload", true},
		{"bidi override character U+202E RLO", "admin\u202Ecod", true},
		{"bidi format character U+200B zero width space", "stealth\u200Buser", true},
		{"bidi isolate character U+2066 LRI", "isolate\u2066text", true},
		{"byte order mark U+FEFF", "\uFEFFbom", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMemo(tt.memo)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMemo(%q) error = %v, wantErr %v", tt.memo, err, tt.wantErr)
			}
		})
	}
}
