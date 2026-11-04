package chat_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
)

func TestSanitizeTerminal_PoCPayload(t *testing.T) {
	// Exact payload from Issue #256
	pocPayload := "\x1b[2J\x1b[H\x1b]8;;http://evil.example\aIMPORTANT: re-enter your wallet phrase at http://evil.example\x1b]8;;\a\a\n"
	sanitized := chat.SanitizeTerminal(pocPayload)

	expected := "IMPORTANT: re-enter your wallet phrase at http://evil.example\n"
	if sanitized != expected {
		t.Fatalf("expected sanitized output %q, got %q", expected, sanitized)
	}

	// Verify dangerous sequences are stripped
	if strings.Contains(sanitized, "\x1b") {
		t.Fatal("sanitized string still contains ESC (0x1B)")
	}
	if strings.Contains(sanitized, "\a") {
		t.Fatal("sanitized string still contains BEL (0x07)")
	}
	if strings.Contains(sanitized, "[2J") {
		t.Fatal("sanitized string still contains screen-clear control sequence [2J")
	}
	if strings.Contains(sanitized, "[H") {
		t.Fatal("sanitized string still contains cursor home control sequence [H")
	}
	// The attacker's URL was only inside the OSC-8 escape parameters, not the visible text;
	// the visible text in the PoC contains http://evil.example, but the escape markers must be gone.
	if strings.Contains(sanitized, "\x1b]8;;") {
		t.Fatal("sanitized string still contains OSC-8 hyperlink sequence")
	}
}

func TestSanitizeTerminal_CSISequences(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "screen clear and cursor home",
			input:    "\x1b[2J\x1b[HHello World",
			expected: "Hello World",
		},
		{
			name:     "color codes SGR",
			input:    "\x1b[31;1mRed Bold\x1b[0m Normal",
			expected: "Red Bold Normal",
		},
		{
			name:     "cursor visibility toggle",
			input:    "\x1b[?25lHidden\x1b[?25hVisible",
			expected: "HiddenVisible",
		},
		{
			name:     "line clear",
			input:    "\x1b[2KCleared line",
			expected: "Cleared line",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chat.SanitizeTerminal(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestSanitizeTerminal_OSCSequences(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "OSC 8 hyperlink with BEL terminator",
			input:    "\x1b]8;;https://example.com\aClick here\x1b]8;;\a",
			expected: "Click here",
		},
		{
			name:     "OSC 8 hyperlink with ST (ESC \\) terminator",
			input:    "\x1b]8;;https://example.com\x1b\\Click here\x1b]8;;\x1b\\",
			expected: "Click here",
		},
		{
			name:     "OSC 0 window title",
			input:    "\x1b]0;Evil Window Title\x07Hello",
			expected: "Hello",
		},
		{
			name:     "OSC 52 clipboard write attempt",
			input:    "\x1b]52;c;cGFzc3dvcmQ=\x07Safe Text",
			expected: "Safe Text",
		},
		{
			name:     "unterminated OSC at EOF",
			input:    "Leading text \x1b]8;;https://evil.com",
			expected: "Leading text ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chat.SanitizeTerminal(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestSanitizeTerminal_C1Controls(t *testing.T) {
	// C1 CSI: \u009b (0x9B), C1 OSC: \u009d (0x9D), C1 ST: \u009c (0x9C)
	c1CSI := "\u009b2J\u009bHHello"
	if got := chat.SanitizeTerminal(c1CSI); got != "Hello" {
		t.Fatalf("expected %q, got %q", "Hello", got)
	}

	c1OSC := "\u009d8;;https://evil.com\u009cLink\u009d8;;\u009c"
	if got := chat.SanitizeTerminal(c1OSC); got != "Link" {
		t.Fatalf("expected %q, got %q", "Link", got)
	}

	rawC1 := "Test\u0080\u0085\u009fMessage"
	if got := chat.SanitizeTerminal(rawC1); got != "TestMessage" {
		t.Fatalf("expected %q, got %q", "TestMessage", got)
	}
}

func TestSanitizeTerminal_C0Controls(t *testing.T) {
	// Bel, Backspace, FormFeed, NUL
	input := "Hello\a\b\f\x00World"
	if got := chat.SanitizeTerminal(input); got != "HelloWorld" {
		t.Fatalf("expected %q, got %q", "HelloWorld", got)
	}

	// CRLF normalized to LF
	crlf := "Line 1\r\nLine 2\r\n"
	if got := chat.SanitizeTerminal(crlf); got != "Line 1\nLine 2\n" {
		t.Fatalf("expected %q, got %q", "Line 1\nLine 2\n", got)
	}

	// Standalone CR stripped (prevents line overwrite attacks)
	standaloneCR := "Prompt: \rFake Prompt: "
	if got := chat.SanitizeTerminal(standaloneCR); got != "Prompt: Fake Prompt: " {
		t.Fatalf("expected %q, got %q", "Prompt: Fake Prompt: ", got)
	}

	// Tabs and newlines preserved
	tabNewline := "\tIndented\n\tSecond line\n"
	if got := chat.SanitizeTerminal(tabNewline); got != tabNewline {
		t.Fatalf("expected %q, got %q", tabNewline, got)
	}
}

func TestSanitizeTerminal_UnicodeAndNormalText(t *testing.T) {
	normal := "Hello, this is a normal message with 123 numbers!"
	if got := chat.SanitizeTerminal(normal); got != normal {
		t.Fatalf("expected normal message intact, got %q", got)
	}

	unicodeText := "Cześć! Zażółć gęślą jaźń. 🚀 Przyjaciele: 世界 Привет مرحبا"
	if got := chat.SanitizeTerminal(unicodeText); got != unicodeText {
		t.Fatalf("expected unicode text intact, got %q", got)
	}

	// Empty string
	if got := chat.SanitizeTerminal(""); got != "" {
		t.Fatalf("expected empty string for empty input, got %q", got)
	}

	// Trailing single ESC
	if got := chat.SanitizeTerminal("End with escape\x1b"); got != "End with escape" {
		t.Fatalf("expected trailing escape stripped, got %q", got)
	}
}

func TestValidateMessage(t *testing.T) {
	// Valid messages
	if err := chat.ValidateMessage("Hello, Alice!"); err != nil {
		t.Fatalf("expected valid message to pass, got: %v", err)
	}
	if err := chat.ValidateMessage("Line 1\nLine 2\r\n\tTabbed"); err != nil {
		t.Fatalf("expected multiline message to pass, got: %v", err)
	}
	if err := chat.ValidateMessage("Zażółć gęślą jaźń 🚀"); err != nil {
		t.Fatalf("expected unicode message to pass, got: %v", err)
	}

	// Disallowed messages
	if err := chat.ValidateMessage(""); err == nil {
		t.Fatal("expected empty message to be rejected")
	}

	pocPayload := "\x1b[2J\x1b[H\x1b]8;;http://evil.example\aIMPORTANT\x1b]8;;\a\a\n"
	if err := chat.ValidateMessage(pocPayload); err == nil {
		t.Fatal("expected PoC payload to be rejected by ValidateMessage")
	}

	if err := chat.ValidateMessage("Hello\x1b[31mRed"); err == nil {
		t.Fatal("expected ANSI escape to be rejected by ValidateMessage")
	}

	if err := chat.ValidateMessage("Hello\aWorld"); err == nil {
		t.Fatal("expected BEL to be rejected by ValidateMessage")
	}

	if err := chat.ValidateMessage("Invalid\rStandalone"); err == nil {
		t.Fatal("expected standalone CR to be rejected by ValidateMessage")
	}

	longMsg := strings.Repeat("A", chat.MaxMessageBytes+1)
	if err := chat.ValidateMessage(longMsg); err == nil {
		t.Fatal("expected message exceeding MaxMessageBytes to be rejected")
	}
}

func TestNewEnvelope_RejectsControlEscapes(t *testing.T) {
	kp, _ := core.GenerateKeyPair()
	dest, _ := core.GenerateKeyPair()

	pocPayload := "\x1b[2J\x1b[H\x1b]8;;http://evil.example\aIMPORTANT\x1b]8;;\a\a\n"
	_, err := chat.NewEnvelope(kp.Address(), dest.Address(), pocPayload, kp, 0)
	if err == nil {
		t.Fatal("expected NewEnvelope to reject message with control escapes")
	}

	validEnv, err := chat.NewEnvelope(kp.Address(), dest.Address(), "Valid clean message", kp, 0)
	if err != nil {
		t.Fatalf("expected NewEnvelope to succeed with clean message, got: %v", err)
	}
	if validEnv == nil {
		t.Fatal("expected non-nil envelope")
	}
}

func TestEnvelope_VerifyFull_RejectsTerminalEscapes(t *testing.T) {
	kp, _ := core.GenerateKeyPair()
	dest, _ := core.GenerateKeyPair()

	// Create envelope directly bypassing NewEnvelope
	ts := core.Now().UnixNano()
	pocPayload := "\x1b[2J\x1b[H\x1b]8;;http://evil.example\aIMPORTANT\x1b]8;;\a\a\n"
	pubKey := kp.PubKeyHex()
	id := chat.ComputeEnvelopeID(kp.Address(), pubKey, dest.Address(), pocPayload, ts)
	idBytes, _ := hex.DecodeString(id)
	sig := ed25519.Sign(kp.Private, idBytes)

	env := &chat.Envelope{
		ID:        id,
		From:      kp.Address(),
		PubKey:    pubKey,
		To:        dest.Address(),
		Message:   pocPayload,
		Timestamp: ts,
		Signature: hex.EncodeToString(sig),
	}

	err := env.VerifyFull(0)
	if err == nil {
		t.Fatal("expected VerifyFull to reject envelope with terminal escapes")
	}
	if !strings.Contains(err.Error(), "disallowed control characters") {
		t.Fatalf("expected error mentioning disallowed control characters, got: %v", err)
	}
}
