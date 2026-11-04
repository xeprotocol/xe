package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/chat"
)

func TestPrintEnvelope_PlainTextSanitizesPoC(t *testing.T) {
	pocPayload := "\x1b[2J\x1b[H\x1b]8;;http://evil.example\aIMPORTANT: re-enter your wallet phrase at http://evil.example\x1b]8;;\a\a\n"

	env := &chat.Envelope{
		ID:        "test-envelope-id",
		From:      "sender-address",
		To:        "victim-address",
		Message:   pocPayload,
		Timestamp: time.Now().UnixNano(),
	}

	var buf bytes.Buffer
	if err := printEnvelope(&buf, env, false); err != nil {
		t.Fatalf("printEnvelope failed: %v", err)
	}

	output := buf.String()

	// Verify that terminal escape sequences are stripped
	if strings.Contains(output, "\x1b") {
		t.Fatalf("output must not contain ESC (0x1B), got: %q", output)
	}
	if strings.Contains(output, "[2J") {
		t.Fatalf("output must not contain screen clear [2J, got: %q", output)
	}
	if strings.Contains(output, "[H") {
		t.Fatalf("output must not contain cursor home [H, got: %q", output)
	}
	if strings.Contains(output, "\a") {
		t.Fatalf("output must not contain BEL (0x07), got: %q", output)
	}
	if strings.Contains(output, "\x1b]8;;") {
		t.Fatalf("output must not contain OSC-8 hyperlink sequence, got: %q", output)
	}

	// Verify that the text content is still present safely
	if !strings.Contains(output, "IMPORTANT: re-enter your wallet phrase at http://evil.example") {
		t.Fatalf("output should contain safe text content, got: %q", output)
	}
}

func TestPrintEnvelope_SanitizesFromAndToAddresses(t *testing.T) {
	env := &chat.Envelope{
		ID:        "test-envelope-id",
		From:      "\x1b[31mattacker-address\x1b[0m",
		To:        "\x1b[2Jvictim-address",
		Message:   "Hello World",
		Timestamp: time.Now().UnixNano(),
	}

	var buf bytes.Buffer
	if err := printEnvelope(&buf, env, false); err != nil {
		t.Fatalf("printEnvelope failed: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "\x1b") {
		t.Fatalf("output contains ESC from addresses: %q", output)
	}
	if !strings.Contains(output, "attacker-address") || !strings.Contains(output, "victim-address") {
		t.Fatalf("sanitized addresses missing from output: %q", output)
	}
}

func TestPrintEnvelope_JSONOutput(t *testing.T) {
	env := &chat.Envelope{
		ID:        "json-env-id",
		From:      "from-addr",
		To:        "to-addr",
		Message:   "Test JSON message",
		Timestamp: 1700000000000000000,
	}

	var buf bytes.Buffer
	if err := printEnvelope(&buf, env, true); err != nil {
		t.Fatalf("printEnvelope json failed: %v", err)
	}

	var decoded chat.Envelope
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode json output: %v", err)
	}
	if decoded.ID != env.ID || decoded.Message != env.Message {
		t.Fatalf("json round-trip mismatch: got %+v, want %+v", decoded, env)
	}
}

func TestPrintEnvelope_CleanMessageFormat(t *testing.T) {
	ts := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	env := &chat.Envelope{
		ID:        "clean-id",
		From:      "alice",
		To:        "bob",
		Message:   "Hello Bob!",
		Timestamp: ts.UnixNano(),
	}

	var buf bytes.Buffer
	if err := printEnvelope(&buf, env, false); err != nil {
		t.Fatalf("printEnvelope failed: %v", err)
	}

	expected := "2026-11-04T10:00:00Z alice -> bob Hello Bob!\n"
	if buf.String() != expected {
		t.Fatalf("expected formatted output %q, got %q", expected, buf.String())
	}
}
