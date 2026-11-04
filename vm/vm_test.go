package vm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInfoRedacted(t *testing.T) {
	var nilInfo *Info
	if got := nilInfo.Redacted(); got != nil {
		t.Fatalf("expected nil for nil Info.Redacted(), got %v", got)
	}

	infoWithoutCreds := &Info{
		LeaseHash: "lease-123",
		Status:    "running",
	}
	redactedWithoutCreds := infoWithoutCreds.Redacted()
	if redactedWithoutCreds == nil || redactedWithoutCreds.Credentials != nil {
		t.Fatalf("expected non-nil with nil Credentials, got %v", redactedWithoutCreds)
	}

	const secret = "supersecretpassword123"
	original := &Info{
		LeaseHash: "lease-456",
		Status:    "active",
		Credentials: &Credentials{
			Username: "root",
			Password: secret,
		},
	}

	redacted := original.Redacted()

	// Ensure original is not mutated
	if original.Credentials.Password != secret {
		t.Fatalf("original password was mutated, expected %q got %q", secret, original.Credentials.Password)
	}

	// Ensure redacted field is cleared
	if redacted.Credentials.Password != "" {
		t.Fatalf("expected empty password on redacted info, got %q", redacted.Credentials.Password)
	}
	if redacted.Credentials.Username != "root" {
		t.Fatalf("expected username 'root', got %q", redacted.Credentials.Username)
	}

	// Ensure JSON serialization omits password entirely
	data, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("json marshal redacted: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("redacted JSON contains secret password: %s", string(data))
	}
	if strings.Contains(string(data), "password") {
		t.Fatalf("redacted JSON contains 'password' key: %s", string(data))
	}

	// Ensure original still serializes password when unredacted (for initial provisioning)
	origBytes, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json marshal original: %v", err)
	}
	if !strings.Contains(string(origBytes), secret) {
		t.Fatalf("original JSON should contain password: %s", string(origBytes))
	}
}
