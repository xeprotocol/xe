package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression test for #998: convertKeyToOpenSSH must never follow a symlink
// planted at the OpenSSH key path (CWE-59). The function is split so the write
// guard can be exercised without invoking openssl.
func TestConvertKeyToOpenSSH_RefusesSymlink(t *testing.T) {
	payload := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n")

	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-target")
	link := filepath.Join(dir, "lease_key_openssh")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	err := writeFileNoFollow(link, payload, 0600)
	if err == nil {
		t.Fatalf("expected an error writing to a symlink path, got nil")
	}
	if data, readErr := os.ReadFile(target); readErr == nil && strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatalf("key material leaked through symlink into %s", target)
	}

	// Control: a fresh path is written as a regular file.
	out := filepath.Join(t.TempDir(), "lease_key_openssh")
	if err := writeFileNoFollow(out, payload, 0600); err != nil {
		t.Fatalf("control write failed: %v", err)
	}
	info, err := os.Lstat(out)
	if err != nil {
		t.Fatalf("control lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("control: expected regular file, got symlink")
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "PRIVATE KEY") {
		t.Fatalf("control: payload missing")
	}
}
