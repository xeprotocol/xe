package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSystemdPackaging(t *testing.T) {
	repoRoot := filepath.Join("..", "..")

	// 1. Ensure legacy deploy/systemd duplicate does not exist
	legacyDir := filepath.Join(repoRoot, "deploy", "systemd")
	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed, but it exists", legacyDir)
	}

	// 2. Ensure deploy/xe-node.service exists and has required directives
	servicePath := filepath.Join(repoRoot, "deploy", "xe-node.service")
	serviceBytes, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", servicePath, err)
	}
	serviceContent := string(serviceBytes)

	requiredServiceDirectives := []string{
		"EnvironmentFile=/etc/xe/xe-node.env",
		"--genesis-dir ${XE_GENESIS_DIR}",
		"--dial ${XE_BOOTSTRAP}",
		"--metrics-addr ${XE_METRICS_ADDR}",
		"--log-level ${XE_LOG_LEVEL}",
		"$XE_EXTRA_ARGS",
		"ExecStartPre=/bin/sh -c",
		"LogRateLimitIntervalSec=30s",
		"LogRateLimitBurst=5000",
	}
	for _, req := range requiredServiceDirectives {
		if !strings.Contains(serviceContent, req) {
			t.Errorf("deploy/xe-node.service missing expected string: %q", req)
		}
	}

	// 3. Ensure deploy/xe-node.env.example contains all referenced variables with non-empty defaults
	envPath := filepath.Join(repoRoot, "deploy", "xe-node.env.example")
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", envPath, err)
	}
	envContent := string(envBytes)

	expectedVars := []string{
		"XE_DATA_DIR",
		"XE_P2P_PORT",
		"XE_BOOTSTRAP",
		"XE_GENESIS_DIR",
		"XE_API_BIND",
		"XE_API_PORT",
		"XE_METRICS_ADDR",
		"XE_LOG_LEVEL",
		"XE_EXTRA_ARGS",
	}
	for _, v := range expectedVars {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(v) + `=`)
		if !re.MatchString(envContent) {
			t.Errorf("deploy/xe-node.env.example missing variable definition for %s", v)
		}
	}

	// 4. Test ExecStartPre logic in isolated subshells
	testCases := []struct {
		name        string
		env         map[string]string
		expectFail  bool
		errContains string
	}{
		{
			name:        "missing genesis dir",
			env:         map[string]string{},
			expectFail:  true,
			errContains: "XE_GENESIS_DIR is not set",
		},
		{
			name:        "nonexistent genesis dir",
			env:         map[string]string{"XE_GENESIS_DIR": "/tmp/nonexistent-genesis-path-1234"},
			expectFail:  true,
			errContains: "does not exist or is not a directory",
		},
		{
			name: "missing genesis json files",
			env: func() map[string]string {
				dir := t.TempDir()
				return map[string]string{"XE_GENESIS_DIR": dir}
			}(),
			expectFail:  true,
			errContains: "must contain both ledger-genesis.json and statechain-genesis.json",
		},
		{
			name: "missing bootstrap",
			env: func() map[string]string {
				dir := t.TempDir()
				_ = os.WriteFile(filepath.Join(dir, "ledger-genesis.json"), []byte("{}"), 0644)
				_ = os.WriteFile(filepath.Join(dir, "statechain-genesis.json"), []byte("{}"), 0644)
				return map[string]string{"XE_GENESIS_DIR": dir}
			}(),
			expectFail:  true,
			errContains: "XE_BOOTSTRAP is unset or REPLACE_ME",
		},
		{
			name: "deprecated XE_DIAL usage",
			env: func() map[string]string {
				dir := t.TempDir()
				_ = os.WriteFile(filepath.Join(dir, "ledger-genesis.json"), []byte("{}"), 0644)
				_ = os.WriteFile(filepath.Join(dir, "statechain-genesis.json"), []byte("{}"), 0644)
				return map[string]string{
					"XE_GENESIS_DIR": dir,
					"XE_DIAL":        "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW",
				}
			}(),
			expectFail:  true,
			errContains: "XE_DIAL is deprecated",
		},
		{
			name: "valid configuration",
			env: func() map[string]string {
				dir := t.TempDir()
				_ = os.WriteFile(filepath.Join(dir, "ledger-genesis.json"), []byte("{}"), 0644)
				_ = os.WriteFile(filepath.Join(dir, "statechain-genesis.json"), []byte("{}"), 0644)
				return map[string]string{
					"XE_GENESIS_DIR": dir,
					"XE_BOOTSTRAP":   "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW",
				}
			}(),
			expectFail: false,
		},
	}

	// Extract the script from ExecStartPre
	preRe := regexp.MustCompile(`(?s)ExecStartPre=/bin/sh -c '(?P<script>.*?)'\n\nExecStart`)
	matches := preRe.FindStringSubmatch(serviceContent)
	if len(matches) < 2 {
		t.Fatalf("could not extract ExecStartPre shell script from service file")
	}
	rawScript := matches[1]
	// Unescape systemd $$ to $
	shScript := strings.ReplaceAll(rawScript, "$$", "$")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", shScript)
			cmd.Env = os.Environ()
			// Override specific env vars
			for k, v := range tc.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			out, err := cmd.CombinedOutput()
			if tc.expectFail {
				if err == nil {
					t.Fatalf("expected command to fail, but it succeeded. Output: %s", string(out))
				}
				if tc.errContains != "" && !strings.Contains(string(out), tc.errContains) {
					t.Fatalf("expected output to contain %q, but got %q", tc.errContains, string(out))
				}
			} else {
				if err != nil {
					t.Fatalf("expected command to succeed, but got error: %v. Output: %s", err, string(out))
				}
			}
		})
	}
}
