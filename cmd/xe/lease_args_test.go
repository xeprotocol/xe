package main

import (
	"strings"
	"testing"
)

func TestParseLeaseArgs_Defaults(t *testing.T) {
	la, err := parseLeaseArgs(nil)
	if err != nil {
		t.Fatalf("unexpected error on empty args: %v", err)
	}
	if la.vcpus != 1 || la.memory != 1024 || la.disk != 1 || la.duration != 300 {
		t.Fatalf("unexpected defaults: %+v", la)
	}
	if la.provider != "" {
		t.Fatalf("expected empty provider default, got %q", la.provider)
	}
}

func TestParseLeaseArgs_ValidFlags(t *testing.T) {
	args := []string{
		"--vcpus", "4",
		"--memory", "4096",
		"--disk", "20",
		"--duration", "1800",
		"--provider", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	la, err := parseLeaseArgs(args)
	if err != nil {
		t.Fatalf("unexpected error on valid args: %v", err)
	}
	if la.vcpus != 4 || la.memory != 4096 || la.disk != 20 || la.duration != 1800 {
		t.Fatalf("unexpected parsed dimensions: %+v", la)
	}
	if la.provider != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected parsed provider: %q", la.provider)
	}
}

func TestParseLeaseArgs_RejectsUnknownFlagsAndTypos(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantUnknown string
	}{
		{
			name:        "typo in duration",
			args:        []string{"--duraton", "3600"},
			wantUnknown: `unknown flag "--duraton"`,
		},
		{
			name:        "typo in provider",
			args:        []string{"--providr", "abcd"},
			wantUnknown: `unknown flag "--providr"`,
		},
		{
			name:        "typo in vcpus",
			args:        []string{"--vcpu", "2"},
			wantUnknown: `unknown flag "--vcpu"`,
		},
		{
			name:        "typo in memory",
			args:        []string{"--mem", "2048"},
			wantUnknown: `unknown flag "--mem"`,
		},
		{
			name:        "typo in disk",
			args:        []string{"--storage", "10"},
			wantUnknown: `unknown flag "--storage"`,
		},
		{
			name:        "arbitrary unknown flag before known flag",
			args:        []string{"--bogus", "--provider", "abcd"},
			wantUnknown: `unknown flag "--bogus"`,
		},
		{
			name:        "unknown flag at end",
			args:        []string{"--duration", "600", "--extra"},
			wantUnknown: `unknown flag "--extra"`,
		},
		{
			name:        "unexpected positional argument",
			args:        []string{"extra-arg"},
			wantUnknown: `unknown flag "extra-arg"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLeaseArgs(tc.args)
			if err == nil {
				t.Fatalf("expected error for args %v, got nil", tc.args)
			}
			if !strings.Contains(err.Error(), tc.wantUnknown) {
				t.Fatalf("expected error containing %q, got %q", tc.wantUnknown, err.Error())
			}
		})
	}
}

func TestParseLeaseArgs_MissingValues(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing vcpus value",
			args:    []string{"--vcpus"},
			wantErr: "--vcpus requires a value",
		},
		{
			name:    "missing memory value",
			args:    []string{"--memory"},
			wantErr: "--memory requires a value",
		},
		{
			name:    "missing disk value",
			args:    []string{"--disk"},
			wantErr: "--disk requires a value",
		},
		{
			name:    "missing duration value",
			args:    []string{"--duration"},
			wantErr: "--duration requires a value",
		},
		{
			name:    "missing provider value",
			args:    []string{"--provider"},
			wantErr: "--provider requires a value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLeaseArgs(tc.args)
			if err == nil {
				t.Fatalf("expected error for args %v, got nil", tc.args)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestParseLeaseArgs_InvalidDimensionValues(t *testing.T) {
	// Negative integer in uintFlag
	if _, err := parseLeaseArgs([]string{"--duration", "-50"}); err == nil {
		t.Fatalf("expected error on negative duration")
	}

	// Non-numeric value in uintFlag
	if _, err := parseLeaseArgs([]string{"--vcpus", "abc"}); err == nil {
		t.Fatalf("expected error on non-numeric vcpus")
	}

	// Zero duration failing ValidateLeaseDimensions
	if _, err := parseLeaseArgs([]string{"--duration", "0"}); err == nil {
		t.Fatalf("expected error on zero duration")
	}
}
