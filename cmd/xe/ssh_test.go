package main

import (
	"strings"
	"testing"
)

func TestBuildSSHArgsDefault(t *testing.T) {
	gwHost := "ldn.test.network"
	gwPort := "2222"
	pemPath := "/tmp/key.pem"
	leaseHash := "abcdef123456"

	args := buildSSHArgs(gwHost, gwPort, pemPath, leaseHash, "", "")

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Errorf("expected StrictHostKeyChecking=no by default, got: %s", joined)
	}
	if !strings.Contains(joined, "UserKnownHostsFile=/dev/null") {
		t.Errorf("expected UserKnownHostsFile=/dev/null by default, got: %s", joined)
	}
	if !strings.Contains(joined, "ProxyCommand=") {
		t.Errorf("expected ProxyCommand, got: %s", joined)
	}
	if !strings.Contains(joined, "root@vm") {
		t.Errorf("expected target root@vm, got: %s", joined)
	}
}

func TestBuildSSHArgsStrictHostKeyChecking(t *testing.T) {
	gwHost := "nyc.test.network"
	gwPort := "2222"
	pemPath := "/home/user/.xe/key.pem"
	leaseHash := "112233445566"

	// Strict host checking enabled ("yes") without custom known_hosts
	args := buildSSHArgs(gwHost, gwPort, pemPath, leaseHash, "yes", "")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Errorf("expected StrictHostKeyChecking=yes, got: %s", joined)
	}
	if strings.Contains(joined, "UserKnownHostsFile=/dev/null") {
		t.Errorf("UserKnownHostsFile=/dev/null should NOT be present when strict checking is enabled: %s", joined)
	}

	// Strict host checking with "accept-new"
	argsAcceptNew := buildSSHArgs(gwHost, gwPort, pemPath, leaseHash, "accept-new", "")
	joinedAcceptNew := strings.Join(argsAcceptNew, " ")
	if !strings.Contains(joinedAcceptNew, "StrictHostKeyChecking=accept-new") {
		t.Errorf("expected StrictHostKeyChecking=accept-new, got: %s", joinedAcceptNew)
	}
}

func TestBuildSSHArgsCustomKnownHosts(t *testing.T) {
	gwHost := "ffm.test.network"
	gwPort := "2222"
	pemPath := "/tmp/key.pem"
	leaseHash := "998877665544"
	customHosts := "/etc/xe/known_hosts"

	args := buildSSHArgs(gwHost, gwPort, pemPath, leaseHash, "yes", customHosts)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Errorf("expected StrictHostKeyChecking=yes, got: %s", joined)
	}
	if !strings.Contains(joined, "UserKnownHostsFile=/etc/xe/known_hosts") {
		t.Errorf("expected UserKnownHostsFile=/etc/xe/known_hosts, got: %s", joined)
	}
}
