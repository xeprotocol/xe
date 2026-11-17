package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createFakeLimactl(t *testing.T, tmpDir string, logFile string, listJSONOutput string) string {
	scriptPath := filepath.Join(tmpDir, "fake_limactl.sh")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
case "$1" in
  --version)
    echo "limactl version 0.20.0"
    exit 0
    ;;
  list)
    cat << 'EOF'
%s
EOF
    exit 0
    ;;
  stop|delete)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`, logFile, listJSONOutput)

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake limactl: %v", err)
	}
	return scriptPath
}

func TestSeg1DRun105LimaRestartPreservesAndAdoptsLiveVMs(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "limactl_invocations.log")

	// Ensure fake cloud image exists to avoid download attempts
	imagesDir := filepath.Join(tmpDir, "images")
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		t.Fatalf("create images dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagesDir, DefaultImageName), []byte("fake image"), 0644); err != nil {
		t.Fatalf("write fake image: %v", err)
	}

	listJSON := strings.TrimSpace(`
{"name": "xe-abcdef123456", "status": "Running", "sshLocalPort": 60022}
{"name": "xe-deadbeef0000", "status": "Stopped", "sshLocalPort": 0}
{"name": "non-xe-vm", "status": "Running", "sshLocalPort": 60023}
`)
	fakeLimactl := createFakeLimactl(t, tmpDir, logFile, listJSON)

	mgr, err := NewLimaManager(tmpDir, fakeLimactl)
	if err != nil {
		t.Fatalf("NewLimaManager failed: %v", err)
	}

	logBytes, _ := os.ReadFile(logFile)
	logContent := string(logBytes)

	// 1. Verify xe-abcdef123456 (Running) was NOT stopped or deleted during construction
	if strings.Contains(logContent, "stop xe-abcdef123456") || strings.Contains(logContent, "delete --force xe-abcdef123456") {
		t.Fatalf("Live running VM xe-abcdef123456 was wrongly stopped or deleted! Log:\n%s", logContent)
	}

	// 2. Verify non-xe-vm was not touched
	if strings.Contains(logContent, "non-xe-vm") {
		t.Fatalf("Non-xe VM was wrongly touched! Log:\n%s", logContent)
	}

	// 3. Verify stopped/dead VM xe-deadbeef0000 WAS cleaned up
	if !strings.Contains(logContent, "stop xe-deadbeef0000") || !strings.Contains(logContent, "delete --force xe-deadbeef0000") {
		t.Fatalf("Stopped orphan VM xe-deadbeef0000 was not cleaned up! Log:\n%s", logContent)
	}

	// 4. Verify registry adoption across restart: mgr.List() must NOT be 0
	vms := mgr.List()
	if len(vms) != 1 {
		t.Fatalf("Expected 1 adopted VM in registry, got %d", len(vms))
	}
	if vms[0].LeaseHash != "abcdef123456" {
		t.Fatalf("Expected adopted lease hash abcdef123456, got %s", vms[0].LeaseHash)
	}

	// 5. Verify Get works for both prefix and full 64-char lease hash
	fullHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	info, err := mgr.Get("abcdef123456")
	if err != nil || info.Status != "running" {
		t.Fatalf("Get by prefix failed: info=%v, err=%v", info, err)
	}
	infoFull, err := mgr.Get(fullHash)
	if err != nil || infoFull.Status != "running" {
		t.Fatalf("Get by full hash failed: info=%v, err=%v", infoFull, err)
	}

	// 6. Verify Teardown succeeds and properly reaps the VM
	if err := mgr.Teardown(fullHash); err != nil {
		t.Fatalf("Teardown of adopted VM failed: %v", err)
	}
	logBytesAfter, _ := os.ReadFile(logFile)
	logContentAfter := string(logBytesAfter)
	if !strings.Contains(logContentAfter, "stop xe-abcdef123456") || !strings.Contains(logContentAfter, "delete --force xe-abcdef123456") {
		t.Fatalf("Teardown did not call stop and delete: %s", logContentAfter)
	}
	if len(mgr.List()) != 0 {
		t.Fatalf("Expected 0 VMs after teardown, got %d", len(mgr.List()))
	}
}

func TestSeg1DRun105LimaRestartDeletesLiveVMs(t *testing.T) {
	// Re-executes the exact reporter scenario: NewLimaManager must not delete running xe- instances
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "limactl.log")

	imagesDir := filepath.Join(tmpDir, "images")
	_ = os.MkdirAll(imagesDir, 0755)
	_ = os.WriteFile(filepath.Join(imagesDir, DefaultImageName), []byte("fake"), 0644)

	listJSON := strings.TrimSpace(`
{"name": "xe-abcdef123456", "status": "Running", "sshLocalPort": 60022}
{"name": "non-xe-instance", "status": "Running", "sshLocalPort": 60023}
`)
	fakeLimactl := createFakeLimactl(t, tmpDir, logFile, listJSON)

	_, err := NewLimaManager(tmpDir, fakeLimactl)
	if err != nil {
		t.Fatalf("NewLimaManager: %v", err)
	}

	logBytes, _ := os.ReadFile(logFile)
	logContent := string(logBytes)
	if strings.Contains(logContent, "stop xe-abcdef123456") || strings.Contains(logContent, "delete --force xe-abcdef123456") {
		t.Fatalf("Lima restart issued delete/stop for live Running VM! Log:\n%s", logContent)
	}
}

func TestSeg1DRun105RegistryLossAcrossRestart(t *testing.T) {
	// Re-executes the exact reporter scenario: fresh manager over the world must retain the VM in registry and teardown must succeed
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "limactl.log")

	imagesDir := filepath.Join(tmpDir, "images")
	_ = os.MkdirAll(imagesDir, 0755)
	_ = os.WriteFile(filepath.Join(imagesDir, DefaultImageName), []byte("fake"), 0644)

	listJSON := strings.TrimSpace(`
{"name": "xe-abcdef123456", "status": "Running", "sshLocalPort": 60022}
`)
	fakeLimactl := createFakeLimactl(t, tmpDir, logFile, listJSON)

	mgr, err := NewLimaManager(tmpDir, fakeLimactl)
	if err != nil {
		t.Fatalf("NewLimaManager: %v", err)
	}

	if len(mgr.List()) == 0 {
		t.Fatalf("Registry loss across restart: fresh manager lists 0 VMs")
	}

	preRestartLease := "abcdef1234567890abcdef1234567890"
	if err := mgr.Teardown(preRestartLease); err != nil {
		t.Fatalf("Teardown of pre-restart lease failed: %v", err)
	}
}

