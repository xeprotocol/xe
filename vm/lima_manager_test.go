package vm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLimaManagerProvisionCreateFailureCleanup(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "limactl.log")
	markerFile := filepath.Join(tempDir, "instance_marker")

	// Fake limactl script simulating create failure after instance state was allocated
	fakeLimactl := filepath.Join(tempDir, "fake_limactl.sh")
	scriptContent := `#!/bin/sh
CMD="$1"
echo "$@" >> "` + logFile + `"
case "$CMD" in
  --version)
    echo "limactl version 0.14.0"
    exit 0
    ;;
  list)
    exit 0
    ;;
  create)
    # Simulate instance created on disk before create command encounters an error
    touch "` + markerFile + `"
    echo "simulated create failure" >&2
    exit 1
    ;;
  delete)
    if [ "$2" = "--force" ]; then
      rm -f "` + markerFile + `"
      exit 0
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`
	if err := os.WriteFile(fakeLimactl, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write fake limactl: %v", err)
	}

	limaHome := filepath.Join(tempDir, "lima-home")
	templateDir := filepath.Join(tempDir, "lima-templates")
	imagesDir := filepath.Join(tempDir, "images")
	for _, dir := range []string{limaHome, templateDir, imagesDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
	}
	dummyImage := filepath.Join(imagesDir, DefaultImageName)
	if err := os.WriteFile(dummyImage, []byte("fake image data"), 0644); err != nil {
		t.Fatalf("failed to write dummy image: %v", err)
	}

	mgr := &LimaManager{
		vms:         make(map[string]*limaVM),
		limaHome:    limaHome,
		limactlPath: fakeLimactl,
		templateDir: templateDir,
		imagePath:   dummyImage,
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	accessKeyHex := hex.EncodeToString(pub)
	leaseHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	expectedVMName := mgr.vmName(leaseHash)

	_, err = mgr.Provision(leaseHash, Resources{VCPUs: 2, MemoryMB: 2048, DiskGB: 20}, accessKeyHex)
	if err == nil {
		t.Fatalf("expected Provision to fail on create error, got nil")
	}
	if !strings.Contains(err.Error(), "lima create:") {
		t.Fatalf("expected 'lima create:' error, got: %v", err)
	}

	// Verify template file was cleaned up
	templatePath := filepath.Join(templateDir, expectedVMName+".yaml")
	if _, statErr := os.Stat(templatePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected template file %s to be deleted, but it exists", templatePath)
	}

	// Verify limactl delete --force was invoked and instance marker was deleted
	if _, statErr := os.Stat(markerFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected instance marker %s to be removed by delete --force, but it still exists", markerFile)
	}

	logData, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("failed to read log file: %v", readErr)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "delete --force "+expectedVMName) {
		t.Fatalf("expected limactl delete --force to be called for %s, calls recorded:\n%s", expectedVMName, logStr)
	}
}

func TestLimaManagerProvisionStartFailureCleanup(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "limactl.log")

	fakeLimactl := filepath.Join(tempDir, "fake_limactl.sh")
	scriptContent := `#!/bin/sh
CMD="$1"
echo "$@" >> "` + logFile + `"
case "$CMD" in
  create)
    exit 0
    ;;
  start)
    echo "simulated start failure" >&2
    exit 1
    ;;
  delete)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`
	if err := os.WriteFile(fakeLimactl, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("failed to write fake limactl: %v", err)
	}

	limaHome := filepath.Join(tempDir, "lima-home")
	templateDir := filepath.Join(tempDir, "lima-templates")
	imagesDir := filepath.Join(tempDir, "images")
	for _, dir := range []string{limaHome, templateDir, imagesDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
	}
	dummyImage := filepath.Join(imagesDir, DefaultImageName)
	if err := os.WriteFile(dummyImage, []byte("fake image data"), 0644); err != nil {
		t.Fatalf("failed to write dummy image: %v", err)
	}

	mgr := &LimaManager{
		vms:         make(map[string]*limaVM),
		limaHome:    limaHome,
		limactlPath: fakeLimactl,
		templateDir: templateDir,
		imagePath:   dummyImage,
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	accessKeyHex := hex.EncodeToString(pub)
	leaseHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	expectedVMName := mgr.vmName(leaseHash)

	_, err = mgr.Provision(leaseHash, Resources{VCPUs: 2, MemoryMB: 2048, DiskGB: 20}, accessKeyHex)
	if err == nil {
		t.Fatalf("expected Provision to fail on start error, got nil")
	}
	if !strings.Contains(err.Error(), "lima start:") {
		t.Fatalf("expected 'lima start:' error, got: %v", err)
	}

	logData, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("failed to read log file: %v", readErr)
	}
	logStr := string(logData)
	if !strings.Contains(logStr, "delete --force "+expectedVMName) {
		t.Fatalf("expected limactl delete --force to be called for %s, calls recorded:\n%s", expectedVMName, logStr)
	}
}
