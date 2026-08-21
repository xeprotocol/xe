package vm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type limaVM struct {
	name         string
	leaseHash    string
	sshLocalPort int
	resources    Resources
	createdAt    int64
}

// DefaultImageName is the expected filename for the Ubuntu cloud image.
const DefaultImageName = "ubuntu-24.04-x86_64.img"

// DefaultImageURL is the upstream URL for the Ubuntu 24.04 cloud image.
const DefaultImageURL = "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img"

type LimaManager struct {
	mu          sync.RWMutex
	vms         map[string]*limaVM // leaseHash → VM state
	limaHome    string
	limactlPath string
	templateDir string
	imagePath   string // local path to the Alpine cloud image (qcow2)
}

func NewLimaManager(dataDir, limactlPath string) (*LimaManager, error) {
	if limactlPath == "" {
		limactlPath = "limactl"
	}

	limaHome := filepath.Join(dataDir, "lima")
	templateDir := filepath.Join(dataDir, "lima-templates")
	imagesDir := filepath.Join(dataDir, "images")

	for _, dir := range []string{limaHome, templateDir, imagesDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	imagePath := filepath.Join(imagesDir, DefaultImageName)

	m := &LimaManager{
		vms:         make(map[string]*limaVM),
		limaHome:    limaHome,
		limactlPath: limactlPath,
		templateDir: templateDir,
		imagePath:   imagePath,
	}

	out, err := m.runLimactl("--version")
	if err != nil {
		return nil, fmt.Errorf("limactl not available: %w", err)
	}
	log.Printf("Lima version: %s", strings.TrimSpace(out))

	// Check if the cloud image is available locally.
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		log.Printf("Lima cloud image not found at %s, downloading...", imagePath)
		if err := downloadImage(DefaultImageURL, imagePath); err != nil {
			return nil, fmt.Errorf("download cloud image: %w", err)
		}
		log.Printf("Lima cloud image downloaded to %s", imagePath)
	} else {
		log.Printf("Lima cloud image: %s", imagePath)
	}

	m.cleanOrphans()

	return m, nil
}

func (m *LimaManager) vmName(leaseHash string) string {
	return "xe-" + leaseHash[:12]
}

func (m *LimaManager) Provision(leaseHash string, res Resources, accessPubKey string) (*Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.vms[leaseHash]; exists {
		return nil, fmt.Errorf("vm already exists for lease %s", leaseHash)
	}

	sshAuthKey, err := ed25519HexToSSHAuthorizedKey(accessPubKey)
	if err != nil {
		return nil, fmt.Errorf("convert access key: %w", err)
	}

	yamlData, err := renderLimaTemplate(res, sshAuthKey, "file://"+m.imagePath)
	if err != nil {
		return nil, err
	}

	name := m.vmName(leaseHash)
	templatePath := filepath.Join(m.templateDir, name+".yaml")
	if err := os.WriteFile(templatePath, yamlData, 0644); err != nil {
		return nil, fmt.Errorf("write template: %w", err)
	}

	if _, err := m.runLimactlWithTimeout(2*time.Minute, "create", "--tty=false", "--name="+name, templatePath); err != nil {
		_ = os.Remove(templatePath)
		return nil, fmt.Errorf("lima create: %w", err)
	}

	if _, err := m.runLimactlWithTimeout(5*time.Minute, "start", "--tty=false", name); err != nil {
		diag := m.captureDiagnosticLogs(name)
		_, _ = m.runLimactl("delete", "--force", name)
		_ = os.Remove(templatePath)
		if diag != "" {
			return nil, fmt.Errorf("lima start: %w\n%s", err, diag)
		}
		return nil, fmt.Errorf("lima start: %w", err)
	}

	sshPort, err := m.waitForSSHPort(name, 2*time.Minute)
	if err != nil {
		diag := m.captureDiagnosticLogs(name)
		_, _ = m.runLimactl("stop", name)
		_, _ = m.runLimactl("delete", "--force", name)
		_ = os.Remove(templatePath)
		if diag != "" {
			return nil, fmt.Errorf("get ssh port: %w\n%s", err, diag)
		}
		return nil, fmt.Errorf("get ssh port: %w", err)
	}

	now := time.Now().UnixNano()
	m.vms[leaseHash] = &limaVM{
		name:         name,
		leaseHash:    leaseHash,
		sshLocalPort: sshPort,
		resources:    res,
		createdAt:    now,
	}

	log.Printf("Lima VM %s provisioned (ssh port %d)", name, sshPort)

	return &Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &res,
		CreatedAt: now,
	}, nil
}

func (m *LimaManager) Teardown(leaseHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, ok := m.vms[leaseHash]
	if !ok {
		return fmt.Errorf("vm not found for lease %s", leaseHash)
	}

	_, _ = m.runLimactl("stop", v.name)
	_, _ = m.runLimactl("delete", "--force", v.name)
	_ = os.Remove(filepath.Join(m.templateDir, v.name+".yaml"))
	delete(m.vms, leaseHash)

	log.Printf("Lima VM %s torn down", v.name)
	return nil
}

func (m *LimaManager) DialSSH(leaseHash string) (net.Conn, error) {
	m.mu.RLock()
	v, ok := m.vms[leaseHash]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("vm not found for lease %s", leaseHash)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", v.sshLocalPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial lima vm ssh: %w", err)
	}
	return conn, nil
}

func (m *LimaManager) Get(leaseHash string) (*Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.vms[leaseHash]
	if !ok {
		return nil, fmt.Errorf("vm not found for lease %s", leaseHash)
	}

	return &Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &v.resources,
		CreatedAt: v.createdAt,
	}, nil
}

func (m *LimaManager) List() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Info, 0, len(m.vms))
	for hash, v := range m.vms {
		out = append(out, &Info{
			LeaseHash: hash,
			Status:    "running",
			Resources: &v.resources,
			CreatedAt: v.createdAt,
		})
	}
	return out
}

func (m *LimaManager) captureDiagnosticLogs(name string) string {
	instanceDir := filepath.Join(m.limaHome, name)
	var parts []string
	for _, logFile := range []string{"ha.stderr.log", "serial.log"} {
		data, err := os.ReadFile(filepath.Join(instanceDir, logFile))
		if err != nil || len(data) == 0 {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		// Keep last 20 lines to avoid overwhelming the error message.
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		parts = append(parts, fmt.Sprintf("[%s]\n%s", logFile, strings.Join(lines, "\n")))
	}
	return strings.Join(parts, "\n")
}

func (m *LimaManager) waitForSSHPort(name string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		port, err := m.getSSHPort(name)
		if err == nil && port > 0 {
			// Verify port is actually listening
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
			if err == nil {
				_ = conn.Close()
				return port, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return 0, fmt.Errorf("ssh port not ready after %s", timeout)
}

func (m *LimaManager) getSSHPort(name string) (int, error) {
	out, err := m.runLimactl("list", "--json")
	if err != nil {
		return 0, err
	}

	// limactl list --json outputs JSONL (one JSON object per line)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Name         string `json:"name"`
			SSHLocalPort int    `json:"sshLocalPort"`
			Status       string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Name == name && entry.SSHLocalPort > 0 {
			return entry.SSHLocalPort, nil
		}
	}
	return 0, fmt.Errorf("vm %s not found in lima list", name)
}

func (m *LimaManager) runLimactl(args ...string) (string, error) {
	return m.runLimactlWithTimeout(30*time.Second, args...)
}

func (m *LimaManager) runLimactlWithTimeout(timeout time.Duration, args ...string) (string, error) {
	cmd := exec.Command(m.limactlPath, args...)
	cmd.Env = append(os.Environ(), "LIMA_HOME="+m.limaHome)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("limactl %s: %w", args[0], err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return "", fmt.Errorf("limactl %s: %s", args[0], msg)
		}
		return stdout.String(), nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("limactl %s: timed out after %s", args[0], timeout)
	}
}

func (m *LimaManager) cleanOrphans() {
	out, err := m.runLimactl("list", "--json")
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if strings.HasPrefix(entry.Name, "xe-") {
			log.Printf("Cleaning orphaned Lima VM: %s (status: %s)", entry.Name, entry.Status)
			_, _ = m.runLimactl("stop", entry.Name)
			_, _ = m.runLimactl("delete", "--force", entry.Name)
		}
	}
}

func ed25519HexToSSHAuthorizedKey(hexKey string) (string, error) {
	if hexKey == "" {
		return "", fmt.Errorf("empty access key")
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}

	keyType := "ssh-ed25519"
	var buf bytes.Buffer
	writeSSHString(&buf, []byte(keyType))
	writeSSHString(&buf, raw)

	return fmt.Sprintf("%s %s", keyType, base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func writeSSHString(buf *bytes.Buffer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf.Write(lenBuf[:])
	buf.Write(data)
}

func downloadImage(url, destPath string) error {
	tempPath := destPath + ".tmp"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return err
	}
	_ = f.Close()

	return os.Rename(tempPath, destPath)
}
