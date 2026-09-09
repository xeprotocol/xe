package vm

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type QEMUConfig struct {
	VFIO VFIOConfig

	QemuBinary         string
	SudoBinary         string
	OVMFCodePath       string
	OVMFVarsTemplate   string
	CloudLocaldsBinary string
	QemuImgBinary      string

	CloudImagePath string

	CloudImageURL string

	SSHHostfwdPort int

	DefaultVCPUs    uint64
	DefaultMemoryMB uint64
	DefaultDiskGB   uint64
}

func (c *QEMUConfig) defaults() {
	if c.QemuBinary == "" {
		c.QemuBinary = "qemu-system-x86_64"
	}
	if c.SudoBinary == "" {
		c.SudoBinary = "sudo"
	}
	if c.OVMFCodePath == "" {
		c.OVMFCodePath = "/usr/share/OVMF/OVMF_CODE_4M.fd"
	}
	if c.OVMFVarsTemplate == "" {
		c.OVMFVarsTemplate = "/usr/share/OVMF/OVMF_VARS_4M.fd"
	}
	if c.CloudLocaldsBinary == "" {
		c.CloudLocaldsBinary = "cloud-localds"
	}
	if c.QemuImgBinary == "" {
		c.QemuImgBinary = "qemu-img"
	}
	if c.CloudImageURL == "" {
		c.CloudImageURL = DefaultImageURL
	}
	if c.SSHHostfwdPort == 0 {
		c.SSHHostfwdPort = 22000
	}
	if c.DefaultVCPUs == 0 {
		c.DefaultVCPUs = 8
	}
	if c.DefaultMemoryMB == 0 {
		c.DefaultMemoryMB = 16384
	}
	if c.DefaultDiskGB == 0 {
		c.DefaultDiskGB = 32
	}
}

type qemuVM struct {
	leaseHash string
	workDir   string
	pidPath   string
	pid       int
	sshPort   int
	resources Resources
	createdAt int64
}

type QEMUManager struct {
	mu       sync.RWMutex
	vms      map[string]*qemuVM
	cfg      QEMUConfig
	workRoot string
}

func NewQEMUManager(dataDir string, cfg QEMUConfig) (*QEMUManager, error) {
	cfg.defaults()
	if err := cfg.VFIO.validate(); err != nil {
		return nil, fmt.Errorf("vfio config: %w", err)
	}

	workRoot := filepath.Join(dataDir, "qemu")
	if err := os.MkdirAll(workRoot, 0755); err != nil {
		return nil, fmt.Errorf("create qemu dir: %w", err)
	}

	if cfg.CloudImagePath == "" {
		cfg.CloudImagePath = filepath.Join(dataDir, "images", DefaultImageName)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.CloudImagePath), 0755); err != nil {
		return nil, fmt.Errorf("create images dir: %w", err)
	}

	if _, err := exec.LookPath(cfg.QemuBinary); err != nil {
		return nil, fmt.Errorf("qemu binary %q not found: %w", cfg.QemuBinary, err)
	}
	if _, err := exec.LookPath(cfg.QemuImgBinary); err != nil {
		return nil, fmt.Errorf("qemu-img binary %q not found: %w", cfg.QemuImgBinary, err)
	}
	if _, err := exec.LookPath(cfg.CloudLocaldsBinary); err != nil {
		return nil, fmt.Errorf("cloud-localds binary %q not found: %w", cfg.CloudLocaldsBinary, err)
	}
	if _, err := os.Stat(cfg.OVMFCodePath); err != nil {
		return nil, fmt.Errorf("OVMF code %q: %w", cfg.OVMFCodePath, err)
	}
	if _, err := os.Stat(cfg.OVMFVarsTemplate); err != nil {
		return nil, fmt.Errorf("OVMF vars template %q: %w", cfg.OVMFVarsTemplate, err)
	}

	if _, err := os.Stat(cfg.CloudImagePath); os.IsNotExist(err) {
		log.Printf("QEMUManager: downloading cloud image to %s", cfg.CloudImagePath)
		if err := downloadImage(cfg.CloudImageURL, cfg.CloudImagePath); err != nil {
			return nil, fmt.Errorf("download cloud image: %w", err)
		}
		log.Printf("QEMUManager: cloud image downloaded")
	}

	m := &QEMUManager{
		vms:      make(map[string]*qemuVM),
		cfg:      cfg,
		workRoot: workRoot,
	}

	m.cleanOrphans()

	return m, nil
}

func (m *QEMUManager) Provision(leaseHash string, res Resources, accessPubKey string) (*Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.vms) > 0 {
		return nil, fmt.Errorf("qemu manager: GPU is already in use by another lease")
	}
	if len(leaseHash) < 12 {
		return nil, fmt.Errorf("lease hash too short: %q", leaseHash)
	}

	bound, err := IsVFIOBound(m.cfg.VFIO.BDF)
	if err != nil {
		return nil, fmt.Errorf("check vfio binding: %w", err)
	}
	if !bound {
		return nil, fmt.Errorf("GPU %s not bound to vfio-pci — provider startup hook must bind it",
			m.cfg.VFIO.BDF)
	}

	sshAuthKey, err := ed25519HexToSSHAuthorizedKey(accessPubKey)
	if err != nil {
		return nil, fmt.Errorf("convert access key: %w", err)
	}

	name := "xe-" + leaseHash[:12]
	workDir := filepath.Join(m.workRoot, name)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}

	seedPath, err := buildSeedISO(workDir, sshAuthKey, leaseHash, m.cfg.CloudLocaldsBinary)
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("build seed.iso: %w", err)
	}

	vcpus := res.VCPUs
	if vcpus < 1 {
		vcpus = m.cfg.DefaultVCPUs
	}
	memMB := res.MemoryMB
	if memMB < 512 {
		memMB = m.cfg.DefaultMemoryMB
	}
	diskGB := res.DiskGB
	if diskGB < 5 {
		diskGB = m.cfg.DefaultDiskGB
	}

	guestImg := filepath.Join(workDir, "guest.qcow2")
	if err := buildQcowOverlay(m.cfg.QemuImgBinary, m.cfg.CloudImagePath, guestImg, diskGB); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("build qcow2: %w", err)
	}

	varsPath := filepath.Join(workDir, "OVMF_VARS.fd")
	if err := copyFile(m.cfg.OVMFVarsTemplate, varsPath); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("copy OVMF vars: %w", err)
	}

	pidPath := filepath.Join(workDir, "qemu.pid")
	serialPath := filepath.Join(workDir, "serial.log")
	args := []string{
		m.cfg.QemuBinary,
		"-name", name,
		"-enable-kvm",
		"-cpu", "host",
		"-smp", strconv.FormatUint(vcpus, 10),
		"-m", strconv.FormatUint(memMB, 10),
		"-machine", "type=q35,accel=kvm,kernel_irqchip=on",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + m.cfg.OVMFCodePath,
		"-drive", "if=pflash,format=raw,file=" + varsPath,
		"-drive", "if=virtio,format=qcow2,file=" + guestImg,
		"-drive", "if=virtio,format=raw,file=" + seedPath,
		"-netdev", fmt.Sprintf("user,id=n0,hostfwd=tcp::%d-:22", m.cfg.SSHHostfwdPort),
		"-device", "virtio-net-pci,netdev=n0",
		"-device", "vfio-pci,host=" + m.cfg.VFIO.BDF,
		"-display", "none",
		"-daemonize",
		"-pidfile", pidPath,
		"-serial", "file:" + serialPath,
	}
	if out, err := exec.Command(m.cfg.SudoBinary, args...).CombinedOutput(); err != nil {

		m.killQEMUByName(name)
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("qemu start: %s: %w", string(out), err)
	}

	pid, err := waitForQEMUPID(name, 60*time.Second)
	if err != nil {
		m.killQEMUByName(name)

		return nil, fmt.Errorf("find qemu pid: %w", err)
	}
	_ = pidPath

	if err := waitForSSHPort(m.cfg.SSHHostfwdPort, 2*time.Minute); err != nil {
		_ = m.killQEMU(pid)
		return nil, fmt.Errorf("ssh not ready: %w", err)
	}

	now := time.Now().UnixNano()
	v := &qemuVM{
		leaseHash: leaseHash,
		workDir:   workDir,
		pidPath:   pidPath,
		pid:       pid,
		sshPort:   m.cfg.SSHHostfwdPort,
		resources: Resources{VCPUs: vcpus, MemoryMB: memMB, DiskGB: diskGB},
		createdAt: now,
	}
	m.vms[leaseHash] = v

	log.Printf("QEMU VM %s provisioned (ssh port %d, pid %d, GPU %s)",
		name, v.sshPort, v.pid, m.cfg.VFIO.BDF)

	return &Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &v.resources,
		CreatedAt: now,
	}, nil
}

func (m *QEMUManager) Teardown(leaseHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, ok := m.vms[leaseHash]
	if !ok {
		return fmt.Errorf("qemu vm not found for lease %s", leaseHash)
	}

	if err := m.killQEMU(v.pid); err != nil {
		log.Printf("QEMU teardown: kill failed: %v", err)
	}

	if m.cfg.VFIO.GPUAdminToolsPath != "" {
		time.Sleep(2 * time.Second)
		if err := m.cfg.VFIO.ResetGPU(); err != nil {
			log.Printf("QEMU teardown: GPU FLR failed: %v", err)
		}
	}

	_ = os.RemoveAll(v.workDir)
	delete(m.vms, leaseHash)

	log.Printf("QEMU VM xe-%s torn down", leaseHash[:12])
	return nil
}

func (m *QEMUManager) DialSSH(leaseHash string) (net.Conn, error) {
	m.mu.RLock()
	v, ok := m.vms[leaseHash]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("qemu vm not found for lease %s", leaseHash)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", v.sshPort), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial qemu vm ssh: %w", err)
	}
	return conn, nil
}

func (m *QEMUManager) Get(leaseHash string) (*Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.vms[leaseHash]
	if !ok {
		return nil, fmt.Errorf("qemu vm not found for lease %s", leaseHash)
	}
	return &Info{
		LeaseHash: leaseHash,
		Status:    "running",
		Resources: &v.resources,
		CreatedAt: v.createdAt,
	}, nil
}

func (m *QEMUManager) List() []*Info {
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

func (m *QEMUManager) killQEMU(pid int) error {
	if pid <= 0 {
		return nil
	}

	_ = exec.Command(m.cfg.SudoBinary, "kill", "-TERM", strconv.Itoa(pid)).Run()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command(m.cfg.SudoBinary, "kill", "-0", strconv.Itoa(pid)).Run(); err != nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := exec.Command(m.cfg.SudoBinary, "kill", "-KILL", strconv.Itoa(pid)).Run(); err != nil {
		return fmt.Errorf("sigkill: %w", err)
	}
	return nil
}

func (m *QEMUManager) cleanOrphans() {
	orphans := pgrepMatch("qemu-system-x86_64", m.workRoot)
	for _, pidStr := range orphans {
		log.Printf("QEMU: cleaning orphan process pid=%s", pidStr)
		_ = exec.Command(m.cfg.SudoBinary, "kill", "-KILL", pidStr).Run()
	}
	if len(orphans) > 0 && m.cfg.VFIO.GPUAdminToolsPath != "" {
		time.Sleep(2 * time.Second)
		if err := m.cfg.VFIO.ResetGPU(); err != nil {
			log.Printf("QEMU: orphan-cleanup GPU FLR failed: %v", err)
		}
	}
}

func (m *QEMUManager) killQEMUByName(name string) {
	for _, pidStr := range pgrepMatch("qemu-system-x86_64", "-name "+name) {
		log.Printf("QEMU: killing stray process pid=%s name=%s", pidStr, name)
		_ = exec.Command(m.cfg.SudoBinary, "kill", "-KILL", pidStr).Run()
	}
}

func pgrepMatch(pattern, mustContain string) []string {
	out, err := exec.Command("pgrep", "-af", pattern).Output()
	if err != nil {
		return nil
	}
	var pids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.Contains(line, mustContain) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			pids = append(pids, fields[0])
		}
	}
	return pids
}

func waitForQEMUPID(vmName string, timeout time.Duration) (int, error) {
	pattern := "-name " + vmName
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pids := pgrepMatch("qemu-system-x86_64", pattern)
		if len(pids) == 1 {
			if pid, err := strconv.Atoi(pids[0]); err == nil && pid > 0 {
				return pid, nil
			}
		}
		if len(pids) > 1 {
			return 0, fmt.Errorf("multiple qemu processes match %q: %v", pattern, pids)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, fmt.Errorf("no qemu process matching %q after %s", pattern, timeout)
}

func waitForSSHPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("ssh port %d not ready after %s", port, timeout)
}

func buildQcowOverlay(qemuImgBinary, basePath, overlayPath string, sizeGB uint64) error {
	cmd := exec.Command(qemuImgBinary, "create",
		"-F", "qcow2",
		"-b", basePath,
		"-f", "qcow2",
		overlayPath,
		fmt.Sprintf("%dG", sizeGB))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img: %s: %w", string(out), err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}
