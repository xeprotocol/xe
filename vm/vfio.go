package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// gpuBDFPattern matches a fully-qualified PCI bus-device-function in the form
// 0000:01:00.0 — the only form sysfs and gpu-admin-tools accept. We reject
// anything else so user-provided values can't escape into shell args.
var gpuBDFPattern = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$`)

// gpuVendorDevicePattern matches the "VENDOR DEVICE" form accepted by the
// vfio-pci new_id sysfs node (e.g. "10de 2331").
var gpuVendorDevicePattern = regexp.MustCompile(`^[0-9a-f]{4} [0-9a-f]{4}$`)

// IsVFIOBound returns true if the PCI device at the given BDF is currently
// bound to the vfio-pci kernel driver. Returns (false, nil) if the device
// has no driver bound.
func IsVFIOBound(bdf string) (bool, error) {
	if !gpuBDFPattern.MatchString(bdf) {
		return false, fmt.Errorf("invalid GPU BDF: %q", bdf)
	}
	driverLink := filepath.Join("/sys/bus/pci/devices", bdf, "driver")
	target, err := os.Readlink(driverLink)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read driver link: %w", err)
	}
	return filepath.Base(target) == "vfio-pci", nil
}

// IOMMUGroup returns the numeric IOMMU group of the device at bdf, or an
// error if the device has no group (IOMMU disabled in kernel).
func IOMMUGroup(bdf string) (string, error) {
	if !gpuBDFPattern.MatchString(bdf) {
		return "", fmt.Errorf("invalid GPU BDF: %q", bdf)
	}
	link := filepath.Join("/sys/bus/pci/devices", bdf, "iommu_group")
	target, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("read iommu_group: %w", err)
	}
	return filepath.Base(target), nil
}

// VFIOConfig captures the host-side knobs the QEMU manager needs to drive the
// GPU. The values are immutable for the lifetime of a manager; per-VM state
// lives elsewhere.
type VFIOConfig struct {
	// BDF is the PCI bus-device-function of the GPU (e.g. "0000:01:00.0").
	BDF string
	// VendorDevice is the "VENDOR DEVICE" pair used by vfio-pci new_id
	// (e.g. "10de 2331"). Used only when binding vfio-pci as part of host
	// bootstrap; the manager will not auto-bind in this ticket's scope.
	VendorDevice string
	// GPUAdminToolsPath is the path to NVIDIA/gpu-admin-tools'
	// nvidia_gpu_tools.py script. Used for CC-mode query/set and FLR.
	GPUAdminToolsPath string
	// SudoBinary is the sudo program used to invoke privileged tools. Empty
	// defaults to "sudo".
	SudoBinary string
}

func (c VFIOConfig) sudo() string {
	if c.SudoBinary == "" {
		return "sudo"
	}
	return c.SudoBinary
}

func (c VFIOConfig) validate() error {
	if !gpuBDFPattern.MatchString(c.BDF) {
		return fmt.Errorf("invalid GPU BDF: %q", c.BDF)
	}
	if c.VendorDevice != "" && !gpuVendorDevicePattern.MatchString(c.VendorDevice) {
		return fmt.Errorf("invalid GPU vendor:device: %q", c.VendorDevice)
	}
	if c.GPUAdminToolsPath != "" {
		if !filepath.IsAbs(c.GPUAdminToolsPath) {
			return fmt.Errorf("GPUAdminToolsPath must be absolute: %q", c.GPUAdminToolsPath)
		}
	}
	return nil
}

// QueryCCMode returns "on", "off", "devtools", or "unknown" for the GPU at
// the configured BDF. Shells out to gpu-admin-tools.
func (c VFIOConfig) QueryCCMode() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.GPUAdminToolsPath == "" {
		return "", fmt.Errorf("QueryCCMode: GPUAdminToolsPath not configured")
	}
	out, err := exec.Command(c.sudo(), "python3", c.GPUAdminToolsPath,
		"--gpu-bdf="+c.BDF, "--query-cc-mode").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query-cc-mode: %s: %w", string(out), err)
	}
	return parseCCMode(string(out))
}

// parseCCMode extracts the CC mode from a gpu-admin-tools --query-cc-mode
// log line of the form "... CC mode is on". When multiple "CC mode is" lines
// appear (e.g. a set+query pipeline), the last one wins since it reflects the
// most recent state.
func parseCCMode(output string) (string, error) {
	var last string
	for _, line := range strings.Split(output, "\n") {
		idx := strings.LastIndex(line, "CC mode is ")
		if idx < 0 {
			continue
		}
		last = strings.TrimSpace(line[idx+len("CC mode is "):])
	}
	switch last {
	case "":
		return "unknown", fmt.Errorf("no CC mode line in gpu-admin-tools output:\n%s", output)
	case "on", "off", "devtools":
		return last, nil
	default:
		return "unknown", fmt.Errorf("unrecognised CC mode token: %q", last)
	}
}

// SetCCModeOff flips the GPU into non-CC mode and triggers a reset so the
// change takes effect before the next VM provision. The flip is persistent
// in GPU firmware across reboots.
func (c VFIOConfig) SetCCModeOff() error {
	if err := c.validate(); err != nil {
		return err
	}
	if c.GPUAdminToolsPath == "" {
		return fmt.Errorf("SetCCModeOff: GPUAdminToolsPath not configured")
	}
	out, err := exec.Command(c.sudo(), "python3", c.GPUAdminToolsPath,
		"--gpu-bdf="+c.BDF, "--set-cc-mode=off", "--reset-after-cc-mode-switch").CombinedOutput()
	if err != nil {
		return fmt.Errorf("set-cc-mode=off: %s: %w", string(out), err)
	}
	return nil
}

// EnsureCCModeOff is the idempotent provider-startup hook: query CC, and if
// it's not "off", flip it. Cheap when already off (just one query).
func (c VFIOConfig) EnsureCCModeOff() error {
	mode, err := c.QueryCCMode()
	if err != nil {
		return fmt.Errorf("EnsureCCModeOff: %w", err)
	}
	if mode == "off" {
		return nil
	}
	return c.SetCCModeOff()
}

// ResetGPU triggers a PCIe Function-Level Reset via gpu-admin-tools. Used
// between tenants so no GPU state (HBM contents, ECC counters, etc.) crosses
// the lease boundary. Cheap (~1s).
func (c VFIOConfig) ResetGPU() error {
	if err := c.validate(); err != nil {
		return err
	}
	if c.GPUAdminToolsPath == "" {
		return fmt.Errorf("ResetGPU: GPUAdminToolsPath not configured")
	}
	out, err := exec.Command(c.sudo(), "python3", c.GPUAdminToolsPath,
		"--gpu-bdf="+c.BDF, "--reset-with-flr").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reset-with-flr: %s: %w", string(out), err)
	}
	return nil
}
