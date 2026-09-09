package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var gpuBDFPattern = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$`)

var gpuVendorDevicePattern = regexp.MustCompile(`^[0-9a-f]{4} [0-9a-f]{4}$`)

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

type VFIOConfig struct {
	BDF string

	VendorDevice string

	GPUAdminToolsPath string

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
