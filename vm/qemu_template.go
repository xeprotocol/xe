package vm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const cloudInitUserDataTemplate = `#cloud-config
hostname: gpu-guest
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - {{.SSHAuthKey}}
ssh_pwauth: false
runcmd:
  - [ systemctl, restart, ssh ]
`

const cloudInitMetaDataTemplate = `instance-id: {{.InstanceID}}
local-hostname: gpu-guest
`

var (
	cloudInitUserDataTmpl = template.Must(template.New("user-data").Parse(cloudInitUserDataTemplate))
	cloudInitMetaDataTmpl = template.Must(template.New("meta-data").Parse(cloudInitMetaDataTemplate))
)

type cloudInitData struct {
	SSHAuthKey string
	InstanceID string
}

// renderCloudInitUserData returns NoCloud user-data with the supplied SSH
// authorized key injected. The key is validated against the same shell-safe
// pattern used by the Lima template (sshAuthKeyPattern in lima_template.go).
func renderCloudInitUserData(sshAuthKey string) ([]byte, error) {
	if !sshAuthKeyPattern.MatchString(sshAuthKey) {
		return nil, fmt.Errorf("cloud-init user-data: invalid SSH auth key format")
	}
	var buf bytes.Buffer
	if err := cloudInitUserDataTmpl.Execute(&buf, cloudInitData{SSHAuthKey: sshAuthKey}); err != nil {
		return nil, fmt.Errorf("cloud-init user-data: %w", err)
	}
	return buf.Bytes(), nil
}

func renderCloudInitMetaData(instanceID string) ([]byte, error) {
	if instanceID == "" {
		return nil, fmt.Errorf("cloud-init meta-data: empty instance-id")
	}
	var buf bytes.Buffer
	if err := cloudInitMetaDataTmpl.Execute(&buf, cloudInitData{InstanceID: instanceID}); err != nil {
		return nil, fmt.Errorf("cloud-init meta-data: %w", err)
	}
	return buf.Bytes(), nil
}

// buildSeedISO writes user-data and meta-data into workDir and shells out to
// cloud-localds to produce a NoCloud seed image at workDir/seed.iso. Returns
// the seed.iso path on success.
func buildSeedISO(workDir, sshAuthKey, instanceID, cloudLocaldsBinary string) (string, error) {
	userData, err := renderCloudInitUserData(sshAuthKey)
	if err != nil {
		return "", err
	}
	metaData, err := renderCloudInitMetaData(instanceID)
	if err != nil {
		return "", err
	}
	udPath := filepath.Join(workDir, "user-data")
	mdPath := filepath.Join(workDir, "meta-data")
	seedPath := filepath.Join(workDir, "seed.iso")
	if err := os.WriteFile(udPath, userData, 0644); err != nil {
		return "", fmt.Errorf("write user-data: %w", err)
	}
	if err := os.WriteFile(mdPath, metaData, 0644); err != nil {
		return "", fmt.Errorf("write meta-data: %w", err)
	}
	if cloudLocaldsBinary == "" {
		cloudLocaldsBinary = "cloud-localds"
	}
	out, err := exec.Command(cloudLocaldsBinary, seedPath, udPath, mdPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cloud-localds: %s: %w", string(out), err)
	}
	return seedPath, nil
}
