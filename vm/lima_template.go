package vm

import (
	"bytes"
	"fmt"
	"regexp"
	"text/template"
)

type limaTemplateData struct {
	ImagePath  string
	CPUs       uint64
	MemorySpec string
	DiskSpec   string
	SSHAuthKey string
}

const limaYAMLTemplate = `vmType: "qemu"
images:
  - location: "{{.ImagePath}}"
    arch: "x86_64"
cpus: {{.CPUs}}
memory: "{{.MemorySpec}}"
disk: "{{.DiskSpec}}"
mounts: []
containerd:
  system: false
  user: false
provision:
  - mode: system
    script: |
      #!/bin/bash
      mkdir -p /root/.ssh && chmod 700 /root/.ssh
      echo '{{.SSHAuthKey}}' >> /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
      sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
      sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
      sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
      systemctl restart sshd
`

var limaTmpl = template.Must(template.New("lima").Parse(limaYAMLTemplate))

// sshAuthKeyPattern matches valid SSH authorized key strings. The key is
// interpolated into a bash script via text/template, so we must reject
// any input containing shell metacharacters to prevent command injection.
var sshAuthKeyPattern = regexp.MustCompile(`^ssh-[a-z0-9-]+ [A-Za-z0-9+/=]+$`)

func renderLimaTemplate(res Resources, sshAuthKey, imagePath string) ([]byte, error) {
	if !sshAuthKeyPattern.MatchString(sshAuthKey) {
		return nil, fmt.Errorf("render lima template: invalid SSH auth key format")
	}

	cpus := res.VCPUs
	if cpus < 1 {
		cpus = 1
	}
	memMB := res.MemoryMB
	if memMB < 512 {
		memMB = 512
	}
	diskGB := res.DiskGB
	if diskGB < 5 {
		diskGB = 5
	}

	data := limaTemplateData{
		ImagePath:  imagePath,
		CPUs:       cpus,
		MemorySpec: fmt.Sprintf("%dMiB", memMB),
		DiskSpec:   fmt.Sprintf("%dGiB", diskGB),
		SSHAuthKey: sshAuthKey,
	}

	var buf bytes.Buffer
	if err := limaTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render lima template: %w", err)
	}
	return buf.Bytes(), nil
}
