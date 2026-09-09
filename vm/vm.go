package vm

import "net"

type Resources struct {
	VCPUs    uint64 `json:"vcpus"`
	MemoryMB uint64 `json:"memory_mb"`
	DiskGB   uint64 `json:"disk_gb"`
}

type Manager interface {
	Provision(leaseHash string, res Resources, accessPubKey string) (*Info, error)
	Teardown(leaseHash string) error
	DialSSH(leaseHash string) (net.Conn, error)
	Get(leaseHash string) (*Info, error)
	List() []*Info
}

type Info struct {
	LeaseHash   string       `json:"lease_hash"`
	Status      string       `json:"status"`
	Resources   *Resources   `json:"resources,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
	CreatedAt   int64        `json:"created_at"`
	Error       string       `json:"error,omitempty"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
