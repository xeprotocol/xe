package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/vm"
)

type mockVMBackend struct {
	nodeBackend
	vms []*vm.Info
}

func (m *mockVMBackend) GetVMs() []*vm.Info {
	return m.vms
}

func (m *mockVMBackend) GetVM(leaseHash string) *vm.Info {
	for _, v := range m.vms {
		if v.LeaseHash == leaseHash {
			return v
		}
	}
	return nil
}

func TestVMEndpointsRedactCredentials(t *testing.T) {
	const sentinelPassword = "super-secret-vm-password-9988"
	backend := &mockVMBackend{
		vms: []*vm.Info{
			{
				LeaseHash: "test-lease-hash",
				Status:    "running",
				Credentials: &vm.Credentials{
					Username: "root",
					Password: sentinelPassword,
				},
			},
		},
	}
	h := (&Handler{node: backend}).Mux()

	for _, path := range []string{"/vms", "/vms/test-lease-hash"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Fatalf("GET %s status=%d, want 200", path, rec.Code)
		}

		body := rec.Body.String()
		if strings.Contains(body, sentinelPassword) {
			t.Fatalf("GET %s leaked plaintext password sentinel: %s", path, body)
		}
		if strings.Contains(body, `"password"`) {
			t.Fatalf("GET %s exposed password key: %s", path, body)
		}
		if !strings.Contains(body, "root") {
			t.Fatalf("GET %s missing expected username: %s", path, body)
		}
	}

	// Nonexistent lease returns 404
	req := httptest.NewRequest("GET", "/vms/unknown-lease", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("GET /vms/unknown-lease status=%d, want 404", rec.Code)
	}
}

func TestVMEndpointsRedactNilCredentials(t *testing.T) {
	backend := &mockVMBackend{
		vms: []*vm.Info{
			{
				LeaseHash: "ssh-only-lease",
				Status:    "running",
			},
		},
	}
	h := (&Handler{node: backend}).Mux()

	req := httptest.NewRequest("GET", "/vms/ssh-only-lease", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d, want 200", rec.Code)
	}

	var info vm.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if info.Credentials != nil {
		t.Fatalf("expected nil credentials for ssh-only lease, got: %+v", info.Credentials)
	}
}
