package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xeprotocol/xe/node"
)

type testMockNode struct {
	nodeBackend
	nodeInfo *node.NodeInfo
	stateKV  map[string]json.RawMessage
}

func (m *testMockNode) GetNodeInfo() *node.NodeInfo {
	if m.nodeInfo != nil {
		return m.nodeInfo
	}
	return &node.NodeInfo{
		ID:        "node-test-123",
		Version:   "1.0.0",
		NetworkID: "testnet-0005",
		Address:   "127.0.0.1:8080",
	}
}

func (m *testMockNode) GetStateKV(key string) (json.RawMessage, bool) {
	if m.stateKV != nil {
		v, ok := m.stateKV[key]
		return v, ok
	}
	return nil, false
}

func (m *testMockNode) GetAllStateKV() map[string]json.RawMessage {
	if m.stateKV != nil {
		return m.stateKV
	}
	return map[string]json.RawMessage{}
}

func (m *testMockNode) GetStateKVByPrefix(prefix string) map[string]json.RawMessage {
	res := make(map[string]json.RawMessage)
	for k, v := range m.stateKV {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			res[k] = v
		}
	}
	return res
}

func (m *testMockNode) GetDelegation() *node.DelegationInfo {
	return &node.DelegationInfo{}
}

func (m *testMockNode) IsBlockFinalized(account, hash string) bool {
	return true
}

func newTestHandler() *Handler {
	mock := &testMockNode{
		stateKV: map[string]json.RawMessage{
			"sys.network_id": json.RawMessage(`"testnet-0005"`),
			"sys.version":    json.RawMessage(`"1.0.0"`),
		},
	}
	return &Handler{node: mock}
}

func TestURLPathNormalizationDivergence(t *testing.T) {
	h := newTestHandler()
	server := httptest.NewServer(h.Mux())
	defer server.Close()

	tests := []struct {
		name       string
		path       string
		wantStatus int
		validate   func(t *testing.T, body []byte)
	}{
		{
			name:       "GET /node/ with trailing slash returns 200 node info",
			path:       "/node/",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var info node.NodeInfo
				if err := json.Unmarshal(body, &info); err != nil {
					t.Fatalf("failed to decode node info: %v", err)
				}
				if info.ID != "node-test-123" {
					t.Errorf("got ID %q, want node-test-123", info.ID)
				}
			},
		},
		{
			name:       "GET /node canonical returns 200 node info",
			path:       "/node",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var info node.NodeInfo
				if err := json.Unmarshal(body, &info); err != nil {
					t.Fatalf("failed to decode node info: %v", err)
				}
				if info.ID != "node-test-123" {
					t.Errorf("got ID %q, want node-test-123", info.ID)
				}
			},
		},
		{
			name:       "GET //node// with redundant slashes returns 200",
			path:       "//node//",
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET /statechain/kv/ with trailing slash returns 200 governance KV map",
			path:       "/statechain/kv/",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var kv map[string]json.RawMessage
				if err := json.Unmarshal(body, &kv); err != nil {
					t.Fatalf("failed to decode kv map: %v", err)
				}
				if _, ok := kv["sys.network_id"]; !ok {
					t.Errorf("missing sys.network_id in statechain kv all response")
				}
			},
		},
		{
			name:       "GET /statechain/kv canonical returns 200 governance KV map",
			path:       "/statechain/kv",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var kv map[string]json.RawMessage
				if err := json.Unmarshal(body, &kv); err != nil {
					t.Fatalf("failed to decode kv map: %v", err)
				}
				if _, ok := kv["sys.network_id"]; !ok {
					t.Errorf("missing sys.network_id in statechain kv all response")
				}
			},
		},
		{
			name:       "GET /statechain/kv/sys.network_id/ with trailing slash returns 200 entry",
			path:       "/statechain/kv/sys.network_id/",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var entry struct {
					Key   string          `json:"key"`
					Value json.RawMessage `json:"value"`
				}
				if err := json.Unmarshal(body, &entry); err != nil {
					t.Fatalf("failed to decode kv entry: %v", err)
				}
				if entry.Key != "sys.network_id" {
					t.Errorf("got key %q, want sys.network_id", entry.Key)
				}
			},
		},
		{
			name:       "GET /statechain/kv/sys.network_id canonical returns 200 entry",
			path:       "/statechain/kv/sys.network_id",
			wantStatus: http.StatusOK,
			validate: func(t *testing.T, body []byte) {
				var entry struct {
					Key   string          `json:"key"`
					Value json.RawMessage `json:"value"`
				}
				if err := json.Unmarshal(body, &entry); err != nil {
					t.Fatalf("failed to decode kv entry: %v", err)
				}
				if entry.Key != "sys.network_id" {
					t.Errorf("got key %q, want sys.network_id", entry.Key)
				}
			},
		},
		{
			name:       "GET /statechain/kv/%2e%2e/sys.network_id collapses dot-segments to /statechain/sys.network_id returning 404 route not found",
			path:       "/statechain/kv/%2e%2e/sys.network_id",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "GET /statechain/kv/./sys.network_id collapses current dot-segment returning 200",
			path:       "/statechain/kv/./sys.network_id",
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET /health/ with trailing slash returns 200",
			path:       "/health/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET / root endpoint returns 200 root discovery document",
			path:       "/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "GET // root with multiple slashes returns 200",
			path:       "//",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(server.URL + tc.path)
			if err != nil {
				t.Fatalf("HTTP request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("got status %d, want %d for %s", resp.StatusCode, tc.wantStatus, tc.path)
			}

			if tc.validate != nil {
				var body []byte
				buf := make([]byte, 4096)
				n, _ := resp.Body.Read(buf)
				body = buf[:n]
				tc.validate(t, body)
			}
		})
	}
}

func TestOpsMuxNormalization(t *testing.T) {
	h := newTestHandler()
	server := httptest.NewServer(OpsMux(h))
	defer server.Close()

	for _, p := range []string{"/health", "/health/", "/ready", "/ready/", "/"} {
		resp, err := http.Get(server.URL + p)
		if err != nil {
			t.Fatalf("request to %s failed: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("expected %s on OpsMux not to be 404, got %d", p, resp.StatusCode)
		}
	}
}
