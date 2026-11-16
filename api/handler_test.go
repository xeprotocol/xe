package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "direct external client",
			remoteAddr: "203.0.113.195:12345",
			headers:    nil,
			expected:   "203.0.113.195",
		},
		{
			name:       "external client with untrusted remoteAddr ignores XFF",
			remoteAddr: "203.0.113.195:12345",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			expected: "203.0.113.195",
		},
		{
			name:       "behind loopback reverse proxy (Caddy)",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195",
			},
			expected: "203.0.113.195",
		},
		{
			name:       "behind chained loopback proxies (Caddy + UI reverse proxy)",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195, 127.0.0.1",
			},
			expected: "203.0.113.195",
		},
		{
			name:       "multi-hop external proxies behind loopback",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.1, 203.0.113.50, 127.0.0.1",
			},
			expected: "203.0.113.50",
		},
		{
			name:       "IPv6 loopback chain",
			remoteAddr: "[::1]:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.50, ::1",
			},
			expected: "203.0.113.50",
		},
		{
			name:       "all loopback fallback",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			expected: "127.0.0.1",
		},
		{
			name:       "fallback to X-Real-IP when XFF empty",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.88",
			},
			expected: "203.0.113.88",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/api/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := clientIP(req)
			if got != tt.expected {
				t.Errorf("clientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestUIReverseProxyClientIPResolution(t *testing.T) {
	var resolvedIP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolvedIP = clientIP(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxyHandler, err := newPrefixProxy("/api", backend.URL)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://ui.test/api/blocks", nil)
	// Simulate request arriving from Caddy on loopback with real client in XFF
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	rec := httptest.NewRecorder()

	proxyHandler.ServeHTTP(rec, req)

	if resolvedIP != "203.0.113.195" {
		t.Errorf("expected clientIP() to resolve %q, got %q", "203.0.113.195", resolvedIP)
	}
}
