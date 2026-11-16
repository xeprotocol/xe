package api

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		expected   string
	}{
		{
			name:       "Direct non-loopback ignores XFF",
			remoteAddr: "203.0.113.195:45678",
			xff:        "1.1.1.1, 127.0.0.1",
			xRealIP:    "2.2.2.2",
			expected:   "203.0.113.195",
		},
		{
			name:       "UI reverse proxy loopback with client IP",
			remoteAddr: "127.0.0.1:54321",
			xff:        "9.9.9.9, 127.0.0.1",
			expected:   "9.9.9.9",
		},
		{
			name:       "UI reverse proxy with chained proxies and ports",
			remoteAddr: "127.0.0.1:54321",
			xff:        "198.51.100.25:1234, 10.0.0.1, 127.0.0.1:3000",
			expected:   "10.0.0.1",
		},
		{
			name:       "UI reverse proxy with single external client IP",
			remoteAddr: "127.0.0.1:54321",
			xff:        "8.8.8.8",
			expected:   "8.8.8.8",
		},
		{
			name:       "UI reverse proxy with all loopback falls back to X-Real-IP",
			remoteAddr: "127.0.0.1:54321",
			xff:        "127.0.0.1, [::1]",
			xRealIP:    "192.0.2.1",
			expected:   "192.0.2.1",
		},
		{
			name:       "UI reverse proxy with only X-Real-IP",
			remoteAddr: "127.0.0.1:54321",
			xRealIP:    "192.0.2.55:9999",
			expected:   "192.0.2.55",
		},
		{
			name:       "UI reverse proxy with no headers",
			remoteAddr: "127.0.0.1:54321",
			expected:   "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", "/test", nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := clientIP(r)
			if got != tt.expected {
				t.Errorf("clientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}
