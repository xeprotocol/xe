package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
)

func TestClientIP_DefaultMode(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		expected   string
	}{
		{
			name:       "Loopback direct client with no headers",
			remoteAddr: "127.0.0.1:54321",
			expected:   "127.0.0.1",
		},
		{
			name:       "Loopback direct client cannot spoof X-Forwarded-For",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.195",
			expected:   "127.0.0.1",
		},
		{
			name:       "Loopback direct client cannot spoof X-Real-IP",
			remoteAddr: "127.0.0.1:54321",
			xRealIP:    "203.0.113.195",
			expected:   "127.0.0.1",
		},
		{
			name:       "Loopback direct client cannot spoof both headers",
			remoteAddr: "127.0.0.1:54321",
			xff:        "198.51.100.1, 10.0.0.1",
			xRealIP:    "192.0.2.1",
			expected:   "127.0.0.1",
		},
		{
			name:       "IPv6 loopback direct client ignores headers",
			remoteAddr: "[::1]:54321",
			xff:        "203.0.113.195",
			expected:   "::1",
		},
		{
			name:       "External direct client ignores headers",
			remoteAddr: "198.51.100.5:12345",
			xff:        "203.0.113.195",
			expected:   "198.51.100.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/test", nil)
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

			// Verify Handler method
			got := h.clientIP(r)
			if got != tt.expected {
				t.Errorf("h.clientIP() = %q, want %q", got, tt.expected)
			}

			// Verify package helper also defaults to untrusted
			gotPkg := clientIP(r)
			if gotPkg != tt.expected {
				t.Errorf("clientIP() = %q, want %q", gotPkg, tt.expected)
			}
		})
	}
}

func TestClientIP_TrustedProxyMode(t *testing.T) {
	h := &Handler{}
	h.SetTrustedProxy(true)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		expected   string
	}{
		{
			name:       "Trusted proxy forwards single client IP",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.195",
			expected:   "203.0.113.195",
		},
		{
			name:       "Trusted proxy forwards client IP with port",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.195:8080",
			expected:   "203.0.113.195",
		},
		{
			name:       "Trusted proxy chained with loopback hop",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.195, 127.0.0.1",
			expected:   "203.0.113.195",
		},
		{
			name:       "Trusted proxy multi-hop chain picks nearest non-loopback",
			remoteAddr: "127.0.0.1:54321",
			xff:        "198.51.100.25, 203.0.113.195, 127.0.0.1:3000",
			expected:   "203.0.113.195",
		},
		{
			name:       "Trusted proxy all loopback in XFF falls back to last candidate",
			remoteAddr: "127.0.0.1:54321",
			xff:        "127.0.0.1, [::1]",
			expected:   "::1",
		},
		{
			name:       "Trusted proxy uses X-Real-IP when XFF empty",
			remoteAddr: "127.0.0.1:54321",
			xRealIP:    "192.0.2.1:9999",
			expected:   "192.0.2.1",
		},
		{
			name:       "Trusted proxy with no headers falls back to remote host",
			remoteAddr: "127.0.0.1:54321",
			expected:   "127.0.0.1",
		},
		{
			name:       "Direct external client ignored even in trusted proxy mode",
			remoteAddr: "198.51.100.5:12345",
			xff:        "203.0.113.195",
			xRealIP:    "192.0.2.1",
			expected:   "198.51.100.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/test", nil)
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

			got := h.clientIP(r)
			if got != tt.expected {
				t.Errorf("h.clientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRateLimitMiddleware_RotatingXFF_CannotBypassInDefaultMode(t *testing.T) {
	h := &Handler{}
	// trustedProxy is false by default

	customRLs := &rateLimiters{
		read:  &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 5},
		write: &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 5},
		probe: &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 5},
	}

	nextCalled := 0
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled++
		w.WriteHeader(http.StatusOK)
	})

	mw := h.rateLimitMiddleware(dummyHandler, customRLs)

	// Send 5 requests with distinct XFF values from the same loopback connection.
	// All 5 should be accepted under the 127.0.0.1 bucket.
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/blocks/send", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Forwarded-For", "10.0.0."+string(rune('0'+i)))
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d failed with status %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	// 6th request with a new XFF value should be rejected because the burst (5) is exhausted
	req := httptest.NewRequest(http.MethodPost, "/blocks/send", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on exhausted burst, got %d", rec.Code)
	}

	if nextCalled != 5 {
		t.Errorf("expected nextHandler to be called 5 times, got %d", nextCalled)
	}
}

func TestRateLimitMiddleware_RotatingXFF_AllowedWhenTrustedProxy(t *testing.T) {
	h := &Handler{}
	h.SetTrustedProxy(true)

	customRLs := &rateLimiters{
		read:  &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 2},
		write: &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 2},
		probe: &ipRateLimiter{entries: make(map[string]*rateLimiterEntry), rate: rate.Limit(10), burst: 2},
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := h.rateLimitMiddleware(dummyHandler, customRLs)

	// With trusted proxy enabled, distinct client IPs forwarded through the proxy
	// are tracked in separate buckets.
	clients := []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}
	for _, client := range clients {
		for reqNum := 1; reqNum <= 2; reqNum++ {
			req := httptest.NewRequest(http.MethodPost, "/blocks/send", nil)
			req.RemoteAddr = "127.0.0.1:40000"
			req.Header.Set("X-Forwarded-For", client)
			rec := httptest.NewRecorder()

			mw.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("client %s request %d failed with status %d", client, reqNum, rec.Code)
			}
		}
	}
}
