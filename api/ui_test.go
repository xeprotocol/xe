package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestUISecurityHeaders(t *testing.T) {
	mockFS := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<html><body>Explorer</body></html>")},
		"wallet/index.html": &fstest.MapFile{Data: []byte("<html><body>Wallet</body></html>")},
	}

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer backendServer.Close()

	handler, err := NewUIHandler(mockFS, UIConfig{
		APITarget:     backendServer.URL,
		WalletEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewUIHandler failed: %v", err)
	}

	testCases := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"Root Explorer", "/", http.StatusOK},
		{"Wallet UI", "/wallet/", http.StatusOK},
		{"Features JSON", "/features.json", http.StatusOK},
		{"Proxied API", "/api/status", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("path %s: expected status %d, got %d", tc.path, tc.wantStatus, rr.Code)
			}

			headers := rr.Header()
			if csp := headers.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "default-src 'self'") {
				t.Errorf("path %s: unexpected or missing Content-Security-Policy: %q", tc.path, csp)
			}

			if xfo := headers.Get("X-Frame-Options"); xfo != "DENY" {
				t.Errorf("path %s: expected X-Frame-Options DENY, got %q", tc.path, xfo)
			}

			if hsts := headers.Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=31536000") {
				t.Errorf("path %s: unexpected or missing Strict-Transport-Security: %q", tc.path, hsts)
			}

			if xcto := headers.Get("X-Content-Type-Options"); xcto != "nosniff" {
				t.Errorf("path %s: expected X-Content-Type-Options nosniff, got %q", tc.path, xcto)
			}

			if ref := headers.Get("Referrer-Policy"); ref != "no-referrer" {
				t.Errorf("path %s: expected Referrer-Policy no-referrer, got %q", tc.path, ref)
			}

			if perm := headers.Get("Permissions-Policy"); !strings.Contains(perm, "geolocation=()") {
				t.Errorf("path %s: unexpected or missing Permissions-Policy: %q", tc.path, perm)
			}
		})
	}
}

func TestUIWalletGate(t *testing.T) {
	mockFS := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<html><body>Explorer</body></html>")},
		"wallet/index.html": &fstest.MapFile{Data: []byte("<html><body>Wallet</body></html>")},
	}

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	// Wallet disabled
	handlerDisabled, err := NewUIHandler(mockFS, UIConfig{
		APITarget:     backendServer.URL,
		WalletEnabled: false,
	})
	if err != nil {
		t.Fatalf("NewUIHandler failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/wallet/", nil)
	rr := httptest.NewRecorder()
	handlerDisabled.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for disabled wallet, got %d", rr.Code)
	}
	// Even 404 responses should retain security headers
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("expected X-Frame-Options DENY on 404, got %q", rr.Header().Get("X-Frame-Options"))
	}
}
