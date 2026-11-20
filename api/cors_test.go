package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name          string
		allowedOrigin string
		reqMethod     string
		reqOrigin     string
		wantStatus    int
		wantAllow     string
		wantVary      string
	}{
		{
			name:          "default wildcard allowedOrigin",
			allowedOrigin: "*",
			reqMethod:     "GET",
			reqOrigin:     "http://example.com",
			wantStatus:    http.StatusOK,
			wantAllow:     "*",
			wantVary:      "",
		},
		{
			name:          "preflight options with wildcard",
			allowedOrigin: "*",
			reqMethod:     "OPTIONS",
			reqOrigin:     "http://example.com",
			wantStatus:    http.StatusNoContent,
			wantAllow:     "*",
			wantVary:      "",
		},
		{
			name:          "single allowed origin matching",
			allowedOrigin: "https://myapp.example",
			reqMethod:     "GET",
			reqOrigin:     "https://myapp.example",
			wantStatus:    http.StatusOK,
			wantAllow:     "https://myapp.example",
			wantVary:      "Origin",
		},
		{
			name:          "single allowed origin mismatch returns default allowed",
			allowedOrigin: "https://myapp.example",
			reqMethod:     "GET",
			reqOrigin:     "http://other.example",
			wantStatus:    http.StatusOK,
			wantAllow:     "https://myapp.example",
			wantVary:      "",
		},
		{
			name:          "comma separated list matching second origin",
			allowedOrigin: "http://localhost:3000, https://myapp.example",
			reqMethod:     "GET",
			reqOrigin:     "https://myapp.example",
			wantStatus:    http.StatusOK,
			wantAllow:     "https://myapp.example",
			wantVary:      "Origin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := corsMiddleware(dummy, tc.allowedOrigin)
			req := httptest.NewRequest(tc.reqMethod, "/node", nil)
			if tc.reqOrigin != "" {
				req.Header.Set("Origin", tc.reqOrigin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status got %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantAllow {
				t.Errorf("Access-Control-Allow-Origin got %q, want %q", got, tc.wantAllow)
			}
			if got := rec.Header().Get("Vary"); got != tc.wantVary {
				t.Errorf("Vary got %q, want %q", got, tc.wantVary)
			}
		})
	}
}
