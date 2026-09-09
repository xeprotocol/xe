package api

import (
	"encoding/json"
	"net/http"

	"github.com/xeprotocol/xe/metrics"
	"github.com/xeprotocol/xe/node"
)

func (h *Handler) SetObserver(o *node.Observer) { h.observer = o }

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if h.observer == nil {

		writeJSONStatus(w, http.StatusOK, map[string]any{
			"status": "ok",
			"ok":     true,
			"note":   "liveness only, and no observability sampler is wired in: this reports that the HTTP server is answering, nothing more. /ready is unavailable.",
		})
		return
	}
	rep := h.observer.Health()
	code := http.StatusOK
	if !rep.OK {
		code = http.StatusServiceUnavailable
	}
	writeJSONStatus(w, code, rep)
}

func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	if h.observer == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"ready":  false,
			"note":   "no observability sampler wired in; readiness cannot be asserted. Fails closed by design.",
		})
		return
	}
	rep := h.observer.Ready()
	code := http.StatusOK
	if !rep.Ready {
		code = http.StatusServiceUnavailable
	}
	writeJSONStatus(w, code, rep)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func OpsMux(h *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /ready", h.handleReady)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"name":      "xe-ops",
			"endpoints": []string{"GET /metrics", "GET /health", "GET /ready"},
		})
	})
	return mux
}

const (
	probeRate, probeBurst = 20, 100
)

func isProbePath(p string) bool {
	return p == "/health" || p == "/ready"
}
