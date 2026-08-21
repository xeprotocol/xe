package api

import (
	"encoding/json"
	"net/http"

	"github.com/xeprotocol/xe/metrics"
	"github.com/xeprotocol/xe/node"
)

// Operational endpoints (#841).
//
// /health and /ready are deliberately different questions:
//
//	GET /health  liveness  — the process is up and its internal loops are
//	                         running. Independent of peers and of consensus, so
//	                         a supervisor never restart-loops a node that is
//	                         merely isolated or waiting on quorum.
//	GET /ready   readiness — this node can serve a correct answer: synced,
//	                         peered, delegated vote weight present, quorum
//	                         reachable, and finality actually advancing.
//
// The distinction is not cosmetic. Zero total delegated vote weight is silent
// finality death — blocks commit, nothing finalizes, every account's spendable
// balance reads empty, and a liveness probe stays green throughout. /ready is
// the endpoint that goes red.
//
// Both fail CLOSED: with no readiness source wired in, /ready answers 503. An
// observability gate that reports OK when it cannot see anything is worse than
// no gate, because it launders ignorance into confidence.
//
// Neither endpoint exposes account-level data: the bodies carry network-wide
// aggregates, the same class of information already public at /node and
// /delegation.

// SetObserver wires the node's observability sampler into the handler. Until it
// is called, /health reports process liveness only and /ready refuses.
func (h *Handler) SetObserver(o *node.Observer) { h.observer = o }

// handleHealth serves GET /health. 200 when live, 503 when not.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if h.observer == nil {
		// The process is answering HTTP, which is what liveness asks. Say so,
		// and say plainly that nothing deeper is being checked.
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

// handleReady serves GET /ready. 200 when ready, 503 when not.
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
	// Probes must never read a cached answer.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// OpsMux is the operator listener: /metrics plus the same two probes, on a
// separate address that defaults to loopback.
//
// /metrics is not on the public API mux on purpose. It is an unauthenticated
// firehose of network-wide state and a cheap amplification target, and a public
// node has no reason to serve it to strangers. Operators who need remote
// scraping bind this listener to a private interface.
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

// Probes get their own per-IP bucket. Sharing the read bucket would let ordinary
// browsing 429 a supervisor's liveness probe, and a supervisor that reads 429 as
// "unhealthy" kills a healthy node — an observability layer must not be able to
// cause the outage it is watching for. The bucket is still bounded: both probes
// serve a cached snapshot, so the work per request is a JSON encode.
const (
	probeRate, probeBurst = 20, 100
)

func isProbePath(p string) bool {
	return p == "/health" || p == "/ready"
}
