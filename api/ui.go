package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// UIConfig configures the embedded UI handler.
type UIConfig struct {
	APITarget     string // base URL of the API server, e.g. "http://127.0.0.1:8080"
	WalletEnabled bool
	FaucetTarget  string // base URL of the external faucet service; empty disables the faucet
}

// NewUIHandler returns an http.Handler that serves the static web UI from fsys
// and reverse-proxies /api/* to cfg.APITarget.
//
// If cfg.FaucetTarget is set, /faucet/* is reverse-proxied to the external
// faucet service (the /faucet prefix is stripped, so /faucet/request hits
// <FaucetTarget>/request). This keeps the browser same-origin so the wallet's
// faucet button works without CORS on the faucet service.
//
// /features.json reports which UI features are enabled so the dashboard can
// show or hide links accordingly. /wallet and /wallet/* are gated on
// cfg.WalletEnabled — disabled returns 404.
//
// Use web.FS for embedded assets, or os.DirFS(path) for filesystem-backed
// development.
func NewUIHandler(fsys fs.FS, cfg UIConfig) (http.Handler, error) {
	target, err := url.Parse(cfg.APITarget)
	if err != nil {
		return nil, fmt.Errorf("parse api target: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("api target must be an absolute URL: %s", cfg.APITarget)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		origDirector(r)
		r.Host = target.Host
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", proxy)

	faucetEnabled := cfg.FaucetTarget != ""
	if faucetEnabled {
		faucetProxy, err := newPrefixProxy("/faucet", cfg.FaucetTarget)
		if err != nil {
			return nil, fmt.Errorf("faucet target: %w", err)
		}
		mux.Handle("/faucet/", faucetProxy)
	}

	features := map[string]bool{
		"wallet": cfg.WalletEnabled,
		"faucet": faucetEnabled,
	}
	featuresBody, _ := json.Marshal(features)

	mux.HandleFunc("/features.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(featuresBody)
	})

	fileServer := http.FileServer(http.FS(fsys))
	mux.Handle("/", walletGate(cfg.WalletEnabled, fileServer))
	return mux, nil
}

// newPrefixProxy builds a reverse proxy to base that strips prefix from the
// request path before forwarding, e.g. prefix "/faucet" maps /faucet/request to
// <base>/request.
func newPrefixProxy(prefix, base string) (http.Handler, error) {
	target, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("target must be an absolute URL: %s", base)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		origDirector(r)
		r.Host = target.Host
	}
	return proxy, nil
}

func walletGate(enabled bool, next http.Handler) http.Handler {
	if enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wallet" || strings.HasPrefix(r.URL.Path, "/wallet/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
