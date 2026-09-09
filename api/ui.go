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

type UIConfig struct {
	APITarget     string
	WalletEnabled bool
	FaucetTarget  string
}

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
