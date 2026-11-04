package api

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/xeprotocol/xe/core"
)

const (
	maxTunnelConnections = 100
	tunnelSkewWindowSec   = 300 // 5 minutes clock skew tolerance
)

func (h *Handler) tunnelSem() chan struct{} {
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()
	if h.tunnelConnSem == nil {
		h.tunnelConnSem = make(chan struct{}, maxTunnelConnections)
	}
	return h.tunnelConnSem
}

func (h *Handler) handleTunnelTCP(w http.ResponseWriter, r *http.Request) {
	leaseHash := r.PathValue("leaseHash")
	if leaseHash == "" {
		writeError(w, http.StatusBadRequest, "missing lease hash")
		return
	}

	lease := h.node.GetLease(leaseHash)
	if lease == nil {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}

	if lease.State != core.LeaseAccepted {
		writeError(w, http.StatusGone, "lease not active")
		return
	}

	if lease.AccessPubKey == "" {
		writeError(w, http.StatusForbidden, "lease has no access key")
		return
	}
	sig := r.Header.Get("X-Signature")
	if sig == "" {
		writeError(w, http.StatusUnauthorized, "missing X-Signature header")
		return
	}
	hashBytes, err := core.DecodeHash(leaseHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lease hash")
		return
	}

	now := time.Now().Unix()

	// Check if request includes timestamp/nonce binding (issue #94)
	tsHeader := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")
	var verifyErr error

	if tsHeader != "" {
		ts, err := strconv.ParseInt(tsHeader, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid X-Timestamp header")
			return
		}
		// Enforce skew window
		diff := now - ts
		if diff < -tunnelSkewWindowSec || diff > tunnelSkewWindowSec {
			writeError(w, http.StatusForbidden, "timestamp expired or out of allowed window")
			return
		}
		// Bound payload: sha256(leaseHash:METHOD:PATH:timestamp:nonce)
		hPayload := sha256.New()
		hPayload.Write([]byte(fmt.Sprintf("%s:%s:%s:%s:%s", leaseHash, r.Method, r.URL.Path, tsHeader, nonce)))
		boundBytes := hPayload.Sum(nil)
		verifyErr = core.VerifyHexSignature(lease.AccessPubKey, sig, boundBytes)
	} else {
		// Standard payload: 32-byte lease hash
		verifyErr = core.VerifyHexSignature(lease.AccessPubKey, sig, hashBytes)
	}

	if verifyErr != nil {
		writeError(w, http.StatusForbidden, "signature verification failed")
		return
	}

	// Single-use replay protection (issues #48, #94)
	h.tunnelMu.Lock()
	if h.tunnelSeenSigs == nil {
		h.tunnelSeenSigs = make(map[string]int64)
	}
	// Prune expired replay records
	for s, exp := range h.tunnelSeenSigs {
		if now > exp {
			delete(h.tunnelSeenSigs, s)
		}
	}
	if exp, seen := h.tunnelSeenSigs[sig]; seen && now <= exp {
		h.tunnelMu.Unlock()
		writeError(w, http.StatusForbidden, "signature already used / replay detected")
		return
	}
	// Retain replay guard for effective lease lifetime (or 1 hour minimum)
	sigExpiry := int64(lease.EffectiveExpiry())
	if sigExpiry <= now {
		sigExpiry = now + 3600
	}
	h.tunnelSeenSigs[sig] = sigExpiry
	h.tunnelMu.Unlock()

	// Concurrency cap: prevent file descriptor exhaustion (issue #48)
	sem := h.tunnelSem()
	select {
	case sem <- struct{}{}:
	default:
		writeError(w, http.StatusServiceUnavailable, "maximum concurrent tunnel connections reached")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		<-sem
		writeError(w, http.StatusInternalServerError, "hijacking not supported")
		return
	}

	tunnel, err := h.node.OpenTunnelForLease(r.Context(), leaseHash)
	if err != nil {
		<-sem
		log.Printf("tunnel tcp: open tunnel for %s: %v", leaseHash[:16], err)
		writeError(w, http.StatusBadGateway, "tunnel error: "+err.Error())
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		<-sem
		_ = tunnel.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if buffered := buf.Reader.Buffered(); buffered > 0 {
			_, _ = io.CopyN(tunnel, buf, int64(buffered))
		}
		_, _ = io.Copy(tunnel, clientConn)
		_ = tunnel.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, tunnel)
		_ = clientConn.Close()
	}()

	wg.Wait()
	<-sem
	_ = tunnel.Close()
	_ = clientConn.Close()
}
