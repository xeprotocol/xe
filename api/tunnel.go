package api

import (
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/xeprotocol/xe/core"
)

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
	// Access requires a live lease — accepted is the only state with a running
	// VM. The legacy Settled bool stays false for cancelled leases (#761).
	if lease.State != core.LeaseAccepted {
		writeError(w, http.StatusGone, "lease not active")
		return
	}

	// Authenticate: caller must sign the lease hash with the lease's access key.
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
	if err := core.VerifyHexSignature(lease.AccessPubKey, sig, hashBytes); err != nil {
		writeError(w, http.StatusForbidden, "signature verification failed")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "hijacking not supported")
		return
	}

	tunnel, err := h.node.OpenTunnelForLease(r.Context(), leaseHash)
	if err != nil {
		log.Printf("tunnel tcp: open tunnel for %s: %v", leaseHash[:16], err)
		writeError(w, http.StatusBadGateway, "tunnel error: "+err.Error())
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		_ = tunnel.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"))

	// P6.2: Use a WaitGroup to ensure both directions finish before closing.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if buffered := buf.Reader.Buffered(); buffered > 0 {
			_, _ = io.CopyN(tunnel, buf, int64(buffered))
		}
		_, _ = io.Copy(tunnel, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, tunnel)
	}()

	wg.Wait()
	_ = tunnel.Close()
	_ = clientConn.Close()
}
