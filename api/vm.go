package api

import (
	"encoding/json"
	"net/http"

	"github.com/xeprotocol/xe/core"
)

func (h *Handler) handleGetProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetProviders())
}

func (h *Handler) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	cert := h.node.GetPerformanceCertificate()
	if cert == nil {
		writeError(w, http.StatusNotFound, "no performance certificate")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *Handler) handleGetCertificateByHash(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "missing certificate hash")
		return
	}
	cert := h.node.GetCertificateByHash(hash)
	if cert == nil {
		writeError(w, http.StatusNotFound, "no certificate with that hash")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *Handler) handleGetCertificateByProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		writeError(w, http.StatusBadRequest, "missing provider address")
		return
	}
	cert := h.node.GetCertificateByProvider(provider)
	if cert == nil {
		writeError(w, http.StatusNotFound, "no certificate for provider")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *Handler) handleGetVMs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetVMs())
}

func (h *Handler) handleGetVM(w http.ResponseWriter, r *http.Request) {
	leaseHash := r.PathValue("lease")
	if leaseHash == "" {
		writeError(w, http.StatusBadRequest, "missing lease hash")
		return
	}
	info := h.node.GetVM(leaseHash)
	if info == nil {
		writeError(w, http.StatusNotFound, "vm not found")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *Handler) handleLeaseRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req struct {
		VCPUs        uint64 `json:"vcpus"`
		MemoryMB     uint64 `json:"memory_mb"`
		DiskGB       uint64 `json:"disk_gb"`
		Duration     uint64 `json:"duration"`
		AccessPubKey string `json:"access_pub_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.VCPUs == 0 && req.MemoryMB == 0 && req.DiskGB == 0 {
		writeError(w, http.StatusBadRequest, "at least one resource required (vcpus, memory_mb, disk_gb)")
		return
	}
	if req.Duration == 0 {
		writeError(w, http.StatusBadRequest, "duration required")
		return
	}

	if err := core.ValidateLeaseDimensions(req.VCPUs, req.MemoryMB, req.DiskGB, req.Duration); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	leaseHash, err := h.node.RequestAndCreateLease(r.Context(), req.VCPUs, req.MemoryMB, req.DiskGB, req.Duration, req.AccessPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"lease_hash": leaseHash,
	})
}
