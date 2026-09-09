package api

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/xeprotocol/xe/directory"
)

func (h *Handler) handleDirectoryRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var reg directory.Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.node.RegisterAccount(&reg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleDirectoryList(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	regs := h.node.ListDirectory()

	sort.Slice(regs, func(i, j int) bool { return regs[i].Account < regs[j].Account })
	writeJSON(w, http.StatusOK, paginateSlice(regs, offset, limit))
}

func (h *Handler) handleDirectoryLookup(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if account == "" {
		writeError(w, http.StatusBadRequest, "missing account")
		return
	}
	reg := h.node.LookupDirectory(account)
	if reg == nil {
		writeError(w, http.StatusNotFound, "account not found in directory")
		return
	}
	writeJSON(w, http.StatusOK, reg)
}
