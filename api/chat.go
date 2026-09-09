package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/node"
)

func (h *Handler) handleChatSend(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var env chat.Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if env.To == "" {
		writeError(w, http.StatusBadRequest, "missing 'to' field")
		return
	}

	if env.From == "" || env.PubKey == "" || env.Signature == "" {
		writeError(w, http.StatusBadRequest, "chat send requires a signed envelope (from + pub_key + signature)")
		return
	}
	if len(env.Message) > chat.MaxMessageBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("message exceeds maximum length of %d bytes", chat.MaxMessageBytes))
		return
	}

	if err := h.node.SendChat(r.Context(), &env); err != nil {

		if errors.Is(err, node.ErrRecipientUnreachable) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleChatMessages(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account")
	if !h.requireChatOwnership(w, r, account) {
		return
	}
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = n
		}
	}
	writeJSON(w, http.StatusOK, h.node.GetChatMessages(account, since))
}

func (h *Handler) handleChatContacts(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account")
	if account == "" {
		if !h.checkAdmin(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, h.node.GetChatAccounts())
		return
	}
	if !h.requireChatOwnership(w, r, account) {
		return
	}
	writeJSON(w, http.StatusOK, h.node.GetChatContacts(account))
}

func (h *Handler) handleChatEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	account := r.URL.Query().Get("account")
	if account == "" {

		if !h.checkAdmin(w, r) {
			return
		}
	} else if !h.requireChatOwnership(w, r, account) {
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := h.node.SubscribeChat()
	defer unsub()

	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}

			if account != "" && msg.From != account && msg.To != account {
				continue
			}
			data, err := json.Marshal(msg)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
