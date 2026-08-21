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

// POST /chat/send — accepts a pre-signed Envelope (for wallets):
// {"id":"...", "from":"...", "to":"...", "signature":"...", ...}
//
// #570/M11: the public API is unauthenticated. The previous "simple request"
// form, where an empty from/signature made the node sign and gossip the message
// under its OWN identity, let any internet caller impersonate/spam as the node
// operator. Only a signed envelope is accepted now — SendChat verifies the
// signature, so the From account must have authorized the message. A node that
// wants to send chat as itself uses Node.SendChatMessage directly, not this
// unauthenticated endpoint.
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
	// #829: `from` is an ADDRESS and cannot verify its own signature, so a
	// self-certifying envelope must also declare `pub_key` (the VERIFYING KEY).
	// VerifyFull re-checks this; naming it here turns an opaque rejection into a
	// clear 400 for wallets that have not been updated.
	if env.From == "" || env.PubKey == "" || env.Signature == "" {
		writeError(w, http.StatusBadRequest, "chat send requires a signed envelope (from + pub_key + signature)")
		return
	}
	if len(env.Message) > chat.MaxMessageBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("message exceeds maximum length of %d bytes", chat.MaxMessageBytes))
		return
	}

	if err := h.node.SendChat(r.Context(), &env); err != nil {
		// An unregistered recipient is a 404 (not a malformed request), so the
		// client can show a distinct, non-fatal message (#746).
		if errors.Is(err, node.ErrRecipientUnreachable) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// GET /chat/messages?account=X&since=0&challenge=Y&sig=Z
// Reading an account's history requires proving ownership of that account (#745).
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

// GET /chat/contacts — returns accounts that have messages
func (h *Handler) handleChatContacts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetChatAccounts())
}

// GET /chat/events?account=X&challenge=Y&sig=Z — SSE stream of new messages.
// A named account requires an ownership proof; the unfiltered firehose (no
// account) is operator-only, gated behind the admin token (#745).
func (h *Handler) handleChatEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	account := r.URL.Query().Get("account")
	if account == "" {
		// Unfiltered stream of every message on the node — operator-only.
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

	// Flush the response headers immediately on connect, before any message
	// arrives. Go's net/http buffers the status line + headers until the first
	// Write/Flush, so without this an idle stream sends nothing on the wire —
	// the client's EventSource never fires onopen and Caddy can't see the
	// text/event-stream content-type to disable response buffering (#698). The
	// leading ":" makes it an SSE comment, which EventSource ignores.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// Heartbeat keeps idle connections alive through intermediaries (proxy /
	// browser idle timeouts) and surfaces dead peers — a failed write means the
	// client is gone, so we stop. Comments are ignored by EventSource.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// Filter by account if specified
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
