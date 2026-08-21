package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"sync"
	"time"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/vm"
	"golang.org/x/time/rate"
)

// nodeBackend defines the node methods the Handler depends on.
// Using an interface allows testing without a live libp2p node.
type nodeBackend interface {
	GetBalance(account string) uint64
	GetAssetBalances(account string) map[string]uint64
	GetSpendableBalances(account string) map[string]uint64
	IsBlockFinalized(account, hash string) bool
	FinalHeight(account string) uint64
	GetKeyset(account string) *core.Keyset
	GetReputation(account string) *core.ReputationAggregate
	GetAllReputations() map[string]*core.ReputationAggregate
	GetChain(account string) []*core.Block
	GetBlock(hash string) *core.Block
	GetPending(account string) []*core.PendingSend
	GetAllPending() []*core.PendingSend
	GetFrontiers() map[string]string
	GetFrontiersDetailed() []node.FrontierInfo
	GetAllAccounts() []node.AccountSummary
	GetSupply() *core.SupplyReport
	GetRecentBlocks(limit int) []*core.Block
	SubmitBlock(b *core.Block) error
	GetConflicts(account string) []*core.Conflict
	GetAllConflicts() []*core.Conflict
	GetDelegation() *node.DelegationInfo
	GetNodeInfo() *node.NodeInfo
	GetActivations() *node.ActivationsInfo
	GetReadiness() *node.ReadinessInfo
	GetLeases() []*core.Lease
	GetLeasesByState(state core.LeaseState) []*core.Lease
	GetLease(leaseHash string) *core.Lease
	GetStateChainTip() *statechain.Block
	GetStateChainBlock(index uint64) *statechain.Block
	GetStateChainBlocks(start, limit uint64) []*statechain.Block
	GetStateChainBlockCount() uint64
	GetStateKV(key string) (json.RawMessage, bool)
	GetStateKVByPrefix(prefix string) map[string]json.RawMessage
	GetAllStateKV() map[string]json.RawMessage
	GetDAOKeyset() *statechain.DAOKeyset
	SubmitStateChainBlock(b *statechain.Block) error
	SendChat(ctx context.Context, env *chat.Envelope) error
	SendChatMessage(ctx context.Context, to, message string) error
	GetChatMessages(account string, since int64) []*chat.Envelope
	GetChatAccounts() []string
	SubscribeChat() (chan *chat.Envelope, func())
	RequestAttestation(leaseHash string) (*core.TimekeeperAttestation, error)
	RegisterAccount(reg *directory.Registration) error
	ListDirectory() []*directory.Registration
	LookupDirectory(account string) *directory.Registration
	GetVMs() []*vm.Info
	GetVM(leaseHash string) *vm.Info
	RequestAndCreateLease(ctx context.Context, vcpus, memoryMB, diskGB, duration uint64, accessPubKey string) (string, error)
	GetProviders() []*node.ProviderInfo
	GetPerformanceCertificate() *perf.Certificate
	GetCertificateByProvider(provider string) *perf.Certificate
	GetCertificateByHash(hash string) *perf.Certificate
	OpenTunnelForLease(ctx context.Context, leaseHash string) (io.ReadWriteCloser, error)
}

// Handler holds a reference to the node and exposes HTTP endpoints.
type Handler struct {
	node       nodeBackend
	corsOrigin string // allowed CORS origin; empty defaults to localhost
	adminToken string // bearer token for operator-only endpoints; empty disables them

	// chat read ownership-proof state (#745), lazily initialized.
	chatAuthMu    sync.Mutex
	chatAuthState *chatAuthState

	// recent-blocks cache (#798), lazily initialized.
	recentMu     sync.Mutex
	recentBlocks []*core.Block
	recentAt     time.Time

	// observer backs /health and /ready (#841). Nil means readiness fails
	// closed; see observability.go.
	observer *node.Observer
}

// NewHandler creates a new Handler wrapping the given node.
func NewHandler(n *node.Node) *Handler {
	return &Handler{node: n}
}

// SetCORSOrigin sets the allowed CORS origin. Use "*" to allow all origins
// (not recommended for production).
func (h *Handler) SetCORSOrigin(origin string) {
	h.corsOrigin = origin
}

// SetAdminToken sets the bearer token required by operator-only endpoints —
// those that sign with the node's key or spend from the operator's wallet
// (#570/C4). With no token configured the endpoints are disabled.
func (h *Handler) SetAdminToken(token string) {
	h.adminToken = token
}

// checkAdmin reports whether the request carries a valid admin bearer token,
// writing the appropriate error response and returning false if not.
func (h *Handler) checkAdmin(w http.ResponseWriter, r *http.Request) bool {
	if h.adminToken == "" {
		writeError(w, http.StatusForbidden, "operator endpoint disabled: no admin token configured (set XE_API_ADMIN_TOKEN)")
		return false
	}
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(h.adminToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid or missing admin token")
		return false
	}
	return true
}

// requireAdmin gates an operator-only handler behind the admin bearer token.
// The public API has no authentication, so anything that spends or signs as
// the operator must never be reachable without it.
func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.checkAdmin(w, r) {
			next(w, r)
		}
	}
}

// apiRoute is a single registered HTTP route. The handler is unexported so
// json.Marshal omits it when the manifest is rendered at GET /.
type apiRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description"`
	handler     http.HandlerFunc
}

// routes returns the canonical list of API endpoints. It's the single source
// of truth used both for mux registration and for the auto-discovery manifest
// served at GET /.
func (h *Handler) routes() []apiRoute {
	return []apiRoute{
		// Node
		{"GET", "/node", "Node info: id, address, version, network, peer list", h.handleGetNodeInfo},

		// Network upgrade / feature activation (#830)
		{"GET", "/network/activations", "sys.activations as of the state-chain tip, plus what this build implements", h.handleGetActivations},
		{"GET", "/network/readiness", "Delegated vote weight by advertised version and feature — the gate the DAO reads before signing an activation", h.handleGetReadiness},
		// Operations (#841). /metrics is deliberately NOT here — it is served
		// on the separate ops listener, which defaults to loopback.
		{"GET", "/health", "Liveness: the process is up and its internal loops are running. Says nothing about consensus", h.handleHealth},
		{"GET", "/ready", "Readiness: synced, peered, delegated vote weight present, quorum reachable, finality advancing. 503 when not ready", h.handleReady},

		// Accounts
		{"GET", "/accounts", "All known accounts with frontier hash and block count", h.handleGetAllAccounts},
		{"GET", "/accounts/{address}/balance", "Per-asset balance for an account", h.handleGetBalance},
		{"GET", "/accounts/{address}/chain", "Full block chain for an account", h.handleGetChain},
		{"GET", "/accounts/{address}/keyset", "Multisig keyset for an account, if any", h.handleGetKeyset},
		{"GET", "/accounts/{address}/reputation", "Per-account reputation aggregate from on-chain lease activity (best-effort; may briefly differ across nodes after a settle propagates)", h.handleGetReputation},
		{"GET", "/reputation", "Reputation aggregates for every known account (best-effort; may briefly differ across nodes after a settle propagates)", h.handleGetAllReputations},
		{"GET", "/frontiers", "Frontier hash for every known account", h.handleGetFrontiers},

		// Supply
		{"GET", "/supply", "Aggregate supply per asset and the conservation identity (#837)", h.handleGetSupply},

		// Pending sends
		{"GET", "/pending", "All pending sends across accounts", h.handleGetAllPending},
		{"GET", "/pending/{address}", "Pending sends to a single account", h.handleGetPending},

		// Blocks
		{"GET", "/blocks/recent", "Most recent blocks across the lattice", h.handleGetRecentBlocks},
		{"GET", "/blocks/{hash}", "Block by hash", h.handleGetBlock},
		{"POST", "/blocks/send", "Submit a signed send block", h.handleSubmitSend},
		{"POST", "/blocks/receive", "Submit a signed receive block", h.handleSubmitReceive},
		{"POST", "/blocks/lease", "Submit a signed lease block", h.handleSubmitLease},
		{"POST", "/blocks/lease_accept", "Submit a signed lease_accept block", h.handleSubmitLeaseAccept},
		{"POST", "/blocks/lease_settle", "Submit a signed lease_settle block", h.handleSubmitLeaseSettle},
		{"POST", "/blocks/lease_cancel", "Submit a signed lease_cancel block", h.handleSubmitLeaseCancel},
		{"POST", "/blocks/lease_force_settle", "Submit a signed lease_force_settle block", h.handleSubmitLeaseForceSettle},
		{"POST", "/blocks/multisig_open", "Submit a signed multisig_open block", h.handleSubmitMultisigOpen},
		{"POST", "/blocks/multisig_update", "Submit a signed multisig_update block", h.handleSubmitMultisigUpdate},
		{"POST", "/blocks/burn", "Submit a signed burn block (XE only)", h.handleSubmitBurn},
		{"POST", "/blocks/mint", "Submit a signed XUSD mint block (authorized minter only; #519)", h.handleSubmitMint},

		// PoW

		// Conflicts
		{"GET", "/conflicts", "All open conflicts", h.handleGetAllConflicts},
		{"GET", "/delegation", "Representative vote weights in micro-XE (#515)", h.handleGetDelegation},
		{"GET", "/conflicts/{account}", "Open conflicts for a single account", h.handleGetAccountConflicts},

		// Compute providers & certificates
		{"GET", "/providers", "Compute providers and their advertised resources", h.handleGetProviders},
		{"GET", "/certificate", "This node's perf certificate (provider mode only)", h.handleGetCertificate},
		{"GET", "/certificate/hash/{hash}", "Retained perf certificate by hash, including expired (#816)", h.handleGetCertificateByHash},
		{"GET", "/certificate/{provider}", "Current unexpired perf certificate for a specific provider", h.handleGetCertificateByProvider},

		// Leases
		{"GET", "/leases", "All leases; filter by ?state=created|accepted|settled|cancelled|unfulfilled", h.handleGetLeases},
		{"GET", "/leases/{hash}", "Lease by hash", h.handleGetLease},
		{"POST", "/lease/request", "Request a lease; node handles signing and PoW (operator only: requires admin bearer token)", h.requireAdmin(h.handleLeaseRequest)},

		// VMs & tunnels
		{"GET", "/vms", "All running VMs", h.handleGetVMs},
		{"GET", "/vms/{lease}", "VM info for a lease", h.handleGetVM},
		{"POST", "/tunnel/{leaseHash}/tcp", "Open a TCP tunnel into a lease's VM", h.handleTunnelTCP},

		// State chain
		{"GET", "/statechain/tip", "Latest state-chain block", h.handleStateChainTip},
		{"GET", "/statechain/blocks", "Range of state-chain blocks", h.handleStateChainBlocks},
		{"GET", "/statechain/blocks/{index}", "State-chain block by index", h.handleStateChainBlock},
		{"GET", "/statechain/kv", "All state-chain KV entries", h.handleStateKVAll},
		{"GET", "/statechain/kv/{key...}", "State-chain KV entry or prefix lookup", h.handleStateKV},
		{"GET", "/statechain/keyset", "DAO keyset (M-of-N timekeepers)", h.handleDAOKeyset},
		{"POST", "/statechain/blocks", "Submit a state-chain block", h.handleSubmitStateChainBlock},

		// Attestation
		{"POST", "/attestation/request", "Request a timekeeper attestation", h.handleAttestationRequest},

		// Directory
		{"GET", "/directory", "All directory registrations (account → libp2p peer)", h.handleDirectoryList},
		{"GET", "/directory/{account}", "Directory entry for an account", h.handleDirectoryLookup},
		{"POST", "/directory/register", "Register own account in the directory", h.handleDirectoryRegister},

		// Chat
		{"POST", "/chat/send", "Send a chat message", h.handleChatSend},
		{"GET", "/chat/auth/challenge", "Issue a challenge to sign for chat read ownership proof", h.handleChatChallenge},
		{"GET", "/chat/messages", "Fetch chat messages for an account (ownership proof required)", h.handleChatMessages},
		{"GET", "/chat/contacts", "Known chat contacts", h.handleChatContacts},
		{"GET", "/chat/events", "Chat event stream (SSE)", h.handleChatEvents},
	}
}

// Mux registers all routes and returns the ServeMux wrapped with CORS middleware.
func (h *Handler) Mux() http.Handler {
	mux := http.NewServeMux()
	for _, r := range h.routes() {
		mux.HandleFunc(r.Method+" "+r.Path, r.handler)
	}
	mux.HandleFunc("GET /{$}", h.handleRoot)

	origin := h.corsOrigin
	if origin == "" {
		origin = "http://localhost:3000"
	}
	// CORS wraps rate limiter so OPTIONS preflight is handled before
	// consuming rate limit tokens.
	return corsMiddleware(rateLimitMiddleware(mux, newRateLimiters()), origin)
}

// handleRoot serves the API discovery manifest at GET /.
func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	info := h.node.GetNodeInfo()
	resp := struct {
		Name      string     `json:"name"`
		Version   string     `json:"version"`
		NetworkID string     `json:"network_id,omitempty"`
		Address   string     `json:"address"`
		NodeID    string     `json:"node_id"`
		Endpoints []apiRoute `json:"endpoints"`
	}{
		Name:      "xe",
		Version:   info.Version,
		NetworkID: info.NetworkID,
		Address:   info.Address,
		NodeID:    info.ID,
		Endpoints: h.routes(),
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func corsMiddleware(next http.Handler, allowedOrigin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipRateLimiter tracks per-IP rate limiters with TTL-based eviction.
type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimiterEntry
	rate    rate.Limit
	burst   int
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const (
	rateLimiterTTL    = 5 * time.Minute
	maxRateLimiterIPs = 100000 // cap entries to ~20 MB of memory
)

// Rate-limit classes. A single global per-IP bucket starved real users: an
// explorer browsing the chain hammers cheap GET reads (recent blocks, accounts,
// chain, statechain, 5s dashboard polls, ~4-way page-load fan-out) and shared
// that one bucket with the genuine abuse vectors. Worse, anyone behind a NAT /
// VPN / corporate or mobile egress arrives as a single IP, so a whole population
// of normal browsers collapsed into one bucket and 429'd each other.
//
// So reads and writes get separate per-IP buckets, sized to the threat:
//   - reads: generous — browsing must never trip it, even for many tabs/users
//     behind one egress IP. Still bounded so a single IP can't scrape unbounded.
//   - writes: tight — POST mutations (signed-block submit, chat, directory
//     register) are where spam/abuse lands. A human submits blocks occasionally.
const (
	readRate, readBurst   = 200, 1000 // cheap GET reads (explorer/browsing)
	writeRate, writeBurst = 10, 50    // POST mutations (block/state submit, chat, directory)
)

// rateLimiters holds one per-IP limiter per endpoint class.
type rateLimiters struct {
	read  *ipRateLimiter
	write *ipRateLimiter
	probe *ipRateLimiter
}

func newRateLimiters() *rateLimiters {
	return &rateLimiters{
		read:  newIPRateLimiter(readRate, readBurst),
		write: newIPRateLimiter(writeRate, writeBurst),
		probe: newIPRateLimiter(probeRate, probeBurst),
	}
}

// pick selects the limiter for a request by class. Caddy's handle_path /api/*
// strips the /api prefix, so the node sees bare paths (/node, /blocks, ...).
// OPTIONS is handled by CORS before reaching here, so requests are GET or POST.
func (rls *rateLimiters) pick(r *http.Request) *ipRateLimiter {
	if r.Method != http.MethodPost {
		if isProbePath(r.URL.Path) {
			return rls.probe
		}
		return rls.read
	}
	return rls.write
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		entries: make(map[string]*rateLimiterEntry),
		rate:    r,
		burst:   burst,
	}
	go rl.sweepLoop()
	return rl
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		// Reject new IPs when the map is at capacity to prevent
		// memory exhaustion from IP-spoofing floods.
		if len(rl.entries) >= maxRateLimiterIPs {
			return rate.NewLimiter(0, 0) // always rejects
		}
		e = &rateLimiterEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter
}

func (rl *ipRateLimiter) sweepLoop() {
	ticker := time.NewTicker(rateLimiterTTL)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rateLimiterTTL)
		for ip, e := range rl.entries {
			if e.lastSeen.Before(cutoff) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func rateLimitMiddleware(next http.Handler, rls *rateLimiters) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rls.pick(r).getLimiter(ip).Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client's IP address for per-IP rate limiting.
//
// Forwarding headers (X-Forwarded-For, X-Real-IP) are trusted ONLY when the
// immediate peer is loopback — i.e. a reverse proxy (Caddy) that terminates TLS
// on this same host and proxies upstream over localhost. From any other peer
// the headers are attacker-controlled and ignored, so the limiter keys on the
// real socket address and cannot be bypassed by header spoofing.
//
// Without this, every HTTPS client behind the local proxy arrives as 127.0.0.1
// and shares a single rate-limit bucket — collapsing the per-IP limiter into a
// per-node global limiter, so one client (or the soak harness's own polling)
// starves everyone else into HTTP 429 (#680). We recover the real client from
// X-Forwarded-For using the RIGHTMOST entry: the hop the trusted proxy itself
// observed and appended, which a client cannot forge by prepending fake entries
// (the leftmost entries are client-supplied and untrusted).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isLoopbackHost(host) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	return host
}

// isLoopbackHost reports whether host is a loopback address (127.0.0.0/8, ::1)
// or the literal "localhost" — the only peers whose forwarding headers clientIP
// trusts.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeSubmitError reports a ledger block-submit failure with the rejection
// reason and a stable machine-readable `retryable` flag (#801). The flag comes
// from core.IsRetryableError — the single classifier already used by sync and
// conflict promotion; there is deliberately no second copy in api/ (AC4). A
// retryable failure (a dependency not yet synced on this node — e.g. a receive
// submitted before its source send, or a frontier race) returns 503 so generic
// retry middleware retries the same block once the dependency lands; a
// deterministically invalid block (bad signature/PoW, structural/value) keeps
// 400. Returning the reason supersedes security review #3's opaque "block
// rejected" — the concern there was clients string-matching validator prose,
// which the `retryable` field now addresses properly.
func writeSubmitError(w http.ResponseWriter, err error) {
	retryable := core.IsRetryableError(err)
	status := http.StatusBadRequest
	if retryable {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"error":     "block rejected: " + err.Error(),
		"retryable": retryable,
	})
}

// GET /accounts/{address}/balance
func (h *Handler) handleGetBalance(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	balances := h.node.GetAssetBalances(address)
	spendable := h.node.GetSpendableBalances(address)
	if spendable == nil {
		spendable = map[string]uint64{}
	}
	resp := struct {
		Address string `json:"address"`
		// Balances is the raw ledger balance (includes unfinalized inflows).
		Balances map[string]uint64 `json:"balances"`
		// Spendable counts only finalized (irreversible) funds — what is safe to
		// spend. Treat this, not Balances, as the settlement figure. (#528)
		Spendable   map[string]uint64 `json:"spendable"`
		FinalHeight uint64            `json:"final_height"`
	}{
		Address:     address,
		Balances:    balances,
		Spendable:   spendable,
		FinalHeight: h.node.FinalHeight(address),
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /accounts/{address}/chain
func (h *Handler) handleGetChain(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	blocks := h.node.GetChain(address)
	// A block is finalized iff its 1-based height is at or below the account's
	// final-height watermark (#525). Read the watermark once and compare per
	// block — avoids an O(n) finalization-store lookup per block, which made
	// this endpoint O(n²) on long chains (#541).
	finalHeight := h.node.FinalHeight(address)
	// #570/M3: bound the response (and per-request work) with ?offset=N&limit=M.
	// Height is 1-based over the full chain, so it is offset+i+1 within the page.
	offset, limit := parsePagination(r)
	page := paginateSlice(blocks, offset, limit)
	views := make([]blockView, 0, len(page))
	for i, b := range page {
		height := uint64(offset + i + 1)
		views = append(views, blockView{Block: b, Finalized: height <= finalHeight})
	}
	// Total is the full chain length: pages are windowed, and without it a
	// client cannot tell a complete chain from page 1 of N (#627).
	resp := struct {
		Address string      `json:"address"`
		Total   int         `json:"total"`
		Blocks  []blockView `json:"blocks"`
	}{
		Address: address,
		Total:   len(blocks),
		Blocks:  views,
	}
	writeJSON(w, http.StatusOK, resp)
}

// blockView is a block plus its finalization status. The embedded *core.Block
// inlines all block fields into the JSON; "finalized" is added alongside. (#528)
type blockView struct {
	*core.Block
	Finalized bool `json:"finalized"`
}

// POST /blocks/send — accept a pre-signed, pre-PoW'd send block
func (h *Handler) handleSubmitSend(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockSend)
}

// POST /blocks/receive — accept a pre-signed, pre-PoW'd receive block
func (h *Handler) handleSubmitReceive(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockReceive)
}

// maxRequestBytes is the maximum allowed request body size (1 MiB).
const maxRequestBytes = 1 << 20

func (h *Handler) submitBlock(w http.ResponseWriter, r *http.Request, expectedType core.BlockType) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var b core.Block
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.Type != expectedType {
		writeError(w, http.StatusBadRequest, "block type mismatch")
		return
	}
	if err := h.node.SubmitBlock(&b); err != nil {
		logging.Warnf("block rejected: %v", err)
		writeSubmitError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, &b)
}

// GET /blocks/{hash}
func (h *Handler) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "missing hash")
		return
	}
	b := h.node.GetBlock(hash)
	if b == nil {
		writeError(w, http.StatusNotFound, "block not found")
		return
	}
	writeJSON(w, http.StatusOK, blockView{Block: b, Finalized: h.node.IsBlockFinalized(b.Account, b.Hash)})
}

// GET /pending/{address}
func (h *Handler) handleGetPending(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	pending := h.node.GetPending(address)
	resp := struct {
		Address string         `json:"address"`
		Pending []pendingEntry `json:"pending"`
	}{
		Address: address,
		Pending: h.enrichPending(pending),
	}
	writeJSON(w, http.StatusOK, resp)
}

// pendingEntry enriches a PendingSend with the send block's timestamp.
type pendingEntry struct {
	SendHash    string `json:"SendHash"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Amount      uint64 `json:"Amount"`
	Asset       string `json:"Asset"`
	Timestamp   int64  `json:"Timestamp"`
}

// enrichPending decorates each PendingSend with the timestamp of its send block
// (0 when the block is not locally available).
func (h *Handler) enrichPending(pending []*core.PendingSend) []pendingEntry {
	entries := make([]pendingEntry, 0, len(pending))
	for _, p := range pending {
		var ts int64
		if b := h.node.GetBlock(p.SendHash); b != nil {
			ts = b.Timestamp
		}
		entries = append(entries, pendingEntry{
			SendHash:    p.SendHash,
			Source:      p.Source,
			Destination: p.Destination,
			Amount:      p.Amount,
			Asset:       p.Asset,
			Timestamp:   ts,
		})
	}
	return entries
}

const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// paginateSlice applies an already-parsed offset/limit window to a slice,
// clamping both ends. Returns an empty (non-nil) slice when offset is past the
// end so the JSON response is [] rather than null. (#570/M3)
func paginateSlice[T any](items []T, offset, limit int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

// paginateMap returns the offset/limit window of a string-keyed map, ordered by
// key so paging is deterministic, rebuilt as a map so the response shape is
// preserved. (#570/M3)
func paginateMap[V any](m map[string]V, offset, limit int) map[string]V {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	page := paginateSlice(keys, offset, limit)
	out := make(map[string]V, len(page))
	for _, k := range page {
		out[k] = m[k]
	}
	return out
}

func parsePagination(r *http.Request) (offset, limit int) {
	limit = defaultPageLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

// GET /pending — returns pending sends with ?offset=N&limit=M pagination.
func (h *Handler) handleGetAllPending(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	page := paginateSlice(h.node.GetAllPending(), offset, limit)
	writeJSON(w, http.StatusOK, h.enrichPending(page))
}

// GET /accounts — returns accounts with ?offset=N&limit=M pagination.
func (h *Handler) handleGetAllAccounts(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	accounts := h.node.GetAllAccounts()
	if offset >= len(accounts) {
		writeJSON(w, http.StatusOK, []node.AccountSummary{})
		return
	}
	end := offset + limit
	if end > len(accounts) {
		end = len(accounts)
	}
	writeJSON(w, http.StatusOK, accounts[offset:end])
}

// GET /supply — aggregate supply per asset with both sides of the conservation
// identity, so a client can check it in one request (#837).
//
// The response is aggregate-only: no address, no per-account amount, nothing
// that identifies a holder. It therefore discloses strictly less than the
// already-public GET /accounts, which is where the per-account figures live.
//
// The underlying walk is cached in core.SupplyAuditor, so this stays cheap under
// the read rate limiter even though a cold computation is O(blocks).
func (h *Handler) handleGetSupply(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetSupply())
}

// recentCacheTTL bounds how often the expensive recent-blocks scan runs. The
// dashboard polls at 5s and buckets the result into 5s bins, so a second of
// staleness is invisible there.
const recentCacheTTL = time.Second

// cachedRecentBlocks returns the newest maxPageLimit blocks, rebuilding at most
// once per recentCacheTTL.
//
// GetRecentBlocks does a store read (and chain copy) per account, so it costs
// ~2ms at limit=50 and ~4ms at limit=1000 for 121 accounts / 8.4k blocks —
// independent of who is asking. Served uncached, one IP staying inside the
// read bucket (200/s, burst 1000) could spend most of a core, and #798 raised
// the ceiling by letting the caller choose the limit (#798).
//
// The returned slice is shared by concurrent requests and must not be mutated;
// callers filter into a new slice or reslice a prefix (both read-only).
func (h *Handler) cachedRecentBlocks() []*core.Block {
	h.recentMu.Lock()
	defer h.recentMu.Unlock()
	if h.recentBlocks != nil && time.Since(h.recentAt) < recentCacheTTL {
		return h.recentBlocks
	}
	h.recentBlocks = h.node.GetRecentBlocks(maxPageLimit)
	h.recentAt = time.Now()
	return h.recentBlocks
}

// GET /blocks/recent — returns recent blocks across all chains, ?limit=M.
// ?since=<unix_ns> additionally drops blocks at or older than the timestamp, so
// a caller wanting a time window (the dashboard's rate chart) fetches only what
// it plots instead of a fixed slab of the newest N regardless of age (#798).
func (h *Handler) handleGetRecentBlocks(w http.ResponseWriter, r *http.Request) {
	_, limit := parsePagination(r)
	blocks := h.cachedRecentBlocks()
	if v := r.URL.Query().Get("since"); v != "" {
		since, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be a unix nanosecond timestamp")
			return
		}
		recent := make([]*core.Block, 0, len(blocks))
		for _, b := range blocks {
			if b.Timestamp > since {
				recent = append(recent, b)
			}
		}
		blocks = recent
	}
	if len(blocks) > limit {
		blocks = blocks[:limit]
	}
	writeJSON(w, http.StatusOK, blocks)
}

// GET /frontiers — ?offset=N&limit=M paginated.
func (h *Handler) handleGetFrontiers(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	frontiers := h.node.GetFrontiersDetailed()
	// The source is a map; without a sort, Go's per-call iteration-order
	// randomization makes consecutive pages overlap and skip entries (#570/M3).
	sort.Slice(frontiers, func(i, j int) bool { return frontiers[i].Account < frontiers[j].Account })
	writeJSON(w, http.StatusOK, paginateSlice(frontiers, offset, limit))
}

// GET /conflicts — returns conflict records across all accounts, ?offset=N&limit=M paginated.
func (h *Handler) handleGetAllConflicts(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, paginateSlice(h.node.GetAllConflicts(), offset, limit))
}

// GET /delegation — returns representative vote weights and the total.
func (h *Handler) handleGetDelegation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetDelegation())
}

// GET /network/activations — the feature activation registry as this node sees
// it, together with the features this BINARY implements. The two together are
// what an operator needs: the chain's schedule, and whether this build can
// honour it (#830).
func (h *Handler) handleGetActivations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetActivations())
}

// GET /network/readiness — delegated vote weight behind each advertised
// version and feature. This is the number the DAO gates an activation on
// (>=90% for 7 consecutive days); peer counts are not a substitute, because
// finality is weighted and a feature activated below ~67% ready weight wedges
// the network rather than forking it (#830).
func (h *Handler) handleGetReadiness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetReadiness())
}

// GET /conflicts/{account} — returns conflict records for a specific account.
func (h *Handler) handleGetAccountConflicts(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if account == "" {
		writeError(w, http.StatusBadRequest, "missing account")
		return
	}
	writeJSON(w, http.StatusOK, h.node.GetConflicts(account))
}

// GET /node — returns node info including peers, addresses, stats.
func (h *Handler) handleGetNodeInfo(w http.ResponseWriter, r *http.Request) {
	info := h.node.GetNodeInfo()
	writeJSON(w, http.StatusOK, info)
}

// GET /leases — optionally filter by ?state=created|accepted|settled|cancelled|unfulfilled
func (h *Handler) handleGetLeases(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	if stateParam := r.URL.Query().Get("state"); stateParam != "" {
		state := core.LeaseState(stateParam)
		if !core.ValidLeaseStates[state] {
			writeError(w, http.StatusBadRequest, "invalid state: must be one of created, accepted, settled, cancelled, unfulfilled")
			return
		}
		writeJSON(w, http.StatusOK, paginateSlice(h.node.GetLeasesByState(state), offset, limit))
		return
	}
	writeJSON(w, http.StatusOK, paginateSlice(h.node.GetLeases(), offset, limit))
}

// GET /leases/{hash}
func (h *Handler) handleGetLease(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "missing hash")
		return
	}
	lease := h.node.GetLease(hash)
	if lease == nil {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

// POST /blocks/lease
func (h *Handler) handleSubmitLease(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLease)
}

// POST /blocks/lease_accept
func (h *Handler) handleSubmitLeaseAccept(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseAccept)
}

// POST /blocks/lease_settle
func (h *Handler) handleSubmitLeaseSettle(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseSettle)
}

// POST /blocks/lease_cancel
func (h *Handler) handleSubmitLeaseCancel(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseCancel)
}

// POST /blocks/lease_force_settle
func (h *Handler) handleSubmitLeaseForceSettle(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseForceSettle)
}

// POST /blocks/multisig_open
func (h *Handler) handleSubmitMultisigOpen(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMultisigOpen)
}

// POST /blocks/multisig_update
func (h *Handler) handleSubmitMultisigUpdate(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMultisigUpdate)
}

// POST /blocks/burn — accept a pre-signed, pre-PoW'd burn block. XE-only;
// the ledger validator enforces the asset constraint.
func (h *Handler) handleSubmitBurn(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockBurn)
}

// POST /blocks/mint — accept a pre-signed, pre-PoW'd XUSD mint block. Authorized
// only for accounts in sys.minter; the ledger validator (validateAndAddMint)
// enforces that and routes the block through AddBlock's conflict/finality path
// like any other block. The faucet service (and, later, the bridge) submit here.
func (h *Handler) handleSubmitMint(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMint)
}

// GET /accounts/{address}/keyset
func (h *Handler) handleGetKeyset(w http.ResponseWriter, r *http.Request) {
	addr := r.PathValue("address")
	if addr == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	ks := h.node.GetKeyset(addr)
	if ks == nil {
		writeError(w, http.StatusNotFound, "not a multisig account")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

// GET /accounts/{address}/reputation
// The reputation index is rebuilt on block-apply, so it is eventually consistent:
// nodes may return slightly different scores for a few hundred ms after a settle propagates.
func (h *Handler) handleGetReputation(w http.ResponseWriter, r *http.Request) {
	addr := r.PathValue("address")
	if addr == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	agg := h.node.GetReputation(addr)
	if agg == nil {
		writeError(w, http.StatusNotFound, "no reputation activity")
		return
	}
	writeJSON(w, http.StatusOK, agg)
}

// GET /reputation
// The reputation index is rebuilt on block-apply, so it is eventually consistent:
// nodes may return slightly different scores for a few hundred ms after a settle propagates.
func (h *Handler) handleGetAllReputations(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, paginateMap(h.node.GetAllReputations(), offset, limit))
}

// GET /statechain/tip
func (h *Handler) handleStateChainTip(w http.ResponseWriter, r *http.Request) {
	tip := h.node.GetStateChainTip()
	if tip == nil {
		writeError(w, http.StatusNotFound, "no tip")
		return
	}
	writeJSON(w, http.StatusOK, tip)
}

// GET /statechain/blocks/{index}
func (h *Handler) handleStateChainBlock(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.ParseUint(r.PathValue("index"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}
	b := h.node.GetStateChainBlock(idx)
	if b == nil {
		writeError(w, http.StatusNotFound, "block not found")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// GET /statechain/blocks?start=N&limit=M
func (h *Handler) handleStateChainBlocks(w http.ResponseWriter, r *http.Request) {
	start := uint64(0)
	limit := uint64(100)
	if v := r.URL.Query().Get("start"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			start = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	blocks := h.node.GetStateChainBlocks(start, limit)
	resp := struct {
		Blocks     []*statechain.Block `json:"blocks"`
		BlockCount uint64              `json:"block_count"`
	}{
		Blocks:     blocks,
		BlockCount: h.node.GetStateChainBlockCount(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /statechain/kv/{key...}
func (h *Handler) handleStateKV(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key")
		return
	}
	val, ok := h.node.GetStateKV(key)
	if !ok {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}{Key: key, Value: val})
}

// GET /statechain/kv?prefix=X — ?offset=N&limit=M paginated (deterministic by key).
func (h *Handler) handleStateKVAll(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	prefix := r.URL.Query().Get("prefix")
	var kv map[string]json.RawMessage
	if prefix != "" {
		kv = h.node.GetStateKVByPrefix(prefix)
	} else {
		kv = h.node.GetAllStateKV()
	}
	writeJSON(w, http.StatusOK, paginateMap(kv, offset, limit))
}

// GET /statechain/keyset
func (h *Handler) handleDAOKeyset(w http.ResponseWriter, r *http.Request) {
	ks := h.node.GetDAOKeyset()
	if ks == nil {
		writeError(w, http.StatusNotFound, "keyset not found")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

// POST /attestation/request
func (h *Handler) handleAttestationRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req struct {
		LeaseHash string `json:"lease_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LeaseHash == "" {
		writeError(w, http.StatusBadRequest, "lease_hash required")
		return
	}
	att, err := h.node.RequestAttestation(req.LeaseHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, att)
}

// POST /statechain/blocks
func (h *Handler) handleSubmitStateChainBlock(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var b statechain.Block
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.node.SubmitStateChainBlock(&b); err != nil {
		logging.Warnf("statechain block rejected: %v", err)
		writeError(w, http.StatusBadRequest, "block rejected: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, &b)
}
