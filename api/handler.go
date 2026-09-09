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
	GetChatContacts(account string) []string
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

type Handler struct {
	node       nodeBackend
	corsOrigin string
	adminToken string

	chatAuthMu    sync.Mutex
	chatAuthState *chatAuthState

	recentMu     sync.Mutex
	recentBlocks []*core.Block
	recentAt     time.Time

	observer *node.Observer
}

func NewHandler(n *node.Node) *Handler {
	return &Handler{node: n}
}

func (h *Handler) SetCORSOrigin(origin string) {
	h.corsOrigin = origin
}

func (h *Handler) SetAdminToken(token string) {
	h.adminToken = token
}

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

func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.checkAdmin(w, r) {
			next(w, r)
		}
	}
}

type apiRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description"`
	handler     http.HandlerFunc
}

func (h *Handler) routes() []apiRoute {
	return []apiRoute{

		{"GET", "/node", "Node info: id, address, version, network, peer list", h.handleGetNodeInfo},

		{"GET", "/network/activations", "sys.activations as of the state-chain tip, plus what this build implements", h.handleGetActivations},
		{"GET", "/network/readiness", "Delegated vote weight by advertised version and feature — the gate the DAO reads before signing an activation", h.handleGetReadiness},

		{"GET", "/health", "Liveness: the process is up and its internal loops are running. Says nothing about consensus", h.handleHealth},
		{"GET", "/ready", "Readiness: synced, peered, delegated vote weight present, quorum reachable, finality advancing. 503 when not ready", h.handleReady},

		{"GET", "/accounts", "All known accounts with frontier hash and block count", h.handleGetAllAccounts},
		{"GET", "/accounts/{address}/balance", "Per-asset balance for an account", h.handleGetBalance},
		{"GET", "/accounts/{address}/chain", "Full block chain for an account", h.handleGetChain},
		{"GET", "/accounts/{address}/keyset", "Multisig keyset for an account, if any", h.handleGetKeyset},
		{"GET", "/accounts/{address}/reputation", "Per-account reputation aggregate from on-chain lease activity (best-effort; may briefly differ across nodes after a settle propagates)", h.handleGetReputation},
		{"GET", "/reputation", "Reputation aggregates for every known account (best-effort; may briefly differ across nodes after a settle propagates)", h.handleGetAllReputations},
		{"GET", "/frontiers", "Frontier hash for every known account", h.handleGetFrontiers},

		{"GET", "/supply", "Aggregate supply per asset and the conservation identity", h.handleGetSupply},

		{"GET", "/pending", "All pending sends across accounts", h.handleGetAllPending},
		{"GET", "/pending/{address}", "Pending sends to a single account", h.handleGetPending},

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
		{"POST", "/blocks/mint", "Submit a signed XUSD mint block (authorized minter only)", h.handleSubmitMint},

		{"GET", "/conflicts", "All open conflicts", h.handleGetAllConflicts},
		{"GET", "/delegation", "Representative vote weights in micro-XE", h.handleGetDelegation},
		{"GET", "/conflicts/{account}", "Open conflicts for a single account", h.handleGetAccountConflicts},

		{"GET", "/providers", "Compute providers and their advertised resources", h.handleGetProviders},
		{"GET", "/certificate", "This node's perf certificate (provider mode only)", h.handleGetCertificate},
		{"GET", "/certificate/hash/{hash}", "Retained perf certificate by hash, including expired", h.handleGetCertificateByHash},
		{"GET", "/certificate/{provider}", "Current unexpired perf certificate for a specific provider", h.handleGetCertificateByProvider},

		{"GET", "/leases", "All leases; filter by ?state=created|accepted|settled|cancelled|unfulfilled", h.handleGetLeases},
		{"GET", "/leases/{hash}", "Lease by hash", h.handleGetLease},
		{"POST", "/lease/request", "Request a lease; node handles signing and PoW (operator only: requires admin bearer token)", h.requireAdmin(h.handleLeaseRequest)},

		{"GET", "/vms", "All running VMs", h.handleGetVMs},
		{"GET", "/vms/{lease}", "VM info for a lease", h.handleGetVM},
		{"POST", "/tunnel/{leaseHash}/tcp", "Open a TCP tunnel into a lease's VM", h.handleTunnelTCP},

		{"GET", "/statechain/tip", "Latest state-chain block", h.handleStateChainTip},
		{"GET", "/statechain/blocks", "Range of state-chain blocks", h.handleStateChainBlocks},
		{"GET", "/statechain/blocks/{index}", "State-chain block by index", h.handleStateChainBlock},
		{"GET", "/statechain/kv", "All state-chain KV entries", h.handleStateKVAll},
		{"GET", "/statechain/kv/{key...}", "State-chain KV entry or prefix lookup", h.handleStateKV},
		{"GET", "/statechain/keyset", "DAO keyset (M-of-N timekeepers)", h.handleDAOKeyset},
		{"POST", "/statechain/blocks", "Submit a state-chain block", h.handleSubmitStateChainBlock},

		{"POST", "/attestation/request", "Request a timekeeper attestation", h.handleAttestationRequest},

		{"GET", "/directory", "All directory registrations (account → libp2p peer)", h.handleDirectoryList},
		{"GET", "/directory/{account}", "Directory entry for an account", h.handleDirectoryLookup},
		{"POST", "/directory/register", "Register own account in the directory", h.handleDirectoryRegister},

		{"POST", "/chat/send", "Send a chat message", h.handleChatSend},
		{"GET", "/chat/auth/challenge", "Issue a challenge to sign for chat read ownership proof", h.handleChatChallenge},
		{"GET", "/chat/messages", "Fetch chat messages for an account (ownership proof required)", h.handleChatMessages},
		{"GET", "/chat/contacts", "Chat contacts for an account (ownership proof required); node-wide list is operator-only", h.handleChatContacts},
		{"GET", "/chat/events", "Chat event stream (SSE)", h.handleChatEvents},
	}
}

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

	return corsMiddleware(rateLimitMiddleware(mux, newRateLimiters()), origin)
}

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
	maxRateLimiterIPs = 100000
)

const (
	readRate, readBurst   = 200, 1000
	writeRate, writeBurst = 10, 50
)

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

		if len(rl.entries) >= maxRateLimiterIPs {
			return rate.NewLimiter(0, 0)
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

		Balances map[string]uint64 `json:"balances"`

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

func (h *Handler) handleGetChain(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address")
		return
	}
	blocks := h.node.GetChain(address)

	finalHeight := h.node.FinalHeight(address)

	offset, limit := parsePagination(r)
	page := paginateSlice(blocks, offset, limit)
	views := make([]blockView, 0, len(page))
	for i, b := range page {
		height := uint64(offset + i + 1)
		views = append(views, blockView{Block: b, Finalized: height <= finalHeight})
	}

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

type blockView struct {
	*core.Block
	Finalized bool `json:"finalized"`
}

func (h *Handler) handleSubmitSend(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockSend)
}

func (h *Handler) handleSubmitReceive(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockReceive)
}

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

type pendingEntry struct {
	SendHash    string `json:"SendHash"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Amount      uint64 `json:"Amount"`
	Asset       string `json:"Asset"`
	Timestamp   int64  `json:"Timestamp"`
}

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

func (h *Handler) handleGetAllPending(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	page := paginateSlice(h.node.GetAllPending(), offset, limit)
	writeJSON(w, http.StatusOK, h.enrichPending(page))
}

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

func (h *Handler) handleGetSupply(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetSupply())
}

const recentCacheTTL = time.Second

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

func (h *Handler) handleGetFrontiers(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	frontiers := h.node.GetFrontiersDetailed()

	sort.Slice(frontiers, func(i, j int) bool { return frontiers[i].Account < frontiers[j].Account })
	writeJSON(w, http.StatusOK, paginateSlice(frontiers, offset, limit))
}

func (h *Handler) handleGetAllConflicts(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, paginateSlice(h.node.GetAllConflicts(), offset, limit))
}

func (h *Handler) handleGetDelegation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetDelegation())
}

func (h *Handler) handleGetActivations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetActivations())
}

func (h *Handler) handleGetReadiness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.node.GetReadiness())
}

func (h *Handler) handleGetAccountConflicts(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if account == "" {
		writeError(w, http.StatusBadRequest, "missing account")
		return
	}
	writeJSON(w, http.StatusOK, h.node.GetConflicts(account))
}

func (h *Handler) handleGetNodeInfo(w http.ResponseWriter, r *http.Request) {
	info := h.node.GetNodeInfo()
	writeJSON(w, http.StatusOK, info)
}

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

func (h *Handler) handleSubmitLease(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLease)
}

func (h *Handler) handleSubmitLeaseAccept(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseAccept)
}

func (h *Handler) handleSubmitLeaseSettle(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseSettle)
}

func (h *Handler) handleSubmitLeaseCancel(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseCancel)
}

func (h *Handler) handleSubmitLeaseForceSettle(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockLeaseForceSettle)
}

func (h *Handler) handleSubmitMultisigOpen(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMultisigOpen)
}

func (h *Handler) handleSubmitMultisigUpdate(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMultisigUpdate)
}

func (h *Handler) handleSubmitBurn(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockBurn)
}

func (h *Handler) handleSubmitMint(w http.ResponseWriter, r *http.Request) {
	h.submitBlock(w, r, core.BlockMint)
}

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

func (h *Handler) handleGetAllReputations(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, paginateMap(h.node.GetAllReputations(), offset, limit))
}

func (h *Handler) handleStateChainTip(w http.ResponseWriter, r *http.Request) {
	tip := h.node.GetStateChainTip()
	if tip == nil {
		writeError(w, http.StatusNotFound, "no tip")
		return
	}
	writeJSON(w, http.StatusOK, tip)
}

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

func (h *Handler) handleDAOKeyset(w http.ResponseWriter, r *http.Request) {
	ks := h.node.GetDAOKeyset()
	if ks == nil {
		writeError(w, http.StatusNotFound, "keyset not found")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

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
