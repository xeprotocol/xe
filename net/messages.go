package net

import (
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

// BlockMsg wraps a block for gossip transport.
type BlockMsg struct {
	Block *core.Block `json:"block"`
}

// VoteMsg wraps a vote for gossip transport.
type VoteMsg struct {
	Vote *core.Vote `json:"vote"`
}

// SyncRequest is sent at the start of a sync containing our frontiers and requested page size.
type SyncRequest struct {
	Frontiers map[string]string `json:"frontiers"`
	PageSize  int               `json:"page_size"`
}

// SyncResponse is one page of missing blocks in a sync stream.
//
// Rejected is populated on the final page (HasMore=false) and lists accounts
// whose remote frontier the server could not locate in its own canonical
// chain. The server's anti-amplification guard refuses to dump full chains
// on unrecognized hashes (see findMissingBlocksPaginated); the client uses
// this list to detect repeated rejection and recover by omitting the account
// from its outgoing frontier map (#406).
type SyncResponse struct {
	Blocks   []*core.Block `json:"blocks"`
	HasMore  bool          `json:"has_more"`
	Cursor   string        `json:"cursor"` // last block hash sent
	Rejected []string      `json:"rejected,omitempty"`
}

// ResourceAdvertisement describes available compute resources from a provider.
type ResourceAdvertisement struct {
	Provider string `json:"provider"` // ADDRESS: the provider's account address
	// ProviderPubKey is the provider's ed25519 public key — a VERIFYING KEY,
	// not an address (#829). See the package note on self-certifying
	// marketplace payloads in marketplace_sign.go.
	ProviderPubKey      string `json:"provider_pub_key"`
	VCPUs               uint64 `json:"vcpus"`
	MemoryMB            uint64 `json:"memory_mb"`
	DiskGB              uint64 `json:"disk_gb"`
	MaxConcurrentLeases uint64 `json:"max_concurrent_leases,omitempty"`
	Timestamp           int64  `json:"timestamp"`
	Signature           string `json:"signature"`
}

// ResourceRequest is a consumer's request for compute resources.
type ResourceRequest struct {
	Consumer string `json:"consumer"` // ADDRESS: the consumer's account address
	// ConsumerPubKey is the consumer's ed25519 public key — a VERIFYING KEY,
	// not an address (#829).
	ConsumerPubKey string `json:"consumer_pub_key"`
	RequestID      string `json:"request_id"`
	VCPUs          uint64 `json:"vcpus"`
	MemoryMB       uint64 `json:"memory_mb"`
	DiskGB         uint64 `json:"disk_gb"`
	Duration       uint64 `json:"duration"` // seconds
	Timestamp      int64  `json:"timestamp"`
	Signature      string `json:"signature"`
}

// ResourceOffer is a provider's response to a resource request.
type ResourceOffer struct {
	Provider string `json:"provider"` // ADDRESS: the provider's account address
	// ProviderPubKey is the provider's ed25519 public key — a VERIFYING KEY,
	// not an address (#829).
	ProviderPubKey string `json:"provider_pub_key"`
	RequestID      string `json:"request_id"`
	VCPUs          uint64 `json:"vcpus"`
	MemoryMB       uint64 `json:"memory_mb"`
	DiskGB         uint64 `json:"disk_gb"`
	Duration       uint64 `json:"duration"`
	TotalCost      uint64 `json:"total_cost"`
	// CertificateHash pins the provider's performance certificate so the
	// consumer can lock in the price multiplier at lease creation (#297).
	CertificateHash string `json:"certificate_hash,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Signature       string `json:"signature"`
}

// StateChainMsg wraps a state chain block for gossip transport.
type StateChainMsg struct {
	Block *statechain.Block `json:"block"`
}

// StateChainSyncRequest is sent by the client to request missing state chain blocks.
type StateChainSyncRequest struct {
	TipIndex int64 `json:"tip_index"` // -1 if empty chain (no blocks beyond genesis)
}

// StateChainSyncResponse is a page of state chain blocks from the server.
type StateChainSyncResponse struct {
	Blocks  []*statechain.Block `json:"blocks"`
	HasMore bool                `json:"has_more"`
}

// MarketplaceMsg wraps marketplace messages for gossip transport.
type MarketplaceMsg struct {
	Type    string                 `json:"type"` // "advertisement", "request", "offer"
	Ad      *ResourceAdvertisement `json:"ad,omitempty"`
	Request *ResourceRequest       `json:"request,omitempty"`
	Offer   *ResourceOffer         `json:"offer,omitempty"`
}
