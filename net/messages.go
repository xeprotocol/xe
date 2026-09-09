package net

import (
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

type BlockMsg struct {
	Block *core.Block `json:"block"`
}

type VoteMsg struct {
	Vote *core.Vote `json:"vote"`
}

type SyncRequest struct {
	Frontiers map[string]string `json:"frontiers"`
	PageSize  int               `json:"page_size"`
}

type SyncResponse struct {
	Blocks   []*core.Block `json:"blocks"`
	HasMore  bool          `json:"has_more"`
	Cursor   string        `json:"cursor"`
	Rejected []string      `json:"rejected,omitempty"`
}

type ResourceAdvertisement struct {
	Provider string `json:"provider"`

	ProviderPubKey      string `json:"provider_pub_key"`
	VCPUs               uint64 `json:"vcpus"`
	MemoryMB            uint64 `json:"memory_mb"`
	DiskGB              uint64 `json:"disk_gb"`
	MaxConcurrentLeases uint64 `json:"max_concurrent_leases,omitempty"`
	Timestamp           int64  `json:"timestamp"`
	Signature           string `json:"signature"`
}

type ResourceRequest struct {
	Consumer string `json:"consumer"`

	ConsumerPubKey string `json:"consumer_pub_key"`
	RequestID      string `json:"request_id"`
	VCPUs          uint64 `json:"vcpus"`
	MemoryMB       uint64 `json:"memory_mb"`
	DiskGB         uint64 `json:"disk_gb"`
	Duration       uint64 `json:"duration"`
	Timestamp      int64  `json:"timestamp"`
	Signature      string `json:"signature"`
}

type ResourceOffer struct {
	Provider string `json:"provider"`

	ProviderPubKey string `json:"provider_pub_key"`
	RequestID      string `json:"request_id"`
	VCPUs          uint64 `json:"vcpus"`
	MemoryMB       uint64 `json:"memory_mb"`
	DiskGB         uint64 `json:"disk_gb"`
	Duration       uint64 `json:"duration"`
	TotalCost      uint64 `json:"total_cost"`

	CertificateHash string `json:"certificate_hash,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Signature       string `json:"signature"`
}

type StateChainMsg struct {
	Block *statechain.Block `json:"block"`
}

type StateChainSyncRequest struct {
	TipIndex int64 `json:"tip_index"`
}

type StateChainSyncResponse struct {
	Blocks  []*statechain.Block `json:"blocks"`
	HasMore bool                `json:"has_more"`
}

type MarketplaceMsg struct {
	Type    string                 `json:"type"`
	Ad      *ResourceAdvertisement `json:"ad,omitempty"`
	Request *ResourceRequest       `json:"request,omitempty"`
	Offer   *ResourceOffer         `json:"offer,omitempty"`
}
