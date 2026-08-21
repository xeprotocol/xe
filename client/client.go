package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/xeprotocol/xe/core"
)

// Client is an HTTP client for the XE node API.
type Client struct {
	BaseURL string
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/")}
}

// NodeInfo returns node metadata including network_id.
func (c *Client) NodeInfo() (map[string]interface{}, error) {
	return c.getJSON(c.BaseURL + "/node")
}

// NetworkID fetches the network ID from the node.
func (c *Client) NetworkID() (string, error) {
	info, err := c.NodeInfo()
	if err != nil {
		return "", err
	}
	id, _ := info["network_id"].(string)
	return id, nil
}

// GetChain returns all blocks for an account, in chain order.
//
// The node windows /accounts/{addr}/chain (default 100, max 1000 blocks per
// page) and reports the full length as "total". This pages through the whole
// chain so callers always get the true tail — taking the last element as the
// frontier is only correct if every page is fetched. A single unpaged GET
// silently returns a stale prefix for any account past 100 blocks.
func (c *Client) GetChain(addr string) ([]*core.Block, error) {
	const pageLimit = 1000 // matches the node's maxPageLimit
	var all []*core.Block
	for offset := 0; ; offset += pageLimit {
		url := fmt.Sprintf("%s/accounts/%s/chain?offset=%d&limit=%d", c.BaseURL, addr, offset, pageLimit)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		var result struct {
			Blocks []*core.Block `json:"blocks"`
			Total  int           `json:"total"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, result.Blocks...)
		if len(result.Blocks) == 0 || len(all) >= result.Total {
			break
		}
	}
	return all, nil
}

// GetBalances returns asset balances for an account.
func (c *Client) GetBalances(addr string) (map[string]uint64, error) {
	resp, err := http.Get(fmt.Sprintf("%s/accounts/%s/balance", c.BaseURL, addr))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var result struct {
		Balances map[string]uint64 `json:"balances"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result.Balances == nil {
		return map[string]uint64{}, nil
	}
	return result.Balances, nil
}

// GetPending returns pending sends for an account.
func (c *Client) GetPending(addr string) ([]*core.PendingSend, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pending/%s", c.BaseURL, addr))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var result struct {
		Pending []*core.PendingSend `json:"pending"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.Pending, nil
}

// SubmitBlock submits a signed block to the node.
func (c *Client) SubmitBlock(b *core.Block, endpoint string) error {
	data, _ := json.Marshal(b)
	resp, err := http.Post(fmt.Sprintf("%s/blocks/%s", c.BaseURL, endpoint), "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// GetProviders returns available compute providers.
func (c *Client) GetProviders() ([]ProviderInfo, error) {
	resp, err := http.Get(c.BaseURL + "/providers")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var providers []ProviderInfo
	_ = json.NewDecoder(resp.Body).Decode(&providers)
	return providers, nil
}

// GetLease returns a lease record by hash.
func (c *Client) GetLease(hash string) (map[string]interface{}, error) {
	return c.getJSON(fmt.Sprintf("%s/leases/%s", c.BaseURL, hash))
}

// GetReputation returns the reputation aggregate for an account. Returns
// (nil, nil) if the account has no reputation activity (404 response).
func (c *Client) GetReputation(addr string) (map[string]interface{}, error) {
	resp, err := http.Get(fmt.Sprintf("%s/accounts/%s/reputation", c.BaseURL, addr))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reputation: status %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetCertificate returns the active performance certificate for a provider.
func (c *Client) GetCertificate(providerAddr string) (map[string]interface{}, error) {
	return c.getJSON(fmt.Sprintf("%s/certificate/%s", c.BaseURL, providerAddr))
}

// GetLeases returns all leases.
func (c *Client) GetLeases() ([]map[string]interface{}, error) {
	resp, err := http.Get(c.BaseURL + "/leases")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var leases []map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&leases)
	return leases, nil
}

// GetVM returns VM info by lease hash.
func (c *Client) GetVM(leaseHash string) (map[string]interface{}, error) {
	resp, err := http.Get(fmt.Sprintf("%s/vms/%s", c.BaseURL, leaseHash))
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func (c *Client) getJSON(url string) (map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// ProviderInfo represents a compute provider.
type ProviderInfo struct {
	Account    string `json:"account"`
	VCPUs      uint64 `json:"vcpus"`
	MemoryMB   uint64 `json:"memory_mb"`
	DiskGB     uint64 `json:"disk_gb"`
	UsedVCPUs  uint64 `json:"used_vcpus"`
	UsedMemMB  uint64 `json:"used_memory_mb"`
	UsedDiskGB uint64 `json:"used_disk_gb"`
	Active     int    `json:"active_leases"`
	Total      int    `json:"total_leases"`
}
