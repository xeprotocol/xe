package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/vm"
)

func (n *Node) registerVMHandlers() {
	// vm_credentials: consumer stores credentials sent by provider after provisioning.
	// Only accept from the lease's provider to prevent credential injection.
	n.Msg.Handle("vm_credentials", func(from peer.ID, payload json.RawMessage) (json.RawMessage, error) {
		var info vm.Info
		if err := json.Unmarshal(payload, &info); err != nil {
			return nil, fmt.Errorf("invalid vm_credentials payload: %w", err)
		}
		// Verify the sender is the lease's provider.
		lease := n.GetLease(info.LeaseHash)
		if lease == nil {
			return nil, fmt.Errorf("lease not found: %s", shortHash(info.LeaseHash))
		}
		providerPeer := n.PeerForAccount(lease.Provider)
		if providerPeer == "" || providerPeer != from {
			return nil, fmt.Errorf("vm_credentials from unauthorized peer")
		}
		n.consumerVMs.Store(info.LeaseHash, &info)
		if info.Credentials != nil {
			log.Printf("Received VM credentials for lease %s (user=%s)", shortHash(info.LeaseHash), info.Credentials.Username)
		} else {
			log.Printf("Received VM info for lease %s (ssh-only)", shortHash(info.LeaseHash))
		}
		return json.Marshal(map[string]bool{"ok": true})
	})

	// vm_status: provider returns VM info for a lease.
	// Response contains only status and resource info, no credentials.
	// Any peer can query — this allows bootstrap nodes to proxy /vms/ requests.
	n.Msg.Handle("vm_status", func(from peer.ID, payload json.RawMessage) (json.RawMessage, error) {
		if n.VMManager == nil {
			return nil, fmt.Errorf("not a provider")
		}
		var req struct {
			LeaseHash string `json:"lease_hash"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("invalid vm_status payload: %w", err)
		}
		info, err := n.VMManager.Get(req.LeaseHash)
		if err != nil {
			return nil, err
		}
		return json.Marshal(info)
	})
}

func (n *Node) PeerForAccount(account string) peer.ID {
	reg, ok := n.Directory.Lookup(account)
	if ok {
		pid, err := peer.Decode(reg.NodePeer)
		if err == nil {
			return pid
		}
	}
	return ""
}

func (n *Node) provisionVM(leaseBlock *core.Block) {
	if n.VMManager == nil {
		return
	}

	info, err := n.VMManager.Provision(leaseBlock.Hash, vm.Resources{
		VCPUs:    leaseBlock.VCPUs,
		MemoryMB: leaseBlock.MemoryMB,
		DiskGB:   leaseBlock.DiskGB,
	}, leaseBlock.AccessPubKey)
	if err != nil {
		log.Printf("VM provision failed for lease %s: %v", shortHash(leaseBlock.Hash), err)
		return
	}
	if info.Credentials != nil {
		log.Printf("VM provisioned for lease %s (user=%s)", shortHash(leaseBlock.Hash), info.Credentials.Username)
	} else {
		log.Printf("VM provisioned for lease %s (ssh-only, no credentials)", shortHash(leaseBlock.Hash))
	}

	// Find the consumer peer and send VM info
	consumerPeer := n.PeerForAccount(leaseBlock.Account)
	if consumerPeer == "" {
		log.Printf("Could not find consumer peer for account %s", shortAddr(leaseBlock.Account))
		return
	}

	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	_, err = n.Msg.Request(ctx, consumerPeer, "vm_credentials", info)
	if err != nil {
		log.Printf("Failed to send VM info to consumer: %v", err)
		return
	}
	log.Printf("Sent VM info to consumer %s for lease %s", consumerPeer.ShortString(), shortHash(leaseBlock.Hash))
}

func (n *Node) teardownVM(lease *core.Lease) {
	if n.VMManager == nil {
		return
	}
	if err := n.VMManager.Teardown(lease.LeaseHash); err != nil {
		log.Printf("VM teardown failed for lease %s: %v", shortHash(lease.LeaseHash), err)
		return
	}
	log.Printf("VM torn down for lease %s", shortHash(lease.LeaseHash))
}

// GetVMs returns all VMs visible to this node (provider VMs + consumer VMs).
func (n *Node) GetVMs() []*vm.Info {
	out := make([]*vm.Info, 0)
	if n.VMManager != nil {
		out = append(out, n.VMManager.List()...)
	}
	seen := make(map[string]bool)
	for _, info := range out {
		seen[info.LeaseHash] = true
	}
	n.consumerVMs.Range(func(key, value any) bool {
		info := value.(*vm.Info)
		if !seen[info.LeaseHash] {
			out = append(out, info)
			seen[info.LeaseHash] = true
		}
		return true
	})
	return out
}

// GetVM returns a VM by lease hash. Checks local state first (provider VMs
// and consumer VMs), then relays to the provider via libp2p if not found.
func (n *Node) GetVM(leaseHash string) *vm.Info {
	if n.VMManager != nil {
		if info, err := n.VMManager.Get(leaseHash); err == nil {
			return info
		}
	}
	if v, ok := n.consumerVMs.Load(leaseHash); ok {
		return v.(*vm.Info)
	}

	// Not found locally — try relaying to the provider via libp2p.
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return nil
	}
	providerPeer := n.PeerForAccount(lease.Provider)
	if providerPeer == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	resp, err := n.Msg.Request(ctx, providerPeer, "vm_status", map[string]string{
		"lease_hash": leaseHash,
	})
	if err != nil {
		return nil
	}
	var info vm.Info
	if json.Unmarshal(resp, &info) != nil {
		return nil
	}
	return &info
}

// RequestAndCreateLease requests a lease via marketplace gossip and creates the lease block.
func (n *Node) RequestAndCreateLease(ctx context.Context, vcpus, memoryMB, diskGB, durationSecs uint64, accessPubKey string) (string, error) {
	offer, err := n.RequestLease(vcpus, memoryMB, diskGB, durationSecs)
	if err != nil {
		return "", fmt.Errorf("request lease: %w", err)
	}

	if err := n.CreateLeaseBlock(offer.Provider, offer.VCPUs, offer.MemoryMB, offer.DiskGB, durationSecs, offer.TotalCost, accessPubKey, offer.CertificateHash); err != nil {
		return "", fmt.Errorf("create lease block: %w", err)
	}

	// Find the lease hash from the latest block
	chain := n.Ledger.GetChain(n.KeyPair.Address())
	if len(chain) == 0 {
		return "", fmt.Errorf("no blocks after lease creation")
	}
	last := chain[len(chain)-1]
	return last.Hash, nil
}
