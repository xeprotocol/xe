package node

import (
	"fmt"
	"log"

	"github.com/xeprotocol/xe/core"
)

func (n *Node) RenewLease(leaseHash string, additionalSecs uint64) (*core.Block, error) {
	myAddr := n.KeyPair.Address()

	lease := n.GetLease(leaseHash)
	if lease == nil {
		return nil, fmt.Errorf("lease %s not found", shortHash(leaseHash))
	}
	if lease.Consumer != myAddr {
		return nil, fmt.Errorf("lease %s is not this node's lease to renew", shortHash(leaseHash))
	}
	if lease.State != core.LeaseAccepted || lease.Settled {
		return nil, fmt.Errorf("lease %s is not renewable in state %q (settled=%v)", shortHash(leaseHash), lease.State, lease.Settled)
	}

	cert := n.GetCertificateByProvider(lease.Provider)
	if cert == nil {
		return nil, fmt.Errorf("provider %s has no current certificate — cannot renew", shortHash(lease.Provider))
	}
	cost, err := core.LeaseCost(lease.VCPUs, lease.MemoryMB, lease.DiskGB, additionalSecs, cert.PriceMultiplierMilli)
	if err != nil {
		return nil, fmt.Errorf("renewal cost: %w", err)
	}

	// Pre-flight check against committed lease caps before gathering attestations (#162)
	if n.StateChain != nil && n.StateChain.FeatureActive(core.FeatureLeaseCaps) {
		if err := lease.WithinRenewalCaps(additionalSecs, cost); err != nil {
			return nil, fmt.Errorf("renewal rejected by committed caps: %w", err)
		}
	}

	var attestations []core.TimekeeperAttestation
	if tkConfig := n.getTimekeeperConfig(); tkConfig != nil {
		attestations, err = n.gatherAttestations(leaseHash, tkConfig)
		if err != nil {
			return nil, fmt.Errorf("gather attestations for lease_renew %s: %w", shortHash(leaseHash), err)
		}
		log.Printf("Gathered %d attestations for lease_renew %s", len(attestations), shortHash(leaseHash))
	}

	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()

	chain := n.Ledger.GetChain(myAddr)
	if len(chain) == 0 {
		return nil, fmt.Errorf("account not open")
	}
	prev := chain[len(chain)-1].Hash
	xusdBal := n.Ledger.GetAssetBalances(myAddr)["XUSD"]
	if cost > xusdBal {
		return nil, fmt.Errorf("insufficient XUSD for renewal: have %d, need %d", xusdBal, cost)
	}

	b := &core.Block{
		Type:            core.BlockLeaseRenew,
		Account:         myAddr,
		Previous:        prev,
		Balance:         xusdBal - cost,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Source:          leaseHash,
		Amount:          cost,
		Duration:        additionalSecs,
		CertificateHash: cert.Hash,
		LockedR:         n.Ledger.CurrentR(),
		LockedPayoutCap: n.Ledger.CurrentPayoutCap(),
		LockedTWAP:      n.Ledger.CurrentTWAP(),
		Attestations:    attestations,
	}
	if err := core.SignBlock(b, n.KeyPair); err != nil {
		return nil, fmt.Errorf("sign lease_renew: %w", err)
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		return nil, fmt.Errorf("add lease_renew: %w", err)
	}
	if n.Gossip != nil {
		if err := n.Gossip.Publish(n.ctx, b); err != nil {
			return nil, fmt.Errorf("gossip lease_renew: %w", err)
		}
	}
	log.Printf("Renewed lease %s: +%ds, cost %d XUSD (renew block %s)", shortHash(leaseHash), additionalSecs, cost, shortHash(b.Hash))
	return b, nil
}


// CapLease issues a one-time lease_cap block from the provider to commit duration/cost caps for an accepted lease (#162).
func (n *Node) CapLease(leaseHash string, capDuration, capCost uint64) (*core.Block, error) {
	myAddr := n.KeyPair.Address()
	lease := n.GetLease(leaseHash)
	if lease == nil {
		return nil, fmt.Errorf("lease %s not found", shortHash(leaseHash))
	}
	if lease.Provider != myAddr {
		return nil, fmt.Errorf("only provider %s can cap lease %s, this node is %s", shortHash(lease.Provider), shortHash(leaseHash), shortHash(myAddr))
	}
	if lease.State != core.LeaseAccepted {
		return nil, fmt.Errorf("lease %s is not accepted (state: %s)", shortHash(leaseHash), lease.State)
	}
	if lease.CapSet {
		return nil, fmt.Errorf("lease %s already has committed caps", shortHash(leaseHash))
	}

	n.blockCreateMu.Lock()
	defer n.blockCreateMu.Unlock()

	chain := n.Ledger.GetChain(myAddr)
	if len(chain) == 0 {
		return nil, fmt.Errorf("account not open")
	}
	prev := chain[len(chain)-1].Hash
	bal := n.Ledger.GetAssetBalances(myAddr)["XUSD"]

	b := &core.Block{
		Type:             core.BlockLeaseCap,
		Account:          myAddr,
		Previous:         prev,
		Balance:          bal,
		Timestamp:        core.Now().UnixNano(),
		Asset:            "XUSD",
		Source:           leaseHash,
		Amount:           0,
		LeaseCapSet:      true,
		LeaseCapDuration: capDuration,
		LeaseCapCost:     capCost,
	}

	if err := core.SignBlock(b, n.KeyPair); err != nil {
		return nil, fmt.Errorf("sign lease_cap: %w", err)
	}
	n.solvePoW(b)

	if err := n.Ledger.AddBlock(b); err != nil {
		return nil, fmt.Errorf("add lease_cap block: %w", err)
	}
	if n.Gossip != nil {
		if err := n.Gossip.Publish(n.ctx, b); err != nil {
			return nil, fmt.Errorf("gossip lease_cap: %w", err)
		}
	}
	log.Printf("Capped lease %s: maxDur=%ds, maxCost=%d XUSD (block %s)", shortHash(leaseHash), capDuration, capCost, shortHash(b.Hash))
	return b, nil
}
