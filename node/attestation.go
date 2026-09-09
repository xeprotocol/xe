package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
)

const (
	AttestationMsgType   = "attest_timestamp"
	AttestationTimeout   = 10 * time.Second
	AttestationGatherMax = 15 * time.Second

	AttestationRateLimit = 30 * time.Second
)

type AttestationRequest struct {
	LeaseHash string `json:"lease_hash"`
}

type AttestationResponse struct {
	Attestation *core.TimekeeperAttestation `json:"attestation"`
}

func (n *Node) canAttest(identifier string) error {
	if lease := n.GetLease(identifier); lease != nil {
		switch lease.State {
		case core.LeaseCreated, core.LeaseAccepted:
			return nil
		}
		return fmt.Errorf("lease %s is %s: no attestation-gated transitions remain", shortHash(identifier), lease.State)
	}
	if n.Directory != nil && len(identifier) == 64 {
		if _, ok := n.Directory.Lookup(identifier); ok {
			return nil
		}
		const zeroMid = "0000000000000000"
		if identifier[32:48] == zeroMid {
			for _, reg := range n.Directory.List() {
				a := reg.Account
				if len(a) == 64 && a[:32] == identifier[:32] && a[48:] == identifier[48:] {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("unknown attestation identifier %s: not a live lease or a registered provider", shortHash(identifier))
}

func (n *Node) registerAttestationHandler() {
	n.attRateMap = make(map[string]time.Time)
	n.Msg.Handle(AttestationMsgType, n.handleAttestationRequest)
}

func (n *Node) handleAttestationRequest(from peer.ID, payload json.RawMessage) (json.RawMessage, error) {
	var req AttestationRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if req.LeaseHash == "" {
		return nil, fmt.Errorf("lease_hash required")
	}

	rateKey := from.String() + ":" + req.LeaseHash
	now := time.Now()
	n.attRateMu.Lock()
	for k, t := range n.attRateMap {
		if now.Sub(t) >= AttestationRateLimit {
			delete(n.attRateMap, k)
		}
	}
	if last, ok := n.attRateMap[rateKey]; ok && now.Sub(last) < AttestationRateLimit {
		n.attRateMu.Unlock()
		return nil, fmt.Errorf("rate limited: retry after %v", AttestationRateLimit-now.Sub(last))
	}
	n.attRateMu.Unlock()

	if len(req.LeaseHash) != 64 {
		return nil, fmt.Errorf("invalid identifier length: %d", len(req.LeaseHash))
	}
	if err := n.canAttest(req.LeaseHash); err != nil {

		logging.Warnf("Attestation request from %s rejected: %v", from.ShortString(), err)
		return nil, err
	}

	n.attRateMu.Lock()
	n.attRateMap[rateKey] = now
	n.attRateMu.Unlock()

	ts := core.Now().UnixNano()
	att, err := core.SignAttestation(req.LeaseHash, ts, n.KeyPair)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}

	logging.Debugf("Signed attestation for lease %s (ts=%d)", shortHash(req.LeaseHash), ts)

	resp := AttestationResponse{Attestation: att}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return raw, nil
}

func (n *Node) gatherAttestations(leaseHash string, config *core.TimekeeperConfig) ([]core.TimekeeperAttestation, error) {
	if config == nil || config.Threshold == 0 {
		return nil, fmt.Errorf("no timekeeper config")
	}

	peers := n.Host.Network().Peers()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no connected peers to gather attestations from")
	}

	ctx, cancel := context.WithTimeout(n.ctx, AttestationGatherMax)
	defer cancel()

	var mu sync.Mutex
	var attestations []core.TimekeeperAttestation

	var wg sync.WaitGroup

	myPub := n.KeyPair.PubKeyHex()
	for _, k := range config.Keys {
		if k == myPub {
			ts := core.Now().UnixNano()
			att, err := core.SignAttestation(leaseHash, ts, n.KeyPair)
			if err == nil {
				mu.Lock()
				attestations = append(attestations, *att)
				mu.Unlock()
				log.Printf("Self-signed attestation for lease %s", shortHash(leaseHash))
			}
			break
		}
	}

	for _, p := range peers {
		wg.Add(1)
		go func(pid peer.ID) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, AttestationTimeout)
			defer reqCancel()

			resp, err := n.Msg.Request(reqCtx, pid, AttestationMsgType, &AttestationRequest{
				LeaseHash: leaseHash,
			})
			if err != nil {
				logging.Warnf("Attestation request to %s failed: %v", pid.ShortString(), err)
				return
			}

			var attResp AttestationResponse
			if err := json.Unmarshal(resp, &attResp); err != nil {
				logging.Warnf("Attestation response from %s: decode error: %v", pid.ShortString(), err)
				return
			}
			if attResp.Attestation == nil {
				return
			}

			mu.Lock()
			attestations = append(attestations, *attResp.Attestation)
			mu.Unlock()
			logging.Debugf("Got attestation from %s for lease %s", pid.ShortString(), shortHash(leaseHash))
		}(p)
	}

	wg.Wait()

	attestations = capAttestations(attestations, leaseHash, config)
	if len(attestations) < config.Threshold {
		return attestations, fmt.Errorf("gathered %d attestations, need %d", len(attestations), config.Threshold)
	}

	return attestations, nil
}

func capAttestations(atts []core.TimekeeperAttestation, leaseHash string, config *core.TimekeeperConfig) []core.TimekeeperAttestation {
	trusted := make(map[string]bool, len(config.Keys))
	for _, k := range config.Keys {
		trusted[k] = true
	}
	seen := make(map[string]bool, len(atts))
	out := make([]core.TimekeeperAttestation, 0, len(atts))
	for _, a := range atts {
		if len(out) >= core.MaxAttestationsPerBlock {
			break
		}
		if !trusted[a.PublicKey] || seen[a.PublicKey] {
			continue
		}
		if err := core.VerifyAttestation(&a, leaseHash); err != nil {
			continue
		}
		seen[a.PublicKey] = true
		out = append(out, a)
	}
	return out
}

func (n *Node) getTimekeeperConfig() *core.TimekeeperConfig {
	raw, ok := n.StateChain.GetKV("sys.timekeepers")
	if !ok {
		return nil
	}
	var config core.TimekeeperConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		log.Printf("Failed to unmarshal sys.timekeepers: %v", err)
		return nil
	}
	if config.Threshold == 0 || len(config.Keys) == 0 {
		return nil
	}
	return &config
}
