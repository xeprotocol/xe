package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"strings"
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

	AttestationRateLimit      = 15 * time.Second
	MaxAttestationRateEntries = 10000
	AttestationAuthDomain     = "xe/attestation-request/v1\x00"
)

type AttestationRequest struct {
	LeaseHash string `json:"lease_hash"`
	PubKey    string `json:"pub_key,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type AttestationResponse struct {
	Attestation *core.TimekeeperAttestation `json:"attestation"`
}

func AttestationRequestProofPayload(identifier string, timestamp int64) []byte {
	h := sha256.New()
	h.Write([]byte(AttestationAuthDomain))
	netID := core.GetNetworkID()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(netID)))
	h.Write(lenBuf[:])
	h.Write([]byte(netID))
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(identifier)))
	h.Write(lenBuf[:])
	h.Write([]byte(identifier))
	binary.BigEndian.PutUint64(lenBuf[:], uint64(timestamp))
	h.Write(lenBuf[:])
	return h.Sum(nil)
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (n *Node) isAuthorizedTimekeeper() error {
	tkConfig := n.getTimekeeperConfig()
	if tkConfig == nil {
		return nil
	}
	if n.KeyPair == nil {
		return fmt.Errorf("node has no keypair configured")
	}
	myPub := strings.ToLower(n.KeyPair.PubKeyHex())
	for _, k := range tkConfig.Keys {
		if strings.ToLower(k) == myPub {
			return nil
		}
	}
	return fmt.Errorf("this node is not an authorized timekeeper")
}

func (n *Node) canAttest(identifier string) error {
	_, err := n.canAttestForCaller("", "", identifier)
	return err
}

func (n *Node) canAttestForCaller(callerPeer, callerAccount, identifier string) (bool, error) {
	if !isLowerHex64(identifier) {
		return false, fmt.Errorf("invalid attestation identifier: must be 64 lowercase hex chars")
	}
	if lease := n.GetLease(identifier); lease != nil {
		switch lease.State {
		case core.LeaseCreated, core.LeaseAccepted:
			return false, nil
		}
		return false, fmt.Errorf("lease %s is %s: no attestation-gated transitions remain", shortHash(identifier), lease.State)
	}
	if callerPeer == "" && callerAccount == "" {
		return false, fmt.Errorf("unknown attestation identifier %s: not a live lease (provider attestation requires caller proof)", shortHash(identifier))
	}
	if n.Directory != nil {
		if reg, ok := n.Directory.Lookup(identifier); ok {
			if (callerPeer != "" && reg.NodePeer == callerPeer) || (callerAccount != "" && reg.Account == callerAccount) {
				return false, nil
			}
			return false, fmt.Errorf("attestation identifier %s belongs to another account", shortHash(identifier))
		}
		const zeroMid = "0000000000000000"
		if identifier[32:48] == zeroMid {
			matchedOther := false
			for _, reg := range n.Directory.List() {
				a := reg.Account
				if len(a) == 64 && a[:32] == identifier[:32] && a[48:] == identifier[48:] {
					if (callerPeer != "" && reg.NodePeer == callerPeer) || (callerAccount != "" && reg.Account == callerAccount) {
						return true, nil
					}
					matchedOther = true
				}
			}
			if matchedOther {
				return false, fmt.Errorf("attestation identifier %s belongs to another account", shortHash(identifier))
			}
		}
	}
	return false, fmt.Errorf("unknown attestation identifier %s: not a live lease or a registered provider", shortHash(identifier))
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

	var (
		att *core.TimekeeperAttestation
		err error
	)
	if req.PubKey != "" || req.Signature != "" {
		att, err = n.RequestAttestationWithProof(from.String(), req.LeaseHash, req.PubKey, req.Timestamp, req.Signature)
	} else {
		att, err = n.RequestAttestationFromPeer(from, req.LeaseHash)
	}
	if err != nil {
		return nil, err
	}

	logging.Debugf("Signed attestation for lease %s (ts=%d)", shortHash(req.LeaseHash), att.Timestamp)

	resp := AttestationResponse{Attestation: att}
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return raw, nil
}

func (n *Node) reserveAttestation(source, identifier string, isBenchEnd bool) (func(), error) {
	idKey := source + ":" + identifier
	srcKey := "src:" + source
	if isBenchEnd {
		srcKey = "src_end:" + source
	}
	now := time.Now()

	n.attRateMu.Lock()
	defer n.attRateMu.Unlock()
	if n.attRateMap == nil {
		n.attRateMap = make(map[string]time.Time)
	}

	for k, t := range n.attRateMap {
		if now.Sub(t) >= AttestationRateLimit {
			delete(n.attRateMap, k)
		}
	}
	if last, ok := n.attRateMap[idKey]; ok && now.Sub(last) < AttestationRateLimit {
		return nil, fmt.Errorf("rate limited: retry after %v", AttestationRateLimit-now.Sub(last))
	}
	if last, ok := n.attRateMap[srcKey]; ok && now.Sub(last) < AttestationRateLimit {
		return nil, fmt.Errorf("rate limited: retry after %v", AttestationRateLimit-now.Sub(last))
	}

	for len(n.attRateMap)+2 > MaxAttestationRateEntries {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, t := range n.attRateMap {
			if first || t.Before(oldestTime) {
				oldestKey = k
				oldestTime = t
				first = false
			}
		}
		if first {
			break
		}
		delete(n.attRateMap, oldestKey)
	}

	n.attRateMap[idKey] = now
	n.attRateMap[srcKey] = now

	released := false
	release := func() {
		n.attRateMu.Lock()
		defer n.attRateMu.Unlock()
		if released {
			return
		}
		released = true
		if t, ok := n.attRateMap[idKey]; ok && t.Equal(now) {
			delete(n.attRateMap, idKey)
		}
		if t, ok := n.attRateMap[srcKey]; ok && t.Equal(now) {
			delete(n.attRateMap, srcKey)
		}
	}
	return release, nil
}

func (n *Node) allowAttestation(source, identifier string) error {
	idKey := source + ":" + identifier
	srcKey := "src:" + source
	now := time.Now()

	n.attRateMu.Lock()
	defer n.attRateMu.Unlock()
	if n.attRateMap == nil {
		n.attRateMap = make(map[string]time.Time)
	}

	for k, t := range n.attRateMap {
		if now.Sub(t) >= AttestationRateLimit {
			delete(n.attRateMap, k)
		}
	}
	if last, ok := n.attRateMap[idKey]; ok && now.Sub(last) < AttestationRateLimit {
		return fmt.Errorf("rate limited: retry after %v", AttestationRateLimit-now.Sub(last))
	}
	if last, ok := n.attRateMap[srcKey]; ok && now.Sub(last) < AttestationRateLimit {
		return fmt.Errorf("rate limited: retry after %v", AttestationRateLimit-now.Sub(last))
	}
	return nil
}

func (n *Node) recordAttestation(source, identifier string) {
	now := time.Now()
	n.attRateMu.Lock()
	defer n.attRateMu.Unlock()
	if n.attRateMap == nil {
		n.attRateMap = make(map[string]time.Time)
	}
	n.attRateMap[source+":"+identifier] = now
	n.attRateMap["src:"+source] = now
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
	if n == nil || n.StateChain == nil {
		return nil
	}
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

func (n *Node) acceptAttestations(leaseHash string) ([]core.TimekeeperAttestation, error) {
	if n.acceptAttestHook != nil {
		return n.acceptAttestHook(leaseHash)
	}
	tkConfig := n.getTimekeeperConfig()
	if tkConfig == nil {
		return nil, nil
	}
	attestations, err := n.gatherAttestations(leaseHash, tkConfig)
	if err != nil {
		return nil, err
	}
	log.Printf("Gathered %d attestations for lease_accept %s", len(attestations), shortHash(leaseHash))
	return attestations, nil
}
