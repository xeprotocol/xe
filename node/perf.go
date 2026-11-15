package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/perf"
)

const (
	certPeerPollInterval = 2 * time.Second

	certRetryInitialDelay = 15 * time.Second
	certRetryMaxDelay     = 5 * time.Minute

	certRenewalLeadDivisor = 7

	certScoreChangeFactor = 2.0
)

type localCertificate struct {
	cert      *perf.Certificate
	nonces    []uint64
	startAtts []core.TimekeeperAttestation
	endAtts   []core.TimekeeperAttestation
}

func (n *Node) generatePerformanceCertificate() error {
	tkConfig := n.getTimekeeperConfig()
	if tkConfig == nil {
		return fmt.Errorf("no timekeeper config")
	}

	providerHex := n.KeyPair.Address()
	startID := providerHex
	endID := providerHex[:32] + "0000000000000000" + providerHex[48:]

	log.Printf("Generating performance certificate (%d puzzles)...", perf.PoWPuzzles)

	startAtts, err := n.gatherAttestations(startID, tkConfig)
	if err != nil {
		return fmt.Errorf("start attestations failed: %w", err)
	}
	startMedian, err := core.ValidateAttestations(startAtts, startID, tkConfig, false)
	if err != nil {
		return fmt.Errorf("start attestations invalid: %w", err)
	}
	log.Printf("Performance certificate: start attested (median=%d)", startMedian)

	providerPubkey, _ := hex.DecodeString(n.KeyPair.PubKeyHex())
	seed := perf.DeriveSeed(startMedian, providerPubkey)
	result := perf.RunBenchmark(seed, perf.PoWPuzzles)
	log.Printf("Performance certificate: benchmark completed in %s (score=%.4f)",
		result.Elapsed, result.Score())

	endAtts, err := n.gatherAttestations(endID, tkConfig)
	if err != nil {
		return fmt.Errorf("end attestations failed: %w", err)
	}
	endMedian, err := core.ValidateAttestations(endAtts, endID, tkConfig, false)
	if err != nil {
		return fmt.Errorf("end attestations invalid: %w", err)
	}

	elapsedSecs := float64(endMedian-startMedian) / 1e9
	if elapsedSecs <= 0 {
		return fmt.Errorf("invalid elapsed time: %.2fs", elapsedSecs)
	}
	score := 1.0 / elapsedSecs

	priceMult := n.providerPriceMultMilli
	if priceMult == 0 {
		priceMult = perf.PriceMultiplierDefault
	}
	if priceMult < perf.PriceMultiplierMin || priceMult > perf.PriceMultiplierMax {
		return fmt.Errorf("price multiplier %d out of bounds [%d, %d] — refusing to issue",
			priceMult, perf.PriceMultiplierMin, perf.PriceMultiplierMax)
	}
	if priceMult != perf.PriceMultiplierDefault {
		logging.Warnf("WARNING: issuing performance certificate with non-baseline price multiplier %d (%.3f×) — "+
			"this is a sim-only feature; production use is gated on anti-cheat",
			priceMult, float64(priceMult)/1000.0)
	}
	cert := &perf.Certificate{
		Provider:        n.KeyPair.Address(),
		Seed:            perf.SeedHex(seed),
		WorkloadVersion: perf.WorkloadVersion,
		Puzzles:         perf.PoWPuzzles,
		WorkProof:       hex.EncodeToString(result.FinalHash[:]),

		CPUHash:              hex.EncodeToString(result.CPUHash[:]),
		Score:                score,
		StartAttestationRoot: perf.AttestationMerkleRoot(startAtts),
		EndAttestationRoot:   perf.AttestationMerkleRoot(endAtts),
		StartMedian:          startMedian,
		EndMedian:            endMedian,
		IssuedAt:             startMedian,
		ExpiresAt:            startMedian + int64(perf.CertificateValidity),
		PriceMultiplierMilli: priceMult,
	}
	if err := perf.SignCertificate(cert, n.KeyPair); err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	n.installCertificate(&localCertificate{
		cert:      cert,
		nonces:    result.Nonces,
		startAtts: startAtts,
		endAtts:   endAtts,
	})
	return nil
}

func (n *Node) installCertificate(lc *localCertificate) {
	cert := lc.cert
	prev := n.perfCert.Swap(lc)
	if prev != nil && prev.cert.Hash != cert.Hash {
		n.retainCertificate(prev.cert)
		if significantScoreChange(prev.cert.Score, cert.Score) {
			logging.Warnf("Performance certificate: renewed score %.4f differs from predecessor %s score %.4f by more than %.0fx "+
				"(a lower score can reflect load during the benchmark)",
				cert.Score, shortHash(prev.cert.Hash), prev.cert.Score, certScoreChangeFactor)
		}
	}
	log.Printf("Performance certificate generated: hash=%s score=%.4f multiplier=%d expires_in=%s",
		shortHash(cert.Hash), cert.Score, cert.PriceMultiplierMilli, time.Duration(cert.ExpiresAt-cert.IssuedAt))

	if err := n.CertGossip.Publish(n.ctx, cert); err != nil {
		log.Printf("Performance certificate: gossip publish failed: %v", err)
	}
}

func significantScoreChange(prev, next float64) bool {
	if prev <= 0 || next <= 0 {
		return false
	}
	return next > prev*certScoreChangeFactor || next < prev/certScoreChangeFactor
}

func certRenewalDelay(cert *perf.Certificate, now int64) time.Duration {
	lifetime := cert.ExpiresAt - cert.IssuedAt
	if lifetime <= 0 {
		lifetime = int64(perf.CertificateValidity)
	}
	renewAt := cert.ExpiresAt - lifetime/certRenewalLeadDivisor
	if renewAt <= now {
		return 0
	}
	return time.Duration(renewAt - now)
}

func (n *Node) maintainCertificate(issue func() error, initialDelay, maxDelay time.Duration) {
	issued := false
	for {
		if lc := n.perfCert.Load(); lc != nil {
			wait := certRenewalDelay(lc.cert, core.Now().UnixNano())

			if issued && wait < initialDelay {
				wait = initialDelay
			}
			if wait > 0 {
				log.Printf("Performance certificate: %s renews in %s (expires_at=%d)",
					shortHash(lc.cert.Hash), wait.Round(time.Second), lc.cert.ExpiresAt)
				timer := time.NewTimer(wait)
				select {
				case <-n.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
		if !certGenerationLoop(n.ctx, issue, initialDelay, maxDelay) {
			return
		}
		issued = true
	}
}

func (n *Node) waitForAttestationPeers() bool {
	ticker := time.NewTicker(certPeerPollInterval)
	defer ticker.Stop()
	for {
		if len(n.Host.Network().Peers()) > 0 {
			return true
		}
		select {
		case <-n.ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func certGenerationLoop(ctx context.Context, attempt func() error, initialDelay, maxDelay time.Duration) bool {
	delay := initialDelay
	for {
		if ctx.Err() != nil {
			return false
		}
		if err := attempt(); err == nil {
			return true
		} else {
			log.Printf("Performance certificate: %v — retrying in %s", err, delay)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}

		if delay = delay * 2; delay > maxDelay {
			delay = maxDelay
		}
	}
}

func (n *Node) certRebroadcastLoop() {
	const rebroadcastInterval = 5 * time.Minute
	ticker := time.NewTicker(rebroadcastInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			lc := n.perfCert.Load()
			if lc == nil {
				continue
			}

			if lc.cert.ExpiresAt <= core.Now().UnixNano() {
				continue
			}
			if err := n.CertGossip.Publish(n.ctx, lc.cert); err != nil {
				log.Printf("Performance certificate: rebroadcast publish failed: %v", err)
			}
		}
	}
}

func (n *Node) GetPerformanceCertificate() *perf.Certificate {
	lc := n.perfCert.Load()
	if lc == nil {
		return nil
	}
	return lc.cert
}

func (n *Node) certificateByHash(hash string) *perf.Certificate {
	if lc := n.perfCert.Load(); lc != nil && lc.cert.Hash == hash {
		return lc.cert
	}
	return n.certs().get(hash)
}

func (n *Node) CertificateNonces(hash string) []uint64 {
	lc := n.perfCert.Load()
	if lc == nil || lc.cert.Hash != hash || lc.nonces == nil {
		return nil
	}
	out := make([]uint64, len(lc.nonces))
	copy(out, lc.nonces)
	return out
}

type CertificateAttestations struct {
	Start []core.TimekeeperAttestation `json:"start"`
	End   []core.TimekeeperAttestation `json:"end"`
}

func (n *Node) CertificateAttestations(hash string) *CertificateAttestations {
	lc := n.perfCert.Load()
	if lc == nil || lc.cert.Hash != hash || (lc.startAtts == nil && lc.endAtts == nil) {
		return nil
	}
	out := &CertificateAttestations{
		Start: make([]core.TimekeeperAttestation, len(lc.startAtts)),
		End:   make([]core.TimekeeperAttestation, len(lc.endAtts)),
	}
	copy(out.Start, lc.startAtts)
	copy(out.End, lc.endAtts)
	return out
}

func (n *Node) certificateInfoByHash(hash string) *core.CertificateInfo {
	cert := n.certificateByHash(hash)
	if cert == nil {
		return nil
	}
	return &core.CertificateInfo{
		Hash:                 cert.Hash,
		Provider:             cert.Provider,
		ExpiresAt:            cert.ExpiresAt,
		PriceMultiplierMilli: cert.PriceMultiplierMilli,
	}
}

func (n *Node) certificateInfoByProvider(provider string) *core.CertificateInfo {
	cert := n.GetCertificateByProvider(provider)
	if cert == nil {
		return nil
	}
	return &core.CertificateInfo{
		Hash:                 cert.Hash,
		Provider:             cert.Provider,
		ExpiresAt:            cert.ExpiresAt,
		PriceMultiplierMilli: cert.PriceMultiplierMilli,
	}
}

func (n *Node) certs() *certSet {
	n.certsOnce.Do(func() {
		if n.certCache == nil {
			n.certCache = newCertSet()
		}
	})
	return n.certCache
}

func (n *Node) GetCertificateByProvider(provider string) *perf.Certificate {
	now := core.Now().UnixNano()

	if lc := n.perfCert.Load(); lc != nil && lc.cert.Provider == provider && lc.cert.ExpiresAt > now {
		return lc.cert
	}
	return n.certs().currentValid(provider, now)
}

func (n *Node) GetCertificateByHash(hash string) *perf.Certificate {
	return n.certificateByHash(hash)
}

func (n *Node) handleCertificateGossip(certs <-chan *perf.Certificate) {
	for cert := range certs {
		n.ingestCertificate(cert)
	}
}

func (n *Node) ingestCertificate(cert *perf.Certificate) bool {
	if cert == nil {
		return false
	}

	if lc := n.perfCert.Load(); lc != nil && cert.Hash == lc.cert.Hash {
		return false
	}

	if err := perf.VerifyCertificateContent(cert); err != nil {
		logging.Warnf("Certificate: rejected %s from %s: %v",
			shortHash(cert.Hash), shortHash(cert.Provider), err)
		return false
	}

	if !n.retainCertificate(cert) {
		return false
	}
	log.Printf("Certificate: retained cert %s for %s (score=%.4f, expires_at=%d)",
		shortHash(cert.Hash), shortHash(cert.Provider), cert.Score, cert.ExpiresAt)
	return true
}

func (n *Node) retainCertificate(cert *perf.Certificate) bool {
	added, evicted := n.certs().put(cert)
	if !added {
		return false
	}

	if cs, ok := n.store.(core.CertificateStore); ok {
		if data, err := json.Marshal(cert); err == nil {
			if err := cs.PutCertificate(cert.Hash, data); err != nil {
				log.Printf("Certificate: persist %s: %v", shortHash(cert.Hash), err)
			}
		}
		for _, hash := range evicted {
			if err := cs.DeleteCertificate(hash); err != nil {
				log.Printf("Certificate: evict %s: %v", shortHash(hash), err)
			}
		}
	}
	return true
}

func (n *Node) loadPersistedCertificates() {
	cs, ok := n.store.(core.CertificateStore)
	if !ok {
		return
	}
	all, err := cs.AllCertificates()
	if err != nil {
		log.Printf("Certificate: load persisted: %v", err)
		return
	}
	loaded := 0
	for key, data := range all {
		var cert perf.Certificate
		if err := json.Unmarshal(data, &cert); err != nil {
			log.Printf("Certificate: decode persisted %s: %v", shortHash(key), err)
			continue
		}

		if added, _ := n.certs().put(&cert); added {
			loaded++
		}
	}
	if loaded > 0 {
		log.Printf("Certificate: loaded %d persisted certificate(s)", loaded)
	}
}

func (n *Node) collectCertificates() []*perf.Certificate {
	out := n.certs().all()
	if lc := n.perfCert.Load(); lc != nil {
		out = append([]*perf.Certificate{lc.cert}, out...)
	}
	return out
}

func (n *Node) quotableCertificate() *perf.Certificate {
	lc := n.perfCert.Load()
	if lc == nil || lc.cert.ExpiresAt <= core.Now().UnixNano() {
		return nil
	}
	return lc.cert
}

func (n *Node) acceptCertificateHash(leaseBlock *core.Block, startTime int64) (string, error) {
	hash := leaseBlock.CertificateHash
	if hash == "" {
		return "", fmt.Errorf("lease pins no performance certificate")
	}
	cert := n.certificateByHash(hash)
	if cert == nil {
		return "", fmt.Errorf("pinned certificate %s not held", shortHash(hash))
	}
	if cert.Provider != n.KeyPair.Address() {
		return "", fmt.Errorf("pinned certificate %s belongs to %s", shortHash(hash), shortHash(cert.Provider))
	}
	if startTime > cert.ExpiresAt {
		return "", fmt.Errorf("pinned certificate %s expired at %d, before start %d", shortHash(hash), cert.ExpiresAt, startTime)
	}
	return hash, nil
}
