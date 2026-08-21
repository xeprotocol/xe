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
	// certPeerPollInterval is how often the startup path re-checks for a
	// connected peer before the first certificate attempt. On a post-wipe boot
	// no peer has connected yet and attestation gathering cannot succeed (#812).
	certPeerPollInterval = 2 * time.Second

	// certRetryInitialDelay and certRetryMaxDelay bound the exponential backoff
	// between certificate attempts. A provider holding no certificate cannot be
	// leased from at all, so attempts continue for the life of the node rather
	// than giving up; the cap keeps the timekeepers (rate-limited per
	// identifier) from being polled hot (#812).
	certRetryInitialDelay = 15 * time.Second
	certRetryMaxDelay     = 5 * time.Minute
)

// generatePerformanceCertificate runs the benchmark with attested timestamps
// and stores the signed certificate on the node. Called on provider startup.
// Every failure path returns an error and stores no certificate, so the caller
// can retry — a swallowed failure left providers permanently unleasable (#812).
func (n *Node) generatePerformanceCertificate() error {
	tkConfig := n.getTimekeeperConfig()
	if tkConfig == nil {
		return fmt.Errorf("no timekeeper config")
	}

	// Use different identifiers for start and end attestations to avoid
	// the per-peer rate limiter (30s cooldown per identifier).
	providerHex := n.KeyPair.Address()
	startID := providerHex                                            // 64 chars
	endID := providerHex[:32] + "0000000000000000" + providerHex[48:] // different 64-char hex

	log.Printf("Generating performance certificate (%d iterations)...", perf.BenchmarkIterations)

	// 1. Gather start attestation.
	startAtts, err := n.gatherAttestations(startID, tkConfig)
	if err != nil {
		return fmt.Errorf("start attestations failed: %w", err)
	}
	startMedian, err := core.ValidateAttestations(startAtts, startID, tkConfig, false)
	if err != nil {
		return fmt.Errorf("start attestations invalid: %w", err)
	}
	log.Printf("Performance certificate: start attested (median=%d)", startMedian)

	// 2. Derive seed and run benchmark. #829: the seed is derived from the
	// provider's PUBLIC KEY, not its address. The seed only has to be
	// provider-unique and deterministic, so either would do cryptographically —
	// but the certificate publishes ProviderPubKey and not the raw key bytes of
	// an address, so keying on the public key is what lets a verifier
	// independently re-derive the seed from the certificate alone.
	providerPubkey, _ := hex.DecodeString(n.KeyPair.PubKeyHex())
	seed := perf.DeriveSeed(startMedian, providerPubkey)
	result := perf.RunBenchmark(seed, perf.BenchmarkIterations)
	log.Printf("Performance certificate: benchmark completed in %s (score=%.4f)",
		result.Elapsed, result.Score())

	// 3. Gather end attestation (uses different ID to avoid rate limiter).
	endAtts, err := n.gatherAttestations(endID, tkConfig)
	if err != nil {
		return fmt.Errorf("end attestations failed: %w", err)
	}
	endMedian, err := core.ValidateAttestations(endAtts, endID, tkConfig, false)
	if err != nil {
		return fmt.Errorf("end attestations invalid: %w", err)
	}

	// 4. Compute score from attested elapsed time.
	elapsedSecs := float64(endMedian-startMedian) / 1e9
	if elapsedSecs <= 0 {
		return fmt.Errorf("invalid elapsed time: %.2fs", elapsedSecs)
	}
	score := 1.0 / elapsedSecs

	// 5. Assemble and sign certificate (compact: merkle roots, not full attestations).
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
			"this is a sim-only feature (#297); production use is gated on anti-cheat (#213/#214/#215)",
			priceMult, float64(priceMult)/1000.0)
	}
	cert := &perf.Certificate{
		Provider:             n.KeyPair.Address(),
		Seed:                 perf.SeedHex(seed),
		WorkloadVersion:      perf.WorkloadVersion,
		Iterations:           perf.BenchmarkIterations,
		WorkProof:            hex.EncodeToString(result.FinalHash[:]),
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

	n.perfCert.Store(cert)
	log.Printf("Performance certificate generated: hash=%s score=%.4f multiplier=%d expires_in=%s",
		shortHash(cert.Hash), cert.Score, priceMult, perf.CertificateValidity)

	// Broadcast to the network so all nodes cache it. A publish failure is not
	// a certificate failure — the cert is issued and stored, and
	// certRebroadcastLoop re-publishes on its own cadence.
	if err := n.CertGossip.Publish(n.ctx, cert); err != nil {
		log.Printf("Performance certificate: gossip publish failed: %v", err)
	}
	return nil
}

// waitForAttestationPeers blocks until at least one peer is connected. The
// startup path used to fire the first certificate attempt on a blind 15s timer,
// which on a post-wipe boot lands before any peer has connected and fails with
// "no connected peers to gather attestations from" (#812). Returns false if the
// node is stopping.
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

// certGenerationLoop calls attempt until it succeeds, backing off exponentially
// from initialDelay up to maxDelay between failures. Returns true once an
// attempt succeeds, or false if ctx is done first — the sleep is interruptible
// so a stopping node never blocks on a pending retry (#812).
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

// certRebroadcastLoop periodically re-publishes the local provider's
// performance certificate so peers that joined the network or recovered
// from a wipe after the initial gossip event can still cache it. Without
// this, post-wipe nodes can only obtain the cert when the provider
// reissues at expiry (up to 7 days — see #409 mode A).
//
// Cadence is conservative: every 5 minutes. The cert is small (~256 bytes
// signed payload) and pubsub dedupes by signature so the cost is bounded.
func (n *Node) certRebroadcastLoop() {
	const rebroadcastInterval = 5 * time.Minute
	ticker := time.NewTicker(rebroadcastInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			cert := n.perfCert.Load()
			if cert == nil {
				continue
			}
			// Stop re-broadcasting if cert has expired.
			if cert.ExpiresAt <= core.Now().UnixNano() {
				continue
			}
			if err := n.CertGossip.Publish(n.ctx, cert); err != nil {
				log.Printf("Performance certificate: rebroadcast publish failed: %v", err)
			}
		}
	}
}

// GetPerformanceCertificate returns the provider's current certificate, or nil.
// Checks local cert first (if provider), then gossip cache.
func (n *Node) GetPerformanceCertificate() *perf.Certificate {
	return n.perfCert.Load()
}

// certificateByHash returns the certificate with the given hash — the local
// provider certificate or one held in the certificate set.
func (n *Node) certificateByHash(hash string) *perf.Certificate {
	if pc := n.perfCert.Load(); pc != nil && pc.Hash == hash {
		return pc
	}
	return n.certs().get(hash)
}

// certificateInfoByHash is the ledger's certificate lookup: it resolves the
// hash a lease or lease_accept block pins into the facts the ledger validates
// against. Expiry is deliberately NOT filtered here — the ledger compares the
// certificate's expiry against the *block's* timestamp, so a block that was
// valid when it was written stays valid forever. Filtering on wall-clock time
// here would make historical blocks unvalidatable and stall cold sync.
func (n *Node) certificateInfoByHash(hash string) *core.CertificateInfo {
	cert := n.certificateByHash(hash)
	if cert == nil {
		return nil
	}
	return &core.CertificateInfo{
		Provider:             cert.Provider,
		ExpiresAt:            cert.ExpiresAt,
		PriceMultiplierMilli: cert.PriceMultiplierMilli,
	}
}

// certs returns this node's certificate set, creating it on first use so that
// a zero-value Node (as constructed in tests) is usable.
func (n *Node) certs() *certSet {
	n.certsOnce.Do(func() {
		if n.certCache == nil {
			n.certCache = newCertSet()
		}
	})
	return n.certCache
}

// GetCertificateByProvider returns the provider's current *usable*
// certificate — the newest one that has not expired — or nil.
//
// This is the discovery answer: consumers read it to quote and write a lease,
// so it must never hand back an expired certificate, which the ledger would
// reject. Retained history is reachable by hash instead
// (GetCertificateByHash), which is what block validation and cold sync need.
func (n *Node) GetCertificateByProvider(provider string) *perf.Certificate {
	now := core.Now().UnixNano()
	// Check if we're the provider.
	if pc := n.perfCert.Load(); pc != nil && pc.Provider == provider && pc.ExpiresAt > now {
		return pc
	}
	return n.certs().currentValid(provider, now)
}

// GetCertificateByHash returns any certificate this node retains by its hash,
// expired or not — the lookup lease blocks and cold sync need (#816).
func (n *Node) GetCertificateByHash(hash string) *perf.Certificate {
	return n.certificateByHash(hash)
}

// handleCertificateGossip processes certificates received from peers via the
// gossip topic.
func (n *Node) handleCertificateGossip(certs <-chan *perf.Certificate) {
	for cert := range certs {
		n.ingestCertificate(cert)
	}
}

// ingestCertificate verifies a certificate received from a peer (via gossip or
// the on-connect pull, #502) and retains it. Returns true if it was newly
// retained. Both the gossip handler and the cert-sync puller funnel through
// here so verification and retention rules stay identical.
//
// Expiry is NOT a rejection reason (#816). A certificate that has expired is
// still the certificate that earlier lease blocks pin, and a node replaying
// that history must be able to obtain and keep it — the ledger validates those
// blocks against the block's own timestamp. Rejecting expired certificates
// here is what left cold-syncing nodes permanently unable to validate lease
// history across a provider rotation.
func (n *Node) ingestCertificate(cert *perf.Certificate) bool {
	if cert == nil {
		return false
	}
	// Skip our own certificate (echo).
	if pc := n.perfCert.Load(); pc != nil && cert.Hash == pc.Hash {
		return false
	}

	// Verify content and signature. Expiry is deliberately not checked.
	if err := perf.VerifyCertificateContent(cert); err != nil {
		logging.Warnf("Certificate: rejected %s from %s: %v",
			shortHash(cert.Hash), shortHash(cert.Provider), err)
		return false
	}

	added, evicted := n.certs().put(cert)
	if !added {
		return false
	}

	// Persist: certificates are chain data since #596 (their hash is bound
	// into lease block hashes). A memory-only cache loses them on restart and
	// permanently breaks cold-sync of the lease history they anchor (#630).
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
	log.Printf("Certificate: retained cert %s for %s (score=%.4f, expires_at=%d)",
		shortHash(cert.Hash), shortHash(cert.Provider), cert.Score, cert.ExpiresAt)
	return true
}

// loadPersistedCertificates seeds the in-memory certificate cache from the
// store at boot so a restarted node keeps serving certificates for the lease
// history it holds — gossip from the original provider may be long gone
// (#630).
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
		// Keyed by hash from the payload itself, so entries written by an
		// older provider-keyed build still load correctly.
		if added, _ := n.certs().put(&cert); added {
			loaded++
		}
	}
	if loaded > 0 {
		log.Printf("Certificate: loaded %d persisted certificate(s)", loaded)
	}
}

// collectCertificates returns every performance certificate this node holds —
// its own (if a provider) plus everything retained from peers — for serving to
// a peer pulling certs on connect (#502).
//
// Expired certificates are included (#816): a cold-syncing peer needs exactly
// the certificates its lease history pins, and those are routinely expired by
// the time it replays them. Withholding them is what made the stall permanent.
// certSet.all() orders current certificates first so that a peer truncating at
// its response cap drops history rather than the certificates needed to accept
// new leases.
func (n *Node) collectCertificates() []*perf.Certificate {
	out := n.certs().all()
	if pc := n.perfCert.Load(); pc != nil {
		out = append([]*perf.Certificate{pc}, out...)
	}
	return out
}
