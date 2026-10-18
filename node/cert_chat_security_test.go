package node

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/perf"
)

func makeSignedTestCert(t *testing.T, kp *core.KeyPair, startMedian int64) *perf.Certificate {
	t.Helper()
	endMedian := startMedian + int64(time.Second)
	pubBytes, _ := hex.DecodeString(kp.PubKeyHex())
	seed := perf.DeriveSeed(startMedian, pubBytes)
	cert := &perf.Certificate{
		Provider:             kp.Address(),
		Seed:                 perf.SeedHex(seed),
		WorkloadVersion:      perf.WorkloadVersion,
		Puzzles:              perf.PoWPuzzles,
		WorkProof:            strings.Repeat("ab", 32),
		CPUHash:              strings.Repeat("cd", 32),
		Score:                1.0,
		StartAttestationRoot: strings.Repeat("11", 32),
		EndAttestationRoot:   strings.Repeat("22", 32),
		StartMedian:          startMedian,
		EndMedian:            endMedian,
		IssuedAt:             startMedian,
		ExpiresAt:            startMedian + int64(perf.CertificateValidity),
		PriceMultiplierMilli: perf.PriceMultiplierDefault,
	}
	if err := perf.SignCertificate(cert, kp); err != nil {
		t.Fatalf("SignCertificate: %v", err)
	}
	return cert
}

func TestCertSetProviderCapEvictsOldestProvider(t *testing.T) {
	cs := newCertSet()
	cs.maxProviders = 3

	base := core.Now().UnixNano()
	var kps []*core.KeyPair
	var certs []*perf.Certificate
	for i := 0; i < 4; i++ {
		kp, _ := core.GenerateKeyPair()
		kps = append(kps, kp)
		certs = append(certs, makeSignedTestCert(t, kp, base+int64(i)*1_000_000))
	}

	for i := 0; i < 3; i++ {
		added, evicted := cs.put(certs[i])
		if !added || len(evicted) != 0 {
			t.Fatalf("put %d: added=%v evicted=%v", i, added, evicted)
		}
	}
	if cs.len() != 3 {
		t.Fatalf("expected 3 certs in certSet, got %d", cs.len())
	}

	// Adding 4th provider with newer IssuedAt evicts provider 0.
	added, evicted := cs.put(certs[3])
	if !added {
		t.Fatalf("expected 4th provider with newer IssuedAt to be added")
	}
	if len(evicted) != 1 || evicted[0] != certs[0].Hash {
		t.Fatalf("expected certs[0] (%s) to be evicted, got %v", certs[0].Hash, evicted)
	}
	if cs.get(certs[0].Hash) != nil {
		t.Fatalf("expected evicted cert to be removed from byHash")
	}
	if cs.len() != 3 {
		t.Fatalf("expected certSet size to remain capped at 3, got %d", cs.len())
	}

	// Adding a provider with an older IssuedAt than all retained providers is rejected.
	staleKP, _ := core.GenerateKeyPair()
	staleCert := makeSignedTestCert(t, staleKP, base-1_000_000)
	if added, _ := cs.put(staleCert); added {
		t.Fatalf("expected stale provider cert older than all retained providers to be rejected at capacity")
	}
}

func TestIsHostedChatRecipientRejectsArbitraryAccounts(t *testing.T) {
	nodeKP, _ := core.GenerateKeyPair()
	unrelatedKP, _ := core.GenerateKeyPair()

	n := &Node{
		KeyPair:   nodeKP,
		Directory: directory.New(directory.DefaultTTL),
	}

	if !n.isHostedChatRecipient(nodeKP.Address()) {
		t.Fatalf("expected node's own account to be accepted as hosted chat recipient")
	}
	if n.isHostedChatRecipient(unrelatedKP.Address()) {
		t.Fatalf("expected unrelated account not hosted on this node to be rejected")
	}
}
