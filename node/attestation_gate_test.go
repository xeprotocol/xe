package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/store"
)

func newTestStateChain(t *testing.T, tkKeys []string) *statechain.Chain {
	t.Helper()
	genesis, err := statechain.LoadGenesis()
	if err != nil {
		t.Fatalf("load genesis: %v", err)
	}
	tkConfig := core.TimekeeperConfig{
		Keys:      tkKeys,
		Threshold: 1,
	}
	tkRaw, err := json.Marshal(tkConfig)
	if err != nil {
		t.Fatalf("marshal tkConfig: %v", err)
	}
	found := false
	for i, op := range genesis.Ops {
		if op.Key == "sys.timekeepers" {
			genesis.Ops[i].Value = tkRaw
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("sys.timekeepers not found in genesis ops")
	}
	genesis.Signatures = nil
	h, err := statechain.HashBlock(genesis)
	if err != nil {
		t.Fatalf("hash genesis: %v", err)
	}
	genesis.Hash = h
	mem := store.NewMemStore()
	sc, err := statechain.NewChain(mem, genesis)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	return sc
}

func TestCanAttest_ZeroMidForgedIdentifierRejected(t *testing.T) {
	n := &Node{
		Directory: directory.New(0),
	}

	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	reg := directory.NewRegistration("peer1", time.Now().UnixNano(), providerKP)
	if err := n.Directory.Register(reg); err != nil {
		t.Fatalf("register provider: %v", err)
	}

	legitAcc := reg.Account
	if len(legitAcc) != 64 {
		t.Fatalf("expected 64 hex chars account, got %d", len(legitAcc))
	}

	// 1. Registered provider account itself is allowed
	if err := n.canAttest(legitAcc); err != nil {
		t.Fatalf("canAttest on registered account failed: %v", err)
	}

	// 2. Forged identifier with zero-mid pattern MUST be rejected
	const zeroMid = "0000000000000000"
	forged := legitAcc[:32] + zeroMid + legitAcc[48:]
	if err := n.canAttest(forged); err == nil {
		t.Fatalf("canAttest should reject forged zero-mid identifier %s", forged)
	} else if !strings.Contains(err.Error(), "unknown attestation identifier") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 3. Unrelated identifier MUST be rejected
	unrelated := strings.Repeat("f", 64)
	if err := n.canAttest(unrelated); err == nil {
		t.Fatalf("canAttest should reject unrelated identifier %s", unrelated)
	}
}

func TestCanAttest_LeaseStates(t *testing.T) {
	memStore := store.NewMemStore()
	n := &Node{
		store: memStore,
	}

	leaseHash := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

	// 1. Lease in LeaseCreated state
	lease := &core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseCreated,
	}
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}
	if err := n.canAttest(leaseHash); err != nil {
		t.Fatalf("canAttest on LeaseCreated failed: %v", err)
	}

	// 2. Lease in LeaseAccepted state
	lease.State = core.LeaseAccepted
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}
	if err := n.canAttest(leaseHash); err != nil {
		t.Fatalf("canAttest on LeaseAccepted failed: %v", err)
	}

	// 3. Lease in LeaseSettled state should be rejected
	lease.State = core.LeaseSettled
	if err := memStore.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}
	if err := n.canAttest(leaseHash); err == nil {
		t.Fatalf("canAttest should reject LeaseSettled")
	} else if !strings.Contains(err.Error(), "no attestation-gated transitions remain") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestIsTimekeeper(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	otherKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate other key pair: %v", err)
	}

	// Case 1: Node with nil KeyPair
	nilNode := &Node{}
	if nilNode.isTimekeeper() {
		t.Fatalf("nil KeyPair should not be a timekeeper")
	}

	// Case 2: Node with nil StateChain
	noSCNode := &Node{KeyPair: kp}
	if noSCNode.isTimekeeper() {
		t.Fatalf("node with nil StateChain should not be a timekeeper")
	}

	// Case 3: Node whose public key is NOT in sys.timekeepers
	sc := newTestStateChain(t, []string{kp.PubKeyHex()})
	nonTKNode := &Node{
		KeyPair:    otherKP,
		StateChain: sc,
	}
	if nonTKNode.isTimekeeper() {
		t.Fatalf("node not in sys.timekeepers keyset should not be a timekeeper")
	}

	// Case 4: Node whose public key IS in sys.timekeepers
	tkNode := &Node{
		KeyPair:    kp,
		StateChain: sc,
	}
	if !tkNode.isTimekeeper() {
		t.Fatalf("authorized timekeeper node should be recognized as a timekeeper")
	}
	if !tkNode.IsTimekeeper() {
		t.Fatalf("IsTimekeeper() should return true")
	}
}

func TestRequestAttestation_Gate(t *testing.T) {
	tkKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate timekeeper key pair: %v", err)
	}
	nonTKKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate non-timekeeper key pair: %v", err)
	}

	sc := newTestStateChain(t, []string{tkKP.PubKeyHex()})
	dir := directory.New(0)

	providerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key pair: %v", err)
	}
	reg := directory.NewRegistration("peer-provider", time.Now().UnixNano(), providerKP)
	if err := dir.Register(reg); err != nil {
		t.Fatalf("register provider: %v", err)
	}

	// Non-timekeeper node
	nonTKNode := &Node{
		KeyPair:    nonTKKP,
		StateChain: sc,
		Directory:  dir,
	}

	validID := reg.Account

	// 1. Non-timekeeper node should be rejected
	_, err = nonTKNode.RequestAttestation("127.0.0.1", validID)
	if err == nil {
		t.Fatalf("non-timekeeper node should not be able to sign attestations")
	}
	if !strings.Contains(err.Error(), "node is not an authorized timekeeper") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. Length check: identifier length != 64
	_, err = nonTKNode.RequestAttestation("127.0.0.1", "short_identifier")
	if err == nil {
		t.Fatalf("short identifier should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid attestation identifier length") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Timekeeper node
	tkNode := &Node{
		KeyPair:    tkKP,
		StateChain: sc,
		Directory:  dir,
	}

	// 3. Timekeeper with forged zero-mid identifier should be rejected by canAttest
	forged := reg.Account[:32] + "0000000000000000" + reg.Account[48:]
	_, err = tkNode.RequestAttestation("127.0.0.1", forged)
	if err == nil {
		t.Fatalf("forged zero-mid identifier should be rejected")
	}
	if !strings.Contains(err.Error(), "unknown attestation identifier") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 4. Timekeeper with valid registered provider identifier should succeed
	att, err := tkNode.RequestAttestation("127.0.0.1", validID)
	if err != nil {
		t.Fatalf("RequestAttestation failed for valid provider: %v", err)
	}
	if att == nil {
		t.Fatalf("expected non-nil attestation")
	}
	if att.PublicKey != tkKP.PubKeyHex() {
		t.Fatalf("attestation public key mismatch: got %s, want %s", att.PublicKey, tkKP.PubKeyHex())
	}
	if err := core.VerifyAttestation(att, validID); err != nil {
		t.Fatalf("failed to verify issued attestation: %v", err)
	}

	// 5. Rate limiting: immediate second request should fail
	_, err = tkNode.RequestAttestation("127.0.0.1", validID)
	if err == nil {
		t.Fatalf("second immediate request should be rate-limited")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
