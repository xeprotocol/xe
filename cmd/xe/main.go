package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	iofs "io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xeprotocol/xe/api"
	"github.com/xeprotocol/xe/client"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/node"
	"github.com/xeprotocol/xe/web"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "node":
		cmdNode(args)
	case "wallet":
		if len(args) == 0 {
			fatal("usage: xe wallet <create|balance>")
		}
		switch args[0] {
		case "create":
			cmdWalletCreate()
		case "balance":
			cmdWalletBalance()
		default:
			fatal("unknown wallet command: %s", args[0])
		}
	case "send":
		if len(args) < 2 {
			fatal("usage: xe send <address> <amount> [--asset XUSD]")
		}
		cmdSend(args)
	case "receive":
		cmdReceive()
	case "faucet":
		// TESTNET ONLY. Requests XUSD from the standalone faucet service, which
		// holds an authorized minter wallet (sys.minter) and sends to the given
		// address. No-op / rejection on networks without a faucet service.
		cmdFaucet()
	case "mint":
		// Ops/bootstrap only: the loaded wallet must be an authorized sys.minter.
		if len(args) < 1 {
			fatal("usage: xe mint <amount>")
		}
		cmdMint(args)
	case "burn":
		if len(args) < 1 {
			fatal("usage: xe burn <amount> [--yes]")
		}
		cmdBurn(args)
	case "providers":
		cmdProviders()
	case "lease":
		if len(args) > 0 && args[0] == "status" {
			if len(args) < 2 {
				fatal("usage: xe lease status <hash>")
			}
			cmdLeaseStatus(args[1])
		} else {
			cmdLease(args)
		}
	case "vm":
		if len(args) < 1 {
			fatal("usage: xe vm <lease-hash>")
		}
		cmdVM(args[0])
	case "ssh":
		if len(args) < 1 {
			fatal("usage: xe ssh <lease-hash>")
		}
		cmdSSH(args[0])
	case "reputation":
		if len(args) < 1 {
			fatal("usage: xe reputation <address>")
		}
		cmdReputation(args[0])
	case "keygen":
		cmdKeygen()
	case "sign-block":
		if len(args) >= 1 {
			// The seed has already leaked into ps/proc/shell history by the
			// time we see it here — refuse rather than honour it (#570/L7).
			fatal("sign-block no longer takes a seed argument (it leaks via ps/proc/shell history): rotate this seed and set XE_SEED instead")
		}
		cmdSignBlock()
	case "verify-genesis":
		cmdVerifyGenesis(args)
	case "version", "--version", "-v":
		fmt.Printf("xe %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `xe — XE network CLI

Usage: xe <command> [args]

Node:
  node [flags]            Start a node daemon
                          Flags include:
                            --api (default true), --api-port 8080, --api-bind 127.0.0.1
                            --ui (default false), --ui-port 8000, --ui-bind 127.0.0.1
                            --ui-dir <path>   serve UI from disk (dev)
                            --ui-faucet <url> proxy /faucet/* to this faucet service (empty = disabled)
                            --wallet (default true)  expose /wallet/ in the embedded UI

Wallet:
  wallet create           Create a new wallet
  wallet balance          Show wallet balance

Transactions:
  send <addr> <amount> [--asset XE|XUSD] [--memo "text"]
                          Send funds; --memo attaches up to 64 bytes of UTF-8
  receive                 Receive all pending sends
  faucet                  Request testnet XUSD from the faucet service to your wallet
  mint <amount>           Mint XUSD (authorized minter wallet only; ops/bootstrap)
  burn <amount> [--yes] [--memo "text"]
                          Permanently destroy XE from your wallet (irreversible)

Compute:
  providers               List compute providers
  lease [flags]           Create a lease
  lease status <hash>     Check lease status
  vm <hash>               Get VM info
  ssh <hash>              SSH into a leased VM

Reputation:
  reputation <addr>       Show reputation aggregate for an account

Tools:
  keygen                  Generate ed25519 SSH keypair
  verify-genesis [flags]  Print the network_id and genesis hashes this binary
                          runs with; --genesis-dir/--genesis/--statechain-genesis
                          verify a supplied genesis instead. --json for machine
                          output; --expect-network-id / --expect-statechain-hash
                          exit non-zero on mismatch.
  sign-block              Sign a block from stdin; seed from XE_SEED env
                          (preferred). A positional <seed> still works but is
                          deprecated — it leaks via ps/proc/shell history.

Global flags (via environment):
  XE_NODE=<url>           Node API URL (default: https://ldn.core.test.network)
  XE_FAUCET=<url>         Faucet service URL (default: https://faucet.test.network)
  XE_WALLET=<file>        Wallet seed file (default: ~/.xe/wallet.seed)

`)
}

// --- Config ---

func nodeURL() string {
	if v := os.Getenv("XE_NODE"); v != "" {
		return v
	}
	return "https://ldn.core.test.network"
}

func faucetURL() string {
	if v := os.Getenv("XE_FAUCET"); v != "" {
		return v
	}
	return "https://faucet.test.network"
}

func walletPath() string {
	if v := os.Getenv("XE_WALLET"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".xe", "wallet.seed")
}

func apiClient() *client.Client {
	return client.New(nodeURL())
}

func initNetworkID() {
	c := apiClient()
	id, err := c.NetworkID()
	if err != nil {
		return
	}
	if id != "" {
		core.SetNetworkID(id)
	}
}

// --- Wallet ---

// The wallet file is unchanged by #829: it stores the 32-byte hex SEED and
// nothing else, so the account address and the public key are both re-derived
// on every load. Since #829 those are two different values — the address is
// sha256("xe/account/v1" || pubkey) — so anywhere the CLI shows an identity it
// shows both, and only ever puts the ADDRESS in a block's account field.
func loadWallet() *core.KeyPair {
	path := walletPath()
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("no wallet found at %s — run: xe wallet create", path)
	}
	seedHex := strings.TrimSpace(string(data))
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		fatal("corrupt wallet file: %s", path)
	}
	return core.KeyPairFromSeed(seed)
}

func cmdWalletCreate() {
	path := walletPath()
	if _, err := os.Stat(path); err == nil {
		kp := loadWallet()
		fmt.Printf("Wallet already exists: %s\n", kp.Address())
		fmt.Printf("  Public key: %s\n", kp.PubKeyHex())
		fmt.Printf("  File: %s\n", path)
		return
	}

	kp, err := core.GenerateKeyPair()
	if err != nil {
		fatal("generate keypair: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fatal("create wallet dir: %v", err)
	}

	seedHex := hex.EncodeToString(kp.Private.Seed())
	if err := os.WriteFile(path, []byte(seedHex+"\n"), 0600); err != nil {
		fatal("write wallet: %v", err)
	}

	fmt.Printf("Wallet created!\n")
	// Address and public key are distinct since #829 — the address is what you
	// receive funds at, the key is only what verifies your signatures.
	fmt.Printf("  Address:    %s\n", kp.Address())
	fmt.Printf("  Public key: %s\n", kp.PubKeyHex())
	fmt.Printf("  File:       %s\n", path)
}

func cmdWalletBalance() {
	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	bals, err := c.GetBalances(addr)
	if err != nil {
		fatal("get balance: %v", err)
	}

	fmt.Printf("Address:    %s\n", addr)
	fmt.Printf("Public key: %s\n", kp.PubKeyHex())
	if len(bals) == 0 {
		fmt.Println("  (no balance)")
	} else {
		for asset, bal := range bals {
			cfg, ok := core.AssetByName(asset)
			if !ok {
				cfg = core.AssetXE
			}
			fmt.Printf("  %s: %s\n", asset, core.FormatAmount(bal, cfg))
		}
	}
}

// --- Send ---

func cmdSend(args []string) {
	initNetworkID()
	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	dest := args[0]
	asset := "XUSD"
	memo := ""
	for i, a := range args {
		if a == "--asset" && i+1 < len(args) {
			asset = args[i+1]
		}
		if a == "--memo" && i+1 < len(args) {
			memo = args[i+1]
		}
	}
	assetCfg, ok := core.AssetByName(asset)
	if !ok {
		fatal("unknown asset %q", asset)
	}
	amount, err := core.ParseAmount(args[1], assetCfg)
	if err != nil {
		fatal("invalid amount %q: %v", args[1], err)
	}
	if amount == 0 {
		fatal("send amount must be greater than zero")
	}
	if err := core.ValidateMemo(memo); err != nil {
		fatal("invalid memo: %v", err)
	}

	chain, _ := c.GetChain(addr)
	bals, _ := c.GetBalances(addr)
	if bals[asset] < amount {
		fatal("insufficient %s: have %s, need %s", asset, core.FormatAmount(bals[asset], assetCfg), core.FormatAmount(amount, assetCfg))
	}

	prev := "0"
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     addr,
		Previous:    prev,
		Balance:     bals[asset] - amount,
		Timestamp:   time.Now().UnixNano(),
		Asset:       asset,
		Destination: dest,
		Amount:      amount,
		Memo:        memo,
	}
	if err := core.SignBlock(b, kp); err != nil {
		fatal("sign: %v", err)
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

	if err := c.SubmitBlock(b, "send"); err != nil {
		fatal("submit: %v", err)
	}
	fmt.Printf("Sent %s %s to %s\n", core.FormatAmount(amount, assetCfg), asset, shortAddr(dest))
	fmt.Printf("  Hash: %s\n", b.Hash)
}

// --- Receive ---

func cmdReceive() {
	initNetworkID()
	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	pending, _ := c.GetPending(addr)
	if len(pending) == 0 {
		fmt.Println("No pending sends to receive.")
		return
	}

	fmt.Printf("Receiving %d pending send(s)...\n", len(pending))
	for _, p := range pending {
		chain, _ := c.GetChain(addr)
		bals, _ := c.GetBalances(addr)

		prev := "0"
		if len(chain) > 0 {
			prev = chain[len(chain)-1].Hash
		}

		b := &core.Block{
			Type:      core.BlockReceive,
			Account:   addr,
			Previous:  prev,
			Balance:   bals[p.Asset] + p.Amount,
			Timestamp: time.Now().UnixNano(),
			Asset:     p.Asset,
			Source:    p.SendHash,
		}
		if err := core.SignBlock(b, kp); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: sign: %v\n", shortHash(p.SendHash), err)
			continue
		}
		hashBytes, _ := hex.DecodeString(b.Hash)
		b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

		if err := c.SubmitBlock(b, "receive"); err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", shortHash(p.SendHash), err)
			continue
		}
		recvCfg, ok := core.AssetByName(p.Asset)
		if !ok {
			recvCfg = core.AssetXE
		}
		fmt.Printf("  Received %s %s from %s\n", core.FormatAmount(p.Amount, recvCfg), p.Asset, shortAddr(p.Source))
	}
}

// --- Faucet ---

// cmdFaucet requests testnet XUSD from the standalone faucet service. TESTNET
// ONLY. The permissionless self-mint claim has been removed (#557): the faucet
// is now an authorized minter wallet (sys.minter) operated as a service. The
// CLI just POSTs the wallet's address; the service mints and sends the XUSD.
func cmdFaucet() {
	kp := loadWallet()
	addr := kp.Address()

	reqBody, _ := json.Marshal(map[string]string{"address": addr})
	resp, err := http.Post(faucetURL()+"/request", "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		fatal("faucet request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		TxHash string `json:"tx_hash"`
		Error  string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if out.Error != "" {
			fatal("faucet: %s", out.Error)
		}
		fatal("faucet: HTTP %d", resp.StatusCode)
	}
	fmt.Printf("Requested testnet XUSD for %s\n", shortAddr(addr))
	if out.TxHash != "" {
		fmt.Printf("  Tx: %s\n", out.TxHash)
	}
}

// --- Mint ---

// cmdMint mints XUSD from the loaded wallet, which MUST be an authorized minter
// (sys.minter). Ops/bootstrap only. The block is built off the wallet's current
// frontier, signed, PoW'd, and submitted via POST /blocks/mint, where the ledger
// validator (validateAndAddMint) enforces minter authorization (#519).
func cmdMint(args []string) {
	initNetworkID()
	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	amount, err := core.ParseAmount(args[0], core.AssetXUSD)
	if err != nil || amount == 0 {
		if err != nil {
			fatal("invalid mint amount %q: %v", args[0], err)
		}
		fatal("mint amount must be greater than zero")
	}

	chain, _ := c.GetChain(addr)
	bals, _ := c.GetBalances(addr)
	prev := "0"
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}

	b := &core.Block{
		Type:      core.BlockMint,
		Account:   addr,
		Previous:  prev,
		Balance:   bals["XUSD"] + amount,
		Timestamp: time.Now().UnixNano(),
		Asset:     "XUSD",
		Amount:    amount,
	}
	if err := core.SignBlock(b, kp); err != nil {
		fatal("sign: %v", err)
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

	if err := c.SubmitBlock(b, "mint"); err != nil {
		fatal("mint: %v", err)
	}
	fmt.Printf("Minted %s XUSD\n", core.FormatAmount(amount, core.AssetXUSD))
	fmt.Printf("  Hash: %s\n", b.Hash)
	fmt.Printf("  New XUSD balance: %s\n", core.FormatAmount(bals["XUSD"]+amount, core.AssetXUSD))
}

// --- Burn ---

// cmdBurn permanently destroys XE from the caller's wallet. Burn is XE-only
// and irreversible; the user is prompted before submission unless --yes is
// passed. The block is signed locally, PoW-attached, then submitted via
// POST /blocks/burn — the ledger validator enforces XE-only at apply time.
func cmdBurn(args []string) {
	initNetworkID()
	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	amount, err := core.ParseAmount(args[0], core.AssetXE)
	if err != nil || amount == 0 {
		if err != nil {
			fatal("invalid burn amount %q: %v", args[0], err)
		}
		fatal("burn amount must be greater than zero")
	}
	skipConfirm := false
	memo := ""
	rest := args[1:]
	for i, a := range rest {
		if a == "--yes" || a == "-y" {
			skipConfirm = true
		}
		if a == "--memo" && i+1 < len(rest) {
			memo = rest[i+1]
		}
	}
	if err := core.ValidateMemo(memo); err != nil {
		fatal("invalid memo: %v", err)
	}

	bals, _ := c.GetBalances(addr)
	xeBal := bals["XE"]
	if xeBal < amount {
		fatal("insufficient XE: have %s, burning %s", core.FormatAmount(xeBal, core.AssetXE), core.FormatAmount(amount, core.AssetXE))
	}

	if !skipConfirm {
		fmt.Printf("This will permanently destroy %s XE from %s.\n", core.FormatAmount(amount, core.AssetXE), shortAddr(addr))
		fmt.Printf("New XE balance will be %s. This cannot be undone. Type 'yes' to confirm: ", core.FormatAmount(xeBal-amount, core.AssetXE))
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(strings.ToLower(resp)) != "yes" {
			fatal("aborted")
		}
	}

	chain, _ := c.GetChain(addr)
	prev := "0"
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}

	b := &core.Block{
		Type:      core.BlockBurn,
		Account:   addr,
		Previous:  prev,
		Balance:   xeBal - amount,
		Timestamp: time.Now().UnixNano(),
		Asset:     "XE",
		Amount:    amount,
		Memo:      memo,
	}
	if err := core.SignBlock(b, kp); err != nil {
		fatal("sign: %v", err)
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

	if err := c.SubmitBlock(b, "burn"); err != nil {
		fatal("submit: %v", err)
	}
	fmt.Printf("Burned %s XE\n", core.FormatAmount(amount, core.AssetXE))
	fmt.Printf("  Hash: %s\n", b.Hash)
	fmt.Printf("  New XE balance: %s\n", core.FormatAmount(xeBal-amount, core.AssetXE))
}

// --- Providers ---

func cmdProviders() {
	c := apiClient()
	providers, err := c.GetProviders()
	if err != nil || len(providers) == 0 {
		fmt.Println("No providers found.")
		return
	}

	for i, p := range providers {
		bals, _ := c.GetBalances(p.Account)
		free := client.ProviderInfo{
			VCPUs:    p.VCPUs - p.UsedVCPUs,
			MemoryMB: p.MemoryMB - p.UsedMemMB,
			DiskGB:   p.DiskGB - p.UsedDiskGB,
		}
		fmt.Printf("[%d] %s\n", i+1, shortAddr(p.Account))
		fmt.Printf("    Total: %d vCPU, %d MB, %d GB\n", p.VCPUs, p.MemoryMB, p.DiskGB)
		fmt.Printf("    Free:  %d vCPU, %d MB, %d GB\n", free.VCPUs, free.MemoryMB, free.DiskGB)
		fmt.Printf("    XUSD:  %s | Leases: %d active, %d total\n", core.FormatAmount(bals["XUSD"], core.AssetXUSD), p.Active, p.Total)
		fmt.Println()
	}
}

// --- Lease ---

// leaseArgs holds the parsed `xe lease` flags.
type leaseArgs struct {
	vcpus, memory, disk, duration uint64
	provider                      string
}

// uintFlag parses args[i] as a uint64, naming the flag in any error. The old
// fmt.Sscanf here discarded its return, so "--duration abc" silently kept the
// default and "--duration 60x" silently took the 60 (#809). It also indexed
// past the end when a flag was passed with no value.
func uintFlag(args []string, i int, name string) (uint64, error) {
	if i >= len(args) {
		return 0, fmt.Errorf("%s requires a value", name)
	}
	v, err := strconv.ParseUint(args[i], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: must be a non-negative integer", name, args[i])
	}
	return v, nil
}

// parseLeaseArgs parses and validates the `xe lease` flags. Validation happens
// here, before the wallet is loaded and long before the proof-of-work, so an
// out-of-range duration fails immediately instead of after a quote, a signature
// and a PoW solve (#809).
//
// The bounds are the compiled-in defaults. LeaseMinDuration is genesis-pinned
// (#524), so a client that has never loaded a genesis may check against
// different values than the network it is talking to — this check is a fast
// fail, and the node-side check in validateAndAddLease is authoritative.
func parseLeaseArgs(args []string) (leaseArgs, error) {
	la := leaseArgs{vcpus: 1, memory: 1024, disk: 1, duration: 300}
	for i := 0; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--vcpus":
			i++
			la.vcpus, err = uintFlag(args, i, "--vcpus")
		case "--memory":
			i++
			la.memory, err = uintFlag(args, i, "--memory")
		case "--disk":
			i++
			la.disk, err = uintFlag(args, i, "--disk")
		case "--duration":
			i++
			la.duration, err = uintFlag(args, i, "--duration")
		case "--provider":
			i++
			if i >= len(args) {
				err = fmt.Errorf("--provider requires a value")
			} else {
				la.provider = args[i]
			}
		}
		if err != nil {
			return leaseArgs{}, err
		}
	}
	if err := core.ValidateLeaseDimensions(la.vcpus, la.memory, la.disk, la.duration); err != nil {
		return leaseArgs{}, err
	}
	return la, nil
}

func cmdLease(args []string) {
	initNetworkID()

	la, err := parseLeaseArgs(args)
	if err != nil {
		fatal("%v", err)
	}
	vcpus, memory, disk, duration := la.vcpus, la.memory, la.disk, la.duration
	providerAddr := la.provider

	kp := loadWallet()
	addr := kp.Address()
	c := apiClient()

	// Find provider first, then fetch their cert to get the rate multiplier.
	if providerAddr == "" {
		// Pass a placeholder stake; we'll recompute after cost is known.
		providerAddr = pickProvider(c, vcpus, memory, disk, 1)
	}
	certData, err := c.GetCertificate(providerAddr)
	if err != nil || certData == nil || certData["hash"] == nil {
		fatal("provider %s has no active certificate", shortAddr(providerAddr))
	}
	certHash := fmt.Sprint(certData["hash"])
	var certMult uint64
	if v, ok := certData["price_multiplier_milli"].(float64); ok {
		certMult = uint64(v)
	}

	cost, err := core.LeaseCost(vcpus, memory, disk, duration, certMult)
	if err != nil {
		fatal("cost calculation: %v", err)
	}
	stake := core.LeaseStake(cost)

	fmt.Printf("Lease: %d vCPU, %d MB, %d GB, %ds (mult=%d)\n", vcpus, memory, disk, duration, certMult)
	fmt.Printf("Cost: %s XUSD, Stake: %s XUSD\n\n", core.FormatAmount(cost, core.AssetXUSD), core.FormatAmount(stake, core.AssetXUSD))

	bals, _ := c.GetBalances(addr)
	if bals["XUSD"] < cost {
		fatal("insufficient XUSD: have %s, need %s", core.FormatAmount(bals["XUSD"], core.AssetXUSD), core.FormatAmount(cost, core.AssetXUSD))
	}

	fmt.Printf("Provider: %s\n", shortAddr(providerAddr))

	// Generate SSH key
	sshPub, _ := generateSSHKey()
	accessPubKeyHex := hex.EncodeToString(sshPub)

	// Build lease block
	chain, _ := c.GetChain(addr)
	bals, _ = c.GetBalances(addr)
	prev := "0"
	if len(chain) > 0 {
		prev = chain[len(chain)-1].Hash
	}

	b := &core.Block{
		Type:            core.BlockLease,
		Account:         addr,
		Previous:        prev,
		Balance:         bals["XUSD"] - cost,
		Timestamp:       time.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     providerAddr,
		Amount:          cost,
		VCPUs:           vcpus,
		MemoryMB:        memory,
		DiskGB:          disk,
		Duration:        duration,
		AccessPubKey:    accessPubKeyHex,
		CertificateHash: certHash,
	}
	if err := core.SignBlock(b, kp); err != nil {
		fatal("sign: %v", err)
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

	// Submit to a node that isn't the provider
	submitURL := pickSubmitNode(c, providerAddr)
	submitClient := client.New(submitURL)
	if err := submitClient.SubmitBlock(b, "lease"); err != nil {
		fatal("submit: %v", err)
	}

	fmt.Printf("Lease submitted: %s\n", b.Hash)
	fmt.Println("Waiting for acceptance...")

	// Poll for acceptance
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		lease, _ := c.GetLease(b.Hash)
		if lease != nil {
			if st, ok := lease["start_time"].(float64); ok && st > 0 {
				fmt.Println("Lease accepted!")
				fmt.Printf("\n  xe vm %s\n  xe ssh %s\n", b.Hash, b.Hash)
				return
			}
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("WARNING: not accepted within 120s")
	fmt.Printf("  xe lease status %s\n", b.Hash)
}

func cmdLeaseStatus(hash string) {
	c := apiClient()
	lease, err := c.GetLease(hash)
	if err != nil || lease == nil || lease["error"] != nil {
		fatal("lease not found: %s", hash)
	}
	data, _ := json.MarshalIndent(lease, "", "  ")
	fmt.Println(string(data))
}

// --- Reputation ---

func cmdReputation(addr string) {
	c := apiClient()
	rep, err := c.GetReputation(addr)
	if err != nil {
		fatal("reputation: %v", err)
	}
	if rep == nil {
		fmt.Printf("no reputation activity for %s\n", addr)
		return
	}
	data, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(data))
}

// --- VM ---

func cmdVM(hash string) {
	c := apiClient()
	vm, err := c.GetVM(hash)
	if err != nil || vm == nil {
		fatal("VM not found for lease %s", hash)
	}
	data, _ := json.MarshalIndent(vm, "", "  ")
	fmt.Println(string(data))
}

// --- SSH ---

func cmdSSH(leaseHash string) {
	c := apiClient()

	// Check lease is active
	lease, _ := c.GetLease(leaseHash)
	if lease == nil {
		fatal("lease not found: %s", leaseHash)
	}
	if settled, _ := lease["settled"].(bool); settled {
		fatal("lease has settled — VM is no longer running")
	}

	// Convert lease key to OpenSSH PEM
	pemPath := sshPEMKeyPath()
	if _, err := os.Stat(pemPath); err != nil {
		seedPath := sshKeyPath()
		data, err := os.ReadFile(seedPath)
		if err != nil {
			fatal("no SSH key found at %s — run: xe lease", seedPath)
		}
		if err := convertKeyToOpenSSH(strings.TrimSpace(string(data)), pemPath); err != nil {
			fatal("convert key: %v", err)
		}
	}

	gwHost := os.Getenv("XE_SSH_HOST")
	if gwHost == "" {
		gwHost = "ldn.test.network"
	}
	gwPort := os.Getenv("XE_SSH_PORT")
	if gwPort == "" {
		gwPort = "2222"
	}

	proxyCmd := fmt.Sprintf("ssh -p %s -i %s -W %%h:%%p -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR %s@%s",
		gwPort, pemPath, leaseHash, gwHost)

	sshArgs := []string{
		"-o", "ProxyCommand=" + proxyCmd,
		"-i", pemPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"root@vm",
	}

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatal("ssh: %v", err)
	}
}

// --- Keygen ---

func cmdKeygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate: %v", err)
	}

	keyPath := "lease_key"
	if _, err := os.Stat(keyPath); err == nil {
		fatal("%s already exists (remove it first)", keyPath)
	}

	// Write OpenSSH PEM
	pemData, err := marshalOpenSSHKey(priv.Seed(), pub)
	if err != nil {
		fatal("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(pemData), 0600); err != nil {
		fatal("write key: %v", err)
	}

	fmt.Printf("Public key (hex): %s\n", hex.EncodeToString(pub))
	fmt.Printf("Private key: %s\n", keyPath)
}

// --- Sign Block ---

// resolveSignSeed reads the signing seed from the XE_SEED environment
// variable. #570/L7: a raw seed passed as argv is visible in `ps`,
// /proc/<pid>/cmdline, and shell history; the env var keeps it out of the
// process argument list. There is no argv form — a seed on the command line
// has already leaked by the time we see it, so it is rejected at the dispatch
// site rather than honoured. Returns the decoded 32-byte seed.
func resolveSignSeed() ([]byte, error) {
	seedHex := strings.TrimSpace(os.Getenv("XE_SEED"))
	if seedHex == "" {
		return nil, fmt.Errorf("no seed provided: set XE_SEED to the 32-byte hex seed")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("invalid seed hex")
	}
	return seed, nil
}

func cmdSignBlock() {
	initNetworkID()
	seed, err := resolveSignSeed()
	if err != nil {
		fatal("%v", err)
	}
	kp := core.KeyPairFromSeed(seed)

	var b core.Block
	if err := json.NewDecoder(os.Stdin).Decode(&b); err != nil {
		fatal("decode block: %v", err)
	}

	// The account field is always rewritten to the signer's address, so any
	// pub_key that came in on stdin is stale by construction. Clear it and let
	// SignBlock declare the signer's own key when this is an opening block —
	// otherwise a caller who pasted a pub_key from another account would get a
	// block that fails ValidatePubKeyDeclaration at every node (#829).
	b.Account = kp.Address()
	b.PubKey = ""
	if err := core.SignBlock(&b, kp); err != nil {
		fatal("sign: %v", err)
	}
	hashBytes, _ := hex.DecodeString(b.Hash)
	b.PoWNonce = core.ComputePoWConcurrent(hashBytes, core.DefaultDifficulty, runtime.NumCPU())

	_ = json.NewEncoder(os.Stdout).Encode(&b)
}

// --- Node ---

func cmdNode(args []string) {
	flags := flag.NewFlagSet("node", flag.ExitOnError)
	port := flags.Int("port", 9000, "P2P listen port")
	apiEnabled := flags.Bool("api", true, "Enable HTTP API server")
	apiPort := flags.Int("api-port", 8080, "HTTP API listen port")
	apiBind := flags.String("api-bind", "127.0.0.1", "HTTP API bind address")
	corsOrigin := flags.String("cors-origin", "", "Allowed CORS origin")
	uiEnabled := flags.Bool("ui", false, "Enable embedded web UI server")
	uiPort := flags.Int("ui-port", 8000, "Web UI listen port")
	uiBind := flags.String("ui-bind", "127.0.0.1", "Web UI bind address")
	uiDir := flags.String("ui-dir", "", "Serve web UI from this filesystem dir instead of the embedded FS (dev)")
	uiFaucet := flags.String("ui-faucet", "", "Base URL of the external faucet service; /faucet/* in the UI is proxied to it (empty = faucet disabled)")
	walletEnabled := flags.Bool("wallet", true, "Expose /wallet/ in the embedded UI; --wallet=false serves 404 for /wallet/*")
	dial := flags.String("dial", "", "Comma-separated bootstrap peer multiaddrs")
	data := flags.String("data", "./data", "Data directory")
	provide := flags.Bool("provide", false, "Enable compute provider mode")
	provVCPUs := flags.Uint64("vcpus", 2, "Provider vCPUs")
	provMemory := flags.Uint64("memory", 2048, "Provider memory (MB)")
	provDisk := flags.Uint64("disk", 20, "Provider disk (GB)")
	provPriceMult := flags.Uint64("price-multiplier", 1000, "Provider price multiplier ×1000 (1000=baseline, 2500=2.5×). Sim-only per #297; non-1000 values require anti-cheat gates before production use.")
	provMinDur := flags.String("min-lease-duration", "", "Reject leases shorter than this (e.g. 1h, 24h). Empty = no min. (#229)")
	provMaxDur := flags.String("max-lease-duration", "", "Reject leases longer than this (e.g. 720h = 30d). Empty = no max. (#229)")
	provMinCost := flags.Uint64("min-lease-cost", 0, "Reject leases below this cost in whole XUSD. 0 = no min. (#229)")
	provMaxCost := flags.Uint64("max-lease-cost", 0, "Reject leases above this cost in whole XUSD. 0 = no max. (#229)")
	provMaxConcurrent := flags.Uint64("max-concurrent-leases", 0, "Cap on active leases (running + provisioning). 0 = bounded only by resource capacity. (#229)")
	sshPort := flags.Int("ssh-port", 0, "SSH gateway port (0 = disabled)")
	limactlPath := flags.String("limactl-path", "", "Path to limactl binary")
	maxConnsPerIP := flags.Int("max-conns-per-ip", 8, "Max inbound connections per source IP (raise for multi-node-per-host setups)")
	maxInboundConns := flags.Int("max-inbound-conns", 0, "Max simultaneous inbound connections, reserving the rest of the connection budget for peers this node dials. 0 = default (256), negative = no split (#840)")
	noDiscovery := flags.Bool("no-discovery", false, "Disable ambient DHT peer discovery. A node with this set only ever peers with its -dial list (#840)")
	discoveryTarget := flags.Int("discovery-peers", 0, "Peer count at or above which ambient discovery stops dialling. 0 = default (24)")
	// Observability (#841).
	metricsAddr := flags.String("metrics-addr", "127.0.0.1:9095", "Operator listener for /metrics, /health and /ready. Loopback by default; empty disables it")
	logLevel := flags.String("log-level", "info", "Log level: debug|info|warn|error")
	logFile := flags.String("log-file", "", "Write logs to this size-bounded rotating file instead of stderr (empty = stderr)")
	logMaxSize := flags.Int("log-max-size", logging.DefaultMaxSizeMB, "Max size in MB of one log file before rotation")
	logMaxFiles := flags.Int("log-max-files", logging.DefaultMaxFiles, "Rotated log files retained beside the live one")
	logJSON := flags.Bool("log-json", false, "Emit logs as JSON instead of text")
	minPeers := flags.Int("ready-min-peers", 1, "Connected-peer floor below which /ready reports not ready")
	finalityStall := flags.Duration("ready-finality-stall", 90*time.Second, "How long the final-height watermark may stay flat, with a backlog present, before /ready reports not ready")
	noMDNS := flags.Bool("disable-mdns", false, "Disable mDNS LAN peer discovery. Peers found this way are whatever else is on the broadcast domain — fine at home, wrong on a shared network, and nondeterministic in tests.")
	genesisDir := flags.String("genesis-dir", "", "Directory holding "+node.LedgerGenesisFile+" and "+node.StateChainGenesisFile+"; joins that network without a rebuild (#733)")
	genesisFile := flags.String("genesis", "", "Path to the ledger genesis JSON (use with --statechain-genesis; default = embedded)")
	scGenesisFile := flags.String("statechain-genesis", "", "Path to the statechain genesis JSON (use with --genesis; default = embedded)")
	_ = flags.Parse(args)

	// Configure logging FIRST: this both levels and size-bounds every log line
	// in the process, including the standard-library calls that have not been
	// converted yet.
	logCloser, err := logging.Init(logging.Config{
		Level:     *logLevel,
		File:      *logFile,
		MaxSizeMB: *logMaxSize,
		MaxFiles:  *logMaxFiles,
		JSON:      *logJSON,
	})
	if err != nil {
		// Before Init succeeds there is no configured logger, so this one call
		// deliberately stays on the standard library.
		log.Fatalf("logging: %v", err)
	}
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}

	// Install the runtime genesis BEFORE anything reads it (#733/#839): the
	// statechain genesis carries sys.network_id, which is bound into every
	// block hash, and the ledger genesis is read the first time a Ledger opens.
	// After logging.Init, so a bad genesis path is reported through the same
	// configured logger as everything else.
	if err := node.ApplyGenesisOverride(node.GenesisPaths{
		Ledger:     *genesisFile,
		StateChain: *scGenesisFile,
		Dir:        *genesisDir,
	}); err != nil {
		logging.Fatalf("genesis: %v", err)
	}

	policy := node.LeaseAcceptPolicy{
		MinCostXUSD:   *provMinCost,
		MaxCostXUSD:   *provMaxCost,
		MaxConcurrent: *provMaxConcurrent,
	}
	if *provMinDur != "" {
		d, err := time.ParseDuration(*provMinDur)
		if err != nil {
			logging.Fatalf("--min-lease-duration: %v", err)
		}
		if d <= 0 {
			logging.Fatalf("--min-lease-duration must be positive, got %s", *provMinDur)
		}
		policy.MinDurationSec = uint64(d / time.Second)
	}
	if *provMaxDur != "" {
		d, err := time.ParseDuration(*provMaxDur)
		if err != nil {
			logging.Fatalf("--max-lease-duration: %v", err)
		}
		if d <= 0 {
			logging.Fatalf("--max-lease-duration must be positive, got %s", *provMaxDur)
		}
		policy.MaxDurationSec = uint64(d / time.Second)
	}
	if err := policy.Validate(); err != nil {
		logging.Fatalf("invalid auto-accept policy: %v", err)
	}

	if *uiEnabled && !*apiEnabled {
		logging.Fatalf("--ui requires --api (the UI proxies /api/* to the API server)")
	}

	logging.Infof("xe %s", version)

	var dialAddrs []string
	if *dial != "" {
		dialAddrs = strings.Split(*dial, ",")
	}

	ctx := context.Background()
	n, err := node.New(ctx, node.Config{
		Port:                 *port,
		DialAddrs:            dialAddrs,
		DataDir:              *data,
		Difficulty:           core.DefaultDifficulty,
		Version:              version,
		Provide:              *provide,
		VCPUs:                *provVCPUs,
		MemoryMB:             *provMemory,
		DiskGB:               *provDisk,
		PriceMultiplierMilli: *provPriceMult,
		AcceptPolicy:         policy,
		LimactlPath:          *limactlPath,
		MaxConnsPerIP:        *maxConnsPerIP,
		MaxInboundConns:      *maxInboundConns,
		DisableDiscovery:     *noDiscovery,
		DiscoveryTarget:      *discoveryTarget,
		DisableMDNS:          *noMDNS,
	})
	if err != nil {
		logging.Fatalf("failed to start node: %v", err)
	}
	defer n.Stop()

	if *sshPort > 0 {
		sshAddr := fmt.Sprintf("0.0.0.0:%d", *sshPort)
		gw, err := node.NewSSHGateway(sshAddr, *data, n)
		if err != nil {
			logging.Fatalf("ssh gateway: %v", err)
		}
		gw.Start()
		defer gw.Stop()
		logging.Infof("SSH gateway listening on %s", gw.Addr())
	}

	// Observability sampler: the source behind /metrics, /health and /ready.
	// Started before the API so the first probe has a real sample to answer
	// with rather than an unexplained empty body.
	role := "node"
	if *provide {
		role = "provider"
	}
	observer := n.StartObservability(node.ObsConfig{
		MinPeers:               *minPeers,
		FinalityStallThreshold: *finalityStall,
		DataDir:                *data,
		Role:                   role,
	})

	var apiSrv *http.Server
	if *apiEnabled {
		apiAddr := fmt.Sprintf("%s:%d", *apiBind, *apiPort)
		h := api.NewHandler(n)
		h.SetObserver(observer)
		if *corsOrigin != "" {
			h.SetCORSOrigin(*corsOrigin)
		}
		// Operator-only endpoints (spend/sign as the node) stay disabled
		// unless an admin token is configured (#570/C4).
		h.SetAdminToken(os.Getenv("XE_API_ADMIN_TOKEN"))
		apiSrv = &http.Server{
			Addr:              apiAddr,
			Handler:           h.Mux(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = apiSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			logging.Infof("API listening on %s", apiAddr)
			if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Errorf("API server error: %v", err)
			}
		}()
	}

	var opsSrv *http.Server
	if *metricsAddr != "" {
		opsHandler := api.NewHandler(n)
		opsHandler.SetObserver(observer)
		opsSrv = &http.Server{
			Addr:              *metricsAddr,
			Handler:           api.OpsMux(opsHandler),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = opsSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			logging.Infof("ops listener on %s (/metrics, /health, /ready)", *metricsAddr)
			if err := opsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Errorf("ops server error: %v", err)
			}
		}()
	}

	var uiSrv *http.Server
	if *uiEnabled {
		var fsys iofs.FS
		if *uiDir != "" {
			fsys = os.DirFS(*uiDir)
			log.Printf("UI serving from %s (--ui-dir)", *uiDir)
		} else {
			fsys = web.FS
		}
		// API target — if API is bound to 0.0.0.0, dial it via loopback
		// rather than the wildcard.
		apiHost := *apiBind
		if apiHost == "0.0.0.0" || apiHost == "::" {
			apiHost = "127.0.0.1"
		}
		apiTarget := fmt.Sprintf("http://%s:%d", apiHost, *apiPort)
		uiHandler, err := api.NewUIHandler(fsys, api.UIConfig{
			APITarget:     apiTarget,
			WalletEnabled: *walletEnabled,
			FaucetTarget:  *uiFaucet,
		})
		if err != nil {
			logging.Fatalf("UI handler: %v", err)
		}
		uiAddr := fmt.Sprintf("%s:%d", *uiBind, *uiPort)
		uiSrv = &http.Server{
			Addr:              uiAddr,
			Handler:           uiHandler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = uiSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			walletNote := "wallet enabled"
			if !*walletEnabled {
				walletNote = "wallet disabled"
			}
			log.Printf("UI listening on %s (proxying /api/* to %s, %s)", uiAddr, apiTarget, walletNote)
			if err := uiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logging.Errorf("UI server error: %v", err)
			}
		}()
	}

	fmt.Printf("Node started on port %d\n", *port)
	if *apiEnabled {
		fmt.Printf("API listening on port %d\n", *apiPort)
	}
	if *uiEnabled {
		fmt.Printf("UI listening on port %d\n", *uiPort)
	}
	// Address is the node's ledger account; the public key is the identity its
	// votes, attestations and directory registration are verified against. They
	// are different values since #829 — print both so operators reading logs
	// can tell which one a peer is quoting.
	fmt.Printf("Address:    %s\n", n.Address())
	fmt.Printf("Public key: %s\n", n.KeyPair.PubKeyHex())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	logging.Debugf("Waiting for signal...")
	sig := <-sigCh
	fmt.Printf("\nReceived %s, shutting down...\n", sig)
}

// --- Helpers ---

// sshKeyPath returns the SSH key path derived from the wallet path.
// Each wallet gets its own SSH key (e.g., ~/.xe/wallet.lease_key).
func sshKeyPath() string {
	wp := walletPath()
	dir := filepath.Dir(wp)
	base := strings.TrimSuffix(filepath.Base(wp), filepath.Ext(wp))
	return filepath.Join(dir, base+".lease_key")
}

func sshPEMKeyPath() string {
	return sshKeyPath() + "_openssh"
}

func generateSSHKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	keyPath := sshKeyPath()
	if data, err := os.ReadFile(keyPath); err == nil {
		seedHex := strings.TrimSpace(string(data))
		seed, err := hex.DecodeString(seedHex)
		if err == nil && len(seed) == ed25519.SeedSize {
			priv := ed25519.NewKeyFromSeed(seed)
			return priv.Public().(ed25519.PublicKey), priv
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate ssh key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		fatal("create key dir: %v", err)
	}
	seedHex := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(keyPath, []byte(seedHex+"\n"), 0600); err != nil {
		fatal("write ssh key: %v", err)
	}
	fmt.Printf("SSH key created: %s\n", keyPath)
	return pub, priv
}

func convertKeyToOpenSSH(seedHex, outPath string) error {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("invalid seed hex")
	}

	// Derive pubkey via openssl
	pubkey, err := deriveED25519PubkeyViaOpenSSL(seed)
	if err != nil {
		return err
	}

	pem, err := marshalOpenSSHKey(seed, pubkey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(pem), 0600)
}

func deriveED25519PubkeyViaOpenSSL(seed []byte) (ed25519.PublicKey, error) {
	// Build PKCS8 DER: fixed prefix for ed25519 + seed
	prefix, _ := hex.DecodeString("302e020100300506032b657004220420")
	der := append(prefix, seed...)

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "xe-key-*.pem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	pem := "-----BEGIN PRIVATE KEY-----\n"
	pem += encodeBase64Lines(der)
	pem += "-----END PRIVATE KEY-----\n"
	_, _ = tmpFile.WriteString(pem)
	_ = tmpFile.Close()
	_ = os.Chmod(tmpFile.Name(), 0600)

	cmd := exec.Command("openssl", "pkey", "-in", tmpFile.Name(), "-pubout", "-outform", "DER")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("openssl: %v", err)
	}
	if len(out) < 44 {
		return nil, fmt.Errorf("unexpected openssl output length: %d", len(out))
	}
	return ed25519.PublicKey(out[12:]), nil
}

func marshalOpenSSHKey(seed []byte, pubkey ed25519.PublicKey) (string, error) {
	sStr := func(data []byte) []byte {
		l := uint32(len(data))
		return append([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}, data...)
	}

	pubBlob := append(sStr([]byte("ssh-ed25519")), sStr(pubkey)...)

	check := uint32(time.Now().UnixNano() & math.MaxUint32)
	priv := []byte{byte(check >> 24), byte(check >> 16), byte(check >> 8), byte(check)}
	priv = append(priv, priv[:4]...) // repeat check
	priv = append(priv, sStr([]byte("ssh-ed25519"))...)
	priv = append(priv, sStr(pubkey)...)
	priv = append(priv, sStr(append(seed, pubkey...))...)
	priv = append(priv, sStr([]byte{})...) // empty comment

	// Pad to 8-byte boundary
	pad := 8 - (len(priv) % 8)
	if pad < 8 {
		for i := 1; i <= pad; i++ {
			priv = append(priv, byte(i))
		}
	}

	buf := []byte("openssh-key-v1\x00")
	buf = append(buf, sStr([]byte("none"))...)
	buf = append(buf, sStr([]byte("none"))...)
	buf = append(buf, sStr([]byte{})...)
	numKeys := []byte{0, 0, 0, 1}
	buf = append(buf, numKeys...)
	buf = append(buf, sStr(pubBlob)...)
	buf = append(buf, sStr(priv)...)

	b64 := encodeBase64Lines(buf)
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + b64 + "-----END OPENSSH PRIVATE KEY-----\n", nil
}

func encodeBase64Lines(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var lines []string
	for i := 0; i < len(encoded); i += 70 {
		end := i + 70
		if end > len(encoded) {
			end = len(encoded)
		}
		lines = append(lines, encoded[i:end])
	}
	return strings.Join(lines, "\n") + "\n"
}

func pickProvider(c *client.Client, vcpus, memoryMB, diskGB, stake uint64) string {
	providers, _ := c.GetProviders()
	if len(providers) == 0 {
		fatal("no providers found")
	}

	var best *client.ProviderInfo
	var bestXUSD uint64
	for i := range providers {
		p := &providers[i]
		if p.VCPUs-p.UsedVCPUs < vcpus || p.MemoryMB-p.UsedMemMB < memoryMB || p.DiskGB-p.UsedDiskGB < diskGB {
			continue
		}
		bals, _ := c.GetBalances(p.Account)
		if bals["XUSD"] >= stake && bals["XUSD"] > bestXUSD {
			best = p
			bestXUSD = bals["XUSD"]
		}
	}
	if best == nil {
		fatal("no provider with sufficient resources and stake")
	}
	return best.Account
}

func pickSubmitNode(c *client.Client, providerAddr string) string {
	allNodes := []string{
		"https://ldn.core.test.network",
		"https://ffm.core.test.network",
		"https://nyc.core.test.network",
	}
	for _, n := range allNodes {
		nc := client.New(n)
		info, err := nc.NodeInfo()
		if err != nil {
			continue
		}
		if addr, ok := info["address"].(string); ok && addr != providerAddr {
			return n
		}
	}
	return nodeURL()
}

func shortAddr(addr string) string {
	if len(addr) > 16 {
		return addr[:8] + "..." + addr[len(addr)-8:]
	}
	return addr
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

// --- verify-genesis ---

// cmdVerifyGenesis reports the chain start this binary will use, so an
// operator can confirm it against the published values BEFORE starting a node
// and BEFORE trusting a downloaded binary (#839 AC5). It touches no data dir
// and opens no network connection.
func cmdVerifyGenesis(args []string) {
	flags := flag.NewFlagSet("verify-genesis", flag.ExitOnError)
	genesisDir := flags.String("genesis-dir", "", "Verify the genesis pair in this directory instead of the embedded one")
	genesisFile := flags.String("genesis", "", "Path to a ledger genesis JSON (use with --statechain-genesis)")
	scGenesisFile := flags.String("statechain-genesis", "", "Path to a statechain genesis JSON (use with --genesis)")
	asJSON := flags.Bool("json", false, "Emit JSON instead of a human-readable summary")
	expectNetwork := flags.String("expect-network-id", "", "Exit non-zero unless the effective network_id equals this")
	expectSC := flags.String("expect-statechain-hash", "", "Exit non-zero unless the effective statechain genesis hash equals this")
	expectLedger := flags.String("expect-ledger-hash", "", "Exit non-zero unless the effective ledger genesis hash equals this")
	_ = flags.Parse(args)

	if err := node.ApplyGenesisOverride(node.GenesisPaths{
		Ledger:     *genesisFile,
		StateChain: *scGenesisFile,
		Dir:        *genesisDir,
	}); err != nil {
		fatal("genesis: %v", err)
	}

	summary, err := node.DescribeGenesis()
	if err != nil {
		fatal("genesis: %v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		fmt.Printf("xe %s\n", version)
		fmt.Printf("network_id                %s\n", summary.NetworkID)
		fmt.Printf("statechain genesis hash   %s\n", summary.StateChainHash)
		fmt.Printf("ledger genesis hash       %s\n", summary.LedgerGenesisHash)
		fmt.Printf("ledger genesis treasury   %s\n", summary.LedgerGenesisAcct)
		fmt.Printf("genesis representative    %s\n", yesNo(summary.RepresentativeIsSet))
		fmt.Printf("source                    %s\n", genesisSource(summary.Overridden))
		if summary.Overridden {
			fmt.Printf("\nembedded in this binary:\n")
			fmt.Printf("  network_id              %s\n", summary.EmbeddedNetworkID)
			fmt.Printf("  statechain genesis hash %s\n", summary.EmbeddedStateHash)
			fmt.Printf("  ledger genesis hash     %s\n", summary.EmbeddedLedgerHash)
		}
		if !summary.RepresentativeIsSet {
			// A genesis with no representative delegates zero vote weight, and
			// zero total weight is silent finality death: blocks commit,
			// nothing ever finalizes, and every health check reports green
			// (#828, core/quorum.go).
			fmt.Printf("\nWARNING: this genesis sets no representative — total delegated weight starts\n")
			fmt.Printf("         at zero, so nothing can finalize until an account delegates.\n")
		}
	}

	failed := false
	for _, c := range []struct{ flag, want, got string }{
		{"--expect-network-id", *expectNetwork, summary.NetworkID},
		{"--expect-statechain-hash", *expectSC, summary.StateChainHash},
		{"--expect-ledger-hash", *expectLedger, summary.LedgerGenesisHash},
	} {
		if c.want != "" && c.want != c.got {
			fmt.Fprintf(os.Stderr, "MISMATCH %s: expected %s, got %s\n", c.flag, c.want, c.got)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func yesNo(b bool) string {
	if b {
		return "set"
	}
	return "NOT SET"
}

func genesisSource(overridden bool) string {
	if overridden {
		return "runtime (--genesis-dir/--genesis)"
	}
	return "embedded in binary"
}
