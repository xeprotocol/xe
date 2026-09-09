package node

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/statechain"
)

const (
	LedgerGenesisFile     = "ledger-genesis.json"
	StateChainGenesisFile = "statechain-genesis.json"
)

type GenesisPaths struct {
	Ledger     string
	StateChain string
	Dir        string
}

func (p GenesisPaths) Resolve() (ledger, statechain string, err error) {
	if p.Dir != "" {
		if p.Ledger != "" || p.StateChain != "" {
			return "", "", fmt.Errorf("--genesis-dir cannot be combined with --genesis or --statechain-genesis")
		}
		info, serr := os.Stat(p.Dir)
		if serr != nil {
			return "", "", fmt.Errorf("--genesis-dir %s: %w", p.Dir, serr)
		}
		if !info.IsDir() {
			return "", "", fmt.Errorf("--genesis-dir %s is not a directory", p.Dir)
		}
		return filepath.Join(p.Dir, LedgerGenesisFile), filepath.Join(p.Dir, StateChainGenesisFile), nil
	}

	if (p.Ledger == "") != (p.StateChain == "") {
		return "", "", fmt.Errorf("--genesis and --statechain-genesis must be supplied together (or use --genesis-dir)")
	}
	return p.Ledger, p.StateChain, nil
}

func ApplyGenesisOverride(p GenesisPaths) error {
	ledgerPath, scPath, err := p.Resolve()
	if err != nil {
		return err
	}
	if ledgerPath == "" && scPath == "" {
		return nil
	}

	ledgerRaw, err := os.ReadFile(ledgerPath)
	if err != nil {
		return fmt.Errorf("read ledger genesis: %w", err)
	}
	scRaw, err := os.ReadFile(scPath)
	if err != nil {
		return fmt.Errorf("read statechain genesis: %w", err)
	}

	scBlock, err := statechain.ParseGenesis(scRaw)
	if err != nil {
		return fmt.Errorf("%s: %w", scPath, err)
	}
	networkID := statechain.NetworkIDFromGenesis(scBlock)
	if networkID == "" {
		return fmt.Errorf("%s: genesis sets no sys.network_id — a node built on it would answer every netcheck handshake with an empty network id and be banned by every peer", scPath)
	}

	if err := core.SetGenesisJSON(ledgerRaw); err != nil {
		return fmt.Errorf("%s: %w", ledgerPath, err)
	}
	if err := statechain.SetGenesisJSON(scRaw); err != nil {

		core.ClearGenesisOverride()
		return fmt.Errorf("%s: %w", scPath, err)
	}

	ledgerBlock, err := core.ParseGenesisDocument(core.GenesisJSON())
	if err != nil {
		core.ClearGenesisOverride()
		statechain.ClearGenesisOverride()
		return fmt.Errorf("%s: %w", ledgerPath, err)
	}

	log.Printf("Genesis: runtime override active (network_id=%s)", networkID)
	log.Printf("Genesis: ledger     %s  hash=%s", ledgerPath, ledgerBlock.Hash)
	log.Printf("Genesis: statechain %s  hash=%s", scPath, scBlock.Hash)
	return nil
}

type GenesisSummary struct {
	NetworkID           string `json:"network_id"`
	LedgerGenesisHash   string `json:"ledger_genesis_hash"`
	LedgerGenesisAcct   string `json:"ledger_genesis_account"`
	StateChainHash      string `json:"statechain_genesis_hash"`
	Overridden          bool   `json:"overridden"`
	EmbeddedNetworkID   string `json:"embedded_network_id"`
	EmbeddedLedgerHash  string `json:"embedded_ledger_genesis_hash"`
	EmbeddedStateHash   string `json:"embedded_statechain_genesis_hash"`
	RepresentativeIsSet bool   `json:"genesis_representative_set"`
}

func DescribeGenesis() (*GenesisSummary, error) {

	ledger, err := core.ParseGenesisDocument(core.GenesisJSON())
	if err != nil {
		return nil, fmt.Errorf("ledger genesis: %w", err)
	}
	sc, err := statechain.LoadGenesis()
	if err != nil {
		return nil, fmt.Errorf("statechain genesis: %w", err)
	}
	embLedger, err := core.ParseGenesisDocument(core.EmbeddedGenesisJSON())
	if err != nil {
		return nil, fmt.Errorf("embedded ledger genesis: %w", err)
	}
	embSC, err := statechain.ParseGenesis(statechain.EmbeddedGenesisJSON())
	if err != nil {
		return nil, fmt.Errorf("embedded statechain genesis: %w", err)
	}
	return &GenesisSummary{
		NetworkID:           statechain.NetworkIDFromGenesis(sc),
		LedgerGenesisHash:   ledger.Hash,
		LedgerGenesisAcct:   ledger.Account,
		StateChainHash:      sc.Hash,
		Overridden:          ledger.Hash != embLedger.Hash || sc.Hash != embSC.Hash,
		EmbeddedNetworkID:   statechain.NetworkIDFromGenesis(embSC),
		EmbeddedLedgerHash:  embLedger.Hash,
		EmbeddedStateHash:   embSC.Hash,
		RepresentativeIsSet: ledger.Representative != "",
	}, nil
}

func preflightDataDirGenesis(s core.Store, dataDir string) error {
	empty, err := s.IsEmpty()
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if empty {
		return nil
	}

	want, err := core.ParseGenesisDocument(core.GenesisJSON())
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	chain, err := s.GetAccountChain(want.Account)
	if err != nil {
		return fmt.Errorf("store: read persisted genesis: %w", err)
	}
	if chain != nil && len(chain.Blocks) > 0 && chain.Blocks[0].Hash == want.Hash {
		return nil
	}

	got := "not found"
	if chain != nil && len(chain.Blocks) > 0 {
		got = chain.Blocks[0].Hash
	} else if found := findPersistedGenesis(s); found != nil {
		got = fmt.Sprintf("%s (treasury %s)", found.Hash, found.Account)
	}

	return fmt.Errorf(`genesis mismatch: this data dir belongs to a different network

  data dir            %s
  configured genesis  %s (treasury %s)
  persisted genesis   %s

The ledger in this data dir was bootstrapped from a different genesis block, so
it cannot be replayed under the configured one. Either:
  - point the node at the matching genesis:  --genesis-dir <archive>
  - or start a fresh node on this network:   rm -rf %s`,
		dataDir, want.Hash, want.Account, got, dataDir)
}

func findPersistedGenesis(s core.Store) *core.Block {
	lister, ok := s.(core.FrontierLister)
	if !ok {
		return nil
	}
	for acct := range lister.AllFrontiers() {
		chain, err := s.GetAccountChain(acct)
		if err != nil || chain == nil || len(chain.Blocks) == 0 {
			continue
		}
		if b := chain.Blocks[0]; b.Type == core.BlockGenesis {
			return b
		}
	}
	return nil
}

const joinDiagnosticInterval = 60 * time.Second

func (n *Node) joinDiagnosticLoop() {
	ticker := time.NewTicker(joinDiagnosticInterval)
	defer ticker.Stop()
	var warned bool
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			if len(n.Host.Network().Peers()) > 0 {
				warned = false
				continue
			}
			if n.gater == nil {
				continue
			}
			last, rejected, aborted := n.gater.LastMismatch()
			if rejected == 0 && aborted == 0 {

				continue
			}
			if warned {
				continue
			}
			warned = true
			n.logJoinFailure(last, rejected, aborted)
		}
	}
}

func (n *Node) logJoinFailure(last *xenet.NetworkMismatch, rejected, aborted int) {
	summary, err := DescribeGenesis()
	ours := "unknown"
	genesis := "unknown"
	if err == nil {
		ours = summary.NetworkID
		genesis = summary.StateChainHash
	}

	var theirs string
	if last != nil {

		theirs = fmt.Sprintf("\n  peer %s reported  network_id=%q genesis=%s\n  rejection reason   %s",
			last.Peer, last.TheirNetworkID, orNone(last.TheirGenesisHash), last.Reason)
	} else {
		theirs = "\n  (every peer closed the handshake before identifying itself — that is what a\n   remote-side network_id rejection looks like from this end)"
	}

	log.Printf(`
=====================================================================
CANNOT JOIN NETWORK — no peers, %d handshake(s) rejected, %d aborted
=====================================================================
  this node is on   network_id=%q genesis=%s%s

  This node's identity comes from its statechain genesis. If the values above
  disagree with the network you meant to join, the binary is running the wrong
  genesis — rebuild is NOT required:

      xe node --genesis-dir /path/to/genesis-archive ...

  Published network_id, genesis hashes and bootstrap multiaddrs:
      docs/run-a-node.md
  Confirm what this binary is running:
      xe verify-genesis
=====================================================================`,
		rejected, aborted, ours, genesis, theirs)
}

func orNone(s string) string {
	if s == "" {
		return "(not advertised)"
	}
	return strconv.Quote(s)
}
