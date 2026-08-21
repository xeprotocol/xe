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

// Conventional filenames inside a genesis directory. These match the layout
// wipe.sh archives, so `--genesis-dir <archive>` is a straight pointer at an
// archived network rather than a two-flag transcription exercise.
const (
	LedgerGenesisFile     = "ledger-genesis.json"
	StateChainGenesisFile = "statechain-genesis.json"
)

// GenesisPaths names the runtime genesis documents a node was pointed at.
// The zero value means "use the genesis compiled into the binary".
type GenesisPaths struct {
	Ledger     string // --genesis
	StateChain string // --statechain-genesis
	Dir        string // --genesis-dir (supplies both, by convention)
}

// Resolve expands Dir into the two concrete paths and rejects contradictory
// combinations. Returns the effective pair.
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
	// A half-specified pair is almost always an operator mistake: the two
	// documents describe one network and mixing a supplied ledger genesis with
	// the embedded statechain genesis (or vice versa) produces a node that
	// cannot join anything. Fail here rather than at the first failed handshake.
	if (p.Ledger == "") != (p.StateChain == "") {
		return "", "", fmt.Errorf("--genesis and --statechain-genesis must be supplied together (or use --genesis-dir)")
	}
	return p.Ledger, p.StateChain, nil
}

// ApplyGenesisOverride installs runtime genesis documents for this process,
// replacing the go:embed defaults (#733, #839). It is a no-op when no paths
// are given, so an unflagged binary keeps its embedded genesis exactly as
// before.
//
// MUST be called before node.New: the statechain genesis carries
// sys.network_id, which is bound into every ledger block hash, and the ledger
// genesis is read the first time a Ledger is opened.
//
// Both documents are validated before either is installed, so a typo in the
// second file cannot leave the process running a half-swapped identity.
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

	// Validate BOTH before installing EITHER.
	scBlock, err := statechain.ParseGenesis(scRaw)
	if err != nil {
		return fmt.Errorf("%s: %w", scPath, err)
	}
	networkID := statechain.NetworkIDFromGenesis(scBlock)
	if networkID == "" {
		return fmt.Errorf("%s: genesis sets no sys.network_id — a node built on it would answer every netcheck handshake with an empty network id and be banned by every peer (#652)", scPath)
	}

	// The ledger genesis hash is computed with an EMPTY network prefix
	// (ValidateGenesisBlock clears it), so validation order does not depend on
	// the network id being installed first. core.SetGenesisJSON validates.
	if err := core.SetGenesisJSON(ledgerRaw); err != nil {
		return fmt.Errorf("%s: %w", ledgerPath, err)
	}
	if err := statechain.SetGenesisJSON(scRaw); err != nil {
		// Roll the ledger genesis back so a failure here leaves the process on
		// the embedded pair rather than a mixed one.
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

// GenesisSummary describes the genesis pair a process is running with. Used by
// the startup banner and by `xe verify-genesis`.
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

// DescribeGenesis reports the effective genesis pair alongside the pair
// compiled into the binary, so an operator can see at a glance whether the
// node is running the embedded network or one supplied at runtime.
func DescribeGenesis() (*GenesisSummary, error) {
	// ParseGenesisDocument, NOT LoadGenesisBlock: LoadGenesisBlock calls
	// ApplyGenesisLeaseTiming, which writes six unguarded package vars
	// (core/ledger.go:289). DescribeGenesis is called from the join watchdog
	// goroutine while consensus is live, so going through LoadGenesisBlock
	// would race those writes against every reader — with identical values,
	// but a race is a race and -race would be right to flag it.
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

// preflightDataDirGenesis refuses to boot when a non-empty data dir was built
// under a different genesis than the one this process is configured with.
//
// Without it the failure surfaced as a bare panic from deep inside NewLedger
// ("persisted genesis chain for <addr> is missing on restart") which names
// neither the genesis the operator supplied nor the remedy. Genesis identity
// is exactly the mistake `--genesis` makes easy to make, so the check pays for
// itself the first time someone points a node at the wrong archive.
func preflightDataDirGenesis(s core.Store, dataDir string) error {
	empty, err := s.IsEmpty()
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if empty {
		return nil
	}
	// Side-effect-free read (see DescribeGenesis): NewLedger applies the
	// genesis lease timing itself, immediately after this check.
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

// findPersistedGenesis scans account frontiers for the stored genesis block.
// Only runs on the mismatch path, so its cost never touches a healthy boot.
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

// joinDiagnosticInterval is how often the join watchdog re-checks. Deliberately
// slower than the 30s bootstrap watchdog so a node that is merely slow to
// connect gets a couple of dial rounds before anything is said.
const joinDiagnosticInterval = 60 * time.Second

// joinDiagnosticLoop turns "this node has no peers" into a statement of WHY.
//
// A node built against the wrong genesis fails by silence today: every
// handshake is refused, peer_count stays 0, sync never starts, and the only
// artefact is a "connection reset by peer" from the remote hanging up first
// (#839). Nothing on the node ever says "you are on the wrong network" — the
// operator has to know to compare genesis hashes by hand.
//
// This loop runs only while the node has zero peers. Once it has any peer it
// stops complaining, so a healthy node never sees it.
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
				// No completed or refused handshakes at all: the bootstrap
				// addresses are unreachable, not disagreeing with us. The
				// bootstrap watchdog already logs each failed dial.
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
		// Remote-supplied strings are quoted (%q) on their way into the log:
		// they are attacker-controlled and an unescaped newline forges log lines.
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
