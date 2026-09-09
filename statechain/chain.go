package statechain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var ErrGap = errors.New("statechain gap")

type Chain struct {
	mu           sync.Mutex
	store        StateChainStore
	kv           *KVStore
	tip          *Block
	genesis      *Block
	onBlock      func(*Block)
	forkCallback func(existing, incoming *Block)

	gapSyncMu   sync.Mutex
	lastGapSync time.Time
}

func NewChain(store StateChainStore, genesis *Block) (*Chain, error) {
	if err := ValidateGenesis(genesis); err != nil {
		return nil, fmt.Errorf("NewChain: %w", err)
	}
	c := &Chain{
		store:   store,
		kv:      NewKVStore(),
		genesis: genesis,
	}

	c.kv.ApplyOps(genesis.Ops)
	c.tip = genesis

	if err := c.replay(); err != nil {
		return nil, fmt.Errorf("NewChain: replay: %w", err)
	}

	if _, err := c.kv.DAOKeyset(); err != nil {
		return nil, fmt.Errorf("NewChain: %w", err)
	}

	return c, nil
}

func (c *Chain) replay() error {
	count, err := c.store.StateBlockCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	blocks, err := c.store.GetStateBlockRange(1, count)
	if err != nil {
		return err
	}
	expected := uint64(1)
	for _, b := range blocks {
		if b.Index != expected {
			return fmt.Errorf("gap: expected block %d, store has %d", expected, b.Index)
		}
		if err := VerifyBlockHash(b); err != nil {
			return fmt.Errorf("block %d: %w", b.Index, err)
		}
		if b.PrevHash != c.tip.Hash {
			return fmt.Errorf("block %d: prev_hash mismatch: expected %s, got %s", b.Index, c.tip.Hash, b.PrevHash)
		}
		if err := c.verifyBlockSignatures(b); err != nil {
			return fmt.Errorf("block %d: %w", b.Index, err)
		}
		if err := c.applyValidated(b); err != nil {
			return fmt.Errorf("block %d: %w", b.Index, err)
		}
		expected++
	}
	if expected-1 != count {
		return fmt.Errorf("gap: store reports %d blocks but only %d were readable", count, expected-1)
	}
	return nil
}

func (c *Chain) verifyBlockSignatures(b *Block) error {
	oracleConfig, _ := c.kv.OracleConfig()
	if oracleConfig != nil && opsMatchPrefix(b.Ops, oracleConfig.AllowedPrefix) {
		return verifyOracleMultisig(b, oracleConfig)
	}
	keyset, err := c.kv.DAOKeyset()
	if err != nil {
		return fmt.Errorf("cannot load keyset: %w", err)
	}
	return verifyMultisig(b, keyset)
}

func (c *Chain) applyValidated(b *Block) error {
	c.kv.ApplyOps(b.Ops)
	c.tip = b
	return nil
}

func (c *Chain) AddBlock(b *Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := VerifyBlockHash(b); err != nil {
		return err
	}

	if b.Index <= c.tip.Index {
		existing, err := c.store.GetStateBlock(b.Index)
		if err != nil {
			return err
		}
		if existing == nil && b.Index == 0 {
			existing = c.genesis
		}
		if existing != nil {
			if existing.Hash == b.Hash {
				return nil
			}

			keyset, kerr := c.kv.DAOKeyset()
			if kerr == nil {
				if verr := verifyMultisig(b, keyset); verr == nil {
					if c.forkCallback != nil {
						c.forkCallback(existing, b)
					}
				}
			}
			return fmt.Errorf("fork detected at index %d: existing %s, incoming %s", b.Index, existing.Hash, b.Hash)
		}
		return nil
	}

	if b.Index != c.tip.Index+1 {
		return fmt.Errorf("expected index %d, got %d: %w", c.tip.Index+1, b.Index, ErrGap)
	}

	if b.PrevHash != c.tip.Hash {
		return fmt.Errorf("prev_hash mismatch: expected %s, got %s", c.tip.Hash, b.PrevHash)
	}

	if b.Timestamp < c.tip.Timestamp {
		return fmt.Errorf("timestamp %d is before previous %d", b.Timestamp, c.tip.Timestamp)
	}

	if len(b.Ops) == 0 {
		return fmt.Errorf("block has no ops")
	}
	blockJSON, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("cannot marshal block: %w", err)
	}
	if len(blockJSON) > MaxBlockSize {
		return fmt.Errorf("block size %d exceeds limit %d", len(blockJSON), MaxBlockSize)
	}
	for _, op := range b.Ops {
		if err := ValidateOp(op); err != nil {
			return err
		}
		if err := validateTransition(c.kv, c.tip, b, op); err != nil {
			return err
		}
	}

	oracleConfig, _ := c.kv.OracleConfig()
	if oracleConfig != nil && opsMatchPrefix(b.Ops, oracleConfig.AllowedPrefix) {

		for _, op := range b.Ops {
			if op.Action == ActionSet {
				if err := validateEpochValue(op.Value, c.kv); err != nil {
					return fmt.Errorf("epoch validation: %w", err)
				}
			}

			if _, exists := c.kv.Get(op.Key); exists {
				return fmt.Errorf("epoch key %q already exists (write-once)", op.Key)
			}
		}
		if err := verifyOracleMultisig(b, oracleConfig); err != nil {
			return err
		}
	} else {

		keyset, err := c.kv.DAOKeyset()
		if err != nil {
			return fmt.Errorf("cannot load keyset: %w", err)
		}
		if err := verifyMultisig(b, keyset); err != nil {
			return err
		}

		if oracleConfig != nil {
			for _, op := range b.Ops {
				if strings.HasPrefix(op.Key, oracleConfig.AllowedPrefix) {
					return fmt.Errorf("DAO block cannot write to oracle prefix %q (key: %s)", oracleConfig.AllowedPrefix, op.Key)
				}
			}
		}
	}

	if err := c.store.PutStateBlock(b); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	c.kv.ApplyOps(b.Ops)
	c.tip = b

	if c.onBlock != nil {
		c.onBlock(b)
	}

	return nil
}

func shortKey(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func verifyMultisig(b *Block, keyset *DAOKeyset) error {
	if len(b.Signatures) == 0 {
		return fmt.Errorf("no signatures")
	}

	keysetMap := make(map[string]bool, len(keyset.Keys))
	for _, k := range keyset.Keys {
		keysetMap[k] = true
	}

	seen := make(map[string]bool, len(b.Signatures))
	validCount := 0

	for _, sig := range b.Signatures {
		if seen[sig.PublicKey] {
			return fmt.Errorf("duplicate signer: %s", shortKey(sig.PublicKey))
		}
		seen[sig.PublicKey] = true

		if !keysetMap[sig.PublicKey] {
			return fmt.Errorf("signer %s not in keyset", shortKey(sig.PublicKey))
		}

		if err := VerifySignature(b.Hash, sig); err != nil {
			return fmt.Errorf("sig from %s: %w", shortKey(sig.PublicKey), err)
		}
		validCount++
	}

	if validCount < keyset.Threshold {
		return fmt.Errorf("insufficient signatures: got %d, need %d", validCount, keyset.Threshold)
	}

	return nil
}

func (c *Chain) Tip() *Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tip
}

func (c *Chain) GetBlock(index uint64) (*Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index == 0 {
		return c.genesis, nil
	}
	return c.store.GetStateBlock(index)
}

func (c *Chain) GetBlocks(start, limit uint64) ([]*Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if start == 0 {
		blocks := []*Block{c.genesis}
		if limit <= 1 {
			return blocks, nil
		}
		stored, err := c.store.GetStateBlockRange(1, limit-1)
		if err != nil {
			return nil, err
		}
		return append(blocks, stored...), nil
	}
	return c.store.GetStateBlockRange(start, limit)
}

func (c *Chain) BlockCount() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	count, err := c.store.StateBlockCount()
	if err != nil {
		return 0, err
	}
	return count + 1, nil
}

func (c *Chain) GetKV(key string) (json.RawMessage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kv.Get(key)
}

func (c *Chain) GetKVByPrefix(prefix string) map[string]json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kv.GetByPrefix(prefix)
}

func (c *Chain) GetAllKV() map[string]json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kv.GetAll()
}

func (c *Chain) DAOKeyset() *DAOKeyset {
	c.mu.Lock()
	defer c.mu.Unlock()
	ks, _ := c.kv.DAOKeyset()
	return ks
}

func (c *Chain) Phase() uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, _ := c.kv.Phase()
	return p
}

func (c *Chain) SetOnBlock(fn func(*Block)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onBlock = fn
}

func (c *Chain) SetForkCallback(fn func(existing, incoming *Block)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forkCallback = fn
}

func opsMatchPrefix(ops []Op, prefix string) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if !strings.HasPrefix(op.Key, prefix) {
			return false
		}
	}
	return true
}

func verifyOracleMultisig(b *Block, config *OracleConfig) error {
	if len(b.Signatures) == 0 {
		return fmt.Errorf("no signatures")
	}

	keysetMap := make(map[string]bool, len(config.Keys))
	for _, k := range config.Keys {
		keysetMap[k] = true
	}

	seen := make(map[string]bool, len(b.Signatures))
	validCount := 0

	for _, sig := range b.Signatures {
		if seen[sig.PublicKey] {
			return fmt.Errorf("duplicate signer: %s", shortKey(sig.PublicKey))
		}
		seen[sig.PublicKey] = true

		if !keysetMap[sig.PublicKey] {
			return fmt.Errorf("signer %s not in oracle keyset", shortKey(sig.PublicKey))
		}

		if err := VerifySignature(b.Hash, sig); err != nil {
			return fmt.Errorf("sig from %s: %w", shortKey(sig.PublicKey), err)
		}
		validCount++
	}

	if validCount < config.Threshold {
		return fmt.Errorf("insufficient oracle signatures: got %d, need %d", validCount, config.Threshold)
	}

	return nil
}
