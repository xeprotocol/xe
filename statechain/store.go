package statechain

// StateChainStore is the persistence interface for state chain blocks.
// KV state is derived in-memory from chain replay — not stored here.
type StateChainStore interface {
	PutStateBlock(block *Block) error
	GetStateBlock(index uint64) (*Block, error) // nil, nil on miss
	GetStateTip() (*Block, error)               // nil, nil if empty
	GetStateBlockRange(start, count uint64) ([]*Block, error)
	StateBlockCount() (uint64, error)
}
