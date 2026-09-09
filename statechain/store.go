package statechain

type StateChainStore interface {
	PutStateBlock(block *Block) error
	GetStateBlock(index uint64) (*Block, error)
	GetStateTip() (*Block, error)
	GetStateBlockRange(start, count uint64) ([]*Block, error)
	StateBlockCount() (uint64, error)
}
