package statechain

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

type memStateChainStore struct {
	blocks map[uint64]*Block
}

func newMemStateChainStore() *memStateChainStore {
	return &memStateChainStore{blocks: make(map[uint64]*Block)}
}

func (m *memStateChainStore) PutStateBlock(b *Block) error {
	cp := *b
	m.blocks[b.Index] = &cp
	return nil
}
func (m *memStateChainStore) GetStateBlock(index uint64) (*Block, error) {
	b, ok := m.blocks[index]
	if !ok {
		return nil, nil
	}
	cp := *b
	return &cp, nil
}
func (m *memStateChainStore) GetStateTip() (*Block, error) {
	if len(m.blocks) == 0 {
		return nil, nil
	}
	b := m.blocks[uint64(len(m.blocks))]
	if b == nil {
		return nil, nil
	}
	cp := *b
	return &cp, nil
}
func (m *memStateChainStore) GetStateBlockRange(start, limit uint64) ([]*Block, error) {
	var out []*Block
	for i := uint64(0); i < limit; i++ {
		b, ok := m.blocks[start+i]
		if !ok {
			break
		}
		cp := *b
		out = append(out, &cp)
	}
	return out, nil
}
func (m *memStateChainStore) StateBlockCount() (uint64, error) {
	return uint64(len(m.blocks)), nil
}

func TestStateChainNilBlockAndSyncResilience(t *testing.T) {
	kp1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	gen, err := GenerateTestGenesis([]string{kp1.PubKeyHex(), kp2.PubKeyHex()}, 2)
	if err != nil {
		t.Fatal(err)
	}

	chain, err := NewChain(newMemStateChainStore(), gen)
	if err != nil {
		t.Fatal(err)
	}

	// AddBlock(nil) must return an error rather than panicking
	if err := chain.AddBlock(nil); err == nil {
		t.Fatal("expected AddBlock(nil) to return error")
	}

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	h2.SetStreamHandler(SyncProtocol, func(s network.Stream) {
		defer s.Close()
		var req syncRequest
		_ = json.NewDecoder(s).Decode(&req)
		enc := json.NewEncoder(s)
		_ = enc.Encode(syncResponse{
			Blocks:  []*Block{nil},
			HasMore: true,
		})
	})

	pi := peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}
	if err := h1.Connect(context.Background(), pi); err != nil {
		t.Fatal(err)
	}

	if err := requestSync(h1, h2.ID(), chain); err != nil {
		t.Fatalf("statechain requestSync returned unexpected error: %v", err)
	}
}
