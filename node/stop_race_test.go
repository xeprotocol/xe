package node

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
)

type closeTrackingStore struct {
	*store.MemStore
	closed      atomic.Bool
	afterClosed atomic.Int32
}

func (s *closeTrackingStore) touch() {
	if s.closed.Load() {
		s.afterClosed.Add(1)
	}
}

func (s *closeTrackingStore) GetAllConflicts() ([]*core.Conflict, error) {
	s.touch()
	return s.MemStore.GetAllConflicts()
}

func (s *closeTrackingStore) GetFrontier(account string) (string, error) {
	s.touch()
	return s.MemStore.GetFrontier(account)
}

func (s *closeTrackingStore) PutVote(v *core.Vote) error {
	s.touch()
	return s.MemStore.PutVote(v)
}

func (s *closeTrackingStore) SaveConflict(c *core.Conflict) error {
	s.touch()
	return s.MemStore.SaveConflict(c)
}

func (s *closeTrackingStore) GetLease(hash string) (*core.Lease, error) {
	s.touch()
	return s.MemStore.GetLease(hash)
}

func (s *closeTrackingStore) Close() error {
	s.closed.Store(true)
	return s.MemStore.Close()
}

func TestNodeStopConcurrentWithPullsAndCallbacksNeverPanicsOrUsesClosedStore(t *testing.T) {
	for iter := 0; iter < 80; iter++ {
		st := &closeTrackingStore{MemStore: store.NewMemStore()}
		kp, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		ledger := core.NewLedger(st, core.LedgerConfig{})
		vm := core.NewVoteManager(st, kp, ledger)
		qm := core.NewQuorumManager(st, st, st, ledger)
		vm.SetQuorumManager(qm)

		leaseHash := "9999999999999999999999999999999999999999999999999999999999999999"
		_ = st.PutBlock(&core.Block{
			Type:        core.BlockLease,
			Hash:        leaseHash,
			Account:     "1111111111111111111111111111111111111111111111111111111111111111",
			Destination: kp.Address(),
			Amount:      1000,
			Asset:       "XUSD",
		})
		_ = st.PutPendingSend(&core.PendingSend{
			Destination: kp.Address(),
			SendHash:    leaseHash,
			Amount:      1000,
			Asset:       "XUSD",
		})

		ctx, cancel := context.WithCancel(context.Background())
		n := &Node{
			Ledger:           ledger,
			KeyPair:          kp,
			VoteMgr:          vm,
			QuorumMgr:        qm,
			store:            st,
			acceptInFlight:   make(map[string]struct{}),
			acceptAttestHook: func(string) ([]core.TimekeeperAttestation, error) { return nil, context.Canceled },
			pullSem:          make(chan struct{}, maxInFlightVotePulls),
			ctx:              ctx,
			cancel:           cancel,
		}
		onConflict := func(c core.Conflict) {
			if !n.enter() {
				return
			}
			defer n.wg.Done()
			vm.OnConflict(c)
		}
		ledger.SetConflictCallback(onConflict)
		ledger.SetBlockAddedCallback(func(b *core.Block) {
			if !n.enter() {
				return
			}
			defer n.wg.Done()
			vm.OnBlockAdded(b)
		})
		qm.PhantomPullFn = n.pullPhantomBlocks
		qm.VotePullFn = n.pullConflictVotes
		qm.OnFinalized = func() { n.spawn(n.VoteMgr.SweepFrontiers) }
		vm.VotePullFn = n.pullFrontierVotes

		n.spawn(func() { n.QuorumMgr.RunStaleConflictSweep(n.ctx.Done()) })

		var callers sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < 16; g++ {
			callers.Add(1)
			go func(id int) {
				defer callers.Done()
				<-start
				for j := 0; j < 10; j++ {
					n.pullPhantomBlocks("acc", "prev", []string{"abcd"})
					n.pullConflictVotes("acc", "prev")
					n.pullFrontierVotes("acc", "prev")
					qm.OnFinalized()
					onConflict(core.Conflict{
						AccountAddress: "acc",
						PreviousHash:   "prev",
						BlockHashes:    []string{"h1", "h2"},
						DetectedAt:     core.Now(),
					})
					if j%3 == 0 {
						n.leaseWatchTick(core.Now(), &n.wg)
					}
					n.spawn(func() {
						_, _ = st.GetAllConflicts()
						_, _ = st.GetFrontier("acc")
						_ = st.SaveConflict(&core.Conflict{
							AccountAddress: "acc",
							PreviousHash:   "prev",
							BlockHashes:    []string{"h1", "h2"},
							DetectedAt:     core.Now(),
						})
						_ = st.PutVote(&core.Vote{
							ConflictAccount: "acc",
							ConflictPrev:    "prev",
							BlockHash:       "h1",
							RepPubKey:       kp.PubKeyHex(),
						})
					})
					_ = id
				}
			}(g)
		}

		close(start)
		time.Sleep(time.Duration(iter%3) * time.Millisecond)
		n.Stop()
		callers.Wait()

		if leaks := st.afterClosed.Load(); leaks != 0 {
			t.Fatalf("iteration %d: %d store operation(s) executed after store.Close()", iter, leaks)
		}
	}
}

func TestPullPhantomAndConflictBoundedByPullSem(t *testing.T) {
	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New client: %v", err)
	}
	t.Cleanup(func() { _ = hClient.Close() })

	hPeer, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New peer: %v", err)
	}
	t.Cleanup(func() { _ = hPeer.Close() })

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	if err := hClient.Connect(dialCtx, peer.AddrInfo{ID: hPeer.ID(), Addrs: hPeer.Addrs()}); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	mClient := xenet.NewMessenger(hClient, nil)
	mPeer := xenet.NewMessenger(hPeer, nil)

	var active atomic.Int32
	var peak atomic.Int32
	entered := make(chan struct{}, 256)
	release := make(chan struct{})

	recordHandler := func() {
		cur := active.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
	}

	mPeer.Handle(xenet.BlockRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		recordHandler()
		return json.Marshal(&xenet.BlockResponse{})
	})
	mPeer.Handle(xenet.VoteRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		recordHandler()
		return json.Marshal(&xenet.VoteResponse{})
	})

	st := store.NewMemStore()
	kp, _ := core.GenerateKeyPair()
	ledger := core.NewLedger(st, core.LedgerConfig{})
	vm := core.NewVoteManager(st, kp, ledger)

	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		Ledger:  ledger,
		Host:    hClient,
		Msg:     mClient,
		VoteMgr: vm,
		store:   st,
		pullSem: make(chan struct{}, maxInFlightVotePulls),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Launch 128 concurrent conflict + phantom pulls; only maxInFlightVotePulls (32) may enter.
	for i := 0; i < 64; i++ {
		n.pullPhantomBlocks("acc", "prev", []string{"h1"})
		n.pullConflictVotes("acc", "prev")
	}

	for i := 0; i < maxInFlightVotePulls; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for slot %d/%d to enter handler", i+1, maxInFlightVotePulls)
		}
	}

	if ok := n.pullFrontierVotes("acc", "prev"); ok {
		t.Fatalf("expected pullFrontierVotes to return false while all %d pullSem slots are occupied", maxInFlightVotePulls)
	}

	close(release)
	n.Stop()

	if gotPeak := int(peak.Load()); gotPeak != maxInFlightVotePulls {
		t.Fatalf("peak concurrent pull handlers = %d, want %d", gotPeak, maxInFlightVotePulls)
	}
}
