package net

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/xeprotocol/xe/core"
)

type recordingLedger struct {
	frontiers map[string]string
	added     []*core.Block
	fail      map[string]error
}

func (l *recordingLedger) Frontiers() map[string]string {
	if l.frontiers == nil {
		return map[string]string{}
	}
	return l.frontiers
}

func (l *recordingLedger) AddSyncedBlock(b *core.Block) error {
	if b == nil {
		return errors.New("nil block reached ledger")
	}
	if err, ok := l.fail[b.Hash]; ok {
		return err
	}
	l.added = append(l.added, b)
	return nil
}

func TestSyncResponseNullElementDecodesToNil(t *testing.T) {
	const payload = `{"blocks":[null]}`
	var resp SyncResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Blocks) != 1 || resp.Blocks[0] != nil {
		t.Fatalf("JSON null must become a nil *core.Block, got %#v", resp.Blocks)
	}

	kept := dropNilBlocks(resp.Blocks, "12D3KooWpeer")
	if len(kept) != 0 {
		t.Fatalf("nil block was kept: %#v", kept)
	}
}

func TestDropNilBlocks(t *testing.T) {
	cases := []struct {
		name string
		in   []*core.Block
		want []string
	}{
		{name: "nil slice", in: nil, want: nil},
		{name: "empty", in: []*core.Block{}, want: nil},
		{name: "clean", in: []*core.Block{{Hash: "a"}}, want: []string{"a"}},
		{name: "only nulls", in: []*core.Block{nil, nil}, want: nil},
		{name: "mixed", in: []*core.Block{nil, {Hash: "a"}, nil, {Hash: "b"}}, want: []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dropNilBlocks(tc.in, "peer")
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (%#v)", len(got), len(tc.want), got)
			}
			for i, hash := range tc.want {
				if got[i] == nil || got[i].Hash != hash {
					t.Fatalf("block %d = %#v, want hash %s", i, got[i], hash)
				}
			}
		})
	}
}

func TestApplySyncedBlocksNeverDereferencesNil(t *testing.T) {
	t.Run("only nils and a nil ledger", func(t *testing.T) {
		cleaned := dropNilBlocks([]*core.Block{nil, nil}, "peer")
		added := applySyncedBlocks(cleaned, nil, newBlockQuarantine(), "peer")
		if added != 0 {
			t.Fatalf("added = %d, want 0", added)
		}
	})

	t.Run("nil beside accepted and rejected", func(t *testing.T) {
		q := newBlockQuarantine()
		led := &recordingLedger{fail: map[string]error{
			"bad": errors.New("rejected by test"),
		}}
		cleaned := dropNilBlocks([]*core.Block{nil, {Hash: "bad"}, nil, {Hash: "good"}}, "peer")
		added := applySyncedBlocks(cleaned, led, q, "peer")
		if added != 1 {
			t.Fatalf("added = %d, want 1", added)
		}
		if len(led.added) != 1 || led.added[0] == nil || led.added[0].Hash != "good" {
			t.Fatalf("ledger got %#v", led.added)
		}
		if !q.contains("bad") {
			t.Fatal("rejected block was not quarantined")
		}
	})

	t.Run("nil beside quarantined hash", func(t *testing.T) {
		q := newBlockQuarantine()
		q.add("good")
		led := &recordingLedger{}
		cleaned := dropNilBlocks([]*core.Block{nil, {Hash: "good"}}, "peer")
		added := applySyncedBlocks(cleaned, led, q, "peer")
		if added != 0 || len(led.added) != 0 {
			t.Fatalf("added=%d ledger=%#v", added, led.added)
		}
	})
}

func TestRequestSyncPanicReturnsError(t *testing.T) {
	err := requestSync(nil, "", nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("panic must come back as an error, got %v", err)
	}
}

func TestRequestSyncDiscardsNilBlocks(t *testing.T) {
	t.Run("single null page", func(t *testing.T) {
		led := &recordingLedger{}
		err := requestSyncAgainst(t, led, `{"blocks":[null],"has_more":false}`)
		if err != nil {
			t.Fatalf("requestSync: %v", err)
		}
		if len(led.added) != 0 {
			t.Fatalf("nil block was applied: %#v", led.added)
		}
	})

	t.Run("null page then a real block", func(t *testing.T) {
		led := &recordingLedger{}
		err := requestSyncAgainst(t, led,
			`{"blocks":[null],"has_more":true}`,
			`{"blocks":[null,{"hash":"good"}],"has_more":false}`,
		)
		if err != nil {
			t.Fatalf("requestSync: %v", err)
		}
		if len(led.added) != 1 || led.added[0].Hash != "good" {
			t.Fatalf("ledger got %#v", led.added)
		}
	})
}

func TestSpawnGateRecoversWorkerPanic(t *testing.T) {
	g := &spawnGate{}
	var finished atomic.Int32

	if !g.spawn(func() { panic("boom") }) {
		t.Fatal("spawn returned false")
	}
	if !g.spawn(func() {
		finished.Add(1)
	}) {
		t.Fatal("spawn returned false")
	}
	if !g.spawn(func() { panic("boom-2") }) {
		t.Fatal("spawn returned false")
	}

	done := make(chan struct{})
	go func() {
		g.wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not return; Done was skipped or the panic escaped")
	}
	if finished.Load() != 1 {
		t.Fatalf("sibling worker finished %d times, want 1", finished.Load())
	}
	if g.spawn(func() {}) {
		t.Fatal("spawn after wait must report the gate closed")
	}
}

func TestIngestSyncPagesFusesOnThirdEmptyPage(t *testing.T) {
	const extra = 20
	pages := []string{
		`{"blocks":[null],"has_more":true}`,
		`{"blocks":[],"has_more":true}`,
	}
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			payload := bytes.Repeat([]byte(page+"\n"), extra)
			dec := json.NewDecoder(bytes.NewReader(payload))
			got, err := ingestSyncPages(dec, nil, "peer")
			if !errors.Is(err, errSyncCircuitOpen) {
				t.Fatalf("err = %v, want circuit open", err)
			}
			if got.pages != maxConsecutiveEmptyPages {
				t.Fatalf("pages = %d, want %d", got.pages, maxConsecutiveEmptyPages)
			}
			if len(got.blocks) != 0 || got.terminal {
				t.Fatalf("pull = %+v", got)
			}
			var next SyncResponse
			if err := dec.Decode(&next); err != nil {
				t.Fatalf("page %d should still be unread: %v", maxConsecutiveEmptyPages+1, err)
			}
		})
	}
}

func TestIngestSyncPagesResetsEmptyStreak(t *testing.T) {
	const payload = "" +
		`{"blocks":[null],"has_more":true}` + "\n" +
		`{"blocks":[],"has_more":true}` + "\n" +
		`{"blocks":[{"hash":"a"}],"has_more":true}` + "\n" +
		`{"blocks":[null],"has_more":true}` + "\n" +
		`{"blocks":[],"has_more":true}` + "\n" +
		`{"blocks":[{"hash":"b"}],"has_more":false}` + "\n"
	got, err := ingestSyncPages(json.NewDecoder(strings.NewReader(payload)), nil, "peer")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !got.terminal || got.pages != 6 || len(got.blocks) != 2 {
		t.Fatalf("pull = %+v", got)
	}
	if got.blocks[0].Hash != "a" || got.blocks[1].Hash != "b" {
		t.Fatalf("blocks = %#v", got.blocks)
	}
}

func TestIngestSyncPagesAllowsATerminalEmptyPage(t *testing.T) {
	const payload = `{"blocks":[],"has_more":false,"rejected":["acc"]}` + "\n"
	got, err := ingestSyncPages(json.NewDecoder(strings.NewReader(payload)), nil, "peer")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !got.terminal || got.pages != 1 || len(got.rejected) != 1 || got.rejected[0] != "acc" {
		t.Fatalf("pull = %+v", got)
	}
}

func TestIngestSyncPagesFusesAtPageCap(t *testing.T) {
	const extra = 3
	page := []byte("{\"blocks\":[{\"hash\":\"h\"}],\"has_more\":true}\n")
	payload := bytes.Repeat(page, maxSyncPages+extra)
	dec := json.NewDecoder(bytes.NewReader(payload))
	got, err := ingestSyncPages(dec, nil, "peer")
	if !errors.Is(err, errSyncCircuitOpen) {
		t.Fatalf("err = %v, want circuit open", err)
	}
	if got.pages != maxSyncPages || len(got.blocks) != maxSyncPages {
		t.Fatalf("pages=%d blocks=%d, want %d", got.pages, len(got.blocks), maxSyncPages)
	}
	var next SyncResponse
	if err := dec.Decode(&next); err != nil {
		t.Fatalf("page %d should still be unread: %v", maxSyncPages+1, err)
	}
}

func TestRequestSyncFusesWhenPeerStallsAfterEmptyPages(t *testing.T) {
	cases := []string{
		`{"blocks":[null],"has_more":true}`,
		`{"blocks":[],"has_more":true}`,
	}
	for _, page := range cases {
		t.Run(page, func(t *testing.T) {
			led := &recordingLedger{}
		err := requestSyncStallAfter(t, led, maxConsecutiveEmptyPages, page)
		if !errors.Is(err, errSyncCircuitOpen) {
			t.Fatalf("err = %v, want circuit open", err)
		}
		if len(led.added) != 0 {
			t.Fatalf("ledger got %#v", led.added)
		}
		})
	}
}

// requestSyncStallAfter writes n copies of page and then holds the stream open.
// Without the circuit breaker, requestSync blocks until the 60s stream deadline.
func requestSyncStallAfter(t *testing.T, led syncLedger, n int, page string) error {
	t.Helper()
	client, server := newLinkedPair(t)

	release := make(chan struct{})
	var once sync.Once
	letGo := func() { once.Do(func() { close(release) }) }
	t.Cleanup(letGo)

	server.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		var req SyncRequest
		if err := json.NewDecoder(io.LimitReader(s, maxSyncRequestBytes)).Decode(&req); err != nil {
			return
		}
		if !strings.HasSuffix(page, "\n") {
			page += "\n"
		}
		for i := 0; i < n; i++ {
			if _, err := io.WriteString(s, page); err != nil {
				return
			}
		}
		<-release
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- requestSync(client, server.ID(), led, newBlockQuarantine(), nil)
	}()
	select {
	case err := <-errCh:
		letGo()
		return err
	case <-time.After(3 * time.Second):
		letGo()
		t.Fatal("requestSync still blocked after empty pages; circuit breaker did not trip")
	}
	return nil
}

func requestSyncAgainst(t *testing.T, led syncLedger, pages ...string) error {
	t.Helper()
	client, server := newLinkedPair(t)
	server.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		var req SyncRequest
		dec := json.NewDecoder(io.LimitReader(s, maxSyncRequestBytes))
		if err := dec.Decode(&req); err != nil {
			return
		}
		for _, page := range pages {
			if !strings.HasSuffix(page, "\n") {
				page += "\n"
			}
			if _, err := io.WriteString(s, page); err != nil {
				return
			}
		}
	})
	return requestSync(client, server.ID(), led, newBlockQuarantine(), nil)
}

func newLinkedPair(t *testing.T) (client, server host.Host) {
	t.Helper()
	mn := mocknet.New()
	t.Cleanup(func() { _ = mn.Close() })

	var err error
	client, err = mn.GenPeer()
	if err != nil {
		t.Fatalf("client peer: %v", err)
	}
	server, err = mn.GenPeer()
	if err != nil {
		t.Fatalf("server peer: %v", err)
	}
	if err := mn.LinkAll(); err != nil {
		t.Fatalf("link: %v", err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return client, server
}
