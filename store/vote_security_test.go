package store

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestMemStoreVoteKeyCaseNormalization(t *testing.T) {
	ms := NewMemStore()
	acc := strings.Repeat("aa", 32)
	prev := strings.Repeat("bb", 32)
	rep := strings.Repeat("cc", 32)
	bh := strings.Repeat("dd", 32)

	v1 := &core.Vote{
		RepPubKey:       rep,
		BlockHash:       bh,
		ConflictAccount: acc,
		ConflictPrev:    prev,
		Timestamp:       100,
		Final:           true,
		Weight:          500,
	}
	if err := ms.PutVote(v1); err != nil {
		t.Fatal(err)
	}

	// Case-variant PutVote must overwrite the same representative key rather than creating a duplicate entry
	v2 := *v1
	v2.RepPubKey = strings.ToUpper(rep)
	if err := ms.PutVote(&v2); err != nil {
		t.Fatal(err)
	}

	votes, err := ms.GetVotesByConflict(strings.ToUpper(acc), strings.ToUpper(prev))
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) != 1 {
		t.Fatalf("expected 1 deduplicated vote in MemStore, got %d", len(votes))
	}

	has, err := ms.HasVoted(strings.ToUpper(acc), prev, strings.ToUpper(rep))
	if err != nil || !has {
		t.Fatalf("expected HasVoted=true for case-variant lookup, got %v (err=%v)", has, err)
	}

	got, err := ms.GetVote(acc, strings.ToUpper(prev), strings.ToUpper(rep))
	if err != nil || got == nil {
		t.Fatalf("expected GetVote to find vote with case-variant key, got %v (err=%v)", got, err)
	}

	if err := ms.DeleteVotesForConflict(strings.ToUpper(acc), strings.ToUpper(prev)); err != nil {
		t.Fatal(err)
	}
	votesAfter, _ := ms.GetVotesByConflict(acc, prev)
	if len(votesAfter) != 0 {
		t.Fatalf("expected 0 votes after DeleteVotesForConflict, got %d", len(votesAfter))
	}
}
