package core

import (
	"errors"
	"testing"
)

func TestIsRetryableError_LeaseRaces(t *testing.T) {
	testCases := []struct {
		err  error
		want bool
	}{
		{errors.New("lease already settled"), true},
		{errors.New("lease not yet expired: need timestamp >= 100, got 50"), true},
		{errors.New("lease settle past grace: timestamp 200 exceeds expiry+grace 150"), true},
		{errors.New("renew-wins: provider built on the settle: retry after sync"), true},
		{errors.New("settle-wins: consumer built on the force-settle: retry after sync"), true},
		{errors.New("cannot force-settle lease in accepted state"), true},
		{errors.New("lease not renewable in settled state"), true},
		{errors.New("lease_settle XE mismatch: expected 10, got 20"), true},
		{errors.New("random unhandled fatal error"), false},
		{nil, false},
	}

	for _, tc := range testCases {
		got := IsRetryableError(tc.err)
		if got != tc.want {
			t.Errorf("IsRetryableError(%v) = %v; want %v", tc.err, got, tc.want)
		}
	}
}
