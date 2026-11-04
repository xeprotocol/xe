package statechain

import (
	"testing"
)

func TestAddNilBlock(t *testing.T) {
	c := &Chain{}
	if err := c.AddBlock(nil); err == nil {
		t.Fatal("expected error adding nil block to chain, got nil")
	}
}
