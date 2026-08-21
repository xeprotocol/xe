package core

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/blake2b"
)

// ErrPoWCancelled is returned when a PoW computation is cancelled via context.
var ErrPoWCancelled = fmt.Errorf("pow computation cancelled")

const (
	// DefaultDifficulty is the production PoW threshold. A valid nonce must
	// produce powHash(nonce, blockHash) >= DefaultDifficulty.
	// ~2M expected attempts → ~1s on a single-core VPS (~2M hashes/sec).
	DefaultDifficulty uint64 = 0xfffff80000000000

	// TestDifficulty is trivially easy — almost any nonce satisfies it.
	// Use in tests to avoid expensive computation.
	TestDifficulty uint64 = 0x0000000000000002
)

// powHash computes an 8-byte blake2b digest over nonce_LE || blockHash and
// interprets the result as a big-endian uint64.
func powHash(nonce uint64, blockHash []byte) uint64 {
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)

	h, _ := blake2b.New(8, nil) // 8-byte output, no key
	h.Write(nonceBytes[:])
	h.Write(blockHash)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum)
}

// ValidatePoW returns true if the given nonce satisfies the difficulty threshold
// for the provided blockHash (as raw bytes). Higher difficulty is harder.
func ValidatePoW(blockHash []byte, nonce uint64, difficulty uint64) bool {
	return powHash(nonce, blockHash) >= difficulty
}

// ComputePoW finds a nonce satisfying ValidatePoW by brute-force from a random
// starting point. It returns the first valid nonce found.
//
// Deprecated: this function loops indefinitely with no cancellation support.
// Prefer ComputePoWWithContext for production use.
func ComputePoW(blockHash []byte, difficulty uint64) uint64 {
	var startBuf [8]byte
	_, _ = rand.Read(startBuf[:])
	start := binary.LittleEndian.Uint64(startBuf[:])

	for nonce := start; ; nonce++ {
		if ValidatePoW(blockHash, nonce, difficulty) {
			return nonce
		}
	}
}

// ComputePoWConcurrent finds a valid nonce using numWorkers goroutines, each
// searching a different random starting offset. Returns the first valid nonce found.
// This is a convenience wrapper around ComputePoWWithContext using context.Background().
func ComputePoWConcurrent(blockHash []byte, difficulty uint64, numWorkers int) uint64 {
	nonce, _ := ComputePoWWithContext(context.Background(), blockHash, difficulty, numWorkers)
	return nonce
}

// ComputePoWWithContext finds a valid nonce using numWorkers goroutines. Workers
// check ctx.Done() periodically and abort if the context is cancelled or times out.
// Returns ErrPoWCancelled if the context expires before a nonce is found.
func ComputePoWWithContext(ctx context.Context, blockHash []byte, difficulty uint64, numWorkers int) (uint64, error) {
	if numWorkers <= 0 {
		numWorkers = 1
	}

	result := make(chan uint64, 1)
	var found atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var startBuf [8]byte
			_, _ = rand.Read(startBuf[:])
			start := binary.LittleEndian.Uint64(startBuf[:])

			for nonce := start; ; nonce++ {
				if found.Load() {
					return
				}
				// Check context every 4096 iterations to avoid syscall overhead.
				if nonce&0xFFF == 0 {
					select {
					case <-ctx.Done():
						return
					default:
					}
				}
				if ValidatePoW(blockHash, nonce, difficulty) {
					if found.CompareAndSwap(false, true) {
						result <- nonce
					}
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		// If all workers exit without finding a nonce (context cancelled),
		// close the result channel to unblock the select below.
		close(result)
	}()

	select {
	case nonce, ok := <-result:
		if !ok {
			return 0, ErrPoWCancelled
		}
		return nonce, nil
	case <-ctx.Done():
		found.Store(true) // signal workers to stop
		return 0, ErrPoWCancelled
	}
}
