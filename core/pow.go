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

var (
	ErrPoWCancelled      = fmt.Errorf("pow computation cancelled")
	ErrPoWMaxIterations  = fmt.Errorf("pow computation exceeded maximum iterations")
	ErrInvalidDifficulty = fmt.Errorf("invalid pow difficulty: threshold is unreachable")
)

const (
	DefaultDifficulty uint64 = 0xfffff80000000000

	TestDifficulty uint64 = 0x0000000000000002

	// MaxPoWDifficulty defines the upper bound of admissible PoW difficulty.
	// Difficulty of ^uint64(0) (0xffffffffffffffff) is mathematically unreachable in practical bounds.
	MaxPoWDifficulty uint64 = 0xfffffffffffffffe

	// DefaultMaxPoWIterations bounds total nonce iterations to prevent unbounded CPU exhaustion.
	DefaultMaxPoWIterations uint64 = 1 << 32
)

// ValidateDifficulty verifies that the difficulty threshold is within reachable bounds.
func ValidateDifficulty(difficulty uint64) error {
	if difficulty > MaxPoWDifficulty {
		return ErrInvalidDifficulty
	}
	return nil
}

func powHash(nonce uint64, blockHash []byte) uint64 {
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)

	h, _ := blake2b.New(8, nil)
	h.Write(nonceBytes[:])
	h.Write(blockHash)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum)
}

func ValidatePoW(blockHash []byte, nonce uint64, difficulty uint64) bool {
	if difficulty == 0 {
		return true
	}
	if difficulty > MaxPoWDifficulty {
		return false
	}
	return powHash(nonce, blockHash) >= difficulty
}

// ComputePoW computes proof of work for a given block hash and difficulty.
// It delegates to ComputePoWWithContext to guarantee bounded execution,
// difficulty bounds enforcement, and safety against infinite loop denial of service.
func ComputePoW(blockHash []byte, difficulty uint64) uint64 {
	nonce, _ := ComputePoWWithContext(context.Background(), blockHash, difficulty, 1)
	return nonce
}

func ComputePoWConcurrent(blockHash []byte, difficulty uint64, numWorkers int) uint64 {
	nonce, _ := ComputePoWWithContext(context.Background(), blockHash, difficulty, numWorkers)
	return nonce
}

func ComputePoWWithContext(ctx context.Context, blockHash []byte, difficulty uint64, numWorkers int) (uint64, error) {
	return ComputePoWWithIterations(ctx, blockHash, difficulty, numWorkers, DefaultMaxPoWIterations)
}

func ComputePoWWithIterations(ctx context.Context, blockHash []byte, difficulty uint64, numWorkers int, maxIterations uint64) (uint64, error) {
	if err := ValidateDifficulty(difficulty); err != nil {
		return 0, err
	}

	if numWorkers <= 0 {
		numWorkers = 1
	}

	if maxIterations == 0 {
		maxIterations = DefaultMaxPoWIterations
	}

	result := make(chan uint64, 1)
	var found atomic.Bool
	var wg sync.WaitGroup

	maxPerWorker := maxIterations / uint64(numWorkers)
	if maxPerWorker == 0 {
		maxPerWorker = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var startBuf [8]byte
			_, _ = rand.Read(startBuf[:])
			start := binary.LittleEndian.Uint64(startBuf[:])

			for count := uint64(0); count < maxPerWorker; count++ {
				if found.Load() {
					return
				}

				nonce := start + count
				if count&0xFFF == 0 {
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
		close(result)
	}()

	select {
	case nonce, ok := <-result:
		if !ok {
			if ctx.Err() != nil {
				return 0, ErrPoWCancelled
			}
			return 0, ErrPoWMaxIterations
		}
		return nonce, nil
	case <-ctx.Done():
		found.Store(true)
		return 0, ErrPoWCancelled
	}
}
