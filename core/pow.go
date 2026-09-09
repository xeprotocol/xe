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

var ErrPoWCancelled = fmt.Errorf("pow computation cancelled")

const (
	DefaultDifficulty uint64 = 0xfffff80000000000

	TestDifficulty uint64 = 0x0000000000000002
)

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
	return powHash(nonce, blockHash) >= difficulty
}

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

func ComputePoWConcurrent(blockHash []byte, difficulty uint64, numWorkers int) uint64 {
	nonce, _ := ComputePoWWithContext(context.Background(), blockHash, difficulty, numWorkers)
	return nonce
}

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

		close(result)
	}()

	select {
	case nonce, ok := <-result:
		if !ok {
			return 0, ErrPoWCancelled
		}
		return nonce, nil
	case <-ctx.Done():
		found.Store(true)
		return 0, ErrPoWCancelled
	}
}
