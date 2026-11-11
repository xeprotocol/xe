package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateDifficulty(t *testing.T) {
	if err := ValidateDifficulty(DefaultDifficulty); err != nil {
		t.Fatalf("expected DefaultDifficulty to be valid, got: %v", err)
	}
	if err := ValidateDifficulty(TestDifficulty); err != nil {
		t.Fatalf("expected TestDifficulty to be valid, got: %v", err)
	}
	if err := ValidateDifficulty(MaxPoWDifficulty); err != nil {
		t.Fatalf("expected MaxPoWDifficulty to be valid, got: %v", err)
	}
	if err := ValidateDifficulty(0xffffffffffffffff); !errors.Is(err, ErrInvalidDifficulty) {
		t.Fatalf("expected ErrInvalidDifficulty for max uint64, got: %v", err)
	}
}

func TestValidatePoW(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	if !ValidatePoW(blockHash, 12345, 0) {
		t.Fatalf("expected difficulty 0 to always validate")
	}
	if ValidatePoW(blockHash, 12345, 0xffffffffffffffff) {
		t.Fatalf("expected max difficulty to be rejected")
	}
}

func TestComputePoW_Success(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	nonce := ComputePoW(blockHash, TestDifficulty)
	if !ValidatePoW(blockHash, nonce, TestDifficulty) {
		t.Fatalf("computed nonce failed validation: %d", nonce)
	}
}

func TestComputePoW_MaxDifficultyDosMitigation(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	done := make(chan uint64, 1)

	go func() {
		nonce := ComputePoW(blockHash, 0xffffffffffffffff)
		done <- nonce
	}()

	select {
	case nonce := <-done:
		if nonce != 0 {
			t.Fatalf("expected 0 nonce on invalid difficulty, got %d", nonce)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("ComputePoW hung on max difficulty - DoS vulnerability not mitigated!")
	}
}

func TestComputePoWWithContext_Cancellation(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// High difficulty that won't solve on first try
	_, err := ComputePoWWithContext(ctx, blockHash, 0xfffffffffffe0000, 2)
	if !errors.Is(err, ErrPoWCancelled) {
		t.Fatalf("expected ErrPoWCancelled on cancelled context, got %v", err)
	}
}

func TestComputePoWWithContext_Timeout(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	// 0xfffffffffffe0000 has 1 in 2^47 probability, mathematically impossible to solve in 20ms
	_, err := ComputePoWWithContext(ctx, blockHash, 0xfffffffffffe0000, 2)
	if !errors.Is(err, ErrPoWCancelled) {
		t.Fatalf("expected ErrPoWCancelled on timeout, got %v", err)
	}
}

func TestComputePoWWithIterations_MaxIterationsExceeded(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")

	// Extremely high difficulty with small iteration budget (10 attempts)
	// Guaranteed to not find solution in 10 attempts
	_, err := ComputePoWWithIterations(context.Background(), blockHash, 0xfffffffffffe0000, 1, 10)
	if !errors.Is(err, ErrPoWMaxIterations) {
		t.Fatalf("expected ErrPoWMaxIterations when iteration ceiling is reached, got %v", err)
	}
}

func TestComputePoWConcurrent_Success(t *testing.T) {
	blockHash := []byte("xe_test_block_hash_sample_data")
	nonce := ComputePoWConcurrent(blockHash, TestDifficulty, 4)
	if !ValidatePoW(blockHash, nonce, TestDifficulty) {
		t.Fatalf("concurrent nonce failed validation: %d", nonce)
	}
}
