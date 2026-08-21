package perf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	// BenchmarkIterations is the number of sequential hash chain iterations.
	// Targets ~60 seconds on mid-range hardware (single-threaded).
	BenchmarkIterations = uint64(375_000_000)

	// MemoryTableSize is the number of 32-byte entries in the memory table.
	// 256 MB = 8,388,608 entries × 32 bytes each.
	MemoryTableSize = uint64(8_388_608)

	// MemoryReads is the number of random reads from the memory table.
	MemoryReads = uint64(1_000_000)

	// WorkloadVersion identifies the benchmark algorithm. Increment when
	// the benchmark changes so certificates aren't compared across versions.
	WorkloadVersion = uint64(3)
)

// BenchmarkResult holds the output of running the full benchmark.
type BenchmarkResult struct {
	Seed        [32]byte
	CPUHash     [32]byte // final hash of sequential chain
	MemoryProof [32]byte // hash of random reads from memory table
	FinalHash   [32]byte // sha256(CPUHash || MemoryProof)
	Iterations  uint64
	Elapsed     time.Duration
}

// Score returns 1.0 / elapsed_seconds. Higher = faster hardware.
func (r *BenchmarkResult) Score() float64 {
	secs := r.Elapsed.Seconds()
	if secs <= 0 {
		return 0
	}
	return 1.0 / secs
}

// DeriveSeed computes the benchmark seed from the attested start timestamp
// and the provider's public key.
func DeriveSeed(startTimestamp int64, providerPubkey []byte) [32]byte {
	h := sha256.New()
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(startTimestamp))
	h.Write(ts[:])
	h.Write(providerPubkey)
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return seed
}

// RunBenchmark executes the full benchmark:
// Phase 1: Sequential hash chain (CPU-bound, ~60s)
// Phase 2: Memory table build + random reads (memory-bound, ~5-10s)
func RunBenchmark(seed [32]byte, iterations uint64) BenchmarkResult {
	start := time.Now()

	// Phase 1: Sequential hash chain.
	h := seed
	for i := uint64(0); i < iterations; i++ {
		h = sha256.Sum256(h[:])
	}
	cpuHash := h

	// Phase 2: Build memory table from the hash chain result.
	table := buildMemoryTable(cpuHash, MemoryTableSize)

	// Phase 3: Random reads from the table.
	memoryProof := randomReads(table, cpuHash, MemoryReads)

	// Final proof combines both phases.
	combined := sha256.Sum256(append(cpuHash[:], memoryProof[:]...))

	return BenchmarkResult{
		Seed:        seed,
		CPUHash:     cpuHash,
		MemoryProof: memoryProof,
		FinalHash:   combined,
		Iterations:  iterations,
		Elapsed:     time.Since(start),
	}
}

// buildMemoryTable creates a table of 32-byte entries where each entry
// is derived from the seed. The table must be held in memory — outsourcing
// over a network adds latency per random read.
func buildMemoryTable(seed [32]byte, entries uint64) [][32]byte {
	table := make([][32]byte, entries)
	h := sha256.New()
	for i := uint64(0); i < entries; i++ {
		h.Reset()
		h.Write(seed[:])
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], i)
		h.Write(idx[:])
		copy(table[i][:], h.Sum(nil))
	}
	return table
}

// randomReads performs seed-derived random reads from the table and returns
// a hash of all read values. Each read index depends on the previous read,
// creating a sequential dependency that prevents prefetching.
func randomReads(table [][32]byte, seed [32]byte, reads uint64) [32]byte {
	n := uint64(len(table))
	h := sha256.New()

	// First index derived from seed.
	idx := binary.BigEndian.Uint64(seed[:8]) % n
	for i := uint64(0); i < reads; i++ {
		entry := table[idx]
		h.Write(entry[:])
		// Next index derived from current entry.
		idx = binary.BigEndian.Uint64(entry[:8]) % n
	}

	var proof [32]byte
	copy(proof[:], h.Sum(nil))
	return proof
}

// VerifyBenchmark re-runs the full benchmark and checks the final hash.
func VerifyBenchmark(seed [32]byte, iterations uint64, expectedFinalHash [32]byte) bool {
	result := RunBenchmark(seed, iterations)
	return result.FinalHash == expectedFinalHash
}

// RunBenchmarkSmall is a test-friendly version with a small memory table.
func RunBenchmarkSmall(seed [32]byte, iterations uint64) BenchmarkResult {
	start := time.Now()

	h := seed
	for i := uint64(0); i < iterations; i++ {
		h = sha256.Sum256(h[:])
	}
	cpuHash := h

	table := buildMemoryTable(cpuHash, 1000)
	memoryProof := randomReads(table, cpuHash, 100)
	combined := sha256.Sum256(append(cpuHash[:], memoryProof[:]...))

	return BenchmarkResult{
		Seed:        seed,
		CPUHash:     cpuHash,
		MemoryProof: memoryProof,
		FinalHash:   combined,
		Iterations:  iterations,
		Elapsed:     time.Since(start),
	}
}

// SeedHex returns the seed as a hex string.
func SeedHex(seed [32]byte) string {
	return hex.EncodeToString(seed[:])
}
