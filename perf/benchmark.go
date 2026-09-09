package perf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	BenchmarkIterations = uint64(375_000_000)

	MemoryTableSize = uint64(8_388_608)

	MemoryReads = uint64(1_000_000)

	WorkloadVersion = uint64(3)
)

type BenchmarkResult struct {
	Seed        [32]byte
	CPUHash     [32]byte
	MemoryProof [32]byte
	FinalHash   [32]byte
	Iterations  uint64
	Elapsed     time.Duration
}

func (r *BenchmarkResult) Score() float64 {
	secs := r.Elapsed.Seconds()
	if secs <= 0 {
		return 0
	}
	return 1.0 / secs
}

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

func RunBenchmark(seed [32]byte, iterations uint64) BenchmarkResult {
	start := time.Now()

	h := seed
	for i := uint64(0); i < iterations; i++ {
		h = sha256.Sum256(h[:])
	}
	cpuHash := h

	table := buildMemoryTable(cpuHash, MemoryTableSize)

	memoryProof := randomReads(table, cpuHash, MemoryReads)

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

func randomReads(table [][32]byte, seed [32]byte, reads uint64) [32]byte {
	n := uint64(len(table))
	h := sha256.New()

	idx := binary.BigEndian.Uint64(seed[:8]) % n
	for i := uint64(0); i < reads; i++ {
		entry := table[idx]
		h.Write(entry[:])

		idx = binary.BigEndian.Uint64(entry[:8]) % n
	}

	var proof [32]byte
	copy(proof[:], h.Sum(nil))
	return proof
}

func VerifyBenchmark(seed [32]byte, iterations uint64, expectedFinalHash [32]byte) bool {
	result := RunBenchmark(seed, iterations)
	return result.FinalHash == expectedFinalHash
}

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

func SeedHex(seed [32]byte) string {
	return hex.EncodeToString(seed[:])
}
