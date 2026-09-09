package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func safeMul(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0, false
	}
	return lo, true
}

func safeAdd(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func ceilDiv(a, b uint64) uint64 {
	if a == 0 {
		return 0
	}
	return (a-1)/b + 1
}

func LeaseStake(cost uint64) uint64 {
	if LeaseStakeDivisor == 0 {
		return 0
	}
	stake := ceilDiv(cost, LeaseStakeDivisor)
	if stake == 0 {
		stake = 1
	}
	return stake
}

func LeaseCost(vcpus, memoryMB, diskGB, duration, multiplierMilli uint64) (uint64, error) {
	if multiplierMilli == 0 {
		return 0, fmt.Errorf("multiplierMilli must be non-zero")
	}
	if duration < LeaseMinDuration {
		return 0, fmt.Errorf("duration must be >= %d seconds, got %d", LeaseMinDuration, duration)
	}
	if duration > LeaseMaxDuration {
		return 0, fmt.Errorf("duration must be <= %d seconds, got %d", LeaseMaxDuration, duration)
	}
	minutes := ceilDiv(duration, 60)

	memGB := ceilDiv(memoryMB, 1024)
	vcpuMicro, ok := safeMul(vcpus, LeaseVCPURate)
	if !ok {
		return 0, fmt.Errorf("overflow: vcpus(%d) * LeaseVCPURate(%d)", vcpus, LeaseVCPURate)
	}
	memMicro, ok := safeMul(memGB, LeaseMemGBRate)
	if !ok {
		return 0, fmt.Errorf("overflow: memGB(%d) * LeaseMemGBRate(%d)", memGB, LeaseMemGBRate)
	}
	diskMicro, ok := safeMul(diskGB, LeaseDiskGBRate)
	if !ok {
		return 0, fmt.Errorf("overflow: diskGB(%d) * LeaseDiskGBRate(%d)", diskGB, LeaseDiskGBRate)
	}
	perHourMicro, ok := safeAdd(vcpuMicro, memMicro)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro vcpu(%d) + mem(%d)", vcpuMicro, memMicro)
	}
	perHourMicro, ok = safeAdd(perHourMicro, diskMicro)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro(%d) + disk(%d)", perHourMicro, diskMicro)
	}
	if perHourMicro == 0 {
		return 0, fmt.Errorf("lease requires at least some resources")
	}
	perMinuteScaled, ok := safeMul(perHourMicro, minutes)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro(%d) * minutes(%d)", perHourMicro, minutes)
	}
	costMicro := ceilDiv(perMinuteScaled, 60)
	scaled, ok := safeMul(costMicro, multiplierMilli)
	if !ok {
		return 0, fmt.Errorf("overflow: costMicro(%d) * multiplierMilli(%d)", costMicro, multiplierMilli)
	}
	cost := ceilDiv(scaled, 1000)
	if cost == 0 {
		cost = 1
	}
	return cost, nil
}

var ErrInvalidPoW = errors.New("invalid proof of work")

const DefaultTimestampWindow = int64(time.Hour)

const (
	LeaseMaxDuration  = uint64(31536000)
	LeaseVCPURate     = uint64(20_000)
	LeaseMemGBRate    = uint64(10_000)
	LeaseDiskGBRate   = uint64(1_000)
	LeaseStakeDivisor = uint64(0)
)

const (
	LeaseMaxVCPUs    = uint64(4_096)
	LeaseMaxMemoryMB = uint64(67_108_864)
	LeaseMaxDiskGB   = uint64(1_048_576)
)

func ValidateLeaseDimensions(vcpus, memoryMB, diskGB, duration uint64) error {
	if vcpus == 0 && memoryMB == 0 && diskGB == 0 {
		return fmt.Errorf("lease must request at least one resource (vcpus, memory, or disk)")
	}
	if vcpus > LeaseMaxVCPUs {
		return fmt.Errorf("lease vcpus must be <= %d, got %d", LeaseMaxVCPUs, vcpus)
	}
	if memoryMB > LeaseMaxMemoryMB {
		return fmt.Errorf("lease memory_mb must be <= %d, got %d", LeaseMaxMemoryMB, memoryMB)
	}
	if diskGB > LeaseMaxDiskGB {
		return fmt.Errorf("lease disk_gb must be <= %d, got %d", LeaseMaxDiskGB, diskGB)
	}
	if duration < LeaseMinDuration {
		return fmt.Errorf("lease duration must be >= %d seconds", LeaseMinDuration)
	}
	if duration > LeaseMaxDuration {
		return fmt.Errorf("lease duration must be <= %d seconds", LeaseMaxDuration)
	}
	return nil
}

const (
	DefaultLeaseMinDuration    = uint64(60)
	DefaultLeaseSettleGrace    = int64(time.Hour)
	DefaultLeaseForceSettleGap = int64(25 * time.Minute)
	DefaultLeaseEscrowExpiry   = int64(365 * 24 * time.Hour)
	DefaultLeaseArchiveGap     = int64(time.Hour)
)

var (
	LeaseMinDuration = DefaultLeaseMinDuration

	LeaseSettleGrace = DefaultLeaseSettleGrace

	LeaseForceSettleGap = DefaultLeaseForceSettleGap

	LeaseEscrowExpiry = DefaultLeaseEscrowExpiry

	LeaseArchiveGap = DefaultLeaseArchiveGap
)

func ApplyGenesisLeaseTiming(b *Block) {
	LeaseMinDuration = DefaultLeaseMinDuration
	LeaseSettleGrace = DefaultLeaseSettleGrace
	LeaseForceSettleGap = DefaultLeaseForceSettleGap
	LeaseEscrowExpiry = DefaultLeaseEscrowExpiry
	LeaseArchiveGap = DefaultLeaseArchiveGap
	MaxAttestationSkew = DefaultMaxAttestationSkew
	if b == nil {
		return
	}
	if b.LeaseMinDurationSecs != 0 {
		LeaseMinDuration = b.LeaseMinDurationSecs
	}
	if b.LeaseSettleGraceNs != 0 {
		LeaseSettleGrace = b.LeaseSettleGraceNs
	}
	if b.LeaseForceSettleGapNs != 0 {
		LeaseForceSettleGap = b.LeaseForceSettleGapNs
	}
	if b.LeaseEscrowExpiryNs != 0 {
		LeaseEscrowExpiry = b.LeaseEscrowExpiryNs
	}
	if b.LeaseArchiveGapNs != 0 {
		LeaseArchiveGap = b.LeaseArchiveGapNs
	}
	if b.MaxAttestationSkewNs != 0 {
		MaxAttestationSkew = b.MaxAttestationSkewNs
	}
}

const RFallback = uint64(2000)

var FaucetMintAmount = 100 * AssetXUSD.UnitsPerToken

type LedgerConfig struct {
	Difficulty uint64

	TimestampWindow int64

	TimekeeperConfigFn func() *TimekeeperConfig

	MinterConfigFn func() *MinterConfig

	CertificateLookupFn func(hash string) *CertificateInfo

	EpochRFn func() uint64

	EpochPayoutCapFn func() uint64

	EpochTWAPFn func() uint64

	EpochAtFn func(ns int64) []EpochParams

	FeatureActiveFn func(feature string) bool
}

const EpochLockTolerance = 3

type EpochParams struct {
	R         uint64
	PayoutCap uint64
	TWAP      uint64
}

type accountLock struct {
	mu      sync.Mutex
	waiters int
}

type Ledger struct {
	locksMu         sync.Mutex
	locks           map[string]*accountLock
	leaseLocksMu    sync.Mutex
	leaseLocks      map[string]*accountLock
	store           Store
	atomicStore     AtomicBlockStore
	difficulty      uint64
	timestampWindow int64

	delegationMu sync.RWMutex
	delegation   map[string]string
	weights      map[string]*big.Int

	repElig repEligibility

	assetBalMu    sync.RWMutex
	assetBalances map[string]map[string]uint64

	blockCount          atomic.Int64
	delegationUnderflow atomic.Uint64
	finalityAdvances    atomic.Uint64
	lastFinalityNs      atomic.Int64
	conflictMu          sync.Mutex
	conflictCallback    func(Conflict)
	blockAddedCallback  func(*Block)
	timekeeperConfigFn  func() *TimekeeperConfig
	minterConfigFn      func() *MinterConfig
	certificateLookupFn func(hash string) *CertificateInfo
	epochRFn            func() uint64
	epochPayoutCapFn    func() uint64
	epochTWAPFn         func() uint64
	epochAtFn           func(ns int64) []EpochParams

	featureActiveFn func(feature string) bool

	keysetMu sync.RWMutex
	keysets  map[string]*Keyset

	accountKeyMu sync.RWMutex
	accountKeys  map[string]string

	reputation *ReputationEngine

	finalStore QuorumStore

	finalVoteStore FinalVoteStore

	cascadeMu     sync.RWMutex
	activeCascade *cascadeBuild
}

func NewLedger(s Store, cfg LedgerConfig) *Ledger {
	abs, ok := s.(AtomicBlockStore)
	if !ok {
		panic("ledger: store must implement AtomicBlockStore")
	}
	l := &Ledger{
		locks:               make(map[string]*accountLock),
		leaseLocks:          make(map[string]*accountLock),
		store:               s,
		atomicStore:         abs,
		difficulty:          cfg.Difficulty,
		timestampWindow:     cfg.TimestampWindow,
		timekeeperConfigFn:  cfg.TimekeeperConfigFn,
		minterConfigFn:      cfg.MinterConfigFn,
		certificateLookupFn: cfg.CertificateLookupFn,
		epochRFn:            cfg.EpochRFn,
		featureActiveFn:     cfg.FeatureActiveFn,
		epochPayoutCapFn:    cfg.EpochPayoutCapFn,
		epochTWAPFn:         cfg.EpochTWAPFn,
		epochAtFn:           cfg.EpochAtFn,
		delegation:          make(map[string]string),
		weights:             make(map[string]*big.Int),
		assetBalances:       make(map[string]map[string]uint64),
		keysets:             make(map[string]*Keyset),
		accountKeys:         make(map[string]string),
	}

	repStore, _ := s.(ReputationStore)
	l.reputation = NewReputationEngine(repStore)

	l.finalStore, _ = s.(QuorumStore)

	l.finalVoteStore, _ = s.(FinalVoteStore)
	empty, err := s.IsEmpty()
	if err != nil {
		panic(fmt.Sprintf("ledger: IsEmpty: %v", err))
	}
	if empty {
		genesis, err := LoadGenesisBlock()
		if err != nil {
			panic(fmt.Sprintf("ledger: load genesis: %v", err))
		}
		commit, prevBal, err := l.prepareBlockWrite(genesis)
		if err != nil {
			panic(fmt.Sprintf("ledger: prepare genesis: %v", err))
		}
		if err := l.commitBlockWrite(commit, prevBal); err != nil {
			panic(fmt.Sprintf("ledger: commit genesis: %v", err))
		}

		if l.finalStore != nil {
			if err := l.finalStore.SetFinalHeight(genesis.Account, 1); err != nil {
				log.Printf("ledger: finalize genesis: %v", err)
			}
		}
		log.Printf("Genesis block applied: %s XE to %s", fmt.Sprint(genesis.Balance), shortAddr(genesis.Account))

		if l.GetTotalDelegatedWeight().Sign() == 0 {
			panic(fmt.Sprintf("ledger: genesis %s yielded ZERO total delegated weight — refusing to bootstrap a network that can never finalize a block", shortHash(genesis.Hash)))
		}
	} else {

		genesisAcct := GenesisAccount()
		gchain, err := l.store.GetAccountChain(genesisAcct)
		if err != nil {
			panic(fmt.Sprintf("ledger: load persisted genesis on restart: %v", err))
		}
		if gchain == nil || len(gchain.Blocks) == 0 {
			panic(fmt.Sprintf("ledger: persisted genesis chain for %s is missing on restart", shortAddr(genesisAcct)))
		}
		ApplyGenesisLeaseTiming(gchain.Blocks[0])

		if err := l.rebuildDelegation(); err != nil {
			panic(fmt.Sprintf("ledger: %v", err))
		}
		if err := l.rebuildAssetBalances(); err != nil {
			panic(fmt.Sprintf("ledger: %v", err))
		}
		l.rebuildKeysets()
		l.rebuildAccountKeys()
		l.rebuildReputation()
		l.initBlockCount()
		l.pruneChainlessAccounts()

		if l.GetTotalDelegatedWeight().Sign() == 0 {
			log.Printf("ERROR: total delegated weight is ZERO on startup — no block can finalize and every balance is unspendable until some account delegates again; the network is in silent finality death")
		}
	}
	return l
}

func (l *Ledger) pruneChainlessAccounts() {
	var pruned int
	for acc := range l.Frontiers() {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil {
			continue
		}
		if chain != nil && len(chain.Blocks) > 0 {
			continue
		}
		if err := l.store.CommitUndo(&BlockUndo{
			Account:           acc,
			Chain:             &AccountChain{},
			FrontierHash:      "0",
			DeleteAccount:     true,
			RestoreDelegation: true,
			PrevRep:           "",
		}); err != nil {
			log.Printf("pruneChainlessAccounts: delete ghost %s: %v", shortAddr(acc), err)
			continue
		}
		l.deleteAccountBalances(acc)
		pruned++
	}
	if pruned > 0 {
		log.Printf("ledger: pruned %d chainless ghost account(s) at startup", pruned)
	}
}

func (l *Ledger) SetConflictCallback(fn func(Conflict)) {
	l.conflictMu.Lock()
	l.conflictCallback = fn
	l.conflictMu.Unlock()
}

func (l *Ledger) SetBlockAddedCallback(fn func(*Block)) {
	l.conflictMu.Lock()
	l.blockAddedCallback = fn
	l.conflictMu.Unlock()
}

func (l *Ledger) acquireAccountLock(accountID string) *accountLock {
	l.locksMu.Lock()
	entry, ok := l.locks[accountID]
	if !ok {
		entry = &accountLock{}
		l.locks[accountID] = entry
	}
	entry.waiters++
	l.locksMu.Unlock()

	entry.mu.Lock()
	return entry
}

func (l *Ledger) acquireAccountLockTry(accountID string) (*accountLock, bool) {
	l.locksMu.Lock()
	entry, ok := l.locks[accountID]
	if !ok {
		entry = &accountLock{}
		l.locks[accountID] = entry
	}
	entry.waiters++
	l.locksMu.Unlock()

	if entry.mu.TryLock() {
		return entry, true
	}
	l.locksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.locks, accountID)
	}
	l.locksMu.Unlock()
	return nil, false
}

func (l *Ledger) releaseAccountLock(accountID string, entry *accountLock) {
	entry.mu.Unlock()

	l.locksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.locks, accountID)
	}
	l.locksMu.Unlock()
}

func (l *Ledger) acquireLeaseLock(leaseHash string) *accountLock {
	l.leaseLocksMu.Lock()
	entry, ok := l.leaseLocks[leaseHash]
	if !ok {
		entry = &accountLock{}
		l.leaseLocks[leaseHash] = entry
	}
	entry.waiters++
	l.leaseLocksMu.Unlock()

	entry.mu.Lock()
	return entry
}

func (l *Ledger) releaseLeaseLock(leaseHash string, entry *accountLock) {
	entry.mu.Unlock()

	l.leaseLocksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.leaseLocks, leaseHash)
	}
	l.leaseLocksMu.Unlock()
}

func isLeaseStateTransition(t BlockType) bool {
	switch t {
	case BlockLeaseAccept, BlockLeaseSettle, BlockLeaseCancel, BlockLeaseForceSettle:
		return true
	}
	return false
}

func (l *Ledger) getAssetBalance(account, asset string) uint64 {
	l.assetBalMu.RLock()
	defer l.assetBalMu.RUnlock()
	if m, ok := l.assetBalances[account]; ok {
		return m[asset]
	}
	return 0
}

func (l *Ledger) addAssetBalance(account, asset string, delta uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	if l.assetBalances[account] == nil {
		l.assetBalances[account] = make(map[string]uint64)
	}
	l.assetBalances[account][asset] += delta
}

func (l *Ledger) subAssetBalance(account, asset string, delta uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	m := l.assetBalances[account]
	if m == nil {
		return
	}
	if delta >= m[asset] {
		m[asset] = 0
		return
	}
	m[asset] -= delta
}

func (l *Ledger) setAssetBalance(account, asset string, balance uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	if l.assetBalances[account] == nil {
		l.assetBalances[account] = make(map[string]uint64)
	}
	l.assetBalances[account][asset] = balance
}

func (l *Ledger) deleteAccountBalances(account string) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	delete(l.assetBalances, account)
}

func (l *Ledger) GetAssetBalances(account string) map[string]uint64 {
	l.assetBalMu.RLock()
	defer l.assetBalMu.RUnlock()
	m := l.assetBalances[account]
	if m == nil {
		return map[string]uint64{}
	}
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (l *Ledger) rebuildAssetBalances() error {
	ls, hasLeases := l.store.(LeaseStore)
	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)

		if err != nil {
			return fmt.Errorf("rebuildAssetBalances: GetAccountChain(%s): %w", shortAddr(acc), err)
		}
		if chain == nil {
			continue
		}
		balByAsset := make(map[string]uint64)
		for _, b := range chain.Blocks {
			asset := b.Asset
			if asset == "" {
				asset = "XE"
			}
			balByAsset[asset] = b.Balance

			if b.Type == BlockLeaseSettle {
				if !hasLeases {
					log.Printf("rebuildAssetBalances: lease_settle block %s but store has no LeaseStore", shortHash(b.Hash))
					continue
				}
				lease, err := ls.GetLease(b.Source)
				if err != nil || lease == nil {
					log.Printf("rebuildAssetBalances: lease_settle block %s references missing lease %s", shortHash(b.Hash), shortHash(b.Source))
					continue
				}
				balByAsset["XUSD"] += lease.Stake
			}
		}
		l.assetBalances[acc] = balByAsset
	}
	return nil
}

func (l *Ledger) GetReputation(account string) *ReputationAggregate {
	return l.reputation.Get(account)
}

func (l *Ledger) AllReputations() map[string]*ReputationAggregate {
	return l.reputation.All()
}

func (l *Ledger) rebuildReputation() {
	l.reputation.Reset()

	ls, ok := l.store.(LeaseStore)
	if !ok {
		return
	}
	leases, err := ls.GetAllLeases()
	if err != nil {
		log.Printf("rebuildReputation: GetAllLeases: %v", err)
		return
	}

	for _, lease := range leases {

		if lease.StartTime == 0 {
			continue
		}

		l.reputation.Apply(ReputationEvent{
			Kind:      EventLeaseAccepted,
			Provider:  lease.Provider,
			Consumer:  lease.Consumer,
			Timestamp: lease.StartTime,
		})
		if !lease.Settled {
			continue
		}

		if lease.State == LeaseExpired {
			continue
		}

		if lease.State == LeaseUnfulfilled {
			forceTs := lookupLeaseForceSettleTimestamp(l.store, lease)
			l.reputation.Apply(ReputationEvent{
				Kind:      EventLeaseUnfulfilled,
				Provider:  lease.Provider,
				Consumer:  lease.Consumer,
				Timestamp: forceTs,
			})
			continue
		}

		settleTs := lookupLeaseSettleTimestamp(l.store, lease)
		l.reputation.Apply(ReputationEvent{
			Kind:         EventLeaseSettled,
			Provider:     lease.Provider,
			Consumer:     lease.Consumer,
			Timestamp:    settleTs,
			DurationSecs: lease.Duration,
		})
	}

	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.Type != BlockLeaseCancel {
				continue
			}
			leaseBlock, err := l.store.GetBlock(b.Source)
			if err != nil || leaseBlock == nil {
				continue
			}
			l.reputation.Apply(ReputationEvent{
				Kind:      EventLeaseCancelled,
				Provider:  leaseBlock.Destination,
				Consumer:  b.Account,
				Timestamp: b.Timestamp,
			})
		}
	}
}

func lookupLeaseSettleTimestamp(store Store, lease *Lease) int64 {
	chain, err := store.GetAccountChain(lease.Provider)
	if err != nil || chain == nil {
		return lease.StartTime + int64(lease.Duration)*1e9
	}
	for _, b := range chain.Blocks {
		if b.Type == BlockLeaseSettle && b.Source == lease.LeaseHash {
			return b.Timestamp
		}
	}
	return lease.StartTime + int64(lease.Duration)*1e9
}

func lookupLeaseForceSettleTimestamp(store Store, lease *Lease) int64 {
	chain, err := store.GetAccountChain(lease.Consumer)
	if err != nil || chain == nil {
		return lease.StartTime + int64(lease.Duration)*1e9
	}
	for _, b := range chain.Blocks {
		if b.Type == BlockLeaseForceSettle && b.Source == lease.LeaseHash {
			return b.Timestamp
		}
	}
	return lease.StartTime + int64(lease.Duration)*1e9
}

func normalizeBlockHex(b *Block) {
	b.Account = strings.ToLower(b.Account)
	b.Previous = strings.ToLower(b.Previous)
	b.Hash = strings.ToLower(b.Hash)
	b.Signature = strings.ToLower(b.Signature)
	b.Destination = strings.ToLower(b.Destination)
	b.Source = strings.ToLower(b.Source)
	b.Representative = strings.ToLower(b.Representative)
	b.PubKey = strings.ToLower(b.PubKey)
	for i := range b.Signatures {
		b.Signatures[i].PublicKey = strings.ToLower(b.Signatures[i].PublicKey)
		b.Signatures[i].Sig = strings.ToLower(b.Signatures[i].Sig)
	}
	if b.MSKeyset != nil {
		for i := range b.MSKeyset.Keys {
			b.MSKeyset.Keys[i] = strings.ToLower(b.MSKeyset.Keys[i])
		}
	}
}

func (l *Ledger) AddBlock(b *Block) error {
	return l.addBlock(b, false)
}

func (l *Ledger) AddSyncedBlock(b *Block) error {
	return l.addBlock(b, true)
}

func (l *Ledger) addBlock(b *Block, skipTimestamp bool) error {
	bc := *b
	if len(bc.Attestations) > 0 {
		bc.Attestations = append([]TimekeeperAttestation(nil), bc.Attestations...)
	}
	b = &bc
	normalizeBlockHex(b)

	if b.Type != BlockLeaseAccept && b.Type != BlockLeaseSettle && b.Type != BlockLeaseForceSettle {
		b.Attestations = nil
	}

	if len(b.Attestations) > MaxAttestationsPerBlock {
		return fmt.Errorf("too many attestations: %d exceeds max %d", len(b.Attestations), MaxAttestationsPerBlock)
	}

	if err := VerifyBlock(b); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if l.difficulty > 0 {
		hashBytes, err := hex.DecodeString(b.Hash)
		if err != nil {
			return fmt.Errorf("decode hash: %w", err)
		}
		if !ValidatePoW(hashBytes, b.PoWNonce, l.difficulty) {
			return ErrInvalidPoW
		}
	}

	if !skipTimestamp && l.timestampWindow > 0 {
		if b.Timestamp < 0 {
			return fmt.Errorf("block timestamp must not be negative")
		}
		nowNanos := Now().UnixNano()
		var delta int64
		if b.Timestamp > nowNanos {
			delta = b.Timestamp - nowNanos
		} else {
			delta = nowNanos - b.Timestamp
		}
		if delta > l.timestampWindow {
			return fmt.Errorf("block timestamp out of range: delta=%v", time.Duration(delta))
		}
	}

	entry := l.acquireAccountLock(b.Account)
	defer l.releaseAccountLock(b.Account, entry)

	if isLeaseStateTransition(b.Type) && b.Source != "" {
		leaseEntry := l.acquireLeaseLock(b.Source)
		defer l.releaseLeaseLock(b.Source, leaseEntry)
	}

	existing, err := l.store.GetBlock(b.Hash)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if existing != nil {
		return nil
	}

	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}

	if cs, ok := l.store.(ConflictStore); ok {

		chain, err := l.store.GetAccountChain(b.Account)
		if err != nil {
			return fmt.Errorf("GetAccountChain (conflict detect): %w", err)
		}

		siblingHash := detectConflictSibling(chain, b)
		if siblingHash == "" {

			conflicts, cerr := cs.GetConflictsForAccount(b.Account)
			if cerr == nil && len(conflicts) > 0 {
				return fmt.Errorf("account has unresolved conflict — block rejected pending resolution")
			}
		} else {

			if l.IsFinalized(b.Account, siblingHash) {
				return fmt.Errorf("block conflicts with finalized block %s — rejected", shortHash(siblingHash))
			}

			if b.Asset == "" {
				return fmt.Errorf("conflict block must have an asset")
			}
			if !IsValidAsset(b.Asset) {
				return fmt.Errorf("conflict block: unsupported asset: %q", b.Asset)
			}

			var parentBalance uint64
			if chain != nil && b.Previous != "0" {
				for _, cb := range chain.Blocks {
					if cb.Asset == b.Asset {
						parentBalance = cb.Balance
					}
					if cb.Hash == b.Previous {
						break
					}
				}
			}
			if err := l.ValidateStagedBlock(b, parentBalance); err != nil {
				return fmt.Errorf("conflict block: %w", err)
			}

			isNew, rerr := recordConflict(cs, b.Account, b.Previous, siblingHash, b.Hash)
			if rerr != nil {
				return fmt.Errorf("recordConflict: %w", rerr)
			}

			record, _ := cs.GetConflict(b.Account, b.Previous)
			bodyNewlyStaged := false
			if record != nil && containsConflictHash(record.BlockHashes, b.Hash) {
				if prev, _ := cs.GetStagedBlock(b.Hash); prev == nil {
					bodyNewlyStaged = true
				}
				if err := cs.SaveStagedBlock(b); err != nil {
					return fmt.Errorf("SaveStagedBlock: %w", err)
				}
			}
			if isNew {

				record, err := cs.GetConflict(b.Account, b.Previous)
				if err == nil && record != nil {

					record.WeightSnapshot = l.snapshotWeights()
					var total uint64
					for _, w := range record.WeightSnapshot {
						total += w
					}
					record.TotalWeight = total
					if err := cs.SaveConflict(record); err != nil {
						return fmt.Errorf("SaveConflict (weight snapshot): %w", err)
					}
					l.conflictMu.Lock()
					cb := l.conflictCallback
					l.conflictMu.Unlock()
					if cb != nil {
						rec := *record
						go cb(rec)
					}
				}
			} else if bodyNewlyStaged {

				l.conflictMu.Lock()
				cb := l.conflictCallback
				l.conflictMu.Unlock()
				if cb != nil && record != nil {
					rec := *record
					go cb(rec)
				}
			}
			return nil
		}
	}

	if b.Asset == "" {
		return fmt.Errorf("block must have an asset")
	}
	if !IsValidAsset(b.Asset) {
		return fmt.Errorf("unsupported asset: %q", b.Asset)
	}

	addErr := l.dispatchValidateAndAdd(b, skipTimestamp)
	if addErr == errUnknownBlockType {
		return fmt.Errorf("unknown block type: %s", b.Type)
	}
	if addErr == nil {

		l.fireBlockAdded(b)
	}
	return addErr
}

var errUnknownBlockType = errors.New("unknown block type")

func (l *Ledger) dispatchValidateAndAdd(b *Block, skipTimestamp bool) error {

	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}
	switch b.Type {
	case BlockSend:
		return l.validateAndAddSend(b)
	case BlockReceive:
		return l.validateAndAddReceive(b)
	case BlockGenesis:
		return l.validateAndAddGenesis(b)
	case BlockLease:
		return l.validateAndAddLease(b)
	case BlockLeaseAccept:
		return l.validateAndAddLeaseAccept(b, skipTimestamp)
	case BlockLeaseSettle:
		return l.validateAndAddLeaseSettle(b, skipTimestamp)
	case BlockLeaseCancel:
		return l.validateAndAddLeaseCancel(b)
	case BlockLeaseForceSettle:
		return l.validateAndAddLeaseForceSettle(b, skipTimestamp)
	case BlockMultisigOpen:
		return l.validateAndAddMultisigOpen(b)
	case BlockMultisigUpdate:
		return l.validateAndAddMultisigUpdate(b)
	case BlockBurn:
		return l.validateAndAddBurn(b)
	case BlockMint:
		return l.validateAndAddMint(b)
	default:

		if dv, gated := darkValidators[b.Type]; gated {
			if !l.FeatureActive(dv.feature) {
				return errFeatureNotActivatedFor(b.Type, dv.feature)
			}
			return dv.validate(l, b, skipTimestamp)
		}
		return errUnknownBlockType
	}
}

func (l *Ledger) fireBlockAdded(b *Block) {
	l.conflictMu.Lock()
	cb := l.blockAddedCallback
	l.conflictMu.Unlock()
	if cb != nil {
		bc := *b
		go cb(&bc)
	}
}

func (l *Ledger) validateAndAddSend(b *Block) error {
	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("send from unopened account: %s", shortAddr(b.Account))
	}

	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}

	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Amount == 0 {
		return fmt.Errorf("send amount must be > 0")
	}
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient balance: have %d, sending %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}
	if b.Destination == "" {
		return fmt.Errorf("send must have a destination")
	}
	if b.Destination == b.Account {
		return fmt.Errorf("cannot send to self")
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.AddPending = &PendingSend{
		SendHash:    b.Hash,
		Source:      b.Account,
		Destination: b.Destination,
		Amount:      b.Amount,
		Asset:       b.Asset,
	}
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) validateAndAddBurn(b *Block) error {
	if b.Asset != "XE" {
		return fmt.Errorf("burn: restricted to XE")
	}
	if b.Destination != "" || b.Source != "" {
		return fmt.Errorf("burn: must not have source or destination")
	}
	if b.Amount == 0 {
		return fmt.Errorf("burn: amount must be > 0")
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("burn from unopened account: %s", shortAddr(b.Account))
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient balance: have %d XE, burning %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return fmt.Errorf("burn: %w", err)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) isLiveLeaseEscrow(sendHash string) bool {

	lease, ok, err := l.getLeaseOverlay(sendHash)
	if !ok || err != nil || lease == nil {
		return false
	}
	return lease.State == LeaseCreated || lease.State == LeaseAccepted
}

func (l *Ledger) validateAndAddReceive(b *Block) error {
	if b.Source == "" {
		return fmt.Errorf("receive must reference a source send")
	}

	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("source send not pending: %s", shortHash(b.Source))
	}
	if pending.Destination != b.Account {
		return fmt.Errorf("send not addressed to this account")
	}

	if l.isLiveLeaseEscrow(b.Source) {
		return fmt.Errorf("cannot receive a live lease escrow: %s", shortHash(b.Source))
	}

	if src := l.GetBlockOrStaged(b.Source); src != nil {
		if l.GetConflict(src.Account, src.Previous) != nil {
			return fmt.Errorf("source send %s is contested by an unresolved conflict — receive deferred pending resolution", shortHash(b.Source))
		}
	}

	pendingAsset := pending.Asset
	if pendingAsset == "" {
		pendingAsset = "XE"
	}
	if b.Asset != pendingAsset {
		return fmt.Errorf("receive asset %q does not match pending send asset %q", b.Asset, pendingAsset)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {

		if b.Previous != "0" {
			return fmt.Errorf("first block on account must have previous=0")
		}
	} else {

		if len(chain.Blocks) > 0 {
			lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
			if b.Timestamp < lastTs {
				return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
			}
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if chain == nil {
		if b.Balance != pending.Amount {
			return fmt.Errorf("open-receive balance mismatch: expected %d, got %d", pending.Amount, b.Balance)
		}
	} else {
		if b.Previous != chain.Frontier() {
			return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
		}
		expectedBal := oldBal + pending.Amount
		if expectedBal < oldBal {
			return fmt.Errorf("receive would overflow uint64 balance")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("receive balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) MintForTesting(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("mint: restricted to XUSD")
	}
	return l.seedForTesting(b)
}

func (l *Ledger) SeedAssetForTesting(b *Block) error {
	if !IsValidAsset(b.Asset) {
		return fmt.Errorf("mint: unsupported asset: %q", b.Asset)
	}
	return l.seedForTesting(b)
}

func (l *Ledger) seedForTesting(b *Block) error {
	if b.Type != BlockMint {
		return fmt.Errorf("mint: block type must be mint")
	}
	if b.Amount == 0 {
		return fmt.Errorf("mint: amount must be > 0")
	}

	if err := VerifyBlock(b); err != nil {
		return fmt.Errorf("mint verify: %w", err)
	}

	if err := l.verifyBlockCredential(b); err != nil {
		return fmt.Errorf("mint verify: %w", err)
	}
	if l.difficulty > 0 {
		hashBytes, err := hex.DecodeString(b.Hash)
		if err != nil {
			return fmt.Errorf("decode hash: %w", err)
		}
		if !ValidatePoW(hashBytes, b.PoWNonce, l.difficulty) {
			return ErrInvalidPoW
		}
	}

	entry := l.acquireAccountLock(b.Account)
	defer l.releaseAccountLock(b.Account, entry)

	existing, err := l.store.GetBlock(b.Hash)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if existing != nil {
		return nil
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}

	if chain == nil {
		if b.Previous != "0" {
			return fmt.Errorf("mint: first block must have previous=0")
		}
		if b.Balance != b.Amount {
			return fmt.Errorf("mint: balance mismatch: expected %d, got %d", b.Amount, b.Balance)
		}
	} else {
		if b.Previous != chain.Frontier() {
			return fmt.Errorf("mint: previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
		}
		if len(chain.Blocks) > 0 {
			lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
			if b.Timestamp < lastTs {
				return fmt.Errorf("mint: timestamp before previous block")
			}
		}
		oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
		if b.Balance != oldBal+b.Amount {
			return fmt.Errorf("mint: balance must be previous + %d", b.Amount)
		}
	}

	return l.addBlockLocked(b)
}

func (l *Ledger) validateAndAddGenesis(b *Block) error {

	empty, err := l.store.IsEmpty()
	if err != nil {
		return fmt.Errorf("IsEmpty: %w", err)
	}
	if !empty {
		return fmt.Errorf("genesis block rejected: ledger is not empty")
	}

	expected, err := LoadGenesisBlock()
	if err != nil {
		return fmt.Errorf("load embedded genesis: %w", err)
	}
	if b.Hash != expected.Hash {
		return fmt.Errorf("genesis hash mismatch: got %s, want %s", shortHash(b.Hash), shortHash(expected.Hash))
	}

	if err := ValidateGenesisBlock(b); err != nil {
		return err
	}

	return l.addBlockLocked(b)
}

func (l *Ledger) validateAndAddMultisigOpen(b *Block) error {
	if b.MSKeyset == nil {
		return fmt.Errorf("multisig_open must include a keyset")
	}
	if err := ValidateKeyset(b.MSKeyset); err != nil {
		return fmt.Errorf("multisig_open keyset: %w", err)
	}

	expected, err := DeriveMultisigAddress(b.MSKeyset)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}
	if b.Account != expected {
		return fmt.Errorf("multisig_open account mismatch: got %s, want %s", shortHash(b.Account), shortHash(expected))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain != nil {
		return fmt.Errorf("multisig_open: account already exists")
	}
	if b.Previous != "0" {
		return fmt.Errorf("multisig_open must have previous=0")
	}
	if b.Balance != 0 {
		return fmt.Errorf("multisig_open balance must be 0, got %d", b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.PutKeyset = b.MSKeyset
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.setKeyset(b.Account, b.MSKeyset)
	return nil
}

func (l *Ledger) validateAndAddMultisigUpdate(b *Block) error {
	if b.MSKeyset == nil {
		return fmt.Errorf("multisig_update must include a keyset")
	}
	if err := ValidateKeyset(b.MSKeyset); err != nil {
		return fmt.Errorf("multisig_update keyset: %w", err)
	}

	oldKs := l.getKeysetOverlay(b.Account)
	if oldKs == nil {
		return fmt.Errorf("multisig_update: account is not multisig")
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("multisig_update: account not found")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Balance != oldBal {
		return fmt.Errorf("multisig_update balance mismatch: expected %d, got %d", oldBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.PutKeyset = b.MSKeyset
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.setKeyset(b.Account, b.MSKeyset)
	return nil
}

func (l *Ledger) GetKeyset(account string) *Keyset {
	l.keysetMu.RLock()
	defer l.keysetMu.RUnlock()
	return l.keysets[account]
}

func (l *Ledger) setKeyset(account string, ks *Keyset) {
	l.keysetMu.Lock()
	defer l.keysetMu.Unlock()
	cp := *ks
	keys := make([]string, len(ks.Keys))
	copy(keys, ks.Keys)
	cp.Keys = keys
	l.keysets[account] = &cp
}

func (l *Ledger) GetAccountKey(account string) string {
	l.accountKeyMu.RLock()
	pub, ok := l.accountKeys[account]
	l.accountKeyMu.RUnlock()
	if ok {
		return pub
	}

	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return ""
	}
	found := ""
	for _, b := range chain.Blocks {
		if b.PubKey != "" {
			found = b.PubKey
		}
	}
	if found == "" {
		return ""
	}
	l.setAccountKey(account, found)
	return found
}

func (l *Ledger) setAccountKey(account, pubKey string) {
	l.accountKeyMu.Lock()
	defer l.accountKeyMu.Unlock()
	l.accountKeys[account] = pubKey
}

func (l *Ledger) rebuildAccountKeys() {
	for acc := range l.Frontiers() {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.PubKey != "" {
				l.accountKeys[acc] = b.PubKey
			}
		}
	}
}

func (l *Ledger) verifyBlockCredential(b *Block) error {
	if err := ValidatePubKeyDeclaration(b); err != nil {
		return err
	}

	if len(b.Signatures) > 0 {
		var ks *Keyset
		if b.Type == BlockMultisigOpen {
			ks = b.MSKeyset
		} else {
			ks = l.GetKeyset(b.Account)
		}
		if ks == nil {
			ks2, err := l.resolveMissingKeyset(b.Account)
			if err != nil {
				return err
			}
			ks = ks2
		}
		if IsSpendingOp(b.Type) {
			if err := VerifyMultisig(b.Hash, b.Signatures, ks); err != nil {
				return fmt.Errorf("multisig: %w", err)
			}
			return nil
		}
		if err := VerifyMultisigAny(b.Hash, b.Signatures, ks); err != nil {
			return fmt.Errorf("multisig: %w", err)
		}
		return nil
	}

	if l.GetKeyset(b.Account) != nil {

		return fmt.Errorf("multisig account requires signatures")
	}

	var pubKey string
	if b.Previous == "0" {
		pubKey = b.PubKey
	} else {
		pubKey = l.GetAccountKey(b.Account)
		if pubKey == "" {
			return fmt.Errorf("signature: unopened account %s has no declared public key", shortAddr(b.Account))
		}
	}
	if err := VerifyBlockSignatureWith(b, pubKey); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	return nil
}

func (l *Ledger) resolveMissingKeyset(account string) (*Keyset, error) {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {

		return nil, fmt.Errorf("GetAccountChain (keyset lookup): %w", err)
	}
	if chain == nil {
		return nil, fmt.Errorf("block has signatures but multisig keyset is not known: unopened account %s (multisig_open not yet synced)", shortAddr(account))
	}
	var found *Keyset
	for _, cb := range chain.Blocks {
		if (cb.Type == BlockMultisigOpen || cb.Type == BlockMultisigUpdate) && cb.MSKeyset != nil {
			found = cb.MSKeyset
		}
	}
	if found == nil {
		return nil, fmt.Errorf("block has signatures but account is not multisig")
	}
	l.setKeyset(account, found)
	return found, nil
}

func (l *Ledger) rebuildKeysets() {
	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.Type == BlockMultisigOpen || b.Type == BlockMultisigUpdate {
				if b.MSKeyset != nil {
					l.keysets[acc] = b.MSKeyset
				}
			}
		}
	}
}

func (l *Ledger) validateAndAddLease(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease block must have asset=XUSD")
	}
	if b.Destination == "" {
		return fmt.Errorf("lease block must have a destination (provider)")
	}
	if b.Destination == b.Account {
		return fmt.Errorf("cannot lease to self")
	}
	if err := ValidateLeaseDimensions(b.VCPUs, b.MemoryMB, b.DiskGB, b.Duration); err != nil {
		return err
	}
	if b.AccessPubKey != "" {
		sshBytes, err := hex.DecodeString(b.AccessPubKey)
		if err != nil {
			return fmt.Errorf("invalid access_pub_key hex: %w", err)
		}
		if len(sshBytes) != 32 {
			return fmt.Errorf("access_pub_key must be 32 bytes, got %d", len(sshBytes))
		}
	}

	if b.CertificateHash == "" {
		return fmt.Errorf("lease block must include certificate_hash")
	}
	if l.certificateLookupFn == nil {
		return fmt.Errorf("lease block cannot be validated: certificate lookup not configured")
	}
	cert := l.certificateLookupFn(b.CertificateHash)
	if cert == nil {
		return fmt.Errorf("certificate %s not found", shortHash(b.CertificateHash))
	}
	if cert.Provider != b.Destination {
		return fmt.Errorf("certificate %s belongs to %s, not lease destination %s",
			shortHash(b.CertificateHash), shortHash(cert.Provider), shortHash(b.Destination))
	}
	if cert.ExpiresAt != 0 && b.Timestamp > cert.ExpiresAt {
		return fmt.Errorf("certificate %s expired at %d, lease timestamp %d",
			shortHash(b.CertificateHash), cert.ExpiresAt, b.Timestamp)
	}
	expectedCost, err := LeaseCost(b.VCPUs, b.MemoryMB, b.DiskGB, b.Duration, cert.PriceMultiplierMilli)
	if err != nil {
		return fmt.Errorf("lease cost %w", err)
	}
	if b.Amount != expectedCost {
		return fmt.Errorf("lease cost mismatch: expected %d (multiplier %d), got %d", expectedCost, cert.PriceMultiplierMilli, b.Amount)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient XUSD balance: have %d, need %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.AddPending = &PendingSend{
		SendHash:    b.Hash,
		Source:      b.Account,
		Destination: b.Destination,
		Amount:      b.Amount,
		Asset:       "XUSD",
	}
	commit.PutLease = &Lease{
		LeaseHash:       b.Hash,
		State:           LeaseCreated,
		Consumer:        b.Account,
		Provider:        b.Destination,
		VCPUs:           b.VCPUs,
		MemoryMB:        b.MemoryMB,
		DiskGB:          b.DiskGB,
		Duration:        b.Duration,
		AccessPubKey:    b.AccessPubKey,
		Cost:            b.Amount,
		CertificateHash: b.CertificateHash,
	}
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) validateAndAddLeaseAccept(b *Block, skipSkew bool) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_accept block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_accept must reference a source lease block")
	}

	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Destination != b.Account {
		return fmt.Errorf("lease_accept: provider account mismatch")
	}

	if existing, ok, err := l.getLeaseOverlay(b.Source); ok {
		if err != nil {
			return fmt.Errorf("GetLease: %w", err)
		}
		if existing != nil && existing.State != LeaseCreated {
			return fmt.Errorf("lease already accepted")
		}
	}

	expectedStake := LeaseStake(leaseBlock.Amount)
	if b.Amount != expectedStake {
		return fmt.Errorf("lease_accept stake mismatch: expected %d, got %d", expectedStake, b.Amount)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_accept from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient XUSD balance for stake: have %d, need %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}

	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_accept: timekeepers not configured")
	}
	tkConfig := l.timekeeperConfigFn()
	if tkConfig == nil {
		return fmt.Errorf("lease_accept: timekeepers not configured")
	}
	startTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfig, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_accept attestation: %w", err)
	}

	if b.CertificateHash == "" {
		return fmt.Errorf("lease_accept: performance certificate required")
	}
	if leaseBlock.CertificateHash != b.CertificateHash {
		return fmt.Errorf("lease_accept: certificate hash %s does not match lease's referenced cert %s",
			shortHash(b.CertificateHash), shortHash(leaseBlock.CertificateHash))
	}
	if l.certificateLookupFn == nil {
		return fmt.Errorf("lease_accept: certificate lookup not configured")
	}
	certInfo := l.certificateLookupFn(b.CertificateHash)
	if certInfo == nil {
		return fmt.Errorf("lease_accept: certificate not found: %s", b.CertificateHash[:12])
	}
	if certInfo.Provider != b.Account {
		return fmt.Errorf("lease_accept: certificate belongs to different provider")
	}
	if startTime > certInfo.ExpiresAt {
		return fmt.Errorf("lease_accept: certificate expired")
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}

	lockedR, lockedCap, lockedTWAP := b.LockedR, b.LockedPayoutCap, b.LockedTWAP
	if lockedR == 0 {
		return fmt.Errorf("lease_accept missing locked emission params: locked_r must be set (the accept must carry locked_r/locked_payout_cap/locked_twap)")
	}
	if l.epochAtFn != nil {

		candidates := l.epochAtFn(startTime)
		if len(candidates) == 0 {

			return fmt.Errorf("lease_accept epoch not yet available for accept time %d: retry after statechain syncs", startTime)
		}
		matched := false
		for i := range candidates {
			e := &candidates[i]
			if lockedR == e.R && lockedCap == e.PayoutCap && lockedTWAP == e.TWAP {
				matched = true
				break
			}
		}

		if !matched {
			cur := candidates[0]
			if skipSkew {

				return fmt.Errorf("lease_accept locked emission mismatch on sync: block (R=%d cap=%d twap=%d) != epoch@accept (R=%d cap=%d twap=%d): retry after statechain syncs",
					lockedR, lockedCap, lockedTWAP, cur.R, cur.PayoutCap, cur.TWAP)
			}
			return fmt.Errorf("lease_accept locked emission mismatch: block (R=%d cap=%d twap=%d) != epoch@accept (R=%d cap=%d twap=%d)",
				lockedR, lockedCap, lockedTWAP, cur.R, cur.PayoutCap, cur.TWAP)
		}
	}

	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseCreated
	commit.PutLease = &Lease{
		LeaseHash:       b.Source,
		State:           LeaseAccepted,
		Consumer:        leaseBlock.Account,
		Provider:        b.Account,
		VCPUs:           leaseBlock.VCPUs,
		MemoryMB:        leaseBlock.MemoryMB,
		DiskGB:          leaseBlock.DiskGB,
		Duration:        leaseBlock.Duration,
		AccessPubKey:    leaseBlock.AccessPubKey,
		Cost:            leaseBlock.Amount,
		Stake:           b.Amount,
		StartTime:       startTime,
		CertificateHash: b.CertificateHash,
		Settled:         false,
		LockedR:         lockedR,
		LockedPayoutCap: lockedCap,
		LockedTWAP:      lockedTWAP,
	}

	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}

	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseAccepted,
		Provider:  b.Account,
		Consumer:  leaseBlock.Account,
		Timestamp: startTime,
	})
	return nil
}

func (l *Ledger) resolveCancelWinsOverAccept(leaseHash, provider string) error {
	pchain, err := l.store.GetAccountChain(provider)
	if err != nil {
		return fmt.Errorf("cancel-wins: GetAccountChain(provider): %w", err)
	}
	if pchain == nil || len(pchain.Blocks) == 0 {

		return fmt.Errorf("cancel-wins: provider accept not found locally: retry after sync")
	}
	acceptIdx := -1
	for i, blk := range pchain.Blocks {
		if blk.Type == BlockLeaseAccept && blk.Source == leaseHash {
			acceptIdx = i
			break
		}
	}
	if acceptIdx == -1 {
		return fmt.Errorf("cancel-wins: provider accept not found locally: retry after sync")
	}
	if acceptIdx != len(pchain.Blocks)-1 {

		return fmt.Errorf("cancel-wins: provider built on the accept: retry after sync")
	}
	if fh := l.FinalHeight(provider); uint64(acceptIdx+1) <= fh {

		return fmt.Errorf("cannot cancel lease in accepted state: accept is finalized")
	}
	acceptBlock := pchain.Blocks[acceptIdx]

	entry, ok := l.acquireAccountLockTry(provider)
	if !ok {
		return fmt.Errorf("cancel-wins: provider chain busy: retry after sync")
	}
	defer l.releaseAccountLock(provider, entry)

	if err := l.undoBlockApply(provider, acceptBlock); err != nil {
		return fmt.Errorf("cancel-wins: unwind provider accept: %w", err)
	}
	log.Printf("lease %s: cancel-wins over a racing accept — unwound provider %s's accept %s",
		shortHash(leaseHash), shortAddr(provider), shortHash(acceptBlock.Hash))
	return nil
}

func (l *Ledger) validateAndAddLeaseCancel(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_cancel block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_cancel must reference a source lease block")
	}

	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Account != b.Account {
		return fmt.Errorf("lease_cancel: only the consumer can cancel a lease")
	}

	if existing, ok, err := l.getLeaseOverlay(b.Source); ok {
		if err != nil {
			return fmt.Errorf("GetLease: %w", err)
		}
		if existing != nil && existing.State == LeaseAccepted && existing.Provider != b.Account {
			if rerr := l.resolveCancelWinsOverAccept(b.Source, existing.Provider); rerr != nil {
				return rerr
			}
		} else if existing != nil && existing.State != LeaseCreated {
			return fmt.Errorf("cannot cancel lease in %s state", existing.State)
		}
	}

	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("no pending send for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_cancel from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	expectedBal := oldBal + leaseBlock.Amount
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	commit.CancelLeaseHash = b.Source

	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseCreated
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseCancelled,
		Provider:  leaseBlock.Destination,
		Consumer:  b.Account,
		Timestamp: b.Timestamp,
	})
	return nil
}

func (l *Ledger) validateAndAddLeaseForceSettle(b *Block, skipSkew bool) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_force_settle block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_force_settle must reference a source lease block")
	}

	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Account != b.Account {
		return fmt.Errorf("lease_force_settle: only the consumer can force-settle a lease")
	}

	lease, ok, err := l.getLeaseOverlay(b.Source)
	if !ok {
		return fmt.Errorf("store does not support leases")
	}
	if err != nil {
		return fmt.Errorf("GetLease: %w", err)
	}
	if lease == nil {
		return fmt.Errorf("lease not found: %s", shortHash(b.Source))
	}
	if lease.Settled {
		return fmt.Errorf("lease already settled")
	}
	if lease.State != LeaseAccepted {

		if lease.State == LeaseCreated {
			return fmt.Errorf("lease not yet accepted for force-settle (state %s): retry after accept", lease.State)
		}
		return fmt.Errorf("cannot force-settle lease in %s state", lease.State)
	}

	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_force_settle: timekeepers not configured")
	}
	tkConfig := l.timekeeperConfigFn()
	if tkConfig == nil {
		return fmt.Errorf("lease_force_settle: timekeepers not configured")
	}
	forceTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfig, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_force_settle attestation: %w", err)
	}
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	eligibleAt := expiry + LeaseSettleGrace + LeaseForceSettleGap
	if forceTime < eligibleAt {
		return fmt.Errorf("lease not yet force-settleable: need timestamp >= %d, got %d", eligibleAt, forceTime)
	}

	if expireAt := expiry + LeaseEscrowExpiry; forceTime >= expireAt {
		return fmt.Errorf("lease escrow expired: refund window closed at %d, got %d", expireAt, forceTime)
	}

	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("no pending escrow for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_force_settle from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	expectedBal := oldBal + leaseBlock.Amount
	if expectedBal < oldBal {
		return fmt.Errorf("lease_force_settle would overflow uint64 balance")
	}
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	commit.UnfulfillLeaseHash = b.Source

	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseAccepted
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}

	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseUnfulfilled,
		Provider:  lease.Provider,
		Consumer:  b.Account,
		Timestamp: b.Timestamp,
	})
	return nil
}

func (l *Ledger) CurrentR() uint64 {
	if l.epochRFn != nil {
		r := l.epochRFn()
		if r > 0 {
			return r
		}
	}
	return RFallback
}

func (l *Ledger) CurrentPayoutCap() uint64 {
	if l.epochPayoutCapFn == nil {
		return 0
	}
	return l.epochPayoutCapFn()
}

func (l *Ledger) CurrentTWAP() uint64 {
	if l.epochTWAPFn == nil {
		return 0
	}
	return l.epochTWAPFn()
}

func CapR(r, payoutCap, twapMilliUSD uint64) uint64 {
	if payoutCap == 0 || twapMilliUSD == 0 {
		return r
	}

	scaled, ok := safeMul(payoutCap, 1000)
	if !ok {
		return r
	}
	rCapMax := ceilDiv(scaled, twapMilliUSD)
	if rCapMax < r {
		return rCapMax
	}
	return r
}

func LeaseEmissionChecked(cost, r uint64) (uint64, error) {
	product, ok := safeMul(cost, r)
	if !ok {
		return 0, fmt.Errorf("lease emission overflow: cost(%d) * r(%d)", cost, r)
	}
	emission := ceilDiv(product, 1000)
	if emission == 0 {
		emission = 1
	}
	return emission, nil
}

func LeaseEmission(cost, r uint64) uint64 {
	emission, _ := LeaseEmissionChecked(cost, r)
	return emission
}

func (l *Ledger) validateAndAddLeaseSettle(b *Block, skipSkew bool) error {
	if b.Asset != "XE" {
		return fmt.Errorf("lease_settle block must have asset=XE")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_settle must reference a source lease hash")
	}

	lease, ok, err := l.getLeaseOverlay(b.Source)
	if !ok {
		return fmt.Errorf("store does not support leases")
	}
	if err != nil {
		return fmt.Errorf("GetLease: %w", err)
	}
	if lease == nil {
		return fmt.Errorf("lease not found: %s", shortHash(b.Source))
	}
	if lease.Settled {
		return fmt.Errorf("lease already settled")
	}
	if lease.Provider != b.Account {
		return fmt.Errorf("lease_settle: provider account mismatch")
	}

	if lease.State != LeaseAccepted {
		if lease.State == LeaseCreated {
			return fmt.Errorf("lease not yet accepted for settle (state %s): retry after accept", lease.State)
		}
		return fmt.Errorf("lease_settle: lease not settleable in %s state", lease.State)
	}

	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_settle: timekeepers not configured")
	}
	tkConfigSettle := l.timekeeperConfigFn()
	if tkConfigSettle == nil {
		return fmt.Errorf("lease_settle: timekeepers not configured")
	}
	settleTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfigSettle, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_settle attestation: %w", err)
	}

	expiry := lease.StartTime + int64(lease.Duration)*1e9
	if settleTime < expiry {
		return fmt.Errorf("lease not yet expired: need timestamp >= %d, got %d", expiry, settleTime)
	}

	if settleTime > expiry+LeaseSettleGrace {
		return fmt.Errorf("lease settle past grace: timestamp %d exceeds expiry+grace %d", settleTime, expiry+LeaseSettleGrace)
	}

	r := lease.LockedR
	payoutCap := lease.LockedPayoutCap
	twap := lease.LockedTWAP
	rCapped := CapR(r, payoutCap, twap)
	expectedXE, err := LeaseEmissionChecked(lease.Cost, rCapped)
	if err != nil {
		return fmt.Errorf("lease_settle: %w", err)
	}
	if b.Amount != expectedXE {
		return fmt.Errorf("lease_settle XE mismatch: expected %d (cost=%d, R=%d, R_capped=%d), got %d", expectedXE, lease.Cost, r, rCapped, b.Amount)
	}

	escrow, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if escrow == nil {
		return fmt.Errorf("no escrow pending to burn for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_settle from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldXEBal := l.getAssetBalanceOverlay(b.Account, "XE")
	expectedBal := oldXEBal + b.Amount
	if expectedBal < oldXEBal {
		return fmt.Errorf("lease_settle would overflow uint64 balance")
	}
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.SettleLeaseHash = b.Source

	commit.DeletePendingID = b.Source

	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseAccepted

	commit.AssetCredit = &AssetDelta{Account: b.Account, Asset: "XUSD", Amount: lease.Stake}

	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}

	l.reputation.Apply(ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     lease.Provider,
		Consumer:     lease.Consumer,
		Timestamp:    b.Timestamp,
		DurationSecs: lease.Duration,
	})

	return nil
}

func (l *Ledger) prepareBlockWrite(b *Block) (*BlockCommit, uint64, error) {

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return nil, 0, fmt.Errorf("GetAccountChain: %w", err)
	}

	prevBalance := l.getAssetBalanceOverlay(b.Account, "XE")
	if chain == nil {
		chain = &AccountChain{}
	}
	chain.Blocks = append(chain.Blocks, b)
	commit := &BlockCommit{
		Block:        b,
		Account:      b.Account,
		Chain:        chain,
		FrontierHash: b.Hash,

		PutAccountKey: b.PubKey,
	}
	return commit, prevBalance, nil
}

func (l *Ledger) commitBlockWrite(c *BlockCommit, prevBalance uint64) error {

	oldRep, fromOverlay := l.overlayDelegationRep(c.Account)
	if !fromOverlay {
		l.delegationMu.RLock()
		oldRep = l.delegation[c.Account]
		l.delegationMu.RUnlock()
	}

	effectiveRep := c.Block.Representative
	if effectiveRep == "" {
		effectiveRep = oldRep
	}
	if effectiveRep == "" {
		c.DeleteDelegation = true
	} else {
		c.DelegationRep = effectiveRep
	}

	if cascade := l.activeCascadeFor(); cascade != nil && cascade.winnerHash == c.Block.Hash {

		if err := l.atomicStore.CommitCascade(cascade.undos, c); err != nil {
			return fmt.Errorf("CommitCascade: %w", err)
		}

		for _, apply := range cascade.memApplies {
			apply()
		}
		l.deactivateCascade()

		l.blockCount.Add(1)
		asset := c.Block.Asset
		if asset == "" {
			asset = "XE"
		}
		l.setAssetBalance(c.Account, asset, c.Block.Balance)

		if c.PutAccountKey != "" {
			l.setAccountKey(c.Account, c.PutAccountKey)
		}

		if c.AssetCredit != nil {
			l.addAssetBalance(c.AssetCredit.Account, c.AssetCredit.Asset, c.AssetCredit.Amount)
		}

		if err := l.updateDelegation(c.Account, prevBalance, c.Block); err != nil {
			return fmt.Errorf("updateDelegation: %w", err)
		}
		return nil
	}

	if err := l.atomicStore.CommitBlock(c); err != nil {
		return fmt.Errorf("CommitBlock: %w", err)
	}
	l.blockCount.Add(1)

	asset := c.Block.Asset
	if asset == "" {
		asset = "XE"
	}
	l.setAssetBalance(c.Account, asset, c.Block.Balance)

	if c.PutAccountKey != "" {
		l.setAccountKey(c.Account, c.PutAccountKey)
	}

	if c.AssetCredit != nil {
		l.addAssetBalance(c.AssetCredit.Account, c.AssetCredit.Asset, c.AssetCredit.Amount)
	}

	if err := l.updateDelegation(c.Account, prevBalance, c.Block); err != nil {
		return fmt.Errorf("updateDelegation: %w", err)
	}
	return nil
}

func (l *Ledger) addBlockLocked(b *Block) error {
	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) Store() Store {
	return l.store
}

func (l *Ledger) GetBalance(account string) uint64 {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetBalance: store read for %s failed: %v — surfacing as balance 0, NOT a genuine miss", shortAddr(account), err)
		return 0
	}
	if chain == nil {
		return 0
	}
	return chain.LatestBalance()
}

func (l *Ledger) GetChain(account string) []*Block {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetChain: store read for %s failed: %v — surfacing as no chain, NOT a genuine miss", shortAddr(account), err)
		return nil
	}
	if chain == nil {
		return nil
	}
	out := make([]*Block, len(chain.Blocks))
	copy(out, chain.Blocks)
	return out
}

var storeReadErrors atomic.Uint64

func StoreReadErrors() uint64 {
	return storeReadErrors.Load()
}

func (l *Ledger) GetPendingForAccount(account string) []*PendingSend {
	result, err := l.store.GetPendingByDest(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetPendingForAccount: store read for %s failed: %v — surfacing as no pending, NOT a genuine miss", shortAddr(account), err)
		return nil
	}
	return result
}

func (l *Ledger) GetAllPending() []*PendingSend {
	result, err := l.store.GetAllPending()
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetAllPending: store read failed: %v — surfacing as no pending, NOT a genuine empty", err)
		return nil
	}
	return result
}

func (l *Ledger) GetRecentBlocks(limit int) []*Block {
	if limit <= 0 {
		return []*Block{}
	}
	frontiers := l.Frontiers()
	result := make([]*Block, 0, limit)

	var minTs int64
	for acc := range frontiers {
		chain := l.GetChain(acc)

		start := len(chain) - limit
		if start < 0 {
			start = 0
		}
		for i := len(chain) - 1; i >= start; i-- {
			b := chain[i]
			if len(result) >= limit && b.Timestamp <= minTs {
				break
			}
			result = append(result, b)
		}

		if len(result) > limit {
			sort.Slice(result, func(i, j int) bool {
				return result[i].Timestamp > result[j].Timestamp
			})
			result = result[:limit]
			minTs = result[limit-1].Timestamp
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp > result[j].Timestamp
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (l *Ledger) GetBlock(hash string) *Block {
	b, err := l.store.GetBlock(hash)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetBlock: store read for %s failed: %v — surfacing as not-found, NOT a genuine miss", shortHash(hash), err)
		return nil
	}
	return b
}

func (l *Ledger) GetBlockOrStaged(hash string) *Block {
	if b := l.GetBlock(hash); b != nil {
		return b
	}
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return nil
	}
	b, err := cs.GetStagedBlock(hash)
	if err != nil {
		return nil
	}
	return b
}

func (l *Ledger) GetConflict(account, previousHash string) *Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return nil
	}
	c, err := cs.GetConflict(account, previousHash)
	if err != nil {
		return nil
	}
	return c
}

func (l *Ledger) GetConflictsForAccount(account string) []*Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return []*Conflict{}
	}
	conflicts, err := cs.GetConflictsForAccount(account)
	if err != nil {
		return []*Conflict{}
	}
	return conflicts
}

func (l *Ledger) GetAllConflicts() []*Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return []*Conflict{}
	}
	conflicts, err := cs.GetAllConflicts()
	if err != nil {
		return []*Conflict{}
	}
	return conflicts
}

func (l *Ledger) AllChains() []string {
	frontiers := l.Frontiers()
	accounts := make([]string, 0, len(frontiers))
	for acc := range frontiers {
		accounts = append(accounts, acc)
	}
	return accounts
}

func (l *Ledger) BlockCount() int {
	return int(l.blockCount.Load())
}

func (l *Ledger) DelegationUnderflows() uint64 {
	return l.delegationUnderflow.Load()
}

func (l *Ledger) recordFinalityAdvance() {
	l.finalityAdvances.Add(1)
	l.lastFinalityNs.Store(Now().UnixNano())
}

func (l *Ledger) FinalityAdvances() uint64 {
	return l.finalityAdvances.Load()
}

func (l *Ledger) LastFinalityNs() int64 {
	return l.lastFinalityNs.Load()
}

func (l *Ledger) initBlockCount() {
	frontiers := l.Frontiers()
	var count int64
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		count += int64(len(chain.Blocks))
	}
	l.blockCount.Store(count)
}

func (l *Ledger) Frontiers() map[string]string {
	if fl, ok := l.store.(FrontierLister); ok {
		return fl.AllFrontiers()
	}
	return map[string]string{}
}

func (l *Ledger) LocksCount() int {
	l.locksMu.Lock()
	defer l.locksMu.Unlock()
	return len(l.locks)
}

func (l *Ledger) rebuildDelegation() error {
	di, ok := l.store.(DelegationIterator)
	if !ok {
		return nil
	}
	err := di.IterateDelegations(func(account, representative string) error {
		if representative == "" {
			return nil
		}
		l.delegation[account] = representative

		chain, err := l.store.GetAccountChain(account)

		if err != nil {
			return fmt.Errorf("GetAccountChain(%s): %w", shortAddr(account), err)
		}
		if chain == nil {
			return nil
		}
		var xeBal uint64
		for _, b := range chain.Blocks {
			a := b.Asset
			if a == "" {
				a = "XE"
			}
			if a == "XE" {
				xeBal = b.Balance
			}
		}
		bal := new(big.Int).SetUint64(xeBal)
		if l.weights[representative] == nil {
			l.weights[representative] = new(big.Int)
		}
		l.weights[representative].Add(l.weights[representative], bal)
		return nil
	})
	if err != nil {
		return fmt.Errorf("rebuildDelegation: %w", err)
	}
	return nil
}

func (l *Ledger) updateDelegation(account string, prevBalance uint64, newBlock *Block) error {
	newRep := newBlock.Representative

	l.assetBalMu.RLock()
	var newXEBal uint64
	if m := l.assetBalances[account]; m != nil {
		newXEBal = m["XE"]
	}
	l.assetBalMu.RUnlock()

	asset := newBlock.Asset
	if asset == "" {
		asset = "XE"
	}
	prevXEBal := prevBalance
	if asset != "XE" {

		prevXEBal = newXEBal
	}

	l.delegationMu.Lock()
	defer l.delegationMu.Unlock()

	oldRep := l.delegation[account]

	effectiveRep := newRep
	if effectiveRep == "" {
		effectiveRep = oldRep
	}

	if oldRep != "" {
		if l.weights[oldRep] == nil {
			l.weights[oldRep] = new(big.Int)
		}
		prev := new(big.Int).SetUint64(prevXEBal)
		l.weights[oldRep].Sub(l.weights[oldRep], prev)
		if l.weights[oldRep].Sign() < 0 {

			n := l.delegationUnderflow.Add(1)
			log.Printf("ERROR: delegation weight underflow for representative %s (balance subtracted: %d); clamped to 0 — DATA CORRUPTION, total underflows=%d",
				shortAddr(oldRep), prevXEBal, n)
			l.weights[oldRep].SetInt64(0)
		}
	}

	if effectiveRep == "" {
		delete(l.delegation, account)
	} else {
		l.delegation[account] = effectiveRep
	}

	if effectiveRep != "" {
		if l.weights[effectiveRep] == nil {
			l.weights[effectiveRep] = new(big.Int)
		}
		l.weights[effectiveRep].Add(l.weights[effectiveRep], new(big.Int).SetUint64(newXEBal))
	}

	return nil
}

func (l *Ledger) snapshotWeights() map[string]uint64 {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	set := l.eligibleAllowlistLocked()
	snap := make(map[string]uint64, len(l.weights))
	for rep, w := range l.weights {
		if w != nil && w.Sign() > 0 && repEligibleLocked(set, rep) {
			if w.IsUint64() {
				snap[rep] = w.Uint64()
			} else {
				snap[rep] = math.MaxUint64
			}
		}
	}
	return snap
}

func (l *Ledger) GetRepresentative(account string) string {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.delegation[account]
}

func (l *Ledger) GetVoteWeight(representative string) *big.Int {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	if !repEligibleLocked(l.eligibleAllowlistLocked(), representative) {
		return new(big.Int)
	}
	w := l.weights[representative]
	if w == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(w)
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

func shortAddr(a string) string {
	return shortHash(a)
}

func (l *Ledger) GetVoteWeights() map[string]uint64 {
	return l.snapshotWeights()
}

func (l *Ledger) GetTotalDelegatedWeight() *big.Int {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.sumEligibleLocked(l.eligibleAllowlistLocked())
}

func (l *Ledger) ValidateStagedBlock(b *Block, parentBalance uint64) error {

	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}
	switch b.Type {
	case BlockSend:
		if b.Amount == 0 {
			return fmt.Errorf("staged send: amount must be > 0")
		}
		if b.Amount > parentBalance {
			return fmt.Errorf("staged send: insufficient balance: have %d, sending %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged send: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
		if b.Destination == "" {
			return fmt.Errorf("staged send: must have a destination")
		}
		if b.Destination == b.Account {
			return fmt.Errorf("staged send: cannot send to self")
		}
	case BlockReceive:
		if b.Source == "" {
			return fmt.Errorf("staged receive: must reference a source send")
		}
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged receive: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged receive: source send not pending: %s", shortHash(b.Source))
		}
		if pending.Destination != b.Account {
			return fmt.Errorf("staged receive: send not addressed to this account")
		}

		if l.isLiveLeaseEscrow(b.Source) {
			return fmt.Errorf("staged receive: cannot receive a live lease escrow: %s", shortHash(b.Source))
		}
		expectedBal := parentBalance + pending.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged receive: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged receive: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLease:
		if b.Amount > parentBalance {
			return fmt.Errorf("staged lease: insufficient balance: have %d, need %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged lease: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockLeaseAccept:
		if b.Amount > parentBalance {
			return fmt.Errorf("staged lease_accept: insufficient balance: have %d, need %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged lease_accept: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockLeaseSettle:

		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_settle: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_settle: no pending escrow for lease")
		}
		expectedBal := parentBalance + b.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged lease_settle: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_settle: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLeaseCancel:
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_cancel: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_cancel: no pending send for lease")
		}
		expectedBal := parentBalance + pending.Amount
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_cancel: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLeaseForceSettle:
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_force_settle: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_force_settle: no pending escrow for lease")
		}
		expectedBal := parentBalance + pending.Amount
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_force_settle: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockMultisigOpen:
		return fmt.Errorf("staged multisig_open: conflicting account opens are invalid")
	case BlockMultisigUpdate:
		if b.Balance != parentBalance {
			return fmt.Errorf("staged multisig_update: balance mismatch: expected %d, got %d", parentBalance, b.Balance)
		}
	case BlockBurn:
		if b.Asset != "XE" {
			return fmt.Errorf("staged burn: restricted to XE")
		}
		if b.Amount == 0 {
			return fmt.Errorf("staged burn: amount must be > 0")
		}
		if b.Amount > parentBalance {
			return fmt.Errorf("staged burn: insufficient balance: have %d XE, burning %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged burn: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockMint:

		if b.Asset != "XUSD" {
			return fmt.Errorf("staged mint: restricted to XUSD")
		}
		if !l.isMinter(b.Account) {
			return fmt.Errorf("staged mint: account %s is not an authorized minter", shortAddr(b.Account))
		}
		if b.Amount == 0 {
			return fmt.Errorf("staged mint: amount must be > 0")
		}
		expectedBal := parentBalance + b.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged mint: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged mint: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	default:
		return fmt.Errorf("staged block: unknown type: %s", b.Type)
	}
	return nil
}

func (l *Ledger) SwapBlock(account string, oldHash, newHash string, newBlock *Block) error {
	if err := VerifyBlock(newBlock); err != nil {
		return fmt.Errorf("SwapBlock: verify replacement: %w", err)
	}

	entry := l.acquireAccountLock(account)
	defer l.releaseAccountLock(account, entry)

	return l.swapBlockLocked(account, oldHash, newHash, newBlock)
}

var ErrWinnerFullValidation = errors.New("winner failed full validation")

func (l *Ledger) swapBlockLocked(account string, oldHash, newHash string, newBlock *Block) error {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return fmt.Errorf("SwapBlock: GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("SwapBlock: account %s not found", shortAddr(account))
	}

	idx := -1
	var oldBlock *Block
	for i, b := range chain.Blocks {
		if b.Hash == oldHash {
			idx = i
			oldBlock = b
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("SwapBlock: block %s not found in chain", shortHash(oldHash))
	}

	if l.finalStore != nil {
		fh, _ := l.finalStore.GetFinalHeight(account)
		if uint64(idx+1) <= fh {
			return fmt.Errorf("SwapBlock: refusing to replace finalized block %s at height %d (final height %d)",
				shortHash(oldHash), idx+1, fh)
		}
	}

	planned := map[string]bool{}
	var plan []cascadeStep
	for i := len(chain.Blocks) - 1; i > idx; i-- {
		b := chain.Blocks[i]
		if planned[b.Hash] {
			continue
		}
		switch b.Type {
		case BlockSend, BlockReceive, BlockBurn, BlockMint:

		default:
			return fmt.Errorf("SwapBlock: cannot unwind descendant %q (%s) of the replaced block — reversing its side-effects is not yet implemented", b.Type, shortHash(b.Hash))
		}
		planned[b.Hash] = true
		if b.Type == BlockSend {
			if ps, _ := l.store.GetPendingSend(b.Hash); ps == nil {
				if err := l.planRollbackOfSend(b.Hash, planned, &plan); err != nil {
					return fmt.Errorf("SwapBlock: %w", err)
				}
			}
		}
		plan = append(plan, cascadeStep{account: account, b: b})
	}
	if oldBlock.Type == BlockSend {
		oldPlan, perr := l.planCascade(oldBlock.Hash, planned)
		if perr != nil {
			return fmt.Errorf("SwapBlock: %w", perr)
		}
		plan = append(plan, oldPlan...)
	}

	plan = append(plan, cascadeStep{account: account, b: oldBlock})

	type heldLock struct {
		acc   string
		entry *accountLock
	}
	seenLock := map[string]bool{}
	var foreign []string
	for _, st := range plan {
		if st.account == account || seenLock[st.account] {
			continue
		}
		seenLock[st.account] = true
		foreign = append(foreign, st.account)
	}
	sort.Strings(foreign)
	var locks []heldLock
	for _, acc := range foreign {
		locks = append(locks, heldLock{acc, l.acquireAccountLock(acc)})
	}
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			l.releaseAccountLock(locks[i].acc, locks[i].entry)
		}
	}()

	cascade := newCascadeBuild(newHash)
	snapshots := map[string]*AccountChain{}
	for _, st := range plan {
		snap, ok := snapshots[st.account]
		if !ok {
			s, serr := l.store.GetAccountChain(st.account)
			if serr != nil {
				return fmt.Errorf("SwapBlock: GetAccountChain(%s): %w", shortAddr(st.account), serr)
			}
			if s == nil {
				return fmt.Errorf("SwapBlock: account %s vanished under the cascade", shortAddr(st.account))
			}
			snap = s
			snapshots[st.account] = snap
		}
		undo, apply, berr := l.buildBlockUndo(st.account, st.b, snap)
		if berr != nil {
			return fmt.Errorf("SwapBlock: build undo for %s: %w", shortHash(st.b.Hash), berr)
		}
		cascade.addUndo(undo, apply)

		snapshots[st.account] = undo.Chain
	}

	if err := l.activateCascade(cascade); err != nil {
		return fmt.Errorf("SwapBlock: %w", err)
	}

	if err := l.dispatchValidateAndAdd(newBlock, true); err != nil {

		l.deactivateCascade()
		return fmt.Errorf("SwapBlock: %w %s, loser kept: %w", ErrWinnerFullValidation, shortHash(newHash), err)
	}

	l.deactivateCascade()
	return nil
}

func (l *Ledger) GetAssetBalanceAtBlock(account, asset, blockHash string) uint64 {
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return 0
	}
	ls, hasLeases := l.store.(LeaseStore)
	xusd := asset == "XUSD"
	var bal uint64
	for _, b := range chain.Blocks {
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if a == asset {
			bal = b.Balance
		}
		if xusd && b.Type == BlockLeaseSettle && hasLeases {
			if lease, lerr := ls.GetLease(b.Source); lerr == nil && lease != nil {
				bal += lease.Stake
			}
		}
		if b.Hash == blockHash {
			break
		}
	}
	return bal
}

func (l *Ledger) GetBlockHeight(account, blockHash string) (uint64, error) {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return 0, fmt.Errorf("GetBlockHeight: GetAccountChain: %w", err)
	}
	if chain == nil {
		return 0, fmt.Errorf("GetBlockHeight: account %s not found", shortAddr(account))
	}
	for i, b := range chain.Blocks {
		if b.Hash == blockHash {
			return uint64(i + 1), nil
		}
	}
	return 0, fmt.Errorf("GetBlockHeight: block %s not found in account %s", shortHash(blockHash), shortAddr(account))
}

func (l *Ledger) FinalHeight(account string) uint64 {
	if l.finalStore == nil {
		return 0
	}
	h, err := l.finalStore.GetFinalHeight(account)
	if err != nil {
		return 0
	}
	return h
}

func (l *Ledger) IsFinalized(account, blockHash string) bool {
	h, err := l.GetBlockHeight(account, blockHash)
	if err != nil || h == 0 {
		return false
	}
	return h <= l.FinalHeight(account)
}

func (l *Ledger) FinalizedChildHash(account, prev string) string {
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return ""
	}
	open := prev == "" || prev == "0"
	fh := l.FinalHeight(account)
	for i, b := range chain.Blocks {
		if b.Previous == prev || (open && i == 0) {
			if uint64(i+1) <= fh {
				return b.Hash
			}
			return ""
		}
	}
	return ""
}
