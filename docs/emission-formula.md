# Lease Emission Formula

When a lease settles, the protocol mints XE to the provider. The amount
is determined by the lease cost and the epoch's effective reputation score.
The epoch's R is bounded by R_collusion, so the XE paid is worth at most
95% of the lease cost at the locked TWAP (phase 1). The Hermite payout cap
is applied on top, but it does not bind under the current parameters.

## Formula

```
emission_mXE = lease_cost_mXCU × R_capped / 1000
R_capped     = min(R, payout_cap × 1000 / twap_milli_usd)
```

### Variables

| Variable | Unit | Description |
|---|---|---|
| `emission_mXE` | micro-XE | XE minted to the provider (1 XE = 1,000,000 mXE) |
| `lease_cost_mXCU` | micro-XCU | Lease cost — the `cost` field on the lease block |
| `R` | unitless, ×1000 | Epoch's effective reputation score (e.g. 2000 = 2.000×) |
| `payout_cap` | unitless, ×1000 | Hermite cap parameter, 1120 to 1550 by FDV (1527 = 1.527× at TWAP $0.25) |
| `twap_milli_usd` | milli-USD | Time-weighted average XE price (e.g. 250 = $0.25) |
| `R_capped` | unitless, ×1000 | R after applying the Hermite cap |

Minimum emission is 1 micro-XE (safety floor).

## Where `lease_cost` comes from — billing granularity

`lease_cost_mXCU` is not a free parameter: every validator re-derives it from
the lease block's own fields (`core.LeaseCost`) and hard-rejects a mismatch, so
the emission above is fully determined by the lease's resources, duration and
the provider's certificate multiplier.

```
minutes    = ceil(duration_seconds / 60)
per_hour   = vcpus × 20_000 + ceil(memory_mb / 1024) × 10_000 + disk_gb × 1_000
cost_mXCU  = ceil(ceil(per_hour × minutes / 60) × multiplier_milli / 1000)
```

Rates are quoted **per hour** (micro-XCU), but billing granularity is **one
minute**: the duration is rounded up to whole minutes and the hourly
rate is divided down by 60. `LeaseMinDuration` is 60s, so the smallest legal
lease is exactly one billing unit.

Whole-hour durations price identically to the previous hour-granular scheme —
only sub-hour and part-hour leases move, and they move down to the minutes they
actually use.

### Worked sub-hour example

1 vCPU, 1 GB RAM, 1 GB disk, **5 minutes** (300s), 1.000× multiplier:

```
minutes    = ceil(300 / 60)                          = 5
per_hour   = 1×20_000 + 1×10_000 + 1×1_000           = 31_000 mXCU/hr
cost_mXCU  = ceil(ceil(31_000 × 5 / 60) × 1000/1000) = 2_584 mXCU
emission   = ceil(2_584 × 2000 / 1000)               = 5_168 mXE   (at R = 2.000)
```

Previously the same lease was quantised up to a whole hour and cost 31,000
mXCU — a 12× overcharge. At the 60-second minimum the overcharge was 60×.

The cheapest legal lease (1 GB disk, 1 minute, 0.500×) costs 9 mXCU, so the
1-micro-XCU cost floor in `LeaseCost` remains unreachable. The 1-micro-XE
emission floor above binds only in that same corner at `r_floor` (0.100×).

## Reading inputs from chain data

- **Lease cost**: query `/leases/{hash}` — the `cost` field is in micro-XCU.
- **R effective**: from the state chain epoch data (`r_effective`).
  Emission parameters are locked onto the lease record at accept time
  (`LockedR`). Legacy leases with `LockedR == 0` fall back to the current
  epoch R at settle time.
- **TWAP and payout_cap**: from state chain oracle data. Also locked onto
  the lease at accept time (`LockedTWAP`, `LockedPayoutCap`).

## Worked example (2026-05-26 soak)

Parameters: R = 2000, TWAP = 250 milli-USD, payout_cap = 1502.

### Provider P2 (1.0x multiplier)

```
cost       = 31,000 mXCU
emission   = 31,000 × 2000 / 1000 = 62,000 mXE per lease
407 leases × 62,000 mXE           = 25,234,000 mXE
```

### Provider P1 (2.5x multiplier)

```
cost       = 77,500 mXCU
emission   = 77,500 × 2000 / 1000 = 155,000 mXE per lease
228 leases × 155,000 mXE          = 35,340,000 mXE
```

### Combined

```
25,234,000 + 35,340,000 = 60,574,000 mXE = 60.574 XE minted
```

635 total leases across both providers, exact to micro-XE.

## Payout bound: R_collusion

The epoch's R (`r_effective`) is bounded by the collusion-safety term
R_collusion. The state chain recomputes R_collusion for every
epoch and requires
`r_effective = min(max(r_volume, r_price_floor), r_collusion)`:

```
R_collusion = factor × (1000 − s_milli) / twap_milli_usd    (integer floor)
```

| Variable | Description |
|---|---|
| `factor` | `r_collusion_factor_milli` in `sys.tokenomics` (950 = 0.95) |
| `s_milli` | Provider stable share: 0 in phase 1, 300 in phase 2 |

The XE minted at settle is therefore worth at most `0.95 × (1 − s)` of the
lease cost at the locked TWAP: 95% in phase 1, 66.5% in phase 2. The ceiling
in the emission rounding adds at most 1 micro-XE. When R_collusion is above
`max(r_volume, r_price_floor)`, the payout is `R × twap_milli_usd / 1000` of
cost, which is lower (50% at R = 2000 and TWAP $0.25). At high TWAP the floor
division lowers the bound further: at TWAP $100, R_collusion is 9 (90% of
cost).

### Edge: R_collusion rounds to 0

When `twap_milli_usd > factor × (1000 − s_milli)` (TWAP above $950 in phase 1,
above $665 in phase 2), R_collusion rounds to 0. The chain reads 0 as "no
collusion bound" and requires `r_effective = max(r_volume, r_price_floor)`.
There the Hermite cap is the only bound, and it allows 112% to 224% of cost.
The reference oracle cannot publish such an epoch (it publishes
`r_source "collusion"` with `r_effective = 0`, which the chain rejects), so
only a non-reference publisher reaches this range. The fix is tracked in.

## Hermite payout cap (inactive)

`CapR` clamps R to `⌈payout_cap × 1000 / twap_milli_usd⌉` before the
emission calculation. The oracle computes `payout_cap` from FDV (genesis
supply × TWAP) on a cubic Hermite curve between the `sys.tokenomics` fields
`hermite_ceiling_milli` (1550, at FDV ≤ $5M) and `hermite_floor_milli`
(1120, at FDV ≥ $1B). At the testnet TWAP of $0.25 it is 1527. Each lease
locks the value at accept (`LockedPayoutCap`).

Under the current envelope the cap never binds. For every epoch with
R_collusion > 0:

```
R_effective ≤ R_collusion = ⌊950 × (1000 − s) / twap⌋ ≤ 950000 / twap
            < 1120000 / twap ≤ ⌈payout_cap × 1000 / twap⌉
```

So `CapR` returns R unchanged. This holds for each renewal segment, which
applies `CapR` to its own locked triple from one epoch. It holds for any
factor the validator accepts (below 1000) while `hermite_floor_milli` is
1000 or more; no validation rule couples the two fields.

The cap has not bound for reference-oracle epochs since R_collusion landed. It is kept as defence in depth in case this
analysis is wrong. It gives no protection
against a false TWAP: both bounds scale with `1 / TWAP`, so a false low TWAP
raises both by the same factor. It binds only in the R_collusion = 0 edge
above.

When `payout_cap` or `twap_milli_usd` is zero the cap is disabled entirely,
preserving backward compatibility with pre-v13 epochs and test fixtures.

## Code reference

See `core/ledger.go`:

- `LeaseCost(vcpus, memoryMB, diskGB, duration, multiplierMilli uint64)` — the
  cost calculation, including the minute quantisation.
- `LeaseEmission(cost, r uint64) uint64` — the emission calculation.
- `CapR(r, payoutCap, twapMilliUSD uint64) uint64` — the Hermite cap.

See `statechain/kvstore.go`:

- `expectedRCollusion` and `validateEpochValue`: the R_collusion check and
  the `r_effective` rule for each epoch.
- `validateAndAddLeaseSettle` — where both are applied during block validation.
