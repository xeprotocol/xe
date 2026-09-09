# Lease Emission Formula

When a lease settles, the protocol mints XE to the provider. The amount
is determined by the lease cost and the epoch's effective reputation score,
subject to the Hermite payout cap.

## Formula

```
emission_mXE = lease_cost_mXUSD × R_capped / 1000
R_capped     = min(R, payout_cap × 1000 / twap_milli_usd)
```

### Variables

| Variable | Unit | Description |
|---|---|---|
| `emission_mXE` | micro-XE | XE minted to the provider (1 XE = 1,000,000 mXE) |
| `lease_cost_mXUSD` | micro-XUSD | Lease cost — the `cost` field on the lease block |
| `R` | unitless, ×1000 | Epoch's effective reputation score (e.g. 2000 = 2.000×) |
| `payout_cap` | unitless, ×1000 | Hermite cap parameter (currently 1502 = 1.502×) |
| `twap_milli_usd` | milli-USD | Time-weighted average XE price (e.g. 250 = $0.25) |
| `R_capped` | unitless, ×1000 | R after applying the Hermite cap |

Minimum emission is 1 micro-XE (safety floor).

## Where `lease_cost` comes from — billing granularity

`lease_cost_mXUSD` is not a free parameter: every validator re-derives it from
the lease block's own fields (`core.LeaseCost`) and hard-rejects a mismatch, so
the emission above is fully determined by the lease's resources, duration and
the provider's certificate multiplier.

```
minutes    = ceil(duration_seconds / 60)
per_hour   = vcpus × 20_000 + ceil(memory_mb / 1024) × 10_000 + disk_gb × 1_000
cost_mXUSD = ceil(ceil(per_hour × minutes / 60) × multiplier_milli / 1000)
```

Rates are quoted **per hour** (micro-XUSD), but billing granularity is **one
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
per_hour   = 1×20_000 + 1×10_000 + 1×1_000           = 31_000 mXUSD/hr
cost_mXUSD = ceil(ceil(31_000 × 5 / 60) × 1000/1000) = 2_584 mXUSD
emission   = ceil(2_584 × 2000 / 1000)               = 5_168 mXE   (at R = 2.000)
```

Previously the same lease was quantised up to a whole hour and cost 31,000
mXUSD — a 12× overcharge. At the 60-second minimum the overcharge was 60×.

The cheapest legal lease (1 GB disk, 1 minute, 0.500×) costs 9 mXUSD, so the
1-micro-XUSD cost floor in `LeaseCost` remains unreachable. The 1-micro-XE
emission floor above binds only in that same corner at `r_floor` (0.100×).

## Reading inputs from chain data

- **Lease cost**: query `/leases/{hash}` — the `cost` field is in micro-XUSD.
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
cost       = 31,000 mXUSD
emission   = 31,000 × 2000 / 1000 = 62,000 mXE per lease
407 leases × 62,000 mXE           = 25,234,000 mXE
```

### Provider P1 (2.5x multiplier)

```
cost       = 77,500 mXUSD
emission   = 77,500 × 2000 / 1000 = 155,000 mXE per lease
228 leases × 155,000 mXE          = 35,340,000 mXE
```

### Combined

```
25,234,000 + 35,340,000 = 60,574,000 mXE = 60.574 XE minted
```

635 total leases across both providers, exact to micro-XE.

## Hermite payout cap

The cap bounds dollar-denominated ROI by clamping R before the emission
calculation. It activates when `R > payout_cap × 1000 / twap_milli_usd`.

At current parameters:

```
threshold = 1502 × 1000 / 250 = 6008
```

With R = 2000, this is well below the threshold — the cap is dormant.
It would only engage if R exceeded 6008 or TWAP rose significantly
(above ~$0.75 at current R values).

When `payout_cap` or `twap_milli_usd` is zero the cap is disabled entirely,
preserving backward compatibility with pre-v13 epochs and test fixtures.

## Code reference

See `core/ledger.go`:

- `LeaseCost(vcpus, memoryMB, diskGB, duration, multiplierMilli uint64)` — the
  cost calculation, including the minute quantisation.
- `LeaseEmission(cost, r uint64) uint64` — the emission calculation.
- `CapR(r, payoutCap, twapMilliUSD uint64) uint64` — the Hermite cap.
- `validateAndAddLeaseSettle` — where both are applied during block validation.
