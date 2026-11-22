# Rare-Failure Fixture Generator (Issue #493)

Module: `shared/src/rare_failure_fixtures.rs`

## What it does

`rare_failure_fixtures` provides a deterministic pseudo-random generator that produces synthetic, structured test fixtures representing edge-case anomalies, hardware extremes, and "black swan" failure scenarios that traditional unit and integration tests miss:

- **Ledger clock anomalies**: timestamp rewind, zero timestamp, leap second jitter, far-future timestamp skew (`u64::MAX - 1000`).
- **Storage TTL exhaustion**: entry expiring in 0 ledgers (archived), 1 ledger remaining, footprint limits.
- **Arithmetic boundaries**: `i128::MAX` with rounding overflow, precision underflows, negative balance breaches, zero division.
- **Cross-contract cascade dropouts**: downstream contract panic, oracle timeout, token transfer revert, orphan locks.
- **Payload corruption**: bit flips in signatures, hash digest mismatches, truncated inputs.

## Public Surface

| Function | Caller | Description |
|---|---|---|
| `register_fixture_generator(env, admin, generator)` | Admin | Authorizes an automated test harness address to generate test batches. |
| `is_authorized_generator(env, caller)` | Read-only | Checks whether caller is registered. |
| `generate_rare_failure_batch(env, caller, config)` | Generator | Generates a deterministic batch of structured test fixtures using seeded PRNG. |
| `validate_simulated_fixture(fixture)` | Pure / Anyone | Asserts fixture invariant validity against expected error classification. |

## Failure Categories & Expected Error Ranges

| Category | Range | Representative Anomalies |
|---|---|---|
| `LedgerClockSkew` | `100..=199` | Timestamp rewind (`clk_rew`), future overflow (`clk_leap`), zero timestamp (`clk_zero`). |
| `StorageTtlExhaustion` | `200..=299` | Archived entry (`ttl_zero`), immediate expiry edge (`ttl_edge`). |
| `ArithmeticBoundary` | `300..=399` | Numeric overflow (`num_ovfl`), negative balance (`num_undr`), division zero (`num_zero`). |
| `CrossContractCascade` | `400..=499` | Downstream timeout (`casc_to`), contract revert (`casc_rvt`). |
| `PayloadCorruption` | `500..=599` | Signature bit-flip (`pay_flip`), hash tampering (`pay_trmp`). |

## Normal, Failure, Retry, and Authorization Paths

- **Normal Path**:
  - Registered generator invokes `generate_rare_failure_batch` with seed and batch limit (`<= 50`).
  - System executes a deterministic XorShift64* PRNG, generating structured `RareFailureFixture` objects.
  - Each fixture contains explicit simulated inputs, ledger parameters, and expected error code.
- **Failure Paths**:
  - `InvalidSeed`: Supplying `seed == 0` is rejected.
  - `EmptyBatch`: Supplying `max_fixtures == 0` is rejected.
  - `BatchLimitExceeded`: Requesting more than `MAX_FIXTURES_PER_BATCH` (50) is rejected to protect host execution budgets.
  - `SimulationValidationFailed`: Any malformed fixture where the expected error code violates category constraints is rejected.
- **Retry and Reproducibility Path**:
  - Generator is 100% deterministic: passing identical `seed` and configuration reproduces identical fixtures bit-for-bit.
  - Different seeds produce statistically distinct anomaly sets.
- **Authorization Path**:
  - Calling generator without registration returns `RareFailureError::Unauthorized`.

## Operational Edge Cases

- **Host Gas Protection**: Capped at 50 fixtures per transaction to avoid hitting Soroban CPU or memory metering thresholds during fuzzing drills.
- **Cross-Platform Determinism**: XorShift64* runs entirely in pure integer arithmetic without floating-point math or OS randomness dependencies, ensuring identical test vectors on x86, ARM, and WASM.

## Migration and Compatibility Plan

Fully additive in `shared/src/rare_failure_fixtures.rs`. No ledger migrations or breaking changes to existing contracts.
