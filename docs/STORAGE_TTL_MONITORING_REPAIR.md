# Storage TTL Renewal Monitoring and Repair Tooling (Issue #326)

Module: `shared/src/ttl_monitor_repair.rs`

## What it does

Monitors and repairs the Time-To-Live (TTL) of persistent storage entries across all Trellis contract key families:
- `AidRecord`
- `TreasuryBalance`
- `GovernanceProposal`
- `OracleSubmission`
- `UserIdentity`

Soroban persistent entries require periodic TTL extensions to avoid ledger archival. This module enables operators and automated keeper bots to inspect entry lifetimes, detect expiring entries, and execute bounded batch repairs before entries risk archival.

## TTL Thresholds

| Status | Remaining Lifetime | Operational Meaning |
|--------|---------------------|---------------------|
| `Safe` | > 17,280 ledgers (~24h) | Entry healthy; no renewal required |
| `ExpiringSoon` | <= 17,280 ledgers | Keeper renewal recommended |
| `Critical` | <= 4,320 ledgers (~6h) | High priority; immediate bump needed |
| `ExpiredOrArchived` | 0 ledgers | Entry archived; requires restoration |

Persistent renewal applies a standard extension bump of **120,960 ledgers** (~7 days).

## Lifecycle & Operations

| Step | Call | Auth | Behavior |
|------|------|------|----------|
| Keeper Onboarding | `register_keeper(keeper, true)` | Admin | Authorizes keeper bot address |
| Diagnostic Check | `assess_entry_ttl(family, key_id, current_ttl)` | Public | Evaluates status without mutating state |
| Single Renewal | `renew_single_entry(family, key_id, current_ttl)` | Keeper / Admin | Extends entry TTL if below safe threshold |
| Batch Repair | `batch_repair_ttl(entries)` | Keeper / Admin | Evaluates and renews up to 100 entries in one call |

## Failure, Retry, and Authorization Paths

- **Normal Path**: Expiring entries are renewed to `Safe`, updating the last renewed ledger sequence and publishing a `(ttl, renewed)` event.
- **Idempotent Retry**: Calling `renew_single_entry` on an already-safe entry is a no-op that returns the safe diagnostic without applying duplicate storage bumps.
- **Batch Bounds & Failure**: If a batch size exceeds `MAX_BATCH_REPAIR_ENTRIES` (100 entries), the entire transaction aborts with `TtlError::BatchLimitExceeded` to prevent out-of-gas transaction failures.
- **Authorization**: Only registered keepers or contract admins can invoke renewal and batch repair. Unregistered callers fail with `TtlError::Unauthorized`.

## Operational Edge Cases

- **Archived Entries**: Entries with `current_ttl == 0` cannot be renewed via normal extension; they must be restored from archive or backfilled. The repair tooling records them in `failed_count` and reports them in the diagnostic report.
- **Gas & Footprint Limits**: Bounded batch size of 100 ensures the transaction remains well within Soroban CPU and read/write byte resource limits.

## Recovery and Rollback Behavior

- TTL renewals are strictly monotonically increasing extensions of entry lifetimes. They do not alter stored business data (amounts, addresses, or status flags).
- No data rollback is required because TTL extensions cannot corrupt state. In the event of a misconfigured keeper, permissions can be revoked immediately via `register_keeper(keeper, false)`.

## Migration Plan

1. Deploy updated `shared` module containing `ttl_monitor_repair.rs`.
2. Admin registers off-chain keeper bot addresses via `register_keeper`.
3. Off-chain monitoring agent scans contract persistent storage indices periodically, filters entries where `ttl <= EXPIRING_SOON_THRESHOLD_LEDGERS`, and submits `batch_repair_ttl`.
