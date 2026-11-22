# Rare Failure and Recovery Fixture Generators (Issue #285)

`shared::failure_fixtures` provides deterministic, seeded fixture generation and lifecycle tracking for rare production failure and recovery paths.

## Supported Scenarios

- `PartialBatchCommit`: A batch commits a subset of items before failing mid-flight.
- `OrphanedLockExpiry`: A temporary lock expires after an external side effect.
- `StaleReplicaRead`: A read replica lags behind canonical state during retry.
- `ConcurrentNonceRace`: Two actors race on the same nonce or idempotency key.
- `RollbackAfterDownstreamReject`: A downstream contract rejects after local mutation.
- `QuotaExhaustionMidRetry`: Retry budget is exhausted during recovery.

## Edge Cases & Recovery / Rollback Behavior

- **Zero ID or Zero Seed**: `build_fixture` / `generate_fixture` reject `fixture_id == 0` or `seed == 0` with `Error::InvalidArgument`.
- **Duplicate Fixture ID**: Persisting a fixture with an already-used `fixture_id` returns `Error::AlreadyClaimed` so completed drills are never overwritten.
- **Idempotent Retry**: Calling `retry_fixture` on an already `Recovered` fixture is a no-op and returns `Ok(fixture)` without consuming additional retry budget.
- **Retry Exhaustion**: Once `retries_used >= retry_budget`, `retry_fixture` transitions the fixture to `FixtureState::Abandoned` and returns `Error::QuotaExceeded`.
- **Rollback**: `rollback_fixture` transitions `Injected`, `Retried`, or `Abandoned` fixtures (where `requires_rollback == true`) to `FixtureState::RolledBack`. Rolling back an already `RolledBack` fixture is idempotent; rolling back a `Recovered` or `Generated` fixture returns `Error::InvalidArgument`.
- **Authorization**: All mutating operations (`generate_fixture`, `inject_failure`, `retry_fixture`, `rollback_fixture`) enforce `require_admin`.

## Contract Preservation

This module is additive in `shared` (`shared::failure_fixtures`) and does not alter any existing contract storage schemas or public entry points.
