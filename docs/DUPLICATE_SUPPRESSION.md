# Duplicate Suppression for Notifications and Webhooks (Issue #280)

`shared::duplicate_suppression` provides deterministic deduplication, bounded retries, and time-windowed suppression for outbound notifications and webhook deliveries.

## Lifecycle & Decisions

1. **Key Derivation**: `compute_dedupe_key` hashes `(channel, recipient, event_id)` via SHA-256.
2. **Normal Dispatch**: First call to `begin_delivery` persists an `InFlight` `DeliveryRecord` and returns `DeliveryDecision::Dispatch`. `complete_delivery` transitions it to `Delivered`.
3. **Duplicate Suppression**: Re-triggering `begin_delivery` for a `Delivered` record within `policy.window_seconds` increments `suppressed_count` and returns `DeliveryDecision::Suppress(count)`. Once `window_seconds` elapses, a fresh dispatch cycle is permitted.
4. **Retry Path**: While `InFlight`, `begin_delivery` increments `attempts` and returns `DeliveryDecision::Retry(attempts)` up to `policy.max_attempts`.

## Edge Cases & Recovery / Rollback Behavior

- **Payload Conflict**: Reusing a `dedupe_key` with a different `payload_hash` is rejected with `Error::InvalidArgument` to prevent silent payload substitution.
- **Retry Exhaustion**: Exceeding `policy.max_attempts` transitions the record to `SuppressionState::FailedPermanent` and returns `Error::QuotaExceeded`.
- **Authorization & Recovery**: `begin_delivery`, `complete_delivery`, and `fail_delivery` require `caller.require_auth()`. Admins can clear a `FailedPermanent` or stuck record via `reset_suppression` (`require_admin`), allowing clean recovery.

## Contract Preservation

This module complements `shared::webhook` and `shared::idempotency` as an additive module without changing any existing webhook verification or idempotency keys.
