# Notification and Webhook Deduplication (Issue #488)

Module: `shared/src/unified_dedup.rs`

## What it does

Implements atomic, replay-safe deduplication with outcome caching across all event channels:
- `InboundWebhook`: External payment gateways, milestone oracles, identity providers.
- `OutboundNotification`: Recipient aid notifications, donor receipts.
- `CrossContractCallback`: Chained inter-contract execution receipts.
- `RelayerRelay`: Off-chain relayer submissions and gasless relay bundles.

Solves distributed at-least-once delivery duplicates, prevents double-spending or duplicate notifications, and caches execution response hashes for idempotent consumer retries.

## Lifecycle & State Machine

```
   [Unseen Event]
         │
  check_and_reserve
         │
         ▼
    (Processing) ───► [Concurrent Attempt] ──► RejectInFlight
         │
   ┌─────┴──────────────────────┐
   │                            │
   ▼                            ▼
finalize_success         finalize_failure
   │                            │
   ▼                            ▼
(Completed)                 (Failed)
   │                            │
[Replay Call]           [Retry < 3 Attempts] ──► (Processing)
   │                            │
   ▼                            ▼
ReturnCached            [Attempts >= 3] ───────► (DeadLetter) ──► RejectDeadLetter
```

## Operations & API

| Operation | Entrypoint | Authorization | Effect |
|-----------|------------|---------------|--------|
| Reserve & Check | `check_and_reserve` | Caller | Atomically checks status; reserves if new, returns cached if completed |
| Finalize Success | `finalize_success` | Caller / Admin | Marks `Completed` and caches 32-byte response hash |
| Finalize Failure | `finalize_failure` | Caller / Admin | Records failure attempt; transitions to `DeadLetter` if >= 3 |
| Query Record | `get_dedup_record` | Public | Inspects record state, attempt count, and response hash |
| Maintenance Prune | `prune_dedup_record` | Admin | Cleans up completed or dead-lettered records |

## Failure, Retry, and Authorization Paths

- **Normal Idempotent Path**:
  1. Caller calls `check_and_reserve` -> receives `DedupAction::Proceed`.
  2. Caller completes business logic and calls `finalize_success` with `response_hash`.
  3. Subsequent duplicate calls with identical key receive `DedupAction::ReturnCached` without re-executing business logic.
- **Concurrent In-Flight Collision**: If a second request arrives while the first is still `Processing`, it receives `DedupAction::RejectInFlight`, preventing race conditions.
- **Retry & Dead-Letter Routing**: Transient errors transition record to `Failed`. Retries increment the attempt counter. When attempts reach `MAX_DEDUP_ATTEMPTS` (3), the event transitions to `DeadLetter`, permanently halting retries.
- **Authorization**: Only the registered caller or admin can transition record states or prune records. Unprivileged callers fail with `DedupError::Unauthorized`.

## Operational Edge Cases

- **Crash Before Finalize**: If a caller crashes while in `Processing`, subsequent calls receive `RejectInFlight` until the transaction boundary rolls back or an authorized retry is issued.
- **Pruning Safety**: Only records in `Completed` or `DeadLetter` status can be pruned. Active `Processing` records cannot be pruned.

## Recovery and Rollback Behavior

- Event state is stored in persistent storage under `DedupKey::Record(idempotency_key)`.
- If an integration failure occurs, dead-letter records can be reviewed by operators, rectified off-chain, and cleaned up via `prune_dedup_record`.

## Migration Plan

1. Deploy updated `shared` module.
2. Inbound webhook handlers call `check_and_reserve` before verifying signatures or mutating state.
3. Outbound notification workers call `check_and_reserve` before dispatching messages.
4. On success, call `finalize_success(key, response_hash)` to enable idempotent caller caching.
