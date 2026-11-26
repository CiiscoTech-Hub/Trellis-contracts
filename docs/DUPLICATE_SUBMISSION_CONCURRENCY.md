# Duplicate-Submission Concurrency Coverage (#580)

## Overview

The Duplicate-Submission Concurrency Coverage module (`testing::concurrency_dup_stale`, `shared::stale_state`, `shared::duplicate_suppression`) validates concurrent mutation handling, idempotent deduplication, and stale-version conflict resolution across multi-actor transaction sequences in the Trellis Soroban contract ecosystem.

In distributed blockchain networks, transient network retries, client reconnection bursts, and parallel transaction submission frequently result in duplicate envelopes reaching the ledger. This test suite and contract subsystem guarantee that:
1. Re-submitting identical transaction payloads is strictly idempotent and safe.
2. Conflicting payloads reusing an active operation ID are rejected before any state mutation.
3. Outdated or stale resource versions fail deterministically without corrupting live contract state.
4. Multi-actor transaction sequences conserve protocol-wide balances and invariants under arbitrary execution interleavings.

---

## Architectural Guarantees

```text
Incoming Transaction Submission
       │
       ▼
[ Operation Fingerprint / ID Check ]
       ├── New ID ──► Enqueue & Mark Pending (attempts = 0)
       ├── Matching ID + Same Payload ──► Idempotent Return (no double-execution)
       └── Matching ID + Conflicting Payload ──► Reject (QueueError::OperationIdConflict)
       │
       ▼
[ Version / Ledger Sequence Guard ]
       ├── Sequence >= Snapshot Sequence ──► Proceed to In-Progress
       └── Sequence < Snapshot Sequence ──► Reject (StaleLedgerSequence / VersionConflict)
       │
       ▼
[ Execution & Completion Gate ]
       ├── State Transition & Asset Transfer
       └── Complete Operation ──► Block Replay (Completed status)
```

### Algorithmic Complexity

| Component | Time Complexity | Space Complexity |
|---|---|---|
| Deduplication Lookup | $O(1)$ temporary storage lookup | $O(1)$ per operation |
| Fingerprint Verification | $O(M)$ where $M \le 256$ payload bytes | $O(1)$ hash/digest |
| Multi-Actor Interleaving | $O(N)$ sequential operations | $O(K)$ active actors |

---

## Operational Execution Paths

### 1. Normal Path
- A client submits an operation with unique ID and payload.
- State transitions to `Pending` and subsequently `InProgress`.
- Re-submission of the identical payload returns the pending/cached status with 0 duplicate effects.
- State transition commits and transitions to `Completed`.
- Subsequent replays are permanently blocked.

### 2. Failure Path
- **Conflicting Payload**: If a caller submits a distinct payload using an already-enqueued operation ID, the operation is immediately rejected with `QueueError::OperationIdConflict`.
- **Double-Completion**: Attempting to call `complete_operation` on an already-completed record fails with `QueueError::AlreadyCompleted`.
- **Stale Ledger / Version**: When a transaction references an obsolete ledger sequence or revision tag lower than the current state, it fails with `StaleLedgerSequence` or `StaleWalletRevision`.

### 3. Retry Path
- If a transient failure occurs during the `InProgress` stage (e.g. paused contract or dependency error):
  - The operation can be retried using conflict resolution (`resolve_conflict`).
  - Choosing `ConflictResolution::Retry` with an updated sequence refreshes the attempt counter and allows safe re-evaluation.
  - Choosing `ConflictResolution::Discard` cleans up the operation record without leaving dangling state.

### 4. Authorization Path
- Queue mutations and operation claims enforce caller validation.
- Unprivileged actors cannot hijack another actor's pending operation, complete unowned operations, or replay administrative actions.
- In multi-actor concurrency tests, actions executed on behalf of unauthorized actors fail closed with `Error::Unauthorized`.

---

## Edge Cases, Recovery, and Rollback Behavior

- **Storage TTL & Expiration**: Operation tracking records are maintained in temporary storage. If an operation is abandoned, it expires cleanly under Soroban TTL policies without requiring manual garbage collection.
- **Interleaved Re-entrancy Protection**: Operations lock the unique operation ID during execution. Simultaneous concurrent attempts in the same ledger frame observe the in-flight lock and abort safely.
- **Rollback Behavior**: If any sub-call within a multi-operation sequence fails, the entire transaction frame reverts atomically under Soroban semantics, ensuring no partial token transfers occur.

---

## Compatibility & Migration Plan

- **Preservation of Existing Contracts**: All deduplication and stale-detection primitives are fully backward-compatible and opt-in for callers.
- **Interface Stability**: Public contract entry points in `TreasuryContract`, `AidContract`, and `PaymentsContract` maintain existing function signatures while using internal idempotency checks.
- **Zero Breaking Schema Changes**: Uses instance and temporary storage namespaces isolated from persistent business records.
