# Deterministic Duplicate Detection and Merge Review (Issue #427)

## Overview & Goal

Candidate duplicate entries arrive from distributed off-chain indexers, replayed webhooks, and retryable batch operations. In humanitarian aid and payments, resolving duplicates cannot depend on non-deterministic arrival orders or wall-clock timestamps.

The [`shared::duplicate_merge_review`](../shared/src/duplicate_merge_review.rs) module provides:
1. Deterministic duplicate candidate detection and grouping.
2. A reviewable, multi-stage merge workflow (`Pending` $\to$ `Approved` $\to$ `Applied` $\to$ `Finalized`).
3. Preserved pre-merge snapshots allowing safe, audited reversions (`Reverted`).

---

## Deterministic Detection & Fingerprinting

Duplicate candidate groups are identified using a fixed FNV-1a hash over normalized fields `(record_id, amount)`:

```rust
pub fn compute_fingerprint(record_id: u64, amount: i128) -> u64
```

- **Arrival-Order Invariance**: The detector sorts candidate groups by `fingerprint` ascending using deterministic insertion sort.
- **Timestamp Exclusion**: Observation timestamps are omitted from the fingerprint so identical records observed at different times always collapse into the same group.

---

## Merge Review State Machine

```
               +-------------+
               |   Pending   |
               +------+------+
                      |
           +----------+----------+
           |                     |
           v                     v
     +------------+        +------------+
     |  Approved  |        |  Rejected  | (Terminal)
     +-----+------+        +------------+
           |
           v
     +------------+
+--->|  Applied   |
|    +-----+------+
|          |
|    +-----+------+
|    |            |
|    v            v
| +----------+ +-----------+
+-+ Reverted | | Finalized | (Terminal, irreversible)
  +----------+ +-----------+
```

### Transition Rules

- **`propose_merge`**: Created from a duplicate candidate group; requires caller authorization.
- **`approve_merge`**: Admin authorization required. Moves `Pending` $\to$ `Approved`.
- **`apply_merge`**: Admin authorization required. Moves `Approved` $\to$ `Applied`. Pre-merge records are stored in `affected_records` for rollback.
- **`revert_merge`**: Admin authorization required. Moves `Applied` $\to$ `Reverted`. Restores pre-merge state.
- **`finalize_merge`**: Admin authorization required. Moves `Applied` $\to$ `Finalized`. Irreversible; permanently locks out `revert_merge`.

---

## Invariants & Rollback Safety

1. **Reversibility**: An applied merge can always be reverted back to `Reverted` as long as it has not been marked `Finalized`.
2. **Idempotency**: Retrying `approve_merge`, `apply_merge`, or `revert_merge` is idempotent and safe against network replays.
3. **Audit Trail**: Every transition emits an on-chain event `("merge", <action>)` with proposal ID and actor address.
