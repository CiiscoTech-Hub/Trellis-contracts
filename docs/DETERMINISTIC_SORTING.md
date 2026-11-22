# Deterministic Sorting for Status and Event Lists (Issue #492)

Module: `shared/src/deterministic_sort.rs`

## What it does

`deterministic_sort` provides total-order, deterministic sorting algorithms with stable tie-breaking for event streams, audit logs, and component status digests in Soroban smart contracts.

Without deterministic sorting:
1. Lists returned from contracts or storage queries depend on non-deterministic iteration order, breaking client pagination cursors.
2. Cryptographic hashing of interfaces or state digests (e.g. `surface_hash` or Merkle proofs) produces sporadic mismatches across nodes.
3. Consensus execution risks divergent state roots if order affects downstream execution.

## Public Surface

| Function | Caller | Description |
|---|---|---|
| `sort_events_deterministic(env, events, direction)` | Pure / Anyone | Sorts event lists deterministically by timestamp, ledger, sequence, and payload hash. |
| `sort_statuses_deterministic(env, statuses, direction)` | Pure / Anyone | Sorts component statuses by severity rank, heartbeat, and component ID. |
| `canonicalize_and_dedup_events(env, events, direction)` | Pure / Anyone | Deterministically sorts and strips adjacent duplicate event records. |
| `is_events_sorted(events, direction)` | Pure / Read-only | Asserts whether an event vector is strictly sorted. |
| `is_statuses_sorted(statuses, direction)` | Pure / Read-only | Asserts whether a status vector is strictly sorted. |

## Ordering Keys & Tie-Breaking Hierarchy

### Events (`SortableEvent`)
1. **Primary**: `timestamp` (ASC / DESC)
2. **Secondary**: `ledger_seq`
3. **Tertiary**: `event_seq`
4. **Stable Tie-Breaker**: Lexicographical byte-by-byte comparison of `payload_hash` (`BytesN<32>`).

### Component Statuses (`SortableStatus`)
1. **Primary**: `severity_rank` (1: Critical, 2: High, 3: Medium, 4: Low, 5: Operational)
2. **Secondary**: `last_heartbeat`
3. **Stable Tie-Breaker**: `component_id` / `is_healthy`

## Normal, Failure, Retry, and Authorization Paths

- **Normal Path**:
  - Caller passes an unordered list of events or statuses.
  - Sorting routine applies insertion sort with $O(N \log N)$ average behavior on near-sorted data and zero extra host allocations for bounded $N \le 128$.
  - Result is guaranteed to be deterministically ordered.
- **Failure Paths**:
  - `CollectionTooLarge`: Supplying a list with $> 128$ items returns `CollectionTooLarge` to protect Soroban CPU budgets.
  - Empty or single-item collections return immediately without allocation.
- **Retry and Idempotency Path**:
  - Sorting an already-sorted list is an idempotent identity operation (`f(f(x)) == f(x)`).
- **Deduplication**:
  - `canonicalize_and_dedup_events` ensures adjacent entries with identical `(timestamp, ledger_seq, event_seq, payload_hash)` are deduplicated cleanly.

## Operational Edge Cases

- **Identical Timestamps**: When high-throughput transactions occur within the same ledger/second, the sequence number and payload hash guarantee a stable, reproducible ordering.
- **Resource Budget Bounds**: Capped at `MAX_SORTABLE_ITEMS = 128` per call. Larger datasets should be paginated using bounded pagination cursors before sorting.

## Migration and Compatibility Plan

Fully additive pure functions in `shared/src/deterministic_sort.rs`. No storage layout or contract breaking changes.
