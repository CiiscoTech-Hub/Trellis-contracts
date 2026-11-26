# Bounded Cache Invalidation and Stale Detection (#579)

## Overview

The Bounded Cache Invalidation and Stale Detection module (`shared::bounded_cache`) provides a ledger-aware, capacity-bounded key-value cache stored in Soroban temporary storage for the Trellis smart contract framework.

In high-throughput smart contract deployments, repeated reads of frequently queried data (e.g., fee schedules, oracle rates, configuration parameters) impose redundant compute and gas overhead. The bounded cache provides an ultra-fast in-memory/temporary layer that guarantees deterministic expiration, deterministic LRU capacity management, and zero non-deterministic clock dependencies.

---

## Architectural Decisions

```text
Cache Read / Write Operation
       │
       ▼
[ Ledger Staleness Evaluation ]
       ├── (current_ledger - written_at) <= max_age_ledgers ──► Cache Hit (Return Value)
       └── (current_ledger - written_at) > max_age_ledgers ──► Stale Entry (Quarantine / Evict)
       │
       ▼
[ Capacity & LRU Eviction ]
       ├── current_size < max_capacity ──► Insert New Key
       └── current_size >= max_capacity ──► Evict Oldest Ledger Sequence Entry ──► Insert
```

1. **Deterministic Staleness Detection**:
   - Cache entries record the writing ledger sequence number (`written_at_ledger`).
   - Evaluates staleness against `max_age_ledgers` rather than non-deterministic wall-clock timestamps.
   - Stale records are quarantined from read paths and return `CacheError::KeyNotFound`.

2. **Capacity Bounding & LRU Eviction**:
   - Configurable capacity bounds (`default: 64`, `absolute max: 256`).
   - Oldest entries by ledger sequence are automatically evicted on write when capacity is reached.
   - Emits `TOPIC_CACHE_EVICT` (`cch_ev`) event on eviction for off-chain monitoring.

3. **Explicit Invalidation & Namespace Flushes**:
   - Key-level invalidation (`invalidate`) removes individual keys in $O(1)$.
   - Namespace-level clearing (`invalidate_all` / `flush_namespace`) resets the entire namespace without unbounded iterations.

---

## Operational Execution Paths

### 1. Normal Path
- Calling `put(env, ns, key, value)` stores the entry stamped with `env.ledger().sequence()`.
- Subsequent `get(env, ns, key)` calls within `max_age_ledgers` return `Ok(value)`.
- When capacity is reached, the entry with the lowest ledger sequence is evicted to make room for the new entry.

### 2. Failure Path
- **Stale Entry Read**: Attempting to read an entry whose age exceeds `max_age_ledgers` fails closed, returning `CacheError::KeyNotFound` and incrementing the stale counter.
- **Uninitialized Namespace**: Calling operations on an unconfigured namespace fails with `CacheError::NotInitialized`.
- **Capacity Exceeded on Init**: Attempting to initialize with `max_capacity > ABSOLUTE_MAX_CAPACITY` (256) returns `CacheError::CapacityExceeded`.

### 3. Retry Path
- After an entry is invalidated or evicted due to staleness, a subsequent write with fresh data immediately restores the key and resets its ledger timestamp.
- Retry operations are idempotent and do not corrupt adjacent cache keys.

### 4. Authorization Path
- Administrative actions (`execute_cache_repair`, `FlushNamespace`, `EvictStale`) require caller authorization (`crate::auth::require_admin`).
- Unauthorized callers attempting to flush or repair the cache are rejected with `CacheError::Unauthorized`.

---

## Edge Cases, Recovery, and Rollback Behavior

- **Ledger Sequence Rollover**: Sequence numbers are strictly monotonic u32 values. In the rare event of ledger sequence resets in local test environments, namespace flushes realign the baseline.
- **TTL Expiration**: Because entries reside in temporary storage, abandoned caches naturally expire and are reclaimed by the Soroban runtime without incurring persistent rent fees.
- **Rollback Behavior**: Cache mutations within an aborted transaction frame are automatically rolled back by the host execution environment, ensuring cache consistency with underlying state.

---

## Compatibility & Migration Plan

- **Contract Preservation**: The cache operates strictly as an auxiliary performance optimization layer. Underlying persistent contracts remain the definitive source of truth.
- **Fail-Safe Design**: Any cache miss or error gracefully falls back to persistent storage reads without interrupting caller workflows.
