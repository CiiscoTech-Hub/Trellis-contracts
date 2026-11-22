# Bounded Cache Invalidation and Stale Detection

## Overview (Issue #500)

Provides a ledger-aware, capacity-bounded key-value cache with deterministic staleness detection, LRU eviction, and explicit invalidation mechanisms in `shared::bounded_cache`.

## Key Architectural Decisions

1. **Deterministic Staleness Detection**:
   - Cache entries record the writing ledger sequence number.
   - Evaluates staleness against `max_age_ledgers` rather than non-deterministic wall-clock timestamps.
   - Stale records are flagged and quarantined from read paths.

2. **Capacity Bounding & LRU Eviction**:
   - Fixed capacity bounds (default: 64 entries, absolute maximum: 256).
   - Oldest entries by ledger sequence are evicted on write when capacity is reached.

3. **Explicit Invalidation & Namespace Flushes**:
   - Key-level invalidation (`invalidate`) removes individual keys.
   - Namespace-level clearing (`invalidate_all` / `flush_namespace`) flushes all entries in O(1) by updating the namespace epoch.

4. **Authorization & Failure Handling**:
   - Modification and repair commands require caller authorization (`admin` or authorized operator).
   - Graceful degradation on missing or corrupt storage entries without panics.
