# Bounded Iteration Protection for Storage Scans

`shared::scan_guard` (Issue #338) closes the one real gap left in this
workspace's existing scan protections, as a small additive primitive rather
than an edit to the module that has it.

## The gap this closes

`shared::pagination` already bounds keyset pagination with a caller-supplied
`max_scan`, but that parameter itself has no ceiling anywhere in
`paginate_id_range` / `paginate_id_list` — nothing stops a call site from
passing an unbounded value and reintroducing the exact out-of-gas,
unbounded-loop risk the module exists to prevent. Several other modules
(`shared::jobs`, `shared::health`, `shared::degradation`,
`shared::event_dead_letter`) also scan a `Vec<u64>`/`Vec<Symbol>` index
directly, with no bound at all beyond the list's current length.

## Design in one paragraph

`clamp_scan_limit` is a pure function that caps any requested scan bound at
`ABSOLUTE_MAX_SCAN`, falling back to `shared::pagination::DEFAULT_MAX_SCAN`
when `0`. Any caller of `shared::pagination`'s functions — or a hand-written
scan loop — can route its `max_scan` through it for defense in depth, with
no change required to `shared::pagination` itself.
`ensure_within_scan_budget` lets a function that wants to scan everything in
one pass (a full chain re-derivation, say) fail fast with
`Error::QuotaExceeded` instead of truncating silently, the same shape
`shared::audit_ledger`'s `MAX_VERIFY_ENTRIES` and `shared::snapshot`'s
`MAX_VERIFY_SNAPSHOTS` already use, generalized to any module.
`get_effective_scan_limit` / `set_scan_limit` let an admin tighten the bound
for a named scope below the default — never above `ABSOLUTE_MAX_SCAN`, which
`set_scan_limit` enforces by clamping rather than trusting the caller.
`bounded_offset_scan` is a generic, hard-capped offset scan over any
`Vec<u64>` id index, for call sites that don't need
`shared::pagination`'s sorted-keyset binary search — a plain pending/
dead-letter/queue list is enough; `has_more` / `next_offset` give the caller
a resume cursor, the same retry shape `PageResponse` already uses.

## Public surface

| Item | Purpose |
|---|---|
| `clamp_scan_limit` | Pure: resolves any requested `max_scan` to a bounded value. |
| `ensure_within_scan_budget` | Pure: fails fast instead of scanning past the bound. |
| `get_effective_scan_limit` / `set_scan_limit` | Per-scope admin-configurable ceiling, always clamped to `ABSOLUTE_MAX_SCAN`. |
| `bounded_offset_scan` | Generic hard-capped offset scan with a resume cursor, for any `Vec<u64>` id index. |

## Who can do what

| Action | Required condition |
|---|---|
| `clamp_scan_limit`, `ensure_within_scan_budget`, `get_effective_scan_limit`, `bounded_offset_scan` | Anyone — pure or read-only |
| `set_scan_limit` | `Role::Admin`, authenticated |

## Operational edge cases

| Situation | Behavior |
|---|---|
| `max_scan` of `0` passed to `clamp_scan_limit` | Resolves to `shared::pagination::DEFAULT_MAX_SCAN`, not "unbounded". |
| `max_scan` above `ABSOLUTE_MAX_SCAN` | Clamped down, never passed through as-is. |
| `ensure_within_scan_budget` with `total` above the effective bound | `Error::QuotaExceeded` — scan in bounded pages instead of this call. |
| Non-admin calls `set_scan_limit` | `Error::Unauthorized`, before any storage write. |
| `set_scan_limit` with `max_scan == 0` | Clears the override; `get_effective_scan_limit` falls back to the shared default again. |
| `set_scan_limit` with a value above `ABSOLUTE_MAX_SCAN` | Succeeds, but the stored value is silently clamped to the ceiling — an admin cannot reintroduce the unbounded-scan risk. |
| `bounded_offset_scan` with `offset` past the end of `ids` | Empty result, `has_more: false` — not an error. |
| `bounded_offset_scan` stops because `max_scan` (not `limit`) was reached | `has_more: true` with `next_offset` pointing just past the last id inspected, so a resumed call continues scanning rather than restarting. |

## Rollback and recovery

This module holds only a per-scope limit override — there is no history to
roll back:

1. **A scope's scan limit was set too low**, causing callers to see
   `has_more: true` far more than expected: call `set_scan_limit` again with
   a larger value (still bounded by `ABSOLUTE_MAX_SCAN`). Takes effect on
   the next call; nothing is migrated.
2. **A scope's scan limit was set too high**, risking an expensive scan:
   the same path, with a smaller value. `get_effective_scan_limit` always
   reflects the current override, so there is nothing stale to clear.
3. **An admin override should be removed entirely**, reverting to the
   shared default: call `set_scan_limit` with `0`.

## Compatibility

Purely additive: new storage keys, no changes to `shared::pagination` or any
other module's behavior or interface. Existing callers of
`paginate_id_range` / `paginate_id_list` are unaffected until they choose to
route their `max_scan` through `clamp_scan_limit` or
`get_effective_scan_limit`.
