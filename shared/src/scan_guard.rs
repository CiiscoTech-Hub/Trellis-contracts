//! Bounded iteration protection for storage scans (Issue #338).
//!
//! `shared::pagination` already bounds keyset pagination over a sorted id
//! range or id list with a caller-supplied `max_scan`, but that parameter
//! itself has no ceiling — nothing stops a call site from passing an
//! unbounded value and reintroducing the exact out-of-gas, unbounded-loop
//! risk the module exists to prevent. Several other modules in this crate
//! (`shared::jobs`, `shared::health`, `shared::degradation`,
//! `shared::event_dead_letter`) also scan a `Vec<u64>`/`Vec<Symbol>` index
//! directly, with no bound at all beyond the list's own current length.
//!
//! This module adds the missing ceiling as a small, reusable primitive
//! rather than editing any of those files:
//!
//! - [`clamp_scan_limit`] is a pure function that caps any requested scan
//!   bound at [`ABSOLUTE_MAX_SCAN`], falling back to
//!   `shared::pagination::DEFAULT_MAX_SCAN` when `0`. Any existing or future
//!   caller of `shared::pagination::paginate_id_range` /
//!   `paginate_id_list` — or of a hand-written scan loop — can route its
//!   `max_scan` through this first for defense in depth.
//! - [`ensure_within_scan_budget`] lets a function that wants to scan
//!   everything in one pass (e.g. a full chain re-derivation) fail fast with
//!   [`Error::QuotaExceeded`] instead of truncating silently or looping
//!   unbounded, the same shape `shared::audit_ledger`'s
//!   `MAX_VERIFY_ENTRIES` / `ScanLimitExceeded` and `shared::snapshot`'s
//!   `MAX_VERIFY_SNAPSHOTS` already use, generalized to any module.
//! - [`get_effective_scan_limit`] / [`set_scan_limit`] let an admin tighten
//!   the bound for a named scope (e.g. `"dead_letters"`, `"pending_jobs"`)
//!   below the default — never above [`ABSOLUTE_MAX_SCAN`], which
//!   [`set_scan_limit`] enforces by clamping rather than trusting the admin.
//! - [`bounded_offset_scan`] is a generic, hard-capped offset scan over any
//!   `Vec<u64>` id index, for call sites that don't need
//!   `shared::pagination`'s sorted-keyset binary search — a plain pending/
//!   dead-letter/queue list is enough. `has_more` / `next_offset` give the
//!   caller a cursor to resume from, the same retry shape
//!   `shared::pagination::PageResponse` already uses.
//!
//! Nothing in `shared::pagination` or any other module changes.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | `max_scan` of `0` passed to [`clamp_scan_limit`] | Resolves to `shared::pagination::DEFAULT_MAX_SCAN`, not "unbounded". |
//! | `max_scan` above [`ABSOLUTE_MAX_SCAN`] | Clamped down, never passed through as-is. |
//! | [`ensure_within_scan_budget`] with `total` above the effective bound | `Error::QuotaExceeded` — the caller should scan in bounded pages instead of this call. |
//! | Non-admin calls [`set_scan_limit`] | `Error::Unauthorized`, before any storage write. |
//! | `set_scan_limit` with `max_scan == 0` | Clears the override; [`get_effective_scan_limit`] falls back to the shared default again. |
//! | `set_scan_limit` with a value above [`ABSOLUTE_MAX_SCAN`] | Succeeds, but the stored value is silently clamped to the ceiling — an admin cannot reintroduce the unbounded-scan risk. |
//! | `bounded_offset_scan` with `offset` past the end of `ids` | Empty result, `has_more: false` — not an error. |
//! | `bounded_offset_scan` stops because `max_scan` (not `limit`) was reached | `has_more: true` with `next_offset` pointing just past the last id inspected, so a resumed call continues scanning rather than restarting. |
//!
//! ## Recovery / rollback
//!
//! This module holds only a per-scope limit override — there is no history
//! to roll back:
//!
//! 1. **A scope's scan limit was set too low**, causing callers to see
//!    `has_more: true` far more than expected: call [`set_scan_limit`] again
//!    with a larger value (still bounded by [`ABSOLUTE_MAX_SCAN`]). Takes
//!    effect on the next call; nothing is migrated.
//! 2. **A scope's scan limit was set too high**, risking an expensive scan:
//!    same path, with a smaller value. [`get_effective_scan_limit`] always
//!    reflects the current override, so there is nothing stale to clear.
//! 3. **An admin override should be removed entirely**, reverting to the
//!    shared default: set it back to `shared::pagination::DEFAULT_MAX_SCAN`
//!    explicitly, or to `0` — [`set_scan_limit`] stores `0` as "no override
//!    configured", and [`get_effective_scan_limit`] falls back to the
//!    default the same way a never-configured scope already does.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::pagination` or
//! any other module's behavior. Existing callers of
//! `shared::pagination::paginate_id_range` / `paginate_id_list` are
//! unaffected until they choose to route their `max_scan` through
//! [`clamp_scan_limit`] or [`get_effective_scan_limit`].

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec};

use crate::auth::{has_role, Role};
use crate::errors::Error;
use crate::pagination::{DEFAULT_MAX_SCAN, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
use crate::storage::{persistent_get, persistent_set};

/// Hard ceiling on any bounded scan in this crate, regardless of what a
/// caller requests or an admin configures. Chosen to stay well under the
/// Soroban CPU instruction budget for a single invocation even when each
/// scanned item requires a persistent-storage read.
pub const ABSOLUTE_MAX_SCAN: u32 = 2_000;

// ---------------------------------------------------------------------------
// Pure clamping
// ---------------------------------------------------------------------------

/// Resolves a requested `max_scan` to a safe, bounded value: `0` becomes
/// `shared::pagination::DEFAULT_MAX_SCAN`, and anything above
/// [`ABSOLUTE_MAX_SCAN`] is capped.
pub fn clamp_scan_limit(requested: u32) -> u32 {
    if requested == 0 {
        DEFAULT_MAX_SCAN
    } else {
        requested.min(ABSOLUTE_MAX_SCAN)
    }
}

/// Fails fast when scanning `total` items would exceed the effective bound,
/// instead of silently truncating or looping unbounded.
pub fn ensure_within_scan_budget(total: u32, max_scan: u32) -> Result<(), Error> {
    if total > clamp_scan_limit(max_scan) {
        Err(Error::QuotaExceeded)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-scope admin configuration
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ScanGuardKey {
    /// `u32` scan-limit override for a named scope. `0` means "unset".
    Limit(Symbol),
}

/// Effective scan limit for `scope`: the admin override if one is set and
/// non-zero, otherwise `shared::pagination::DEFAULT_MAX_SCAN`. Always
/// re-clamped at read time, so a value stored before `ABSOLUTE_MAX_SCAN`
/// was lowered (if it ever is) can never leak through unbounded.
pub fn get_effective_scan_limit(env: &Env, scope: Symbol) -> u32 {
    let stored: u32 = persistent_get(env, &ScanGuardKey::Limit(scope)).unwrap_or(0);
    clamp_scan_limit(stored)
}

/// Sets the scan-limit override for `scope`. Admin-gated. `0` clears the
/// override (falling back to the shared default again); any other value is
/// clamped to [`ABSOLUTE_MAX_SCAN`] regardless of what is requested — an
/// admin can tighten the bound, never remove the ceiling.
pub fn set_scan_limit(
    env: &Env,
    admin: &Address,
    scope: Symbol,
    max_scan: u32,
) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    let stored = if max_scan == 0 { 0 } else { clamp_scan_limit(max_scan) };
    persistent_set(env, &ScanGuardKey::Limit(scope), &stored);
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic bounded offset scan
// ---------------------------------------------------------------------------

/// Result of one [`bounded_offset_scan`] call.
#[derive(Clone)]
pub struct BoundedScanResult<T> {
    pub items: Vec<T>,
    /// Number of ids actually inspected during this call.
    pub scanned: u32,
    /// `true` when the scan stopped before reaching the end of `ids`,
    /// whether because `limit` or `max_scan` was reached.
    pub has_more: bool,
    /// Offset to resume from on the next call. Equal to `ids.len()` when
    /// `has_more` is `false`.
    pub next_offset: u32,
}

/// Scans `ids[offset..]` in order, calling `probe` on each id and keeping
/// the ones it returns `Some` for, until `limit` matches are collected or
/// `max_scan` ids have been inspected — whichever comes first.
///
/// Unlike `shared::pagination::paginate_id_list`, `ids` need not be sorted
/// and no binary search is performed; this suits a plain pending/dead-
/// letter/queue index where keyset stability does not matter as much as a
/// hard scan ceiling. `max_scan` is always routed through
/// [`clamp_scan_limit`], so this function can never scan unbounded no
/// matter what its caller requests.
pub fn bounded_offset_scan<T, F>(
    env: &Env,
    ids: &Vec<u64>,
    offset: u32,
    limit: u32,
    max_scan: u32,
    mut probe: F,
) -> BoundedScanResult<T>
where
    T: Clone + soroban_sdk::IntoVal<Env, soroban_sdk::Val> + soroban_sdk::TryFromVal<Env, soroban_sdk::Val>,
    F: FnMut(u64) -> Option<T>,
{
    let effective_limit = if limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        limit.min(MAX_PAGE_LIMIT)
    };
    let effective_max_scan = clamp_scan_limit(max_scan);
    let total = ids.len();

    let mut items: Vec<T> = Vec::new(env);
    let mut scanned: u32 = 0;
    let mut idx = offset;

    while idx < total && (items.len() as u32) < effective_limit && scanned < effective_max_scan {
        let id = ids.get(idx).unwrap_or(0);
        scanned = scanned.saturating_add(1);
        if let Some(item) = probe(id) {
            items.push_back(item);
        }
        idx = idx.saturating_add(1);
    }

    BoundedScanResult {
        items,
        scanned,
        has_more: idx < total,
        next_offset: idx,
    }
}
