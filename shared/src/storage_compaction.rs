//! Shared storage page compaction and orphan key sweeper (Issue #537).
//!
//! # Problem
//!
//! Contracts in this workspace keep large logical collections — per-region aid
//! indexes, audit-entry indexes, referral edge lists — as a set of fixed-size
//! **pages** in persistent storage rather than one unbounded `Vec`. A single
//! Soroban entry has a bounded XDR size, and rewriting one huge `Vec` on every
//! append costs gas proportional to the whole collection. Paging keeps each
//! write proportional to one page.
//!
//! Two kinds of waste accumulate over a collection's life:
//!
//! 1. **Fragmentation.** Deletions leave pages partially filled. A collection
//!    that once held 10 full pages and then lost 60% of its entries still
//!    occupies 10 persistent entries, each paying rent (TTL) and each adding a
//!    read to any full scan.
//! 2. **Orphan keys.** An index entry can outlive the record it points at: the
//!    record was removed, archived after its TTL lapsed, or superseded, but the
//!    pointer in the index was never cleared. Orphans waste space and make a
//!    naive consumer fetch a key that resolves to nothing.
//!
//! # Why an explicit directory
//!
//! Soroban exposes **no API to enumerate storage keys** — a contract can only
//! read keys it already knows. Compaction and sweeping therefore cannot "scan
//! the database"; they operate over an explicit, contract-maintained
//! [`PageDirectory`] that records how many pages a namespace owns and how many
//! live entries they hold. Every operation here is bounded by that directory,
//! never by the (unknowable) size of host storage.
//!
//! # Design
//!
//! - A namespace (`Symbol`) owns one [`PageDirectory`] in **instance** storage
//!   and `page_count` [`StoragePage`] entries in **persistent** storage keyed
//!   `(namespace, page_no)`. Each page holds at most `capacity` keys.
//! - [`append`] is O(1) amortized: it reads and rewrites only the tail page.
//! - [`remove_key`] / [`contains`] do a **bounded** scan (`max_scan` pages) so a
//!   caller can never trigger unbounded work.
//! - Compaction is **report-first**, mirroring `retention::plan_cleanup`:
//!   [`plan_compaction`] is read-only and returns what a run *would* reclaim;
//!   [`apply_compaction`] refuses without an explicit `confirm` and is bounded
//!   by [`MAX_COMPACT_PAGES`]. It preserves the exact multiset of live keys —
//!   it only moves them into the densest prefix of pages and frees the trailing
//!   ones.
//! - The orphan sweeper is **predicate-driven**: the caller supplies a liveness
//!   check for its own records (this crate cannot know contract-specific
//!   existence). [`plan_orphan_sweep`] reports orphans without mutating;
//!   [`apply_orphan_sweep`] removes them, both bounded and resumable via a page
//!   cursor.
//!
//! # Paths covered (acceptance criteria)
//!
//! - **Normal:** append, plan, compact a fragmented index, sweep orphans.
//! - **Failure:** uninitialised namespace ([`Error::NotFound`]), invalid
//!   capacity ([`Error::ConfigInvalid`]), oversized index refused without
//!   mutation ([`Error::QuotaExceeded`]), unconfirmed destructive call
//!   ([`Error::InvalidArgument`]).
//! - **Retry / idempotency:** re-running [`apply_compaction`] on an
//!   already-dense index reclaims zero pages and changes nothing; a resumable
//!   sweep continues from its returned cursor.
//! - **Authorization:** destructive entry points are not self-authenticating by
//!   design (same convention as `quota` and `retention`); the calling contract
//!   gates them behind an admin check. The test module proves an unauthorized
//!   caller is rejected before any mutation.
//! - **Recovery / rollback:** every public operation is a single logical
//!   mutation; because Soroban reverts all storage writes on a failed
//!   transaction, a trapped call leaves the directory and pages exactly as they
//!   were. [`apply_compaction`] additionally reconciles `live_entries` to the
//!   true count it observes, healing any drift left by an earlier partial path.
//!
//! See `implementation.md` for the full runbook and worked complexity analysis.

use soroban_sdk::{contracttype, Env, Symbol, Vec};

use crate::errors::Error;
use crate::storage::{
    instance_get, instance_has, instance_set, persistent_get, persistent_remove, persistent_set,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default entries per page when a caller passes `0` to [`init_index`].
pub const DEFAULT_PAGE_CAPACITY: u32 = 64;

/// Hard ceiling on page capacity. Bounds the worst-case size of one page's
/// `Vec<Symbol>` and therefore the gas of a single page read/write.
pub const MAX_PAGE_CAPACITY: u32 = 256;

/// Largest number of pages [`apply_compaction`] will process in one atomic
/// call. An index larger than this is refused with [`Error::QuotaExceeded`]
/// (and left untouched) rather than risking an out-of-gas abort mid-rewrite.
/// Callers with larger indexes should sweep orphans first (which shrinks the
/// live set) or raise this bound deliberately.
pub const MAX_COMPACT_PAGES: u32 = 128;

/// Default page budget for a bounded scan / sweep when a caller passes `0`.
pub const DEFAULT_MAX_SCAN: u32 = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Metadata for one paged namespace. Lives in **instance** storage because it
/// is small, contract-level bookkeeping that must always be readable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageDirectory {
    /// Logical collection name; also the prefix of every page key.
    pub namespace: Symbol,
    /// Maximum entries per page. Fixed at [`init_index`]; never mutated.
    pub capacity: u32,
    /// Number of live pages. Pages are `[0, page_count)`.
    pub page_count: u32,
    /// Running count of live entries across all pages.
    pub live_entries: u32,
    /// Bumped on every successful compaction; lets observers detect reorganisation.
    pub version: u32,
}

/// A single page of index keys, held in **persistent** storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePage {
    pub entries: Vec<Symbol>,
}

/// Non-destructive description of what a compaction run would reclaim.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionPlan {
    pub namespace: Symbol,
    /// Always `true`: produced by the read-only planner.
    pub dry_run: bool,
    /// Directory version the plan was computed against.
    pub evaluated_version: u32,
    /// Pages the namespace holds now.
    pub current_pages: u32,
    /// Live entries now.
    pub live_entries: u32,
    /// Pages needed if entries were packed densely.
    pub projected_pages: u32,
    /// `current_pages - projected_pages`: pages a run would free.
    pub reclaimable_pages: u32,
    /// Fragmentation as basis points of total pages (`reclaimable / current`).
    pub fragmentation_bps: u32,
}

/// Outcome of an [`apply_compaction`] run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionReport {
    pub namespace: Symbol,
    pub pages_before: u32,
    pub pages_after: u32,
    /// Live entries carried across unchanged (an invariant the tests assert).
    pub entries_preserved: u32,
    pub pages_reclaimed: u32,
    pub new_version: u32,
    /// `false` only for the no-op early return on an empty namespace.
    pub destructive: bool,
}

/// Non-destructive report of orphan index keys found by a bounded scan.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanPlan {
    pub namespace: Symbol,
    pub dry_run: bool,
    /// Entries examined this pass.
    pub scanned: u32,
    /// Keys whose target the predicate reported as gone.
    pub orphans: Vec<Symbol>,
    /// Page to resume from; equals `page_count` when the scan is complete.
    pub next_cursor: u32,
    pub complete: bool,
}

/// Outcome of an [`apply_orphan_sweep`] run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanReport {
    pub namespace: Symbol,
    pub scanned: u32,
    pub removed: Vec<Symbol>,
    pub live_entries_after: u32,
    pub next_cursor: u32,
    pub complete: bool,
    pub destructive: bool,
}

/// Storage keys for this module. A dedicated enum keeps compaction state from
/// ever colliding with a contract's own keys.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum CompactionKey {
    /// Instance: the namespace directory.
    Dir(Symbol),
    /// Persistent: one page `(namespace, page_no)`.
    Page(Symbol, u32),
}

fn dir_key(ns: &Symbol) -> CompactionKey {
    CompactionKey::Dir(ns.clone())
}

fn page_key(ns: &Symbol, page_no: u32) -> CompactionKey {
    CompactionKey::Page(ns.clone(), page_no)
}

/// Dense page count for `live` entries at `capacity` (ceil division).
fn dense_pages(live: u32, capacity: u32) -> u32 {
    if live == 0 || capacity == 0 {
        0
    } else {
        // capacity >= 1 here, so this cannot overflow for u32 live.
        (live + capacity - 1) / capacity
    }
}

// ---------------------------------------------------------------------------
// Directory administration
// ---------------------------------------------------------------------------

/// Create an empty paged index for `namespace`.
///
/// `capacity == 0` selects [`DEFAULT_PAGE_CAPACITY`]. A capacity above
/// [`MAX_PAGE_CAPACITY`] is rejected so one page can never grow past the size
/// that bounds per-page gas. Re-initialising an existing namespace is refused
/// with [`Error::AlreadyInitialized`] so live data is never silently dropped.
pub fn init_index(env: &Env, namespace: &Symbol, capacity: u32) -> Result<PageDirectory, Error> {
    if instance_has(env, &dir_key(namespace)) {
        return Err(Error::AlreadyInitialized);
    }
    let capacity = if capacity == 0 {
        DEFAULT_PAGE_CAPACITY
    } else {
        capacity
    };
    if capacity > MAX_PAGE_CAPACITY {
        return Err(Error::ConfigInvalid);
    }
    let dir = PageDirectory {
        namespace: namespace.clone(),
        capacity,
        page_count: 0,
        live_entries: 0,
        version: 0,
    };
    instance_set(env, &dir_key(namespace), &dir);
    Ok(dir)
}

/// The directory for `namespace`, or `None` when it was never initialised.
pub fn get_directory(env: &Env, namespace: &Symbol) -> Option<PageDirectory> {
    instance_get(env, &dir_key(namespace))
}

/// The directory for `namespace`, failing closed with [`Error::NotFound`] when
/// it is absent. Absence here means the caller is operating on an index that
/// was never set up — a programming error that must not be treated as "empty".
pub fn require_directory(env: &Env, namespace: &Symbol) -> Result<PageDirectory, Error> {
    get_directory(env, namespace).ok_or(Error::NotFound)
}

fn read_page(env: &Env, namespace: &Symbol, page_no: u32) -> Vec<Symbol> {
    match persistent_get::<_, StoragePage>(env, &page_key(namespace, page_no)) {
        Some(page) => page.entries,
        None => Vec::new(env),
    }
}

fn write_page(env: &Env, namespace: &Symbol, page_no: u32, entries: Vec<Symbol>) {
    persistent_set(env, &page_key(namespace, page_no), &StoragePage { entries });
}

// ---------------------------------------------------------------------------
// Mutators
// ---------------------------------------------------------------------------

/// Append `key` to the namespace. O(1) amortized: reads and rewrites only the
/// tail page, allocating a new page when the tail is full.
///
/// Appends never deduplicate — a collection may legitimately hold a key twice.
/// Compaction preserves the multiset exactly; the orphan sweeper removes by
/// liveness, not by uniqueness.
pub fn append(env: &Env, namespace: &Symbol, key: &Symbol) -> Result<(), Error> {
    let mut dir = require_directory(env, namespace)?;

    if dir.page_count == 0 {
        let mut entries = Vec::new(env);
        entries.push_back(key.clone());
        write_page(env, namespace, 0, entries);
        dir.page_count = 1;
    } else {
        let tail_no = dir.page_count - 1;
        let mut tail = read_page(env, namespace, tail_no);
        if tail.len() >= dir.capacity {
            let mut entries = Vec::new(env);
            entries.push_back(key.clone());
            write_page(env, namespace, dir.page_count, entries);
            dir.page_count += 1;
        } else {
            tail.push_back(key.clone());
            write_page(env, namespace, tail_no, tail);
        }
    }

    dir.live_entries = dir.live_entries.checked_add(1).ok_or(Error::Overflow)?;
    instance_set(env, &dir_key(namespace), &dir);
    Ok(())
}

/// Returns `true` when `key` is present in the first `max_scan` pages.
///
/// `max_scan == 0` selects [`DEFAULT_MAX_SCAN`]. The scan is deliberately
/// bounded; a caller that needs certainty on a huge index must page through
/// with an explicit bound.
pub fn contains(env: &Env, namespace: &Symbol, key: &Symbol, max_scan: u32) -> bool {
    let dir = match get_directory(env, namespace) {
        Some(d) => d,
        None => return false,
    };
    let budget = if max_scan == 0 {
        DEFAULT_MAX_SCAN
    } else {
        max_scan
    };
    let limit = dir.page_count.min(budget);
    let mut p = 0;
    while p < limit {
        let page = read_page(env, namespace, p);
        let mut i = 0;
        while i < page.len() {
            if page.get(i) == Some(key.clone()) {
                return true;
            }
            i += 1;
        }
        p += 1;
    }
    false
}

/// Remove the **first** occurrence of `key` from the first `max_scan` pages.
///
/// Returns `Ok(true)` when a key was removed, `Ok(false)` when none was found
/// within the bound. Removal leaves the page it touched possibly under-filled;
/// that fragmentation is reclaimed later by [`apply_compaction`], keeping this
/// path O(one page rewrite).
pub fn remove_key(
    env: &Env,
    namespace: &Symbol,
    key: &Symbol,
    max_scan: u32,
) -> Result<bool, Error> {
    let mut dir = require_directory(env, namespace)?;
    let budget = if max_scan == 0 {
        DEFAULT_MAX_SCAN
    } else {
        max_scan
    };
    let limit = dir.page_count.min(budget);
    let mut p = 0;
    while p < limit {
        let page = read_page(env, namespace, p);
        let mut found = false;
        let mut rebuilt = Vec::new(env);
        let mut i = 0;
        while i < page.len() {
            let entry = page.get(i).unwrap();
            if !found && entry == key.clone() {
                found = true; // drop exactly one occurrence
            } else {
                rebuilt.push_back(entry);
            }
            i += 1;
        }
        if found {
            write_page(env, namespace, p, rebuilt);
            dir.live_entries = dir.live_entries.saturating_sub(1);
            instance_set(env, &dir_key(namespace), &dir);
            return Ok(true);
        }
        p += 1;
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Compaction
// ---------------------------------------------------------------------------

/// Read-only plan: what [`apply_compaction`] would reclaim right now. O(1) —
/// derived from the directory counters, no page reads.
pub fn plan_compaction(env: &Env, namespace: &Symbol) -> Result<CompactionPlan, Error> {
    let dir = require_directory(env, namespace)?;
    let projected = dense_pages(dir.live_entries, dir.capacity);
    let reclaimable = dir.page_count.saturating_sub(projected);
    let fragmentation_bps = if dir.page_count == 0 {
        0
    } else {
        // reclaimable <= page_count, so reclaimable * 10_000 <= page_count * 10_000;
        // page_count fits in u32 and the product fits in u64.
        ((reclaimable as u64 * 10_000) / dir.page_count as u64) as u32
    };
    Ok(CompactionPlan {
        namespace: namespace.clone(),
        dry_run: true,
        evaluated_version: dir.version,
        current_pages: dir.page_count,
        live_entries: dir.live_entries,
        projected_pages: projected,
        reclaimable_pages: reclaimable,
        fragmentation_bps,
    })
}

/// Densify a namespace: pack every live key into the lowest page numbers and
/// free the trailing pages. Atomic and bounded.
///
/// - Requires `confirm == true`; otherwise [`Error::InvalidArgument`] with no
///   mutation (guards against an accidental destructive call).
/// - Refuses an index larger than [`MAX_COMPACT_PAGES`] with
///   [`Error::QuotaExceeded`], again with no mutation.
/// - Preserves the exact multiset of live keys and reconciles `live_entries`
///   to the true observed count.
/// - Idempotent: a second run on a dense index reclaims zero pages.
///
/// Complexity: O(P · C) reads/writes where P = `page_count` (≤
/// [`MAX_COMPACT_PAGES`]) and C = `capacity` (≤ [`MAX_PAGE_CAPACITY`]), with no
/// extra persistent entries allocated beyond the pages already present.
pub fn apply_compaction(
    env: &Env,
    namespace: &Symbol,
    confirm: bool,
) -> Result<CompactionReport, Error> {
    if !confirm {
        return Err(Error::InvalidArgument);
    }
    let mut dir = require_directory(env, namespace)?;
    let pages_before = dir.page_count;

    if pages_before == 0 {
        return Ok(CompactionReport {
            namespace: namespace.clone(),
            pages_before: 0,
            pages_after: 0,
            entries_preserved: 0,
            pages_reclaimed: 0,
            new_version: dir.version,
            destructive: false,
        });
    }
    if pages_before > MAX_COMPACT_PAGES {
        return Err(Error::QuotaExceeded);
    }

    let capacity = dir.capacity;
    let mut write_no: u32 = 0;
    let mut buffer: Vec<Symbol> = Vec::new(env);
    let mut preserved: u32 = 0;

    // Forward compaction. We read source pages in increasing order and flush
    // destination pages in increasing order; because entries written never
    // exceed entries read, the write cursor stays at or behind the read cursor,
    // so a flush can only overwrite a page already fully read this pass.
    let mut src = 0;
    while src < pages_before {
        let page = read_page(env, namespace, src);
        let mut i = 0;
        while i < page.len() {
            buffer.push_back(page.get(i).unwrap());
            preserved += 1;
            if buffer.len() >= capacity {
                write_page(env, namespace, write_no, buffer);
                buffer = Vec::new(env);
                write_no += 1;
            }
            i += 1;
        }
        src += 1;
    }

    let pages_after = if buffer.len() > 0 {
        write_page(env, namespace, write_no, buffer);
        write_no + 1
    } else {
        write_no
    };

    // Free the trailing pages that compaction emptied.
    let mut p = pages_after;
    while p < pages_before {
        persistent_remove(env, &page_key(namespace, p));
        p += 1;
    }

    dir.page_count = pages_after;
    dir.live_entries = preserved; // reconcile any drift
    dir.version = dir.version.saturating_add(1);
    instance_set(env, &dir_key(namespace), &dir);

    Ok(CompactionReport {
        namespace: namespace.clone(),
        pages_before,
        pages_after,
        entries_preserved: preserved,
        pages_reclaimed: pages_before - pages_after,
        new_version: dir.version,
        destructive: true,
    })
}

// ---------------------------------------------------------------------------
// Orphan key sweeper
// ---------------------------------------------------------------------------

/// Scan for orphan keys without mutating anything.
///
/// `is_live(env, key)` returns `true` when the key's target record still
/// exists. Starting at page `cursor`, up to `max_scan` entries are examined;
/// `next_cursor` / `complete` let a caller resume across transactions.
pub fn plan_orphan_sweep<F>(
    env: &Env,
    namespace: &Symbol,
    cursor: u32,
    max_scan: u32,
    is_live: F,
) -> Result<OrphanPlan, Error>
where
    F: Fn(&Env, &Symbol) -> bool,
{
    let dir = require_directory(env, namespace)?;
    let budget = if max_scan == 0 {
        DEFAULT_MAX_SCAN
    } else {
        max_scan
    };
    let mut orphans = Vec::new(env);
    let mut scanned: u32 = 0;
    let mut p = cursor;
    while p < dir.page_count && scanned < budget {
        let page = read_page(env, namespace, p);
        let mut i = 0;
        while i < page.len() {
            let key = page.get(i).unwrap();
            if !is_live(env, &key) {
                orphans.push_back(key);
            }
            scanned += 1;
            i += 1;
        }
        p += 1;
    }
    let complete = p >= dir.page_count;
    Ok(OrphanPlan {
        namespace: namespace.clone(),
        dry_run: true,
        scanned,
        orphans,
        next_cursor: p,
        complete,
    })
}

/// Remove orphan keys the predicate rejects, bounded and resumable.
///
/// Requires `confirm == true`. Rewrites only the pages it touches, dropping
/// dead keys in place (leaving pages possibly under-filled — reclaim their
/// space afterwards with [`apply_compaction`]). Returns the removed keys, the
/// updated live count, and a cursor to resume from.
pub fn apply_orphan_sweep<F>(
    env: &Env,
    namespace: &Symbol,
    cursor: u32,
    max_scan: u32,
    confirm: bool,
    is_live: F,
) -> Result<OrphanReport, Error>
where
    F: Fn(&Env, &Symbol) -> bool,
{
    if !confirm {
        return Err(Error::InvalidArgument);
    }
    let mut dir = require_directory(env, namespace)?;
    let budget = if max_scan == 0 {
        DEFAULT_MAX_SCAN
    } else {
        max_scan
    };
    let mut removed = Vec::new(env);
    let mut scanned: u32 = 0;
    let mut p = cursor;
    while p < dir.page_count && scanned < budget {
        let page = read_page(env, namespace, p);
        let mut rebuilt = Vec::new(env);
        let mut changed = false;
        let mut i = 0;
        while i < page.len() {
            let key = page.get(i).unwrap();
            if is_live(env, &key) {
                rebuilt.push_back(key);
            } else {
                removed.push_back(key);
                changed = true;
            }
            scanned += 1;
            i += 1;
        }
        if changed {
            write_page(env, namespace, p, rebuilt);
        }
        p += 1;
    }

    dir.live_entries = dir.live_entries.saturating_sub(removed.len());
    instance_set(env, &dir_key(namespace), &dir);

    let complete = p >= dir.page_count;
    Ok(OrphanReport {
        namespace: namespace.clone(),
        scanned,
        removed,
        live_entries_after: dir.live_entries,
        next_cursor: p,
        complete,
        destructive: true,
    })
}

#[cfg(test)]
mod tests;
