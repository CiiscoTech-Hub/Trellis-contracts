//! On-chain, queryable protocol changelog (Issue #340).
//!
//! `changelog/entries.json` + `changelog/schema.json` (Issue #126, see
//! `docs/CHANGELOG_SCHEMA.md`) already give this workspace a machine-readable
//! changelog, validated in CI. It is deliberately a **git-repo artifact**:
//! an indexer or client SDK has to clone the repo (or fetch the raw file
//! from GitHub) to read it, and a contract itself has no way to query "what
//! protocol-affecting changes have shipped since version N" at all — there
//! is nothing on-chain to ask.
//!
//! This module is the on-chain complement, not a replacement: an
//! append-only, admin-recorded log of the same kind of fact
//! (`changelog/schema.json`'s `impact`/`summary`/`migration_notes`/`issue`
//! shape, reused field-for-field) that any caller — a contract, an indexer,
//! a client SDK — can query directly from the deployed contract with no
//! git access, and that a contract's own logic can consult before acting
//! (e.g. refusing to proceed if a breaking change has landed it hasn't
//! accounted for).
//!
//! - [`record_protocol_change`] enforces the exact same rule
//!   `changelog/schema.json`'s `allOf`/`if`/`then` conditional enforces
//!   off-chain: `migration_notes` must be non-empty when `impact` is
//!   [`ChangeImpact::Breaking`]. Admin-gated.
//! - Entries are immutable and append-only, like `shared::audit_ledger` —
//!   there is no update or delete entry point. A wrong or incomplete entry
//!   is corrected by recording a new one with `supersedes` pointing at it,
//!   never by editing history.
//! - [`list_protocol_changes_since`] and [`has_breaking_change_since`] are
//!   bounded via `shared::scan_guard`, so neither can scan unbounded as the
//!   log grows.
//!
//! Nothing in `changelog/entries.json`, its schema, or
//! `scripts/validate-changelog.cjs` changes; this module does not read or
//! write that file (a contract cannot access the filesystem). The two
//! stay in sync by convention: a PR that adds a `changelog/entries.json`
//! entry for a deployed change should also call `record_protocol_change`
//! once that change ships, the same way the existing entry pairs with a
//! `CHANGELOG.md` line.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | Non-admin calls `record_protocol_change` | `Error::Unauthorized`, before anything is validated or stored. |
//! | `summary` is empty | `Error::InvalidArgument`. |
//! | `impact == Breaking` and `migration_notes` is empty | `Error::InvalidArgument` — the same rule `changelog/schema.json` enforces off-chain. |
//! | `supersedes` names a `seq` that does not exist | `Error::NotFound`, before the new entry is written. |
//! | `get_protocol_change(0)` or any `seq` beyond the current length | `None`, not an error. |
//! | `has_breaking_change_since` is asked about a window with more than `shared::scan_guard::ABSOLUTE_MAX_SCAN` entries | Scans only up to the ceiling and returns `false` if none of *those* were breaking — a true answer further back in a very long window can be missed. Call `list_protocol_changes_since` in explicit ranges instead when the window may be that large. |
//! | Two entries recorded for the same `module` | `latest_protocol_change_for_module` always reflects the most recently recorded one; older entries remain readable by `seq` via `get_protocol_change`. |
//!
//! ## Recovery / rollback
//!
//! Entries are never edited or deleted — "fixing" one means recording a
//! correction, exactly as a regular changelog never rewrites a shipped
//! entry:
//!
//! 1. **An entry was recorded with the wrong `impact`, or missing/wrong
//!    `migration_notes`**: record a new entry describing the correction,
//!    with `supersedes` set to the original's `seq`. The original stays
//!    exactly as recorded, so anyone who already read and acted on it can
//!    see what changed and why.
//! 2. **An entry should never have been recorded at all** (e.g. duplicate):
//!    record a correcting entry with `impact: Internal` and a `summary`
//!    saying so, `supersedes` pointing at it. There is no delete path, by
//!    design — the same append-only guarantee `shared::audit_ledger` gives
//!    its own entries.
//! 3. **Retry after a validation failure**: `record_protocol_change`
//!    performs no partial writes — a rejected call changes nothing, so
//!    simply correct the input (non-empty `summary`, non-empty
//!    `migration_notes` for a breaking change, a valid `supersedes`) and
//!    call it again.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `changelog/entries.json`,
//! its schema, `scripts/validate-changelog.cjs`, or any contract interface.

use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol, Vec};

use crate::auth::{has_role, Role};
use crate::errors::Error;
use crate::scan_guard::{clamp_scan_limit, ABSOLUTE_MAX_SCAN};
use crate::storage::{instance_get, instance_set, persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Mirrors `changelog/schema.json`'s `impact` enum exactly.
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeImpact {
    /// An existing caller or indexer must change something to keep working.
    Breaking = 0,
    /// Additive; existing callers are unaffected.
    Compatible = 1,
    /// Protocol-adjacent but not itself an observable behavior change.
    Internal = 2,
}

/// One immutable, append-only protocol changelog entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolChangeEntry {
    /// 1-based, monotonically increasing sequence; the entry's id.
    pub seq: u64,
    /// Which module/contract this entry concerns, e.g. `"treasury"`.
    pub module: Symbol,
    pub impact: ChangeImpact,
    /// One sentence, from the caller/indexer's point of view.
    pub summary: String,
    /// What an integrator must do. Required non-empty when `impact` is `Breaking`.
    pub migration_notes: String,
    /// The schema/protocol version this entry corresponds to, or `0` when none.
    pub schema_version: u32,
    /// The GitHub issue this closes, or `0` when none.
    pub issue: u32,
    pub recorded_ledger: u32,
    pub recorded_at: u64,
    pub recorded_by: Address,
    /// `seq` of a prior entry this corrects, if any.
    pub supersedes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProtocolChangelogKey {
    /// `u64` current length (instance storage: contract-level checkpoint).
    Length,
    /// One entry by `seq`.
    Entry(u64),
    /// Latest `seq` recorded for a given module.
    ModuleLatest(Symbol),
}

/// Event topic for every recorded protocol change.
pub const PROTOCOL_CHANGELOG_TOPIC: Symbol = symbol_short!("proto_cl");

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Current number of recorded entries.
pub fn length(env: &Env) -> u64 {
    instance_get(env, &ProtocolChangelogKey::Length).unwrap_or(0)
}

/// Reads the entry at `seq`, if it exists. `seq == 0` is never valid and
/// always returns `None`.
pub fn get_protocol_change(env: &Env, seq: u64) -> Option<ProtocolChangeEntry> {
    if seq == 0 {
        return None;
    }
    persistent_get(env, &ProtocolChangelogKey::Entry(seq))
}

/// The most recently recorded entry overall, if any.
pub fn latest_protocol_change(env: &Env) -> Option<ProtocolChangeEntry> {
    let len = length(env);
    if len == 0 {
        None
    } else {
        get_protocol_change(env, len)
    }
}

/// The most recently recorded entry for `module`, if any.
pub fn latest_protocol_change_for_module(env: &Env, module: Symbol) -> Option<ProtocolChangeEntry> {
    let seq: u64 = persistent_get(env, &ProtocolChangelogKey::ModuleLatest(module))?;
    get_protocol_change(env, seq)
}

/// Lists entries strictly after `from_seq` (`0` means "from the beginning"),
/// bounded by `shared::scan_guard::clamp_scan_limit(limit)`.
pub fn list_protocol_changes_since(
    env: &Env,
    from_seq: u64,
    limit: u32,
) -> Vec<ProtocolChangeEntry> {
    let len = length(env);
    let max_scan = clamp_scan_limit(limit) as u64;
    let mut out: Vec<ProtocolChangeEntry> = Vec::new(env);
    let mut seq = from_seq.saturating_add(1).max(1);
    let mut scanned: u64 = 0;
    while seq <= len && scanned < max_scan {
        if let Some(entry) = get_protocol_change(env, seq) {
            out.push_back(entry);
        }
        seq = seq.saturating_add(1);
        scanned = scanned.saturating_add(1);
    }
    out
}

/// Whether any entry strictly after `from_seq` is `Breaking`, scanning at
/// most `shared::scan_guard::ABSOLUTE_MAX_SCAN` entries. See the module
/// docs' edge-case table for what happens when the window is longer than
/// that.
pub fn has_breaking_change_since(env: &Env, from_seq: u64) -> bool {
    let len = length(env);
    let max_scan = ABSOLUTE_MAX_SCAN as u64;
    let mut seq = from_seq.saturating_add(1).max(1);
    let mut scanned: u64 = 0;
    while seq <= len && scanned < max_scan {
        if let Some(entry) = get_protocol_change(env, seq) {
            if entry.impact == ChangeImpact::Breaking {
                return true;
            }
        }
        seq = seq.saturating_add(1);
        scanned = scanned.saturating_add(1);
    }
    false
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Records a new protocol changelog entry. Admin-gated.
///
/// Enforces the same rule `changelog/schema.json` enforces off-chain:
/// `summary` must be non-empty, and `migration_notes` must be non-empty
/// when `impact` is [`ChangeImpact::Breaking`]. `supersedes`, when
/// provided, must name an existing entry.
pub fn record_protocol_change(
    env: &Env,
    admin: &Address,
    module: Symbol,
    impact: ChangeImpact,
    summary: String,
    migration_notes: String,
    schema_version: u32,
    issue: u32,
    supersedes: Option<u64>,
) -> Result<ProtocolChangeEntry, Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();

    if summary.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if impact == ChangeImpact::Breaking && migration_notes.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if let Some(prior) = supersedes {
        if get_protocol_change(env, prior).is_none() {
            return Err(Error::NotFound);
        }
    }

    let seq = length(env).saturating_add(1);
    let entry = ProtocolChangeEntry {
        seq,
        module: module.clone(),
        impact,
        summary,
        migration_notes,
        schema_version,
        issue,
        recorded_ledger: env.ledger().sequence(),
        recorded_at: env.ledger().timestamp(),
        recorded_by: admin.clone(),
        supersedes,
    };
    persistent_set(env, &ProtocolChangelogKey::Entry(seq), &entry);
    instance_set(env, &ProtocolChangelogKey::Length, &seq);
    persistent_set(env, &ProtocolChangelogKey::ModuleLatest(module.clone()), &seq);

    env.events().publish(
        (PROTOCOL_CHANGELOG_TOPIC, symbol_short!("recorded"), module),
        (seq, impact as u32, schema_version),
    );

    Ok(entry)
}
