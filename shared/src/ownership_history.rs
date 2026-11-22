//! Append-only audit history for admin ownership transfers (Issue #450).
//!
//! [`crate::auth`] implements the two-step transfer (propose → accept, with an
//! expiry timestamp). This module records every step of that flow as a
//! readable, ordered history entry so operators can answer "who held
//! ownership, who proposed what, and why did a transfer not complete" without
//! replaying ledger events.
//!
//! Every transition writes exactly one [`OwnershipAuditEntry`]:
//!
//! | Action      | Written by                                       |
//! |-------------|--------------------------------------------------|
//! | `Proposed`  | `propose_ownership_transfer`                     |
//! | `Accepted`  | `accept_ownership_transfer`                      |
//! | `Cancelled` | `cancel_ownership_transfer`                      |
//! | `Expired`   | [`expire_ownership_transfer`], or a new proposal |
//! |             | that replaces an already-expired one             |
//!
//! Entries are never rewritten or removed. See `docs/OWNERSHIP_TRANSFER.md`.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Vec};

use crate::auth::{get_pending_ownership_transfer, KEY_PENDING_OWNER};
use crate::errors::Error;
use crate::storage::{persistent_read, persistent_set};

/// Largest page [`ownership_history`] returns in one call.
pub const MAX_OWNERSHIP_HISTORY_PAGE: u32 = 50;

/// What happened to a pending ownership transfer.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipAction {
    /// The current owner proposed a transfer.
    Proposed,
    /// The target accepted before expiry; ownership changed.
    Accepted,
    /// The current owner withdrew the proposal.
    Cancelled,
    /// The proposal passed its expiry without being accepted.
    Expired,
}

/// One step of the ownership transfer flow.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipAuditEntry {
    /// Zero-based, append-only position in the history.
    pub seq: u64,
    /// The transition that happened.
    pub action: OwnershipAction,
    /// Address that triggered the transition.
    pub actor: Address,
    /// Owner at the time the transfer was proposed.
    pub previous_owner: Address,
    /// Proposed new owner.
    pub target_owner: Address,
    /// Expiry timestamp of the transfer this entry is about.
    pub expiry: u64,
    /// Ledger timestamp of the transition.
    pub timestamp: u64,
    /// Ledger sequence of the transition.
    pub ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipHistoryKey {
    /// Number of entries written so far (`u64`).
    Count,
    /// Entry by `seq`.
    Entry(u64),
}

/// Appends one entry. Called by the auth transfer functions after their own
/// authorization checks have passed; it is not an entry point.
pub(crate) fn record_ownership_action(
    env: &Env,
    action: OwnershipAction,
    actor: &Address,
    previous_owner: &Address,
    target_owner: &Address,
    expiry: u64,
) -> OwnershipAuditEntry {
    let seq = ownership_history_len(env);
    let entry = OwnershipAuditEntry {
        seq,
        action,
        actor: actor.clone(),
        previous_owner: previous_owner.clone(),
        target_owner: target_owner.clone(),
        expiry,
        timestamp: env.ledger().timestamp(),
        ledger: env.ledger().sequence(),
    };
    persistent_set(env, &OwnershipHistoryKey::Entry(seq), &entry);
    persistent_set(env, &OwnershipHistoryKey::Count, &(seq + 1));
    env.events().publish(
        (symbol_short!("auth"), symbol_short!("own_hist")),
        entry.clone(),
    );
    entry
}

/// Number of history entries ever written.
pub fn ownership_history_len(env: &Env) -> u64 {
    persistent_read(env, &OwnershipHistoryKey::Count).unwrap_or(0)
}

/// Reads one history entry.
pub fn get_ownership_history_entry(env: &Env, seq: u64) -> Option<OwnershipAuditEntry> {
    persistent_read(env, &OwnershipHistoryKey::Entry(seq))
}

/// Returns up to `limit` entries starting at `start`, oldest first.
///
/// `limit` must be between 1 and [`MAX_OWNERSHIP_HISTORY_PAGE`]; anything
/// else returns [`Error::InvalidArgument`] so one read stays bounded. A
/// `start` past the end returns an empty page.
pub fn ownership_history(
    env: &Env,
    start: u64,
    limit: u32,
) -> Result<Vec<OwnershipAuditEntry>, Error> {
    if limit == 0 || limit > MAX_OWNERSHIP_HISTORY_PAGE {
        return Err(Error::InvalidArgument);
    }
    let total = ownership_history_len(env);
    let mut out = Vec::new(env);
    let mut seq = start;
    while seq < total && out.len() < limit {
        if let Some(entry) = get_ownership_history_entry(env, seq) {
            out.push_back(entry);
        }
        seq += 1;
    }
    Ok(out)
}

/// Clears a pending transfer whose expiry has passed and records `Expired`.
///
/// Permissionless so a stale proposal never depends on the old owner to clean
/// it up; `caller` must still authorize so the history names a real actor.
///
/// `accept_ownership_transfer` also clears an expired proposal, but it returns
/// `Err(TransferExpired)`, and an error returned from a contract invocation
/// rolls back that invocation's writes. This function is the path that makes
/// the cleanup durable.
///
/// Returns [`Error::NoPendingTransfer`] when nothing is pending and
/// [`Error::InvalidArgument`] when the pending transfer has not expired yet.
pub fn expire_ownership_transfer(
    env: &Env,
    caller: &Address,
) -> Result<OwnershipAuditEntry, Error> {
    caller.require_auth();
    let transfer = get_pending_ownership_transfer(env).ok_or(Error::NoPendingTransfer)?;
    if env.ledger().timestamp() <= transfer.expiry {
        return Err(Error::InvalidArgument);
    }
    env.storage().instance().remove(&KEY_PENDING_OWNER);
    Ok(record_ownership_action(
        env,
        OwnershipAction::Expired,
        caller,
        &transfer.current_owner,
        &transfer.target_owner,
        transfer.expiry,
    ))
}
