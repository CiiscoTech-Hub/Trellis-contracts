//! Partial-failure reporting and retry for `shared::batch` results (Issue #339).
//!
//! `shared::batch::execute_multi_transfer` already gives atomic and
//! non-atomic batch semantics, per-operation results, and aggregate
//! succeeded/failed counts — but once a non-atomic batch finishes with some
//! failures, there is no addressable record of **which** transfers failed
//! and why, and no way to retry just the failed subset: the caller would
//! have to zip the original transfer list against `BatchResult.results` by
//! hand and rebuild a new batch itself.
//!
//! This module adds that reporting and retry layer on top of
//! `shared::batch`, without changing it:
//!
//! - [`record_batch_failures`] zips a `BatchResult` back against the
//!   `BatchTransfer`s that produced it and persists an addressable
//!   [`BatchFailureReport`] — one [`BatchFailureDetail`] per failed
//!   transfer, with its original index, recipient, amount, and a
//!   retryable/non-retryable classification. Returns `None` when there was
//!   nothing to record.
//! - [`retry_batch_failures`] is the retry path: it re-submits only the
//!   entries marked `retryable`, **always as a non-atomic batch**
//!   regardless of what the original run used (see Design), and updates
//!   the report in place. Only the original caller or an admin may trigger
//!   it, and it authenticates before anything runs — the authorization
//!   path.
//! - [`discard_batch_failure_report`] is the admin-gated cleanup/rollback
//!   path for a report that will never be retried (e.g. every remaining
//!   entry is non-retryable).
//!
//! Retryability reuses `shared::jobs::is_retryable_error`, with one
//! correction: `shared::batch::BatchError` codes (the 800–899 range, e.g.
//! a zero-amount transfer rejected at validation) are always treated as
//! **not** retryable, because `is_retryable_error` was designed around
//! `shared::errors::Error` codes and defaults unrecognized codes to
//! retryable — which would otherwise misclassify a permanent validation
//! failure as transient.
//!
//! ## Design
//!
//! - **Why retry always forces non-atomic.** `execute_multi_transfer` in
//!   `Atomic` mode stops at the first failure, so `BatchResult.results` can
//!   be *shorter* than the input list — the transfers after the break point
//!   were never attempted at all. Retrying only the failed subset atomically
//!   would reintroduce that same short-circuit and silently lose track of
//!   entries past the first retry failure. Forcing `NonAtomic` guarantees
//!   one result per retried transfer, which this module's bookkeeping
//!   depends on.
//! - **Why the retry target is read from the report, not the caller.**
//!   `token` is captured at recording time; a retry call only supplies
//!   `max_operations`, so a caller cannot redirect a retry to a different
//!   asset than the one that actually failed.
//! - **Non-retryable entries are never silently dropped.** They stay in the
//!   report (`resolved` only becomes `true` once nothing retryable remains
//!   *and* nothing failed on the latest retry), surfaced for a maintainer to
//!   act on via [`discard_batch_failure_report`] or a corrected manual
//!   transfer.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | `record_batch_failures` on a result with `failed == 0` | Returns `None`; nothing is stored. |
//! | `record_batch_failures` after an `Atomic` result | Only validation-stage failures are ever present to record — an execution-stage failure in `Atomic` mode panics and aborts the transaction before `execute_multi_transfer` can return at all. |
//! | `retry_batch_failures` on an unknown `batch_id` | `Error::NotFound`. |
//! | `retry_batch_failures` on an already-`resolved` report | `Error::InvalidTransition`. |
//! | Caller is neither the report's original caller nor an admin | `Error::Unauthorized`, before anything is read further. |
//! | Every remaining failure is non-retryable | `Error::InvalidTransition` — nothing to retry; use [`discard_batch_failure_report`]. |
//! | A retried transfer fails again | Kept in the report with its new `error_code` and re-classified `retryable`; `resolved` stays `false`. |
//! | A retried transfer succeeds | Removed from the report; `succeeded` on the report increases. |
//! | `max_operations` passed to `retry_batch_failures` is too small for the retryable subset | `Error::InvalidArgument` (from `shared::batch::BatchError::BatchTooLarge`), report left untouched. |
//! | Non-admin calls `discard_batch_failure_report` | `Error::Unauthorized`. |
//!
//! ## Recovery / rollback
//!
//! 1. **Some failures are permanent** (non-retryable, e.g. a validation
//!    error that needs a corrected amount): [`retry_batch_failures`] will
//!    never resubmit them. Either fix the input and submit a fresh,
//!    unrelated batch, or call [`discard_batch_failure_report`] once the
//!    report is no longer actionable.
//! 2. **A retry itself needs to be retried**: [`retry_batch_failures`] is
//!    idempotent to call again on the same `batch_id` — each call only acts
//!    on whatever is still outstanding in the report.
//! 3. **A report was recorded against the wrong `caller`** (should not
//!    happen if `record_batch_failures` is always called with the same
//!    `caller` that authorized the original batch, but if it is): an admin
//!    can still call [`retry_batch_failures`], since admin access is always
//!    accepted alongside the original caller.
//!
//! ## Compatibility
//!
//! Purely additive: new storage keys, no changes to `shared::batch` or
//! `shared::jobs`. A contract adopts this by calling
//! [`record_batch_failures`] after its own `execute_multi_transfer` call
//! when `result.failed > 0`.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::{has_role, Role};
use crate::batch::{
    execute_multi_transfer, BatchConfig, BatchMode, BatchResult, BatchTransfer, OperationResult,
};
use crate::errors::Error;
use crate::jobs::is_retryable_error;
use crate::storage::{instance_get, instance_set, persistent_get, persistent_remove, persistent_set};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One failed transfer within a recorded batch, addressable for retry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchFailureDetail {
    /// Position in the original transfer list.
    pub index: u32,
    pub to: Address,
    pub amount: i128,
    pub error_code: u32,
    pub retryable: bool,
}

/// Addressable record of a batch's failures, retried in place as entries
/// are resolved.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchFailureReport {
    pub batch_id: u64,
    /// Address that authorized the original (and must authorize any retry).
    pub caller: Address,
    /// Asset the original batch transferred; retries always target this token.
    pub token: Address,
    pub total: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub retryable_count: u32,
    pub failures: Vec<BatchFailureDetail>,
    pub created_ledger: u32,
    /// `true` once nothing retryable remains and the latest retry (if any)
    /// left zero failures.
    pub resolved: bool,
}

// ---------------------------------------------------------------------------
// Storage keys and events
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum BatchRetryKey {
    Counter,
    Report(u64),
}

/// Event topic for batch-failure recording and retry.
pub const BATCH_RETRY_TOPIC: Symbol = symbol_short!("bat_rtry");

fn next_batch_id(env: &Env) -> u64 {
    let current: u64 = instance_get(env, &BatchRetryKey::Counter).unwrap_or(0);
    let next = current.saturating_add(1);
    instance_set(env, &BatchRetryKey::Counter, &next);
    next
}

fn save_report(env: &Env, report: &BatchFailureReport) {
    persistent_set(env, &BatchRetryKey::Report(report.batch_id), report);
}

/// `shared::batch::BatchError` codes (800-899) are validation/config
/// failures, never retryable; everything else defers to
/// `shared::jobs::is_retryable_error`.
fn classify_retryable(code: u32) -> bool {
    if (800..900).contains(&code) {
        false
    } else {
        is_retryable_error(code)
    }
}

fn count_retryable(details: &Vec<BatchFailureDetail>) -> u32 {
    let mut count: u32 = 0;
    let mut i: u32 = 0;
    while i < details.len() {
        if details.get(i).unwrap().retryable {
            count = count.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    count
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Reads the failure report for `batch_id`, if one exists.
pub fn get_batch_failure_report(env: &Env, batch_id: u64) -> Option<BatchFailureReport> {
    persistent_get(env, &BatchRetryKey::Report(batch_id))
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// Zips `result` back against the `transfers` that produced it and persists
/// an addressable [`BatchFailureReport`]. Returns `None` when there is
/// nothing to record (`result.failed == 0`, or no failures line up with a
/// corresponding transfer).
pub fn record_batch_failures(
    env: &Env,
    caller: &Address,
    token: &Address,
    transfers: &Vec<BatchTransfer>,
    result: &BatchResult,
) -> Option<BatchFailureReport> {
    if result.failed == 0 {
        return None;
    }

    let scanned = result.results.len().min(transfers.len());
    let mut failures: Vec<BatchFailureDetail> = Vec::new(env);
    let mut retryable_count: u32 = 0;
    let mut i: u32 = 0;
    while i < scanned {
        let outcome = result.results.get(i).unwrap();
        if let OperationResult::Failure(code) = outcome {
            let retryable = classify_retryable(code);
            if retryable {
                retryable_count = retryable_count.saturating_add(1);
            }
            let t = transfers.get(i).unwrap();
            failures.push_back(BatchFailureDetail {
                index: i,
                to: t.to,
                amount: t.amount,
                error_code: code,
                retryable,
            });
        }
        i = i.saturating_add(1);
    }

    if failures.is_empty() {
        return None;
    }

    let batch_id = next_batch_id(env);
    let report = BatchFailureReport {
        batch_id,
        caller: caller.clone(),
        token: token.clone(),
        total: result.total,
        succeeded: result.succeeded,
        failed: failures.len(),
        retryable_count,
        failures,
        created_ledger: env.ledger().sequence(),
        resolved: false,
    };
    save_report(env, &report);
    env.events().publish(
        (BATCH_RETRY_TOPIC, symbol_short!("recorded")),
        (batch_id, report.failed, retryable_count),
    );
    Some(report)
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

/// Re-submits every `retryable` entry in `batch_id`'s report as a fresh,
/// forced-`NonAtomic` batch (see module docs for why), and updates the
/// report in place.
///
/// `caller` must be the report's original caller or hold [`Role::Admin`],
/// and must authenticate.
pub fn retry_batch_failures(
    env: &Env,
    caller: &Address,
    batch_id: u64,
    max_operations: u32,
) -> Result<BatchResult, Error> {
    let mut report = get_batch_failure_report(env, batch_id).ok_or(Error::NotFound)?;
    if report.resolved {
        return Err(Error::InvalidTransition);
    }
    if *caller != report.caller && !has_role(env, caller, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    caller.require_auth();

    let failure_count = report.failures.len();
    let mut retry_transfers: Vec<BatchTransfer> = Vec::new(env);
    let mut retry_originals: Vec<BatchFailureDetail> = Vec::new(env);
    let mut kept: Vec<BatchFailureDetail> = Vec::new(env);
    let mut i: u32 = 0;
    while i < failure_count {
        let detail = report.failures.get(i).unwrap();
        if detail.retryable {
            retry_transfers.push_back(BatchTransfer {
                to: detail.to.clone(),
                amount: detail.amount,
            });
            retry_originals.push_back(detail);
        } else {
            kept.push_back(detail);
        }
        i = i.saturating_add(1);
    }

    if retry_transfers.is_empty() {
        return Err(Error::InvalidTransition);
    }

    let retry_config = BatchConfig {
        mode: BatchMode::NonAtomic,
        max_operations,
    };
    let retry_result = execute_multi_transfer(env, caller, &report.token, &retry_transfers, &retry_config)
        .map_err(|_| Error::InvalidArgument)?;

    let mut remaining = kept;
    let mut k: u32 = 0;
    while k < retry_transfers.len() {
        let outcome = retry_result.results.get(k).unwrap();
        if let OperationResult::Failure(code) = outcome {
            let original = retry_originals.get(k).unwrap();
            remaining.push_back(BatchFailureDetail {
                index: original.index,
                to: original.to,
                amount: original.amount,
                error_code: code,
                retryable: classify_retryable(code),
            });
        }
        k = k.saturating_add(1);
    }

    report.succeeded = report.succeeded.saturating_add(retry_result.succeeded);
    report.failed = remaining.len();
    report.retryable_count = count_retryable(&remaining);
    report.failures = remaining;
    report.resolved = report.failed == 0;
    save_report(env, &report);

    env.events().publish(
        (BATCH_RETRY_TOPIC, symbol_short!("retried")),
        (batch_id, retry_result.succeeded, report.failed),
    );

    Ok(retry_result)
}

// ---------------------------------------------------------------------------
// Admin cleanup / rollback
// ---------------------------------------------------------------------------

/// Drops the report for `batch_id` entirely. Admin-gated — use this once a
/// report is no longer actionable (e.g. every remaining entry is
/// non-retryable).
pub fn discard_batch_failure_report(env: &Env, admin: &Address, batch_id: u64) -> Result<(), Error> {
    if !has_role(env, admin, Role::Admin) {
        return Err(Error::Unauthorized);
    }
    admin.require_auth();
    get_batch_failure_report(env, batch_id).ok_or(Error::NotFound)?;
    persistent_remove(env, &BatchRetryKey::Report(batch_id));
    Ok(())
}
