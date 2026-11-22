//! Persistent registry behind the operator dashboard for unresolved partial
//! failures (Issue #443).
//!
//! [`crate::dashboard`] can classify, redact and group partial failures, but
//! only for a `Vec` the caller already holds. This module keeps those failures
//! on-chain with an explicit operator workflow, so the dashboard has a source
//! of truth to read from:
//!
//! ```text
//!   record_partial_failure ──▶ Unresolved / Retryable ──(resolve)──▶ Resolved
//!            │ (same operation, still open)   │      └──(ignore)───▶ Ignored
//!            ▼                                │                         │
//!      existing id returned                   │ record_retry_outcome    │
//!                                             │ (success) ──▶ Resolved  │
//!                                             ◀──────── reopen_failure ─┘
//! ```
//!
//! - Only open failures (`Unresolved` or `Retryable`) are indexed, so the
//!   dashboard read is bounded by [`MAX_OPEN_FAILURES`], not by history.
//! - Operator actions (`resolve`, `ignore`, `reopen`) require the admin and
//!   write a [`FailureResolution`] for audit. Closed failures keep their record.
//! - Reads return only [`RedactedPartialFailure`] views, never raw external
//!   reference ids.
//!
//! See `docs/PARTIAL_FAILURE_DASHBOARD.md` ("Operator registry").

use soroban_sdk::{contracttype, symbol_short, Address, Env, String, Symbol, Vec};

use crate::auth::require_admin;
use crate::dashboard::{
    create_partial_failure, group_by_age, group_by_operation_type, group_by_retryability,
    group_by_severity, redact_partial_failure, FailureGroup, FailureSeverity, FailureState,
    OperationKind, OperationType, PartialFailure, RedactedPartialFailure,
};
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_read, persistent_remove, persistent_set};

/// Upper bound on simultaneously open failures. Recording beyond it returns
/// [`Error::QuotaExceeded`] so the dashboard read can never become unbounded;
/// resolving or ignoring failures frees room.
pub const MAX_OPEN_FAILURES: u32 = 200;

/// Largest page [`unresolved_failures`] returns.
pub const MAX_FAILURE_PAGE: u32 = 50;

/// Topic prefix for registry events.
pub const FAILURE_TOPIC: Symbol = symbol_short!("pfail");

/// Operator decision recorded when a failure leaves the open set.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureResolution {
    pub failure_id: u64,
    /// `Resolved` or `Ignored`.
    pub outcome: FailureState,
    /// Operator, or `None` when a successful retry closed the failure.
    pub operator: Option<Address>,
    /// Short reason code, e.g. `refunded`, `dup`, `retry_ok`.
    pub note: Symbol,
    pub ledger: u32,
}

/// Aggregate view of the open failures.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresolvedSummary {
    pub open: u32,
    pub critical: u32,
    pub retryable: u32,
    /// Earliest `failed_at_ledger` among open failures.
    pub oldest_failed_at_ledger: Option<u32>,
    /// Groupings by operation type, severity, age and retryability, computed
    /// with ages refreshed to the current ledger.
    pub groups: Vec<FailureGroup>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureRegistryKey {
    /// Last allocated id (`u64`).
    NextId,
    /// `Vec<u64>` of open failure ids, oldest first.
    Open,
    /// `PartialFailure` by id.
    Failure(u64),
    /// Open failure id for an operation, used to deduplicate reports.
    ByOperation(OperationType, u64),
    /// `FailureResolution` by id.
    Resolution(u64),
}

fn is_open(state: FailureState) -> bool {
    matches!(state, FailureState::Unresolved | FailureState::Retryable)
}

fn open_ids(env: &Env) -> Vec<u64> {
    persistent_get(env, &FailureRegistryKey::Open).unwrap_or_else(|| Vec::new(env))
}

fn save_open_ids(env: &Env, ids: &Vec<u64>) {
    if ids.is_empty() {
        persistent_remove(env, &FailureRegistryKey::Open);
    } else {
        persistent_set(env, &FailureRegistryKey::Open, ids);
    }
}

fn load(env: &Env, failure_id: u64) -> Result<PartialFailure, Error> {
    persistent_get(env, &FailureRegistryKey::Failure(failure_id)).ok_or(Error::NotFound)
}

fn save(env: &Env, failure: &PartialFailure) {
    persistent_set(env, &FailureRegistryKey::Failure(failure.failure_id), failure);
}

fn with_current_age(env: &Env, mut failure: PartialFailure) -> PartialFailure {
    failure.age_ledgers = env
        .ledger()
        .sequence()
        .saturating_sub(failure.failed_at_ledger);
    failure
}

/// Removes `failure` from the open set and records why.
fn close(
    env: &Env,
    mut failure: PartialFailure,
    outcome: FailureState,
    operator: Option<Address>,
    note: Symbol,
) -> PartialFailure {
    failure.state = outcome;
    save(env, &failure);

    let mut ids = open_ids(env);
    if let Some(pos) = ids.first_index_of(failure.failure_id) {
        let _ = ids.remove(pos);
        save_open_ids(env, &ids);
    }
    persistent_remove(
        env,
        &FailureRegistryKey::ByOperation(failure.operation_type, failure.operation_id),
    );

    let resolution = FailureResolution {
        failure_id: failure.failure_id,
        outcome,
        operator,
        note,
        ledger: env.ledger().sequence(),
    };
    persistent_set(env, &FailureRegistryKey::Resolution(failure.failure_id), &resolution);
    env.events().publish(
        (FAILURE_TOPIC, symbol_short!("closed"), failure.failure_id),
        resolution,
    );
    failure
}

/// Records a partial failure detected by contract code and returns its id.
///
/// Not an entry point: call it from the code path that observed the failure.
/// Reporting the same `(operation_type, operation_id)` again while the first
/// report is still open returns the existing id, so a retried report never
/// duplicates a dashboard row.
pub fn record_partial_failure(
    env: &Env,
    operation_type: OperationType,
    operation_id: u64,
    error_code: u32,
    failed_at_ledger: u32,
    operation_kind: OperationKind,
    description: String,
) -> Result<u64, Error> {
    let op_key = FailureRegistryKey::ByOperation(operation_type, operation_id);
    if let Some(existing) = persistent_read::<_, u64>(env, &op_key) {
        return Ok(existing);
    }

    let mut ids = open_ids(env);
    if ids.len() >= MAX_OPEN_FAILURES {
        return Err(Error::QuotaExceeded);
    }

    let id: u64 = persistent_read::<_, u64>(env, &FailureRegistryKey::NextId)
        .unwrap_or(0)
        .saturating_add(1);
    let failure = create_partial_failure(
        env,
        id,
        operation_type,
        operation_id,
        error_code,
        failed_at_ledger,
        operation_kind,
        description,
    );

    persistent_set(env, &FailureRegistryKey::NextId, &id);
    save(env, &failure);
    persistent_set(env, &op_key, &id);
    ids.push_back(id);
    save_open_ids(env, &ids);
    env.events().publish(
        (FAILURE_TOPIC, symbol_short!("recorded"), id),
        (failure.operation_type, failure.severity, failure.error_code),
    );
    Ok(id)
}

/// Records the outcome of retrying a `Retryable` failure.
///
/// A successful retry closes the failure as `Resolved` with note `retry_ok`.
/// A failed retry increments `retry_attempts` and leaves it open. Failures
/// that are not `Retryable` return [`Error::InvalidArgument`].
pub fn record_retry_outcome(
    env: &Env,
    failure_id: u64,
    succeeded: bool,
) -> Result<PartialFailure, Error> {
    let mut failure = load(env, failure_id)?;
    if failure.state != FailureState::Retryable {
        return Err(Error::InvalidArgument);
    }
    failure.retry_attempts = failure.retry_attempts.saturating_add(1);
    if succeeded {
        return Ok(close(
            env,
            failure,
            FailureState::Resolved,
            None,
            symbol_short!("retry_ok"),
        ));
    }
    save(env, &failure);
    Ok(failure)
}

/// Marks an open failure as fixed. Admin only.
pub fn resolve_failure(
    env: &Env,
    operator: &Address,
    failure_id: u64,
    note: Symbol,
) -> Result<PartialFailure, Error> {
    require_admin(env, operator)?;
    let failure = load(env, failure_id)?;
    if !is_open(failure.state) {
        return Err(Error::InvalidArgument);
    }
    Ok(close(env, failure, FailureState::Resolved, Some(operator.clone()), note))
}

/// Accepts an open failure as not needing action. Admin only.
pub fn ignore_failure(
    env: &Env,
    operator: &Address,
    failure_id: u64,
    note: Symbol,
) -> Result<PartialFailure, Error> {
    require_admin(env, operator)?;
    let failure = load(env, failure_id)?;
    if !is_open(failure.state) {
        return Err(Error::InvalidArgument);
    }
    Ok(close(env, failure, FailureState::Ignored, Some(operator.clone()), note))
}

/// Puts a resolved or ignored failure back on the dashboard. Admin only.
///
/// This is the rollback for a mistaken operator decision. The failure returns
/// to `Retryable` or `Unresolved` according to its error code, and its
/// resolution record is removed. Fails with [`Error::InvalidArgument`] if the
/// failure is already open or if another open report now exists for the same
/// operation, and with [`Error::QuotaExceeded`] if the open set is full.
pub fn reopen_failure(
    env: &Env,
    operator: &Address,
    failure_id: u64,
) -> Result<PartialFailure, Error> {
    require_admin(env, operator)?;
    let mut failure = load(env, failure_id)?;
    if is_open(failure.state) {
        return Err(Error::InvalidArgument);
    }
    let op_key = FailureRegistryKey::ByOperation(failure.operation_type, failure.operation_id);
    if persistent_read::<_, u64>(env, &op_key).is_some() {
        return Err(Error::InvalidArgument);
    }
    let mut ids = open_ids(env);
    if ids.len() >= MAX_OPEN_FAILURES {
        return Err(Error::QuotaExceeded);
    }

    failure.state = if failure.is_retryable {
        FailureState::Retryable
    } else {
        FailureState::Unresolved
    };
    save(env, &failure);
    ids.push_back(failure_id);
    save_open_ids(env, &ids);
    persistent_set(env, &op_key, &failure_id);
    persistent_remove(env, &FailureRegistryKey::Resolution(failure_id));
    env.events().publish(
        (FAILURE_TOPIC, symbol_short!("reopened"), failure_id),
        operator.clone(),
    );
    Ok(failure)
}

/// Reads one failure, open or closed.
pub fn get_failure(env: &Env, failure_id: u64) -> Option<PartialFailure> {
    persistent_read(env, &FailureRegistryKey::Failure(failure_id))
}

/// Reads the operator decision that closed a failure.
pub fn get_failure_resolution(env: &Env, failure_id: u64) -> Option<FailureResolution> {
    persistent_read(env, &FailureRegistryKey::Resolution(failure_id))
}

/// Number of open failures.
pub fn open_failure_count(env: &Env) -> u32 {
    open_ids(env).len()
}

/// Redacted page of open failures, oldest first.
///
/// `cursor` is the last failure id the caller saw (or `None` to start).
/// `limit` must be 1..=[`MAX_FAILURE_PAGE`].
pub fn unresolved_failures(
    env: &Env,
    cursor: Option<u64>,
    limit: u32,
) -> Result<Vec<RedactedPartialFailure>, Error> {
    if limit == 0 || limit > MAX_FAILURE_PAGE {
        return Err(Error::InvalidArgument);
    }
    let mut out = Vec::new(env);
    for id in open_ids(env).iter() {
        if out.len() >= limit {
            break;
        }
        if let Some(seen) = cursor {
            if id <= seen {
                continue;
            }
        }
        if let Some(failure) = get_failure(env, id) {
            out.push_back(redact_partial_failure(env, &with_current_age(env, failure)));
        }
    }
    Ok(out)
}

/// Counts and groupings over every open failure.
pub fn unresolved_summary(env: &Env) -> UnresolvedSummary {
    let mut open = Vec::new(env);
    let mut critical = 0u32;
    let mut retryable = 0u32;
    let mut oldest: Option<u32> = None;
    for id in open_ids(env).iter() {
        let Some(failure) = get_failure(env, id) else {
            continue;
        };
        let failure = with_current_age(env, failure);
        if failure.severity == FailureSeverity::Critical {
            critical += 1;
        }
        if failure.state == FailureState::Retryable {
            retryable += 1;
        }
        oldest = Some(match oldest {
            Some(current) if current <= failure.failed_at_ledger => current,
            _ => failure.failed_at_ledger,
        });
        open.push_back(failure);
    }

    let mut groups = Vec::new(env);
    for group in group_by_operation_type(env, &open).iter() {
        groups.push_back(group);
    }
    for group in group_by_severity(env, &open).iter() {
        groups.push_back(group);
    }
    for group in group_by_age(env, &open).iter() {
        groups.push_back(group);
    }
    for group in group_by_retryability(env, &open).iter() {
        groups.push_back(group);
    }

    UnresolvedSummary {
        open: open.len(),
        critical,
        retryable,
        oldest_failed_at_ledger: oldest,
        groups,
    }
}
