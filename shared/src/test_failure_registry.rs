//! Operator dashboard registry for unresolved partial failures (Issue #443).
//!
//! Covers the normal path (record → list → resolve), failure paths (bad ids,
//! closing twice, a full open set), the retry path (retry outcomes and
//! deduplicated re-reports) and authorization (operator actions are admin-only).

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Env, String,
};

use crate::{
    auth::set_admin,
    dashboard::{FailureSeverity, FailureState, OperationKind, OperationType},
    errors::Error,
    failure_registry::{
        get_failure, get_failure_resolution, ignore_failure, open_failure_count,
        record_partial_failure, record_retry_outcome, reopen_failure, resolve_failure,
        unresolved_failures, unresolved_summary, MAX_FAILURE_PAGE, MAX_OPEN_FAILURES,
    },
};

#[contract]
pub struct DummyFailureContract;

#[contractimpl]
impl DummyFailureContract {
    pub fn noop(_env: Env) {}
}

/// Retryable (transient) shared error code.
const RETRYABLE: u32 = 6; // Error::Expired
/// Terminal shared error code that is also classified Critical.
const TERMINAL: u32 = 1; // Error::Unauthorized

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(100);
    let admin = Address::generate(&env);
    let id = env.register_contract(None, DummyFailureContract);
    env.as_contract(&id, || set_admin(&env, &admin));
    (env, id, admin)
}

fn report(env: &Env, op: OperationType, op_id: u64, code: u32) -> Result<u64, Error> {
    record_partial_failure(
        env,
        op,
        op_id,
        code,
        90,
        OperationKind::ContractCall,
        String::from_str(env, "settlement leg failed"),
    )
}

#[test]
fn recorded_failures_appear_on_the_dashboard_until_resolved() {
    let (env, id, admin) = setup();

    let (retryable, terminal) = env.as_contract(&id, || {
        let a = report(&env, OperationType::Payment, 1, RETRYABLE).unwrap();
        let b = report(&env, OperationType::Webhook, 2, TERMINAL).unwrap();
        (a, b)
    });

    env.ledger().set_sequence_number(150);
    env.as_contract(&id, || {
        assert_eq!(open_failure_count(&env), 2);
        let page = unresolved_failures(&env, None, 10).unwrap();
        assert_eq!(page.len(), 2);
        let first = page.get(0).unwrap();
        assert_eq!(first.failure_id, retryable);
        assert_eq!(first.state, FailureState::Retryable);
        // Age is refreshed to the current ledger, not frozen at record time.
        assert_eq!(first.age_ledgers, 60);
        assert_eq!(page.get(1).unwrap().state, FailureState::Unresolved);

        let summary = unresolved_summary(&env);
        assert_eq!(summary.open, 2);
        assert_eq!(summary.retryable, 1);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.oldest_failed_at_ledger, Some(90));
        assert!(!summary.groups.is_empty());
    });

    env.as_contract(&id, || {
        let closed = resolve_failure(&env, &admin, terminal, symbol_short!("refunded")).unwrap();
        assert_eq!(closed.state, FailureState::Resolved);

        let resolution = get_failure_resolution(&env, terminal).unwrap();
        assert_eq!(resolution.outcome, FailureState::Resolved);
        assert_eq!(resolution.operator, Some(admin.clone()));
        assert_eq!(resolution.note, symbol_short!("refunded"));

        // Closed failures leave the dashboard but keep their record.
        assert_eq!(open_failure_count(&env), 1);
        assert_eq!(unresolved_summary(&env).critical, 0);
        assert_eq!(get_failure(&env, terminal).unwrap().state, FailureState::Resolved);
    });
}

#[test]
fn re_reporting_an_open_operation_is_deduplicated() {
    let (env, id, admin) = setup();
    env.as_contract(&id, || {
        let first = report(&env, OperationType::Transfer, 7, RETRYABLE).unwrap();
        let again = report(&env, OperationType::Transfer, 7, RETRYABLE).unwrap();
        assert_eq!(first, again);
        // Same operation id under a different type is a different failure.
        let other = report(&env, OperationType::Worker, 7, RETRYABLE).unwrap();
        assert_ne!(first, other);
        assert_eq!(open_failure_count(&env), 2);
    });
    env.as_contract(&id, || {
        ignore_failure(&env, &admin, 1, symbol_short!("dup")).unwrap();
        // Once closed, a new report for the operation opens a new row.
        let fresh = report(&env, OperationType::Transfer, 7, RETRYABLE).unwrap();
        assert_eq!(fresh, 3);
    });
}

#[test]
fn retry_outcomes_update_attempts_and_close_on_success() {
    let (env, id, _admin) = setup();
    env.as_contract(&id, || {
        let fid = report(&env, OperationType::ExternalApi, 1, RETRYABLE).unwrap();

        let failed = record_retry_outcome(&env, fid, false).unwrap();
        assert_eq!(failed.retry_attempts, 1);
        assert_eq!(failed.state, FailureState::Retryable);
        assert_eq!(open_failure_count(&env), 1);

        let ok = record_retry_outcome(&env, fid, true).unwrap();
        assert_eq!(ok.retry_attempts, 2);
        assert_eq!(ok.state, FailureState::Resolved);
        assert_eq!(open_failure_count(&env), 0);
        let resolution = get_failure_resolution(&env, fid).unwrap();
        assert_eq!(resolution.operator, None);
        assert_eq!(resolution.note, symbol_short!("retry_ok"));

        // Terminal failures and closed failures cannot be retried.
        let terminal = report(&env, OperationType::Contract, 2, TERMINAL).unwrap();
        assert_eq!(
            record_retry_outcome(&env, terminal, true),
            Err(Error::InvalidArgument)
        );
        assert_eq!(record_retry_outcome(&env, fid, true), Err(Error::InvalidArgument));
        assert_eq!(record_retry_outcome(&env, 999, true), Err(Error::NotFound));
    });
}

#[test]
fn reopen_rolls_back_a_mistaken_decision() {
    let (env, id, admin) = setup();
    let fid = env.as_contract(&id, || {
        report(&env, OperationType::Payment, 5, TERMINAL).unwrap()
    });
    env.as_contract(&id, || {
        ignore_failure(&env, &admin, fid, symbol_short!("noise")).unwrap();
    });
    env.as_contract(&id, || {
        let reopened = reopen_failure(&env, &admin, fid).unwrap();
        assert_eq!(reopened.state, FailureState::Unresolved);
        assert_eq!(reopened.severity, FailureSeverity::Critical);
        assert_eq!(open_failure_count(&env), 1);
        assert_eq!(get_failure_resolution(&env, fid), None);
        // Reopened failures deduplicate re-reports again.
        assert_eq!(report(&env, OperationType::Payment, 5, TERMINAL).unwrap(), fid);
    });
    env.as_contract(&id, || {
        // Already open.
        assert_eq!(reopen_failure(&env, &admin, fid), Err(Error::InvalidArgument));
    });
}

#[test]
fn closing_twice_or_unknown_ids_fail() {
    let (env, id, admin) = setup();
    let fid = env.as_contract(&id, || {
        report(&env, OperationType::Payment, 1, TERMINAL).unwrap()
    });
    env.as_contract(&id, || {
        resolve_failure(&env, &admin, fid, symbol_short!("fixed")).unwrap();
    });
    env.as_contract(&id, || {
        assert_eq!(
            resolve_failure(&env, &admin, fid, symbol_short!("fixed")),
            Err(Error::InvalidArgument)
        );
    });
    env.as_contract(&id, || {
        assert_eq!(
            ignore_failure(&env, &admin, 42, symbol_short!("x")),
            Err(Error::NotFound)
        );
    });
}

#[test]
fn operator_actions_require_the_admin() {
    let (env, id, _admin) = setup();
    let stranger = Address::generate(&env);
    env.as_contract(&id, || {
        let fid = report(&env, OperationType::Payment, 1, TERMINAL).unwrap();
        assert_eq!(
            resolve_failure(&env, &stranger, fid, symbol_short!("x")),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            ignore_failure(&env, &stranger, fid, symbol_short!("x")),
            Err(Error::Unauthorized)
        );
        assert_eq!(reopen_failure(&env, &stranger, fid), Err(Error::Unauthorized));
        assert_eq!(open_failure_count(&env), 1);
    });
}

#[test]
fn reads_are_bounded_and_paginated() {
    let (env, id, _admin) = setup();
    env.as_contract(&id, || {
        for op_id in 0..3u64 {
            report(&env, OperationType::Worker, op_id, RETRYABLE).unwrap();
        }
        assert_eq!(unresolved_failures(&env, None, 0), Err(Error::InvalidArgument));
        assert_eq!(
            unresolved_failures(&env, None, MAX_FAILURE_PAGE + 1),
            Err(Error::InvalidArgument)
        );

        let first = unresolved_failures(&env, None, 2).unwrap();
        assert_eq!(first.len(), 2);
        let last_seen = first.get(1).unwrap().failure_id;
        let rest = unresolved_failures(&env, Some(last_seen), 2).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest.get(0).unwrap().failure_id, 3);
    });
}

#[test]
fn the_open_set_is_capped() {
    let (env, id, _admin) = setup();
    env.budget().reset_unlimited();
    env.as_contract(&id, || {
        for op_id in 0..(MAX_OPEN_FAILURES as u64) {
            report(&env, OperationType::Worker, op_id, RETRYABLE).unwrap();
        }
        assert_eq!(
            report(&env, OperationType::Worker, 10_000, RETRYABLE),
            Err(Error::QuotaExceeded)
        );
        // A duplicate of an open report still resolves to its id.
        assert_eq!(report(&env, OperationType::Worker, 0, RETRYABLE), Ok(1));
    });
}
