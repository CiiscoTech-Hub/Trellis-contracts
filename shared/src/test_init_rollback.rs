//! Deterministic rollback tests for failed external side effects (Issue #433).
//!
//! Verifies that multi-step initialization sequences with external side effects
//! adhere to strict deterministic rollback semantics:
//! - Normal initialization completes cleanly when all steps succeed.
//! - Failure in a downstream external call (e.g. cross-contract initialization or side effect)
//!   halts the deployment and transitions the tracker to `AwaitingRollback`.
//! - Verification strictly blocks `RolledBack` state until all side effects are proven undone.
//! - Clean retry is permitted once rollback verification passes.
//! - All mutating transitions enforce administrator authorization.

#![cfg(test)]

use crate::auth::{grant_role, set_admin, Role};
use crate::errors::Error;
use crate::init_rollback::{
    begin_initialization, complete_init_step, complete_rollback, fail_init_step, get_tracker,
    verify_rollback, InitRollbackVerification, InitStep, InitStepOutcome, InitStepProbe,
    InitializationStatus,
};
use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Env, Vec,
};

#[contract]
struct InitRollbackTestFixture;

#[contractimpl]
impl InitRollbackTestFixture {}

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, InitRollbackTestFixture);
    let admin = Address::generate(&env);
    env.as_contract(&contract_id, || {
        set_admin(&env, &admin);
        grant_role(&env, &admin, &admin, Role::Admin).unwrap();
    });
    (env, contract_id, admin)
}

fn sample_steps(env: &Env) -> Vec<InitStep> {
    let mut steps = Vec::new(env);
    steps.push_back(InitStep {
        index: 0,
        name: symbol_short!("treasury"),
        outcome: InitStepOutcome::Pending,
    });
    steps.push_back(InitStep {
        index: 1,
        name: symbol_short!("aid"),
        outcome: InitStepOutcome::Pending,
    });
    steps.push_back(InitStep {
        index: 2,
        name: symbol_short!("oracle"),
        outcome: InitStepOutcome::Pending,
    });
    steps
}

#[test]
fn test_normal_initialization_path() {
    let (env, contract_id, admin) = setup();
    let id = symbol_short!("dep_norm");
    let steps = sample_steps(&env);

    let tracker = env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 1000).unwrap()
    });
    assert_eq!(tracker.status, InitializationStatus::InProgress);
    assert_eq!(tracker.attempt, 1);
    assert_eq!(tracker.cursor, 0);

    // Step 0 succeeds (Treasury initialized)
    let t0 = env.as_contract(&contract_id, || {
        complete_init_step(&env, &admin, &id, 0, 1010).unwrap()
    });
    assert_eq!(t0.cursor, 1);
    assert_eq!(t0.steps.get(0).unwrap().outcome, InitStepOutcome::Completed);

    // Step 1 succeeds (Aid initialized)
    let t1 = env.as_contract(&contract_id, || {
        complete_init_step(&env, &admin, &id, 1, 1020).unwrap()
    });
    assert_eq!(t1.cursor, 2);
    assert_eq!(t1.steps.get(1).unwrap().outcome, InitStepOutcome::Completed);

    // Step 2 succeeds (Oracle initialized) -> marks whole sequence Completed
    let t2 = env.as_contract(&contract_id, || {
        complete_init_step(&env, &admin, &id, 2, 1030).unwrap()
    });
    assert_eq!(t2.status, InitializationStatus::Completed);
    assert_eq!(t2.cursor, 3);
    assert_eq!(t2.steps.get(2).unwrap().outcome, InitStepOutcome::Completed);
}

#[test]
fn test_failed_external_side_effect_requires_verified_rollback() {
    let (env, contract_id, admin) = setup();
    let id = symbol_short!("dep_fail");
    let steps = sample_steps(&env);

    env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 2000).unwrap()
    });

    // Step 0 succeeds (External Treasury state initialized)
    env.as_contract(&contract_id, || {
        complete_init_step(&env, &admin, &id, 0, 2010).unwrap()
    });

    // Step 1: External Aid contract call fails midway with error 5 (ContractPaused)
    let t_fail = env.as_contract(&contract_id, || {
        fail_init_step(&env, &admin, &id, 1, Error::ContractPaused as u32, 2020).unwrap()
    });
    assert_eq!(t_fail.status, InitializationStatus::AwaitingRollback);
    assert_eq!(t_fail.cursor, 1);

    // Operator probes external contracts:
    // Case 1: Treasury still has state (compensation was incomplete!)
    let mut incomplete_probes = Vec::new(&env);
    incomplete_probes.push_back(InitStepProbe {
        index: 0,
        still_initialized: true, // incomplete rollback
    });
    incomplete_probes.push_back(InitStepProbe {
        index: 1,
        still_initialized: false,
    });

    let verif_incomplete = env.as_contract(&contract_id, || {
        verify_rollback(&env, &id, &incomplete_probes).unwrap()
    });
    assert!(!verif_incomplete.fully_rolled_back);
    assert_eq!(verif_incomplete.first_not_rolled_back, Some(0));

    // Hard gate: complete_rollback MUST reject incomplete compensation
    let rlbk_err = env.as_contract(&contract_id, || {
        complete_rollback(&env, &admin, &id, &verif_incomplete, 2030)
    });
    assert_eq!(rlbk_err, Err(Error::InvalidTransition));

    // Case 2: Operator compensates and verifies all side effects are cleanly rolled back
    let mut clean_probes = Vec::new(&env);
    clean_probes.push_back(InitStepProbe {
        index: 0,
        still_initialized: false, // cleanly undone
    });
    clean_probes.push_back(InitStepProbe {
        index: 1,
        still_initialized: false, // cleanly undone
    });

    let verif_clean = env.as_contract(&contract_id, || {
        verify_rollback(&env, &id, &clean_probes).unwrap()
    });
    assert!(verif_clean.fully_rolled_back);
    assert_eq!(verif_clean.checked, 2);

    // Hard gate: complete_rollback passes only with verified clean state
    let t_rolled_back = env.as_contract(&contract_id, || {
        complete_rollback(&env, &admin, &id, &verif_clean, 2040).unwrap()
    });
    assert_eq!(t_rolled_back.status, InitializationStatus::RolledBack);
    assert_eq!(t_rolled_back.cursor, 0);

    // Verify step statuses in storage
    let stored = env.as_contract(&contract_id, || get_tracker(&env, &id)).unwrap();
    assert_eq!(stored.steps.get(0).unwrap().outcome, InitStepOutcome::RolledBack);
    assert_eq!(stored.steps.get(1).unwrap().outcome, InitStepOutcome::RolledBack);

    // Retry path: After verified rollback, retry succeeds with attempt 2
    let t_retry = env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 2100).unwrap()
    });
    assert_eq!(t_retry.status, InitializationStatus::InProgress);
    assert_eq!(t_retry.attempt, 2);
    assert_eq!(t_retry.cursor, 0);
}

#[test]
fn test_authorization_paths_enforced() {
    let (env, contract_id, admin) = setup();
    let unauthorized = Address::generate(&env);
    let id = symbol_short!("dep_auth");
    let steps = sample_steps(&env);

    // Non-admin cannot begin initialization
    let err_begin = env.as_contract(&contract_id, || {
        begin_initialization(&env, &unauthorized, id.clone(), steps.clone(), 3000)
    });
    assert_eq!(err_begin, Err(Error::Unauthorized));

    // Admin starts it
    env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 3000).unwrap()
    });

    // Non-admin cannot complete step
    let err_complete = env.as_contract(&contract_id, || {
        complete_init_step(&env, &unauthorized, &id, 0, 3010)
    });
    assert_eq!(err_complete, Err(Error::Unauthorized));

    // Non-admin cannot fail step
    let err_fail = env.as_contract(&contract_id, || {
        fail_init_step(&env, &unauthorized, &id, 0, 500, 3010)
    });
    assert_eq!(err_fail, Err(Error::Unauthorized));
}

#[test]
fn test_operational_edge_cases() {
    let (env, contract_id, admin) = setup();
    let id = symbol_short!("dep_edge");
    let steps = sample_steps(&env);

    env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 4000).unwrap()
    });

    // Cannot begin duplicate while in progress
    let err_dup = env.as_contract(&contract_id, || {
        begin_initialization(&env, &admin, id.clone(), steps.clone(), 4001)
    });
    assert_eq!(err_dup, Err(Error::AlreadyInitialized));

    // Cannot complete wrong step index (expecting 0, got 1)
    let err_idx = env.as_contract(&contract_id, || {
        complete_init_step(&env, &admin, &id, 1, 4010)
    });
    assert_eq!(err_idx, Err(Error::InvalidTransition));

    // Cannot verify rollback when tracker is InProgress
    let clean_probes = Vec::new(&env);
    let err_verif = env.as_contract(&contract_id, || {
        verify_rollback(&env, &id, &clean_probes)
    });
    assert_eq!(err_verif, Err(Error::InvalidTransition));

    // Verification ID mismatch rejected by complete_rollback
    let foreign_verif = InitRollbackVerification {
        id: symbol_short!("other_id"),
        checked: 2,
        fully_rolled_back: true,
        first_not_rolled_back: None,
        verified_at: 4020,
    };
    let err_mismatch = env.as_contract(&contract_id, || {
        complete_rollback(&env, &admin, &id, &foreign_verif, 4030)
    });
    assert_eq!(err_mismatch, Err(Error::InvalidTransition));
}
