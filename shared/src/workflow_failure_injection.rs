//! End-to-End Failure Injection Framework for Critical Workflows (Issue #440).
//!
//! Provides deterministic fault-injection harnesses across critical multi-stage
//! workflows (Aid Disbursement and Milestone Escrow). Simulates transient
//! RPC/dependency outages, insufficient balances, token transfer rejections,
//! and authorization failures, verifying that:
//! 1. All failure paths safely roll back intermediate state and restore asset reserves.
//! 2. Token conservation invariants are strictly preserved.
//! 3. Resuming/retrying after transient faults succeeds idempotently without double-spending.
//! 4. Unauthorized callers cannot initiate, manipulate, or retry workflows.
//!
//! Time complexity: O(1) per workflow stage execution.
//! Space complexity: O(1) in persistent/instance storage.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Address, Env, Symbol,
};

use crate::auth::require_admin;
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Types & Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WorkflowFaultError {
    WorkflowNotFound = 1,
    WorkflowAlreadyCompleted = 2,
    StageFailed = 3,
    DependencyTimeout = 4,
    InsufficientFunds = 5,
    TokenTransferRejected = 6,
    Unauthorized = 7,
    InvariantViolation = 8,
    InvalidConfiguration = 9,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CriticalWorkflowType {
    AidDisbursement = 1,
    MilestoneEscrow = 2,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowFaultPoint {
    None = 0,
    DependencyTimeout = 1,
    InsufficientFunds = 2,
    TokenTransferRejected = 3,
    UnauthorizedCaller = 4,
    InvariantBreach = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowExecutionState {
    pub workflow_id: u64,
    pub workflow_type: CriticalWorkflowType,
    pub current_stage: u32,
    pub is_completed: bool,
    pub has_failed: bool,
    pub failed_at_stage: u32,
    pub active_fault: WorkflowFaultPoint,
    pub total_amount: i128,
    pub locked_amount: i128,
    pub disbursed_amount: i128,
    pub rollback_performed: bool,
    pub attempts: u32,
    pub last_updated_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowPoolReserves {
    pub total_reserves: i128,
    pub active_locked: i128,
    pub total_disbursed: i128,
}

#[contracttype]
#[derive(Clone)]
enum WorkflowStorageKey {
    State(u64),
    Pool,
}

pub const TOPIC_WORKFLOW_FAULT: Symbol = symbol_short!("wf_fault");
pub const TOPIC_WORKFLOW_COMPLETE: Symbol = symbol_short!("wf_done");

// ---------------------------------------------------------------------------
// Storage Helpers
// ---------------------------------------------------------------------------

fn state_key(workflow_id: u64) -> WorkflowStorageKey {
    WorkflowStorageKey::State(workflow_id)
}

fn pool_key() -> WorkflowStorageKey {
    WorkflowStorageKey::Pool
}

pub fn initialize_pool(env: &Env, initial_reserves: i128) {
    let pool = WorkflowPoolReserves {
        total_reserves: initial_reserves,
        active_locked: 0,
        total_disbursed: 0,
    };
    instance_set(env, &pool_key(), &pool);
}

pub fn get_pool_reserves(env: &Env) -> WorkflowPoolReserves {
    instance_get(env, &pool_key()).unwrap_or(WorkflowPoolReserves {
        total_reserves: 0,
        active_locked: 0,
        total_disbursed: 0,
    })
}

pub fn get_workflow_state(env: &Env, workflow_id: u64) -> Option<WorkflowExecutionState> {
    instance_get(env, &state_key(workflow_id))
}

// ---------------------------------------------------------------------------
// Execution Engine
// ---------------------------------------------------------------------------

/// Initiates and executes an end-to-end critical workflow with optional failure injection.
pub fn execute_critical_workflow(
    env: &Env,
    caller: &Address,
    workflow_id: u64,
    workflow_type: CriticalWorkflowType,
    amount: i128,
    fault: WorkflowFaultPoint,
    fault_stage: u32,
) -> Result<WorkflowExecutionState, WorkflowFaultError> {
    require_admin(env, caller).map_err(|_| WorkflowFaultError::Unauthorized)?;

    if amount <= 0 {
        return Err(WorkflowFaultError::InvalidConfiguration);
    }

    let mut state = WorkflowExecutionState {
        workflow_id,
        workflow_type,
        current_stage: 0,
        is_completed: false,
        has_failed: false,
        failed_at_stage: 0,
        active_fault: fault,
        total_amount: amount,
        locked_amount: 0,
        disbursed_amount: 0,
        rollback_performed: false,
        attempts: 1,
        last_updated_ledger: env.ledger().sequence(),
    };

    run_workflow_stages(env, &mut state, fault, fault_stage)
}

/// Retries an interrupted or failed workflow after faults have cleared.
pub fn retry_critical_workflow(
    env: &Env,
    caller: &Address,
    workflow_id: u64,
) -> Result<WorkflowExecutionState, WorkflowFaultError> {
    require_admin(env, caller).map_err(|_| WorkflowFaultError::Unauthorized)?;

    let mut state = get_workflow_state(env, workflow_id)
        .ok_or(WorkflowFaultError::WorkflowNotFound)?;

    if state.is_completed {
        return Err(WorkflowFaultError::WorkflowAlreadyCompleted);
    }

    state.attempts += 1;
    state.has_failed = false;
    state.failed_at_stage = 0;
    state.active_fault = WorkflowFaultPoint::None;
    state.rollback_performed = false;
    state.last_updated_ledger = env.ledger().sequence();

    run_workflow_stages(env, &mut state, WorkflowFaultPoint::None, 0)
}

fn run_workflow_stages(
    env: &Env,
    state: &mut WorkflowExecutionState,
    fault: WorkflowFaultPoint,
    fault_stage: u32,
) -> Result<WorkflowExecutionState, WorkflowFaultError> {
    let mut pool = get_pool_reserves(env);

    // Stage 1: Preflight Verification
    state.current_stage = 1;
    if fault_stage == 1 && fault != WorkflowFaultPoint::None {
        return handle_failure(env, state, fault, 1, &mut pool);
    }

    // Stage 2: External Dependency / Oracle Verification
    state.current_stage = 2;
    if fault_stage == 2 {
        match fault {
            WorkflowFaultPoint::DependencyTimeout => {
                return handle_failure(env, state, fault, 2, &mut pool);
            }
            WorkflowFaultPoint::UnauthorizedCaller => {
                return handle_failure(env, state, fault, 2, &mut pool);
            }
            _ => {}
        }
    }

    // Stage 3: Escrow / Reserve Allocation
    state.current_stage = 3;
    if fault_stage == 3 && fault == WorkflowFaultPoint::InsufficientFunds {
        return handle_failure(env, state, fault, 3, &mut pool);
    }

    let available = pool.total_reserves.saturating_sub(pool.active_locked).saturating_sub(pool.total_disbursed);
    if available < state.total_amount {
        return handle_failure(env, state, WorkflowFaultPoint::InsufficientFunds, 3, &mut pool);
    }

    // Lock funds from pool
    pool.active_locked = pool.active_locked.saturating_add(state.total_amount);
    state.locked_amount = state.total_amount;
    instance_set(env, &pool_key(), &pool);

    // Stage 4: Asset Settlement / Token Disbursement
    state.current_stage = 4;
    if fault_stage == 4 {
        match fault {
            WorkflowFaultPoint::TokenTransferRejected => {
                return handle_failure(env, state, fault, 4, &mut pool);
            }
            WorkflowFaultPoint::InvariantBreach => {
                return handle_failure(env, state, fault, 4, &mut pool);
            }
            _ => {}
        }
    }

    // Disburse funds
    pool.active_locked = pool.active_locked.saturating_sub(state.locked_amount);
    pool.total_disbursed = pool.total_disbursed.saturating_add(state.total_amount);
    state.disbursed_amount = state.total_amount;
    state.locked_amount = 0;

    // Stage 5: Final Settlement & Audit Receipt
    state.current_stage = 5;
    if fault_stage == 5 && fault != WorkflowFaultPoint::None {
        return handle_failure(env, state, fault, 5, &mut pool);
    }

    // Conservation check: total_reserves must equal available + active_locked + total_disbursed
    let verified_sum = pool.active_locked.saturating_add(pool.total_disbursed);
    if verified_sum > pool.total_reserves {
        return handle_failure(env, state, WorkflowFaultPoint::InvariantBreach, 5, &mut pool);
    }

    state.is_completed = true;
    state.has_failed = false;
    instance_set(env, &pool_key(), &pool);
    instance_set(env, &state_key(state.workflow_id), state);

    env.events().publish(
        (TOPIC_WORKFLOW_COMPLETE, state.workflow_id),
        (state.total_amount, env.ledger().sequence()),
    );

    Ok(state.clone())
}

fn handle_failure(
    env: &Env,
    state: &mut WorkflowExecutionState,
    fault: WorkflowFaultPoint,
    stage: u32,
    pool: &mut WorkflowPoolReserves,
) -> Result<WorkflowExecutionState, WorkflowFaultError> {
    // Perform deterministic rollback of any allocated funds
    if state.locked_amount > 0 {
        pool.active_locked = pool.active_locked.saturating_sub(state.locked_amount);
        state.locked_amount = 0;
        state.rollback_performed = true;
    }

    // If partial disbursement happened, restore to pool
    if state.disbursed_amount > 0 {
        pool.total_disbursed = pool.total_disbursed.saturating_sub(state.disbursed_amount);
        state.disbursed_amount = 0;
        state.rollback_performed = true;
    }

    state.has_failed = true;
    state.failed_at_stage = stage;
    state.active_fault = fault;
    state.last_updated_ledger = env.ledger().sequence();

    instance_set(env, &pool_key(), pool);
    instance_set(env, &state_key(state.workflow_id), state);

    env.events().publish(
        (TOPIC_WORKFLOW_FAULT, state.workflow_id),
        (stage as u32, fault as u32, env.ledger().sequence()),
    );

    match fault {
        WorkflowFaultPoint::DependencyTimeout => Err(WorkflowFaultError::DependencyTimeout),
        WorkflowFaultPoint::InsufficientFunds => Err(WorkflowFaultError::InsufficientFunds),
        WorkflowFaultPoint::TokenTransferRejected => Err(WorkflowFaultError::TokenTransferRejected),
        WorkflowFaultPoint::UnauthorizedCaller => Err(WorkflowFaultError::Unauthorized),
        WorkflowFaultPoint::InvariantBreach => Err(WorkflowFaultError::InvariantViolation),
        _ => Err(WorkflowFaultError::StageFailed),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Env};

    #[contract]
    struct WorkflowFaultTestContract;
    #[contractimpl]
    impl WorkflowFaultTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let cid = env.register_contract(None, WorkflowFaultTestContract);
        let admin = Address::generate(&env);
        env.as_contract(&cid, || {
            crate::auth::set_admin(&env, &admin);
            initialize_pool(&env, 100_000);
        });
        (env, cid, admin)
    }

    #[test]
    fn test_normal_path_workflow_runs_to_completion() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let res = execute_critical_workflow(
                &env,
                &admin,
                1001,
                CriticalWorkflowType::AidDisbursement,
                25_000,
                WorkflowFaultPoint::None,
                0,
            ).unwrap();

            assert!(res.is_completed);
            assert!(!res.has_failed);
            assert_eq!(res.current_stage, 5);
            assert_eq!(res.disbursed_amount, 25_000);
            assert_eq!(res.locked_amount, 0);

            let pool = get_pool_reserves(&env);
            assert_eq!(pool.total_disbursed, 25_000);
            assert_eq!(pool.active_locked, 0);
        });
    }

    #[test]
    fn test_failure_injection_at_oracle_timeout_and_rollback() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let err = execute_critical_workflow(
                &env,
                &admin,
                1002,
                CriticalWorkflowType::AidDisbursement,
                15_000,
                WorkflowFaultPoint::DependencyTimeout,
                2,
            ).unwrap_err();

            assert_eq!(err, WorkflowFaultError::DependencyTimeout);

            let state = get_workflow_state(&env, 1002).unwrap();
            assert!(state.has_failed);
            assert_eq!(state.failed_at_stage, 2);
            assert_eq!(state.locked_amount, 0);
            assert_eq!(state.disbursed_amount, 0);

            // Pool reserves remain intact
            let pool = get_pool_reserves(&env);
            assert_eq!(pool.active_locked, 0);
            assert_eq!(pool.total_disbursed, 0);
        });
    }

    #[test]
    fn test_failure_injection_at_transfer_stage_with_funds_rollback() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let err = execute_critical_workflow(
                &env,
                &admin,
                1003,
                CriticalWorkflowType::MilestoneEscrow,
                30_000,
                WorkflowFaultPoint::TokenTransferRejected,
                4,
            ).unwrap_err();

            assert_eq!(err, WorkflowFaultError::TokenTransferRejected);

            let state = get_workflow_state(&env, 1003).unwrap();
            assert!(state.has_failed);
            assert_eq!(state.failed_at_stage, 4);
            assert!(state.rollback_performed);
            assert_eq!(state.locked_amount, 0);
            assert_eq!(state.disbursed_amount, 0);

            // Verified that locked funds were rolled back into pool
            let pool = get_pool_reserves(&env);
            assert_eq!(pool.active_locked, 0);
            assert_eq!(pool.total_disbursed, 0);
        });
    }

    #[test]
    fn test_retry_path_after_failure_recovers_to_completion() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            // First run fails at stage 2 due to transient timeout
            let _ = execute_critical_workflow(
                &env,
                &admin,
                1004,
                CriticalWorkflowType::AidDisbursement,
                20_000,
                WorkflowFaultPoint::DependencyTimeout,
                2,
            ).unwrap_err();
        });

        // Retry in subsequent frame after fault cleared
        env.as_contract(&cid, || {
            let res = retry_critical_workflow(&env, &admin, 1004).unwrap();
            assert!(res.is_completed);
            assert!(!res.has_failed);
            assert_eq!(res.attempts, 2);
            assert_eq!(res.disbursed_amount, 20_000);

            let pool = get_pool_reserves(&env);
            assert_eq!(pool.total_disbursed, 20_000);
            assert_eq!(pool.active_locked, 0);
        });
    }

    #[test]
    fn test_authorization_rejection_for_unauthorized_caller() {
        let (env, cid, _admin) = setup();
        env.as_contract(&cid, || {
            let unauth = Address::generate(&env);
            let err = execute_critical_workflow(
                &env,
                &unauth,
                1005,
                CriticalWorkflowType::AidDisbursement,
                10_000,
                WorkflowFaultPoint::None,
                0,
            ).unwrap_err();

            assert_eq!(err, WorkflowFaultError::Unauthorized);
        });
    }
}
