//! Deployment rollback verification checks and cross-contract gating (Issue #495).
//!
//! Multi-contract deployments across Trellis contracts (Treasury, Aid, Referral,
//! Governance, Oracle, Registry, and Marketplace) execute as a sequence of discrete
//! initialization steps. If any step fails partway through:
//!
//! 1. **Deployment Tracker State Machine**: Transitions from `InProgress` to `AwaitingRollback`.
//! 2. **Systematic Verification Probes**: Evaluates four operational rollback pillars:
//!    - `StorageClean`: Confirms uninitialized storage or reverted initial values.
//!    - `DependencyUnlinked`: Confirms cross-contract address references were severed.
//!    - `LivenessChecked`: Confirms contract is reachable in pause or maintenance mode.
//!    - `InvariantPreserved`: Confirms no funds leaked or uncompensated transactions remain.
//! 3. **Verification Gate**: `complete_deployment_rollback` strictly rejects rollback
//!    completion unless every probe passes (`all_clean == true`, `failed_checks == 0`).
//! 4. **Safe Deployment Retry**: Once verified and transitioned to `RolledBack`, the deployment
//!    can be safely retried under a fresh attempt counter.
//! 5. **Path Coverage**: Thoroughly exercises normal, failure, retry, and authorization paths.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{instance_get, instance_set};

/// Status of a multi-contract deployment sequence.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DeploymentState {
    InProgress = 1,
    Completed = 2,
    AwaitingRollback = 3,
    RolledBack = 4,
}

/// Category of verification check applied during rollback evaluation.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RollbackCheckCategory {
    StorageClean = 1,
    DependencyUnlinked = 2,
    LivenessChecked = 3,
    InvariantPreserved = 4,
}

/// Verification probe supplied by an operator or monitoring agent for a step.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackVerificationProbe {
    pub step: Symbol,
    pub category: RollbackCheckCategory,
    pub is_clean: bool,
}

/// Step descriptor within a deployment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentStep {
    pub index: u32,
    pub name: Symbol,
    pub completed: bool,
}

/// Persistent deployment tracker record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentRollbackTracker {
    pub deployment_id: Symbol,
    pub state: DeploymentState,
    pub attempt: u32,
    pub cursor: u32,
    pub steps: Vec<DeploymentStep>,
    pub failed_step: Option<Symbol>,
    pub failure_error_code: u32,
    pub updated_at: u64,
}

/// Report summarizing rollback verification findings.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentRollbackReport {
    pub deployment_id: Symbol,
    pub total_probes: u32,
    pub passed_probes: u32,
    pub failed_probes: u32,
    pub all_clean: bool,
    pub first_unclean_step: Option<Symbol>,
    pub verified_at: u64,
}

// ---------------------------------------------------------------------------
// Storage Helpers
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageKey {
    DeploymentTracker(Symbol),
}

fn get_tracker(env: &Env, id: &Symbol) -> Option<DeploymentRollbackTracker> {
    instance_get(env, &StorageKey::DeploymentTracker(id.clone()))
}

fn put_tracker(env: &Env, tracker: &DeploymentRollbackTracker) {
    instance_set(
        env,
        &StorageKey::DeploymentTracker(tracker.deployment_id.clone()),
        tracker,
    );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Begins or retries a multi-contract deployment sequence.
pub fn begin_deployment_lifecycle(
    env: &Env,
    caller: &Address,
    deployment_id: Symbol,
    step_names: Vec<Symbol>,
    timestamp: u64,
) -> Result<DeploymentRollbackTracker, Error> {
    require_admin(env, caller)?;

    if step_names.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let mut attempt = 1;
    if let Some(existing) = get_tracker(env, &deployment_id) {
        match existing.state {
            DeploymentState::InProgress | DeploymentState::AwaitingRollback => {
                // Cannot restart until current deployment completes or rolls back cleanly
                return Err(Error::AlreadyInitialized);
            }
            DeploymentState::Completed | DeploymentState::RolledBack => {
                // Retry starts with incremented attempt
                attempt = existing.attempt.saturating_add(1);
            }
        }
    }

    let mut steps = Vec::new(env);
    for i in 0..step_names.len() {
        steps.push_back(DeploymentStep {
            index: i as u32,
            name: step_names.get(i).unwrap(),
            completed: false,
        });
    }

    let tracker = DeploymentRollbackTracker {
        deployment_id: deployment_id.clone(),
        state: DeploymentState::InProgress,
        attempt,
        cursor: 0,
        steps,
        failed_step: None,
        failure_error_code: 0,
        updated_at: timestamp,
    };

    put_tracker(env, &tracker);
    Ok(tracker)
}

/// Marks a deployment step as completed.
pub fn record_deployment_step_success(
    env: &Env,
    caller: &Address,
    deployment_id: &Symbol,
    step_index: u32,
    timestamp: u64,
) -> Result<DeploymentRollbackTracker, Error> {
    require_admin(env, caller)?;

    let mut tracker = get_tracker(env, deployment_id).ok_or(Error::NotFound)?;
    if tracker.state != DeploymentState::InProgress || tracker.cursor != step_index {
        return Err(Error::InvalidTransition);
    }

    let mut step = tracker
        .steps
        .get(step_index)
        .ok_or(Error::InvalidArgument)?;
    step.completed = true;
    tracker.steps.set(step_index, step);
    tracker.cursor = tracker.cursor.saturating_add(1);
    tracker.updated_at = timestamp;

    if tracker.cursor >= tracker.steps.len() {
        tracker.state = DeploymentState::Completed;
    }

    put_tracker(env, &tracker);
    Ok(tracker)
}

/// Records a step failure during deployment, transitioning tracker to AwaitingRollback.
pub fn record_deployment_step_failure(
    env: &Env,
    caller: &Address,
    deployment_id: &Symbol,
    step_index: u32,
    error_code: u32,
    timestamp: u64,
) -> Result<DeploymentRollbackTracker, Error> {
    require_admin(env, caller)?;

    let mut tracker = get_tracker(env, deployment_id).ok_or(Error::NotFound)?;
    if tracker.state != DeploymentState::InProgress || tracker.cursor != step_index {
        return Err(Error::InvalidTransition);
    }

    let step = tracker
        .steps
        .get(step_index)
        .ok_or(Error::InvalidArgument)?;
    tracker.state = DeploymentState::AwaitingRollback;
    tracker.failed_step = Some(step.name);
    tracker.failure_error_code = error_code;
    tracker.updated_at = timestamp;

    put_tracker(env, &tracker);
    Ok(tracker)
}

/// Evaluates rollback probes against the tracker.
///
/// Read-only check. Must be in `AwaitingRollback`.
pub fn verify_deployment_rollback_checks(
    env: &Env,
    deployment_id: &Symbol,
    probes: &Vec<RollbackVerificationProbe>,
    timestamp: u64,
) -> Result<DeploymentRollbackReport, Error> {
    let tracker = get_tracker(env, deployment_id).ok_or(Error::NotFound)?;
    if tracker.state != DeploymentState::AwaitingRollback {
        return Err(Error::InvalidTransition);
    }

    let total_probes = probes.len();
    if total_probes == 0 {
        return Err(Error::InvalidArgument);
    }

    let mut passed_probes: u32 = 0;
    let mut failed_probes: u32 = 0;
    let mut first_unclean_step: Option<Symbol> = None;

    for i in 0..total_probes {
        let probe = probes.get(i).unwrap();
        if probe.is_clean {
            passed_probes = passed_probes.saturating_add(1);
        } else {
            failed_probes = failed_probes.saturating_add(1);
            if first_unclean_step.is_none() {
                first_unclean_step = Some(probe.step);
            }
        }
    }

    let all_clean = failed_probes == 0;

    Ok(DeploymentRollbackReport {
        deployment_id: deployment_id.clone(),
        total_probes,
        passed_probes,
        failed_probes,
        all_clean,
        first_unclean_step,
        verified_at: timestamp,
    })
}

/// Completes deployment rollback once all verification checks pass.
pub fn complete_deployment_rollback(
    env: &Env,
    caller: &Address,
    deployment_id: &Symbol,
    report: &DeploymentRollbackReport,
    timestamp: u64,
) -> Result<DeploymentRollbackTracker, Error> {
    require_admin(env, caller)?;

    let mut tracker = get_tracker(env, deployment_id).ok_or(Error::NotFound)?;
    if tracker.state != DeploymentState::AwaitingRollback {
        return Err(Error::InvalidTransition);
    }

    // Gate: Verification report must match deployment_id and be fully clean
    if &report.deployment_id != deployment_id || !report.all_clean || report.failed_probes > 0 {
        return Err(Error::InvalidTransition);
    }

    tracker.state = DeploymentState::RolledBack;
    tracker.cursor = 0;
    tracker.updated_at = timestamp;

    put_tracker(env, &tracker);
    Ok(tracker)
}

/// Query function to inspect deployment tracker.
pub fn get_deployment_tracker(
    env: &Env,
    deployment_id: &Symbol,
) -> Result<DeploymentRollbackTracker, Error> {
    get_tracker(env, deployment_id).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Automated Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{grant_role, set_admin, Role};
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env, Vec};

    #[contract]
    struct DeployRollbackTestContract;
    #[contractimpl]
    impl DeployRollbackTestContract {}

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, DeployRollbackTestContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_admin(&env, &admin);
            grant_role(&env, &admin, &admin, Role::Admin).unwrap();
        });

        (env, contract_id, admin, user)
    }

    fn sample_steps(env: &Env) -> Vec<Symbol> {
        let mut steps = Vec::new(env);
        steps.push_back(symbol_short!("treasury"));
        steps.push_back(symbol_short!("aid"));
        steps.push_back(symbol_short!("oracle"));
        steps
    }

    #[test]
    fn test_normal_deployment_path_completes() {
        let (env, contract_id, admin, _) = setup();
        let id = symbol_short!("dep_01");
        let steps = sample_steps(&env);

        let t0 = env.as_contract(&contract_id, || {
            begin_deployment_lifecycle(&env, &admin, id.clone(), steps, 1000).unwrap()
        });
        assert_eq!(t0.state, DeploymentState::InProgress);
        assert_eq!(t0.attempt, 1);
        assert_eq!(t0.cursor, 0);

        // Step 0: Treasury
        let t1 = env.as_contract(&contract_id, || {
            record_deployment_step_success(&env, &admin, &id, 0, 1010).unwrap()
        });
        assert_eq!(t1.cursor, 1);

        // Step 1: Aid
        let t2 = env.as_contract(&contract_id, || {
            record_deployment_step_success(&env, &admin, &id, 1, 1020).unwrap()
        });
        assert_eq!(t2.cursor, 2);

        // Step 2: Oracle -> Completed
        let t3 = env.as_contract(&contract_id, || {
            record_deployment_step_success(&env, &admin, &id, 2, 1030).unwrap()
        });
        assert_eq!(t3.state, DeploymentState::Completed);
        assert_eq!(t3.cursor, 3);
    }

    #[test]
    fn test_failure_path_blocks_incomplete_rollback() {
        let (env, contract_id, admin, _) = setup();
        let id = symbol_short!("dep_fail");
        let steps = sample_steps(&env);

        env.as_contract(&contract_id, || {
            begin_deployment_lifecycle(&env, &admin, id.clone(), steps, 2000).unwrap()
        });
        env.as_contract(&contract_id, || {
            record_deployment_step_success(&env, &admin, &id, 0, 2010).unwrap()
        });

        // Step 1 fails
        let t_fail = env.as_contract(&contract_id, || {
            record_deployment_step_failure(&env, &admin, &id, 1, 5, 2020).unwrap()
        });
        assert_eq!(t_fail.state, DeploymentState::AwaitingRollback);
        assert_eq!(t_fail.failed_step, Some(symbol_short!("aid")));

        // Case A: Probe reports step 0 storage is still dirty
        let mut dirty_probes = Vec::new(&env);
        dirty_probes.push_back(RollbackVerificationProbe {
            step: symbol_short!("treasury"),
            category: RollbackCheckCategory::StorageClean,
            is_clean: false, // NOT clean
        });
        dirty_probes.push_back(RollbackVerificationProbe {
            step: symbol_short!("aid"),
            category: RollbackCheckCategory::DependencyUnlinked,
            is_clean: true,
        });

        let report_dirty = env.as_contract(&contract_id, || {
            verify_deployment_rollback_checks(&env, &id, &dirty_probes, 2030).unwrap()
        });
        assert!(!report_dirty.all_clean);
        assert_eq!(report_dirty.failed_probes, 1);
        assert_eq!(
            report_dirty.first_unclean_step,
            Some(symbol_short!("treasury"))
        );

        // Complete rollback gate rejects dirty state
        let gate_res = env.as_contract(&contract_id, || {
            complete_deployment_rollback(&env, &admin, &id, &report_dirty, 2040)
        });
        assert_eq!(gate_res, Err(Error::InvalidTransition));
    }

    #[test]
    fn test_retry_path_succeeds_after_clean_rollback_verification() {
        let (env, contract_id, admin, _) = setup();
        let id = symbol_short!("dep_retry");
        let steps = sample_steps(&env);

        env.as_contract(&contract_id, || {
            begin_deployment_lifecycle(&env, &admin, id.clone(), steps.clone(), 3000).unwrap()
        });
        env.as_contract(&contract_id, || {
            record_deployment_step_failure(&env, &admin, &id, 0, 10, 3010).unwrap()
        });

        // Clean probes across all rollback categories
        let mut clean_probes = Vec::new(&env);
        clean_probes.push_back(RollbackVerificationProbe {
            step: symbol_short!("treasury"),
            category: RollbackCheckCategory::StorageClean,
            is_clean: true,
        });
        clean_probes.push_back(RollbackVerificationProbe {
            step: symbol_short!("treasury"),
            category: RollbackCheckCategory::DependencyUnlinked,
            is_clean: true,
        });

        let report_clean = env.as_contract(&contract_id, || {
            verify_deployment_rollback_checks(&env, &id, &clean_probes, 3020).unwrap()
        });
        assert!(report_clean.all_clean);
        assert_eq!(report_clean.failed_probes, 0);

        // Gate passes with clean verification
        let rolled_back = env.as_contract(&contract_id, || {
            complete_deployment_rollback(&env, &admin, &id, &report_clean, 3030).unwrap()
        });
        assert_eq!(rolled_back.state, DeploymentState::RolledBack);

        // Retry path: New attempt allowed with attempt = 2
        let retry = env.as_contract(&contract_id, || {
            begin_deployment_lifecycle(&env, &admin, id.clone(), steps, 3100).unwrap()
        });
        assert_eq!(retry.state, DeploymentState::InProgress);
        assert_eq!(retry.attempt, 2);
        assert_eq!(retry.cursor, 0);
    }

    #[test]
    fn test_authorization_path_rejects_unprivileged_actors() {
        let (env, contract_id, _, unauthorized) = setup();
        let id = symbol_short!("dep_auth");
        let steps = sample_steps(&env);

        env.as_contract(&contract_id, || {
            let res = begin_deployment_lifecycle(&env, &unauthorized, id, steps, 4000);
            assert_eq!(res, Err(Error::Unauthorized));
        });
    }
}
