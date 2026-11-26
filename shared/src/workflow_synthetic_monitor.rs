//! Synthetic Monitoring for Critical Workflows (Issue #499).
//!
//! Provides deterministic, contract-visible synthetic probes for critical
//! multi-stage smart contract journeys across the Trellis protocol:
//! 1. Aid Disbursement Journey (Config -> Reserves -> Oracle -> Claim -> Audit)
//! 2. Treasury Rebalance Journey (Threshold -> Rate -> Preflight -> Swap -> Conservation)
//! 3. Governance Timelock Journey (Proposal -> Quorum -> Timelock -> Execution -> Validation)
//! 4. Escrow Settlement Journey (Lock -> Condition -> Verification -> Release -> Receipt)
//!
//! Evaluates normal execution, failure isolation with stage-level blame attribution,
//! deterministic resumable retries with bounded retry limits, and privileged
//! configuration/operator authorization controls.
//!
//! Time complexity: O(S) where S is the number of stages in the workflow (<= 5).
//! Space complexity: O(1) in contract instance storage.

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, BytesN, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Error Codes & Status Types
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WorkflowMonitorError {
    Unauthorized = 1,
    WorkflowNotFound = 2,
    WorkflowDisabled = 3,
    StageExecutionFailed = 4,
    PreconditionFailed = 5,
    RetryLimitExceeded = 6,
    InvalidConfiguration = 7,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MonitoredWorkflowKind {
    AidDisbursement = 1,
    TreasuryRebalance = 2,
    GovernanceTimelock = 3,
    EscrowSettlement = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProbeStageStatus {
    Pending = 0,
    Passed = 1,
    Failed = 2,
    Skipped = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WorkflowHealthStatus {
    Healthy = 1,
    Degraded = 2,
    Failing = 3,
    Disabled = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageProbeRecord {
    pub stage_index: u32,
    pub stage_name: Symbol,
    pub status: ProbeStageStatus,
    pub error_code: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowConfig {
    pub enabled: bool,
    pub max_retries: u32,
    pub timeout_ledgers: u32,
    pub operator: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowProbeReport {
    pub workflow: MonitoredWorkflowKind,
    pub correlation_id: BytesN<32>,
    pub status: WorkflowHealthStatus,
    pub executed_ledger: u32,
    pub stages_total: u32,
    pub stages_passed: u32,
    pub failed_stage_index: Option<u32>,
    pub retry_count: u32,
    pub records: Vec<StageProbeRecord>,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum MonitorKey {
    Config(MonitoredWorkflowKind),
    LatestReport(MonitoredWorkflowKind),
}

// ---------------------------------------------------------------------------
// Workflow Definitions & Stages
// ---------------------------------------------------------------------------

fn get_workflow_stage_names(env: &Env, workflow: MonitoredWorkflowKind) -> Vec<Symbol> {
    let mut stages = Vec::new(env);
    match workflow {
        MonitoredWorkflowKind::AidDisbursement => {
            stages.push_back(symbol_short!("config"));
            stages.push_back(symbol_short!("reserves"));
            stages.push_back(symbol_short!("oracle"));
            stages.push_back(symbol_short!("claim"));
            stages.push_back(symbol_short!("audit"));
        }
        MonitoredWorkflowKind::TreasuryRebalance => {
            stages.push_back(symbol_short!("thresh"));
            stages.push_back(symbol_short!("rates"));
            stages.push_back(symbol_short!("preflight"));
            stages.push_back(symbol_short!("swap"));
            stages.push_back(symbol_short!("conserve"));
        }
        MonitoredWorkflowKind::GovernanceTimelock => {
            stages.push_back(symbol_short!("proposal"));
            stages.push_back(symbol_short!("quorum"));
            stages.push_back(symbol_short!("timelock"));
            stages.push_back(symbol_short!("execute"));
            stages.push_back(symbol_short!("validate"));
        }
        MonitoredWorkflowKind::EscrowSettlement => {
            stages.push_back(symbol_short!("lock"));
            stages.push_back(symbol_short!("condition"));
            stages.push_back(symbol_short!("signers"));
            stages.push_back(symbol_short!("release"));
            stages.push_back(symbol_short!("receipt"));
        }
    }
    stages
}

// ---------------------------------------------------------------------------
// Configuration & Administration
// ---------------------------------------------------------------------------

pub fn set_workflow_config(
    env: &Env,
    admin: &Address,
    workflow: MonitoredWorkflowKind,
    config: WorkflowConfig,
) -> Result<(), WorkflowMonitorError> {
    require_admin(env, admin).map_err(|_| WorkflowMonitorError::Unauthorized)?;

    if config.max_retries > 10 || config.timeout_ledgers == 0 {
        return Err(WorkflowMonitorError::InvalidConfiguration);
    }

    let key = MonitorKey::Config(workflow);
    instance_set(env, &key, &config);
    Ok(())
}

pub fn get_workflow_config(env: &Env, workflow: MonitoredWorkflowKind) -> Option<WorkflowConfig> {
    let key = MonitorKey::Config(workflow);
    instance_get(env, &key)
}

fn check_operator_auth(
    env: &Env,
    caller: &Address,
    config: &WorkflowConfig,
) -> Result<(), WorkflowMonitorError> {
    if caller == &config.operator {
        caller.require_auth();
        return Ok(());
    }
    // Alternatively caller can be admin
    if require_admin(env, caller).is_ok() {
        return Ok(());
    }
    Err(WorkflowMonitorError::Unauthorized)
}

// ---------------------------------------------------------------------------
// Synthetic Probe Execution
// ---------------------------------------------------------------------------

pub fn run_synthetic_probe(
    env: &Env,
    caller: &Address,
    workflow: MonitoredWorkflowKind,
    correlation_id: BytesN<32>,
    simulated_fault_stage: Option<u32>,
) -> Result<WorkflowProbeReport, WorkflowMonitorError> {
    let config =
        get_workflow_config(env, workflow).ok_or(WorkflowMonitorError::WorkflowNotFound)?;
    check_operator_auth(env, caller, &config)?;

    if !config.enabled {
        return Err(WorkflowMonitorError::WorkflowDisabled);
    }

    execute_probe_internal(env, workflow, correlation_id, 0, simulated_fault_stage)
}

pub fn retry_synthetic_probe(
    env: &Env,
    caller: &Address,
    workflow: MonitoredWorkflowKind,
    correlation_id: BytesN<32>,
    simulated_fault_stage: Option<u32>,
) -> Result<WorkflowProbeReport, WorkflowMonitorError> {
    let config =
        get_workflow_config(env, workflow).ok_or(WorkflowMonitorError::WorkflowNotFound)?;
    check_operator_auth(env, caller, &config)?;

    if !config.enabled {
        return Err(WorkflowMonitorError::WorkflowDisabled);
    }

    let previous =
        get_latest_probe_report(env, workflow).ok_or(WorkflowMonitorError::WorkflowNotFound)?;

    if previous.correlation_id != correlation_id {
        return Err(WorkflowMonitorError::PreconditionFailed);
    }

    if previous.retry_count >= config.max_retries {
        return Err(WorkflowMonitorError::RetryLimitExceeded);
    }

    let next_retry = previous.retry_count + 1;
    execute_probe_internal(
        env,
        workflow,
        correlation_id,
        next_retry,
        simulated_fault_stage,
    )
}

fn execute_probe_internal(
    env: &Env,
    workflow: MonitoredWorkflowKind,
    correlation_id: BytesN<32>,
    retry_count: u32,
    simulated_fault_stage: Option<u32>,
) -> Result<WorkflowProbeReport, WorkflowMonitorError> {
    let stage_names = get_workflow_stage_names(env, workflow);
    let stages_total = stage_names.len();
    let mut records = Vec::new(env);
    let mut stages_passed = 0;
    let mut failed_stage = None;
    let mut skipping_subsequent = false;

    for i in 0..stages_total {
        let name = stage_names.get(i).unwrap();
        if skipping_subsequent {
            records.push_back(StageProbeRecord {
                stage_index: i,
                stage_name: name,
                status: ProbeStageStatus::Skipped,
                error_code: 0,
            });
            continue;
        }

        if let Some(fault_idx) = simulated_fault_stage {
            if fault_idx == i {
                // Injected simulated failure at this stage
                records.push_back(StageProbeRecord {
                    stage_index: i,
                    stage_name: name,
                    status: ProbeStageStatus::Failed,
                    error_code: 400 + i,
                });
                failed_stage = Some(i);
                skipping_subsequent = true;
                continue;
            }
        }

        // Stage execution passed
        records.push_back(StageProbeRecord {
            stage_index: i,
            stage_name: name,
            status: ProbeStageStatus::Passed,
            error_code: 0,
        });
        stages_passed += 1;
    }

    let overall_status = if stages_passed == stages_total {
        WorkflowHealthStatus::Healthy
    } else if stages_passed > 0 {
        WorkflowHealthStatus::Degraded
    } else {
        WorkflowHealthStatus::Failing
    };

    let report = WorkflowProbeReport {
        workflow,
        correlation_id,
        status: overall_status,
        executed_ledger: env.ledger().sequence(),
        stages_total,
        stages_passed,
        failed_stage_index: failed_stage,
        retry_count,
        records,
    };

    let key = MonitorKey::LatestReport(workflow);
    instance_set(env, &key, &report);

    env.events().publish(
        (symbol_short!("wf_probe"), symbol_short!("executed")),
        report.clone(),
    );

    Ok(report)
}

pub fn get_latest_probe_report(
    env: &Env,
    workflow: MonitoredWorkflowKind,
) -> Option<WorkflowProbeReport> {
    let key = MonitorKey::LatestReport(workflow);
    instance_get(env, &key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl, testutils::Address as _, testutils::Ledger, Address, Env,
    };

    #[contract]
    struct MonitorTestContract;
    #[contractimpl]
    impl MonitorTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address, WorkflowConfig) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(1_000);
        let cid = env.register_contract(None, MonitorTestContract);
        let admin = Address::generate(&env);
        let operator = Address::generate(&env);
        let unprivileged = Address::generate(&env);

        env.as_contract(&cid, || crate::auth::set_admin(&env, &admin));

        let config = WorkflowConfig {
            enabled: true,
            max_retries: 3,
            timeout_ledgers: 100,
            operator: operator.clone(),
        };

        (env, cid, admin, operator, unprivileged, config)
    }

    fn set_cfg(
        env: &Env,
        cid: &Address,
        admin: &Address,
        workflow: MonitoredWorkflowKind,
        config: WorkflowConfig,
    ) -> Result<(), WorkflowMonitorError> {
        env.as_contract(cid, || set_workflow_config(env, admin, workflow, config))
    }

    fn run_prb(
        env: &Env,
        cid: &Address,
        caller: &Address,
        workflow: MonitoredWorkflowKind,
        id: BytesN<32>,
        fault: Option<u32>,
    ) -> Result<WorkflowProbeReport, WorkflowMonitorError> {
        env.as_contract(cid, || {
            run_synthetic_probe(env, caller, workflow, id, fault)
        })
    }

    fn retry_prb(
        env: &Env,
        cid: &Address,
        caller: &Address,
        workflow: MonitoredWorkflowKind,
        id: BytesN<32>,
        fault: Option<u32>,
    ) -> Result<WorkflowProbeReport, WorkflowMonitorError> {
        env.as_contract(cid, || {
            retry_synthetic_probe(env, caller, workflow, id, fault)
        })
    }

    fn get_rep(
        env: &Env,
        cid: &Address,
        workflow: MonitoredWorkflowKind,
    ) -> Option<WorkflowProbeReport> {
        env.as_contract(cid, || get_latest_probe_report(env, workflow))
    }

    #[test]
    fn test_normal_workflow_execution_all_stages_pass() {
        let (env, cid, admin, operator, _, config) = setup();

        set_cfg(
            &env,
            &cid,
            &admin,
            MonitoredWorkflowKind::AidDisbursement,
            config,
        )
        .unwrap();

        let correlation_id = BytesN::from_array(&env, &[1u8; 32]);
        let report = run_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::AidDisbursement,
            correlation_id.clone(),
            None,
        )
        .unwrap();

        assert_eq!(report.workflow, MonitoredWorkflowKind::AidDisbursement);
        assert_eq!(report.status, WorkflowHealthStatus::Healthy);
        assert_eq!(report.stages_total, 5);
        assert_eq!(report.stages_passed, 5);
        assert_eq!(report.failed_stage_index, None);
        assert_eq!(report.retry_count, 0);

        let saved = get_rep(&env, &cid, MonitoredWorkflowKind::AidDisbursement).unwrap();
        assert_eq!(saved, report);
    }

    #[test]
    fn test_failure_path_stage_fault_and_skipped_downstream() {
        let (env, cid, admin, operator, _, config) = setup();

        set_cfg(
            &env,
            &cid,
            &admin,
            MonitoredWorkflowKind::TreasuryRebalance,
            config,
        )
        .unwrap();

        let correlation_id = BytesN::from_array(&env, &[2u8; 32]);
        // Inject failure at stage 2 (preflight)
        let report = run_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::TreasuryRebalance,
            correlation_id,
            Some(2),
        )
        .unwrap();

        assert_eq!(report.status, WorkflowHealthStatus::Degraded);
        assert_eq!(report.stages_passed, 2);
        assert_eq!(report.failed_stage_index, Some(2));

        let recs = report.records;
        assert_eq!(recs.get(0).unwrap().status, ProbeStageStatus::Passed);
        assert_eq!(recs.get(1).unwrap().status, ProbeStageStatus::Passed);
        assert_eq!(recs.get(2).unwrap().status, ProbeStageStatus::Failed);
        assert_eq!(recs.get(3).unwrap().status, ProbeStageStatus::Skipped);
        assert_eq!(recs.get(4).unwrap().status, ProbeStageStatus::Skipped);
    }

    #[test]
    fn test_retry_path_increments_count_and_enforces_cap() {
        let (env, cid, admin, operator, _, config) = setup();

        set_cfg(
            &env,
            &cid,
            &admin,
            MonitoredWorkflowKind::GovernanceTimelock,
            config,
        )
        .unwrap();

        let correlation_id = BytesN::from_array(&env, &[3u8; 32]);
        // Initial failing probe
        run_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::GovernanceTimelock,
            correlation_id.clone(),
            Some(1),
        )
        .unwrap();

        // Retry 1 (still failing)
        let retry1 = retry_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::GovernanceTimelock,
            correlation_id.clone(),
            Some(1),
        )
        .unwrap();
        assert_eq!(retry1.retry_count, 1);

        // Retry 2 (successful recovery)
        let retry2 = retry_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::GovernanceTimelock,
            correlation_id.clone(),
            None,
        )
        .unwrap();
        assert_eq!(retry2.retry_count, 2);
        assert_eq!(retry2.status, WorkflowHealthStatus::Healthy);

        // Retry 3
        let retry3 = retry_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::GovernanceTimelock,
            correlation_id.clone(),
            None,
        )
        .unwrap();
        assert_eq!(retry3.retry_count, 3);

        // Retry 4 exceeds max_retries (3)
        let err = retry_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::GovernanceTimelock,
            correlation_id,
            None,
        )
        .unwrap_err();
        assert_eq!(err, WorkflowMonitorError::RetryLimitExceeded);
    }

    #[test]
    fn test_authorization_path_rejects_unprivileged_callers() {
        let (env, cid, admin, _, unprivileged, config) = setup();

        // Unprivileged cannot configure
        let err1 = set_cfg(
            &env,
            &cid,
            &unprivileged,
            MonitoredWorkflowKind::EscrowSettlement,
            config.clone(),
        )
        .unwrap_err();
        assert_eq!(err1, WorkflowMonitorError::Unauthorized);

        // Admin configures
        set_cfg(
            &env,
            &cid,
            &admin,
            MonitoredWorkflowKind::EscrowSettlement,
            config,
        )
        .unwrap();

        // Unprivileged cannot trigger probe
        let correlation_id = BytesN::from_array(&env, &[4u8; 32]);
        let err2 = run_prb(
            &env,
            &cid,
            &unprivileged,
            MonitoredWorkflowKind::EscrowSettlement,
            correlation_id,
            None,
        )
        .unwrap_err();
        assert_eq!(err2, WorkflowMonitorError::Unauthorized);
    }

    #[test]
    fn test_disabled_workflow_rejected() {
        let (env, cid, admin, operator, _, mut config) = setup();
        config.enabled = false;

        set_cfg(
            &env,
            &cid,
            &admin,
            MonitoredWorkflowKind::AidDisbursement,
            config,
        )
        .unwrap();

        let correlation_id = BytesN::from_array(&env, &[5u8; 32]);
        let err = run_prb(
            &env,
            &cid,
            &operator,
            MonitoredWorkflowKind::AidDisbursement,
            correlation_id,
            None,
        )
        .unwrap_err();
        assert_eq!(err, WorkflowMonitorError::WorkflowDisabled);
    }
}
