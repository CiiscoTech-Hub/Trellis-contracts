//! Permission-diff preview and rollback plan generator before policy changes (Issue #496).
//!
//! Enables administrators and governance operators to preview the precise delta
//! of a proposed role or policy update before committing it to on-chain state:
//!
//! 1. **Pure Pre-flight Simulation**: Compares current permission grants against proposed
//!    grants without mutating underlying contract storage or emitting external side effects.
//! 2. **Granular Delta Classification**: Categorizes grants into `added`, `revoked`, and `unchanged`.
//! 3. **Blast Radius & Risk Weighting**: Computes an explainable risk score (0-100) based on
//!    the sensitivity of newly granted capabilities (e.g., `UpgradeContracts`, `PauseContracts`,
//!    `TreasuryOperations`, `ManageRoles`).
//! 4. **Deterministic Rollback Plan**: Produces an exact inverse compensation plan
//!    (`restore` previously revoked grants, `strip` newly added grants) enabling immediate
//!    safe rollback if operational drift occurs.
//! 5. **Path Coverage**: Thoroughly tests normal, failure, retry, and authorization paths.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::errors::Error;

/// Individual permission capability recognized in Trellis access-control.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PolicyCapability {
    UseOwnResources = 1,
    ManageConfiguration = 2,
    ManageRoles = 3,
    TreasuryOperations = 4,
    PauseContracts = 5,
    ReferralConfiguration = 6,
    SubmitOracle = 7,
    UpgradeContracts = 8,
    ReadAuditTrail = 9,
    ServiceOperation = 10,
    EmergencyShutdown = 11,
}

impl PolicyCapability {
    /// Returns the risk weight of granting this capability (1-30).
    pub fn risk_weight(&self) -> u32 {
        match self {
            PolicyCapability::EmergencyShutdown => 30,
            PolicyCapability::UpgradeContracts => 25,
            PolicyCapability::ManageRoles => 20,
            PolicyCapability::TreasuryOperations => 20,
            PolicyCapability::PauseContracts => 15,
            PolicyCapability::ManageConfiguration => 10,
            PolicyCapability::SubmitOracle => 8,
            PolicyCapability::ReferralConfiguration => 5,
            PolicyCapability::ReadAuditTrail => 3,
            PolicyCapability::ServiceOperation => 2,
            PolicyCapability::UseOwnResources => 1,
        }
    }
}

/// A single permission grant associating a principal, role, and capability.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyGrantRecord {
    pub principal: Address,
    pub role: Symbol,
    pub capability: PolicyCapability,
}

/// Comprehensive permission-diff report produced by preview simulation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionDiffReport {
    /// Target principal or role subject.
    pub subject: Address,
    /// Grants that would be newly added.
    pub added: Vec<PolicyGrantRecord>,
    /// Grants that would be revoked.
    pub revoked: Vec<PolicyGrantRecord>,
    /// Grants that remain unchanged.
    pub unchanged: Vec<PolicyGrantRecord>,
    /// Cumulative blast-radius risk score (capped at 100).
    pub risk_score: u32,
    /// Whether the proposed policy makes any change at all.
    pub has_changes: bool,
}

/// Compensating rollback plan generated to revert a proposed change if needed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRollbackPlan {
    pub subject: Address,
    pub grants_to_restore: Vec<PolicyGrantRecord>,
    pub grants_to_strip: Vec<PolicyGrantRecord>,
}

/// Compares `current_grants` against `proposed_grants` for a given subject.
///
/// Pure and non-mutating. Caller must be an authorized administrator.
pub fn preview_permission_diff(
    env: &Env,
    caller: &Address,
    subject: &Address,
    current_grants: &Vec<PolicyGrantRecord>,
    proposed_grants: &Vec<PolicyGrantRecord>,
) -> Result<PermissionDiffReport, Error> {
    require_admin(env, caller)?;

    let mut added = Vec::new(env);
    let mut revoked = Vec::new(env);
    let mut unchanged = Vec::new(env);
    let mut cumulative_risk: u32 = 0;

    // Check proposed against current (find added and unchanged)
    for i in 0..proposed_grants.len() {
        let proposed = proposed_grants.get(i).unwrap();
        if &proposed.principal != subject {
            return Err(Error::InvalidArgument);
        }

        let mut found_in_current = false;
        for j in 0..current_grants.len() {
            let current = current_grants.get(j).unwrap();
            if current == proposed {
                found_in_current = true;
                break;
            }
        }

        if found_in_current {
            unchanged.push_back(proposed);
        } else {
            cumulative_risk = cumulative_risk.saturating_add(proposed.capability.risk_weight());
            added.push_back(proposed);
        }
    }

    // Check current against proposed (find revoked)
    for i in 0..current_grants.len() {
        let current = current_grants.get(i).unwrap();
        if &current.principal != subject {
            return Err(Error::InvalidArgument);
        }

        let mut found_in_proposed = false;
        for j in 0..proposed_grants.len() {
            let proposed = proposed_grants.get(j).unwrap();
            if current == proposed {
                found_in_proposed = true;
                break;
            }
        }

        if !found_in_proposed {
            revoked.push_back(current);
        }
    }

    let has_changes = added.len() > 0 || revoked.len() > 0;
    let risk_score = cumulative_risk.min(100);

    Ok(PermissionDiffReport {
        subject: subject.clone(),
        added,
        revoked,
        unchanged,
        risk_score,
        has_changes,
    })
}

/// Generates an exact inverse rollback plan from a permission-diff report.
pub fn generate_policy_rollback_plan(report: &PermissionDiffReport) -> PolicyRollbackPlan {
    PolicyRollbackPlan {
        subject: report.subject.clone(),
        grants_to_restore: report.revoked.clone(),
        grants_to_strip: report.added.clone(),
    }
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
    struct PermDiffTestContract;
    #[contractimpl]
    impl PermDiffTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PermDiffTestContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let subject = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_admin(&env, &admin);
            grant_role(&env, &admin, &admin, Role::Admin).unwrap();
        });

        (env, contract_id, admin, user, subject)
    }

    #[test]
    fn test_normal_path_permission_diff_and_risk_scoring() {
        let (env, contract_id, admin, _, subject) = setup();

        let mut current = Vec::new(&env);
        current.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });
        current.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("operator"),
            capability: PolicyCapability::ServiceOperation,
        });

        // Proposed: revoke ServiceOperation, keep ReadAuditTrail, add UpgradeContracts
        let mut proposed = Vec::new(&env);
        proposed.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });
        proposed.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("upgrader"),
            capability: PolicyCapability::UpgradeContracts,
        });

        env.as_contract(&contract_id, || {
            let diff =
                preview_permission_diff(&env, &admin, &subject, &current, &proposed).unwrap();
            assert!(diff.has_changes);
            assert_eq!(diff.added.len(), 1);
            assert_eq!(
                diff.added.get(0).unwrap().capability,
                PolicyCapability::UpgradeContracts
            );
            assert_eq!(diff.revoked.len(), 1);
            assert_eq!(
                diff.revoked.get(0).unwrap().capability,
                PolicyCapability::ServiceOperation
            );
            assert_eq!(diff.unchanged.len(), 1);
            assert_eq!(
                diff.unchanged.get(0).unwrap().capability,
                PolicyCapability::ReadAuditTrail
            );

            // Risk weight for UpgradeContracts is 25
            assert_eq!(diff.risk_score, 25);

            // Test Rollback Plan Synthesis
            let plan = generate_policy_rollback_plan(&diff);
            assert_eq!(plan.grants_to_restore.len(), 1);
            assert_eq!(
                plan.grants_to_restore.get(0).unwrap().capability,
                PolicyCapability::ServiceOperation
            );
            assert_eq!(plan.grants_to_strip.len(), 1);
            assert_eq!(
                plan.grants_to_strip.get(0).unwrap().capability,
                PolicyCapability::UpgradeContracts
            );
        });
    }

    #[test]
    fn test_failure_path_subject_mismatch_rejected() {
        let (env, contract_id, admin, _, subject) = setup();
        let other_subject = Address::generate(&env);

        let mut current = Vec::new(&env);
        current.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });

        // Proposed grant has mismatched subject address
        let mut proposed = Vec::new(&env);
        proposed.push_back(PolicyGrantRecord {
            principal: other_subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });

        env.as_contract(&contract_id, || {
            let res = preview_permission_diff(&env, &admin, &subject, &current, &proposed);
            assert_eq!(res, Err(Error::InvalidArgument));
        });
    }

    #[test]
    fn test_retry_path_idempotent_pure_diff() {
        let (env, contract_id, admin, _, subject) = setup();

        let mut current = Vec::new(&env);
        current.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });

        let mut proposed = Vec::new(&env);
        proposed.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("admin"),
            capability: PolicyCapability::EmergencyShutdown,
        });

        // First call
        let diff1 = env.as_contract(&contract_id, || {
            preview_permission_diff(&env, &admin, &subject, &current, &proposed).unwrap()
        });
        // Second call (retry)
        let diff2 = env.as_contract(&contract_id, || {
            preview_permission_diff(&env, &admin, &subject, &current, &proposed).unwrap()
        });

        assert_eq!(diff1, diff2);
        assert_eq!(diff1.risk_score, 30);
    }

    #[test]
    fn test_authorization_path_rejects_unauthorized_preview() {
        let (env, contract_id, _, unauthorized, subject) = setup();

        let current = Vec::new(&env);
        let proposed = Vec::new(&env);

        env.as_contract(&contract_id, || {
            let res = preview_permission_diff(&env, &unauthorized, &subject, &current, &proposed);
            assert_eq!(res, Err(Error::Unauthorized));
        });
    }

    #[test]
    fn test_identical_policies_produce_zero_risk_no_changes() {
        let (env, contract_id, admin, _, subject) = setup();

        let mut current = Vec::new(&env);
        current.push_back(PolicyGrantRecord {
            principal: subject.clone(),
            role: symbol_short!("reader"),
            capability: PolicyCapability::ReadAuditTrail,
        });

        let proposed = current.clone();

        env.as_contract(&contract_id, || {
            let diff =
                preview_permission_diff(&env, &admin, &subject, &current, &proposed).unwrap();
            assert!(!diff.has_changes);
            assert_eq!(diff.added.len(), 0);
            assert_eq!(diff.revoked.len(), 0);
            assert_eq!(diff.unchanged.len(), 1);
            assert_eq!(diff.risk_score, 0);
        });
    }
}
