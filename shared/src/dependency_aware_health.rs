//! Dependency-Aware Public Health Status Engine (Issue #487).
//!
//! Evaluates holistic system availability by aggregating the health states of
//! all internal and external dependencies (Oracle Price Feeds, SAC Token
//! Contracts, Off-chain Indexers, Payment Bridges, and Governance Timelocks).
//!
//! Core Architectural Invariants:
//! 1. Exit Guarantees: User fund exits (refunds, claims, emergency withdrawals)
//!    are NEVER blocked, even when external dependencies are completely Down.
//!    `can_exit_funds` evaluates to `true` under all system health statuses.
//! 2. Criticality-Weighted Degradation: If a `Critical` dependency goes Down,
//!    new commitments (deposits, disbursements) are safely suspended (`EmergencyHalted`).
//!    Non-critical degradation informs frontends without halting on-chain flows.
//! 3. Structured User Guidance: Health states and degradation reasons are
//!    closed enumerations, preventing confidential infrastructure data leaks.
//! 4. Authorized Status Reporting: Only verified reporters or protocol admins
//!    can update dependency heartbeats and latency metrics.
//!
//! Time complexity: O(D) where D is the number of registered dependencies (<= 20).
//! Space complexity: O(D) in instance storage.

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::auth::require_admin;
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Error Codes & Enums
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DependencyHealthError {
    Unauthorized = 1,
    DependencyNotFound = 2,
    InvalidCriticality = 3,
    HeartbeatStale = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DependencyType {
    OraclePriceFeed = 1,
    AssetContract = 2,
    OffchainIndexer = 3,
    PaymentBridge = 4,
    GovernanceTimelock = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Criticality {
    Critical = 1,
    High = 2,
    Medium = 3,
    Low = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ComponentHealth {
    Healthy = 1,
    Degraded = 2,
    Down = 3,
    Unknown = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CompositeSystemStatus {
    Operational = 1,
    Degraded = 2,
    SeverelyDegraded = 3,
    EmergencyHalted = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyRecord {
    pub id: Symbol,
    pub dep_type: DependencyType,
    pub criticality: Criticality,
    pub health: ComponentHealth,
    pub latency_ms: u32,
    pub last_heartbeat_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicHealthVerdict {
    pub status: CompositeSystemStatus,
    pub total_dependencies: u32,
    pub healthy_count: u32,
    pub degraded_count: u32,
    pub down_count: u32,
    pub can_exit_funds: bool,
    pub can_disburse_aid: bool,
    pub can_accept_deposits: bool,
    pub can_submit_governance: bool,
    pub last_evaluated_ledger: u32,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum HealthKey {
    Reporter(Address),
    DepIds,
    DepRecord(Symbol),
}

// ---------------------------------------------------------------------------
// Authorization & Reporter Management
// ---------------------------------------------------------------------------

pub fn register_health_reporter(
    env: &Env,
    admin: &Address,
    reporter: &Address,
    authorized: bool,
) -> Result<(), DependencyHealthError> {
    require_admin(env, admin).map_err(|_| DependencyHealthError::Unauthorized)?;

    let key = HealthKey::Reporter(reporter.clone());
    instance_set(env, &key, &authorized);

    env.events().publish(
        (symbol_short!("health"), symbol_short!("reporter")),
        (reporter.clone(), authorized),
    );
    Ok(())
}

pub fn is_reporter(env: &Env, address: &Address) -> bool {
    let key = HealthKey::Reporter(address.clone());
    instance_get(env, &key).unwrap_or(false)
}

fn require_reporter_or_admin(env: &Env, caller: &Address) -> Result<(), DependencyHealthError> {
    caller.require_auth();
    if is_reporter(env, caller) || require_admin(env, caller).is_ok() {
        Ok(())
    } else {
        Err(DependencyHealthError::Unauthorized)
    }
}

// ---------------------------------------------------------------------------
// Dependency Registration & Heartbeat Reporting
// ---------------------------------------------------------------------------

pub fn register_dependency(
    env: &Env,
    admin: &Address,
    id: Symbol,
    dep_type: DependencyType,
    criticality: Criticality,
) -> Result<(), DependencyHealthError> {
    require_admin(env, admin).map_err(|_| DependencyHealthError::Unauthorized)?;

    let record = DependencyRecord {
        id: id.clone(),
        dep_type,
        criticality,
        health: ComponentHealth::Healthy,
        latency_ms: 0,
        last_heartbeat_ledger: env.ledger().sequence(),
    };

    let key = HealthKey::DepRecord(id.clone());
    instance_set(env, &key, &record);

    let mut ids: Vec<Symbol> =
        instance_get(env, &HealthKey::DepIds).unwrap_or_else(|| Vec::new(env));
    let mut exists = false;
    for existing in ids.iter() {
        if existing == id {
            exists = true;
            break;
        }
    }
    if !exists {
        ids.push_back(id.clone());
        instance_set(env, &HealthKey::DepIds, &ids);
    }

    env.events().publish(
        (symbol_short!("health"), symbol_short!("register")),
        (id, criticality),
    );

    Ok(())
}

pub fn report_dependency_heartbeat(
    env: &Env,
    caller: &Address,
    id: Symbol,
    health: ComponentHealth,
    latency_ms: u32,
) -> Result<(), DependencyHealthError> {
    require_reporter_or_admin(env, caller)?;

    let key = HealthKey::DepRecord(id.clone());
    let mut record: DependencyRecord =
        instance_get(env, &key).ok_or(DependencyHealthError::DependencyNotFound)?;

    record.health = health;
    record.latency_ms = latency_ms;
    record.last_heartbeat_ledger = env.ledger().sequence();

    instance_set(env, &key, &record);

    env.events().publish(
        (symbol_short!("health"), symbol_short!("heartbeat")),
        (id, health, latency_ms),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Composite Health Evaluation
// ---------------------------------------------------------------------------

pub fn get_composite_health(env: &Env) -> PublicHealthVerdict {
    let ids: Vec<Symbol> = instance_get(env, &HealthKey::DepIds).unwrap_or_else(|| Vec::new(env));
    let total = ids.len();

    let mut healthy = 0;
    let mut degraded = 0;
    let mut down = 0;
    let mut critical_down = false;
    let mut critical_degraded = false;
    let mut high_down_count = 0;

    for id in ids.iter() {
        let key = HealthKey::DepRecord(id);
        if let Some(record) = instance_get::<HealthKey, DependencyRecord>(env, &key) {
            match record.health {
                ComponentHealth::Healthy => healthy += 1,
                ComponentHealth::Degraded => {
                    degraded += 1;
                    if record.criticality == Criticality::Critical {
                        critical_degraded = true;
                    }
                }
                ComponentHealth::Down => {
                    down += 1;
                    if record.criticality == Criticality::Critical {
                        critical_down = true;
                    } else if record.criticality == Criticality::High {
                        high_down_count += 1;
                    }
                }
                ComponentHealth::Unknown => degraded += 1,
            }
        }
    }

    let status = if critical_down || high_down_count >= 2 {
        CompositeSystemStatus::EmergencyHalted
    } else if critical_degraded || high_down_count == 1 {
        CompositeSystemStatus::SeverelyDegraded
    } else if degraded > 0 || down > 0 {
        CompositeSystemStatus::Degraded
    } else {
        CompositeSystemStatus::Operational
    };

    // Exit is ALWAYS permitted under all conditions
    let can_exit_funds = true;

    // Disbursement and new deposits are gated under severe halt
    let can_disburse_aid = status != CompositeSystemStatus::EmergencyHalted;
    let can_accept_deposits =
        status == CompositeSystemStatus::Operational || status == CompositeSystemStatus::Degraded;
    let can_submit_governance = status != CompositeSystemStatus::EmergencyHalted;

    PublicHealthVerdict {
        status,
        total_dependencies: total,
        healthy_count: healthy,
        degraded_count: degraded,
        down_count: down,
        can_exit_funds,
        can_disburse_aid,
        can_accept_deposits,
        can_submit_governance,
        last_evaluated_ledger: env.ledger().sequence(),
    }
}

pub fn is_action_permitted(env: &Env, action: Symbol) -> bool {
    let verdict = get_composite_health(env);
    if action == symbol_short!("exit")
        || action == symbol_short!("refund")
        || action == symbol_short!("withdraw")
    {
        return verdict.can_exit_funds;
    }
    if action == symbol_short!("disburse") || action == symbol_short!("claim") {
        return verdict.can_disburse_aid;
    }
    if action == symbol_short!("deposit") {
        return verdict.can_accept_deposits;
    }
    if action == symbol_short!("gov") {
        return verdict.can_submit_governance;
    }
    true
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
    struct HealthTestContract;
    #[contractimpl]
    impl HealthTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(10_000);
        let cid = env.register_contract(None, HealthTestContract);
        let admin = Address::generate(&env);
        let reporter = Address::generate(&env);
        let unprivileged = Address::generate(&env);

        env.as_contract(&cid, || {
            crate::auth::set_admin(&env, &admin);
        });

        reg_rep(&env, &cid, &admin, &reporter, true).unwrap();

        // Register core dependencies
        reg_dep(
            &env,
            &cid,
            &admin,
            symbol_short!("oracle"),
            DependencyType::OraclePriceFeed,
            Criticality::Critical,
        )
        .unwrap();

        reg_dep(
            &env,
            &cid,
            &admin,
            symbol_short!("token_xlm"),
            DependencyType::AssetContract,
            Criticality::Critical,
        )
        .unwrap();

        reg_dep(
            &env,
            &cid,
            &admin,
            symbol_short!("indexer"),
            DependencyType::OffchainIndexer,
            Criticality::Medium,
        )
        .unwrap();

        (env, cid, admin, reporter, unprivileged)
    }

    fn reg_rep(
        env: &Env,
        cid: &Address,
        admin: &Address,
        rep: &Address,
        auth: bool,
    ) -> Result<(), DependencyHealthError> {
        env.as_contract(cid, || register_health_reporter(env, admin, rep, auth))
    }

    fn chk_rep(env: &Env, cid: &Address, addr: &Address) -> bool {
        env.as_contract(cid, || is_reporter(env, addr))
    }

    fn reg_dep(
        env: &Env,
        cid: &Address,
        admin: &Address,
        id: Symbol,
        t: DependencyType,
        c: Criticality,
    ) -> Result<(), DependencyHealthError> {
        env.as_contract(cid, || register_dependency(env, admin, id, t, c))
    }

    fn rep_hb(
        env: &Env,
        cid: &Address,
        caller: &Address,
        id: Symbol,
        h: ComponentHealth,
        lat: u32,
    ) -> Result<(), DependencyHealthError> {
        env.as_contract(cid, || report_dependency_heartbeat(env, caller, id, h, lat))
    }

    fn get_health(env: &Env, cid: &Address) -> PublicHealthVerdict {
        env.as_contract(cid, || get_composite_health(env))
    }

    fn action_ok(env: &Env, cid: &Address, action: Symbol) -> bool {
        env.as_contract(cid, || is_action_permitted(env, action))
    }

    #[test]
    fn test_normal_all_dependencies_healthy_operational() {
        let (env, cid, _, _, _) = setup();

        let verdict = get_health(&env, &cid);
        assert_eq!(verdict.status, CompositeSystemStatus::Operational);
        assert_eq!(verdict.total_dependencies, 3);
        assert_eq!(verdict.healthy_count, 3);
        assert_eq!(verdict.degraded_count, 0);
        assert_eq!(verdict.down_count, 0);
        assert!(verdict.can_exit_funds);
        assert!(verdict.can_disburse_aid);
        assert!(verdict.can_accept_deposits);
        assert!(verdict.can_submit_governance);
    }

    #[test]
    fn test_failure_critical_dependency_down_emergency_halted() {
        let (env, cid, _, reporter, _) = setup();

        // Report Oracle as DOWN
        rep_hb(
            &env,
            &cid,
            &reporter,
            symbol_short!("oracle"),
            ComponentHealth::Down,
            5_000,
        )
        .unwrap();

        let verdict = get_health(&env, &cid);
        assert_eq!(verdict.status, CompositeSystemStatus::EmergencyHalted);
        assert_eq!(verdict.down_count, 1);

        // Crucial Invariant: Exit of user funds is STILL ALLOWED!
        assert!(verdict.can_exit_funds);
        assert!(action_ok(&env, &cid, symbol_short!("exit")));
        assert!(action_ok(&env, &cid, symbol_short!("refund")));

        // New commitments gated
        assert!(!verdict.can_disburse_aid);
        assert!(!verdict.can_accept_deposits);
    }

    #[test]
    fn test_non_critical_degradation() {
        let (env, cid, _, reporter, _) = setup();

        // Medium criticality dependency degraded (indexer latency)
        rep_hb(
            &env,
            &cid,
            &reporter,
            symbol_short!("indexer"),
            ComponentHealth::Degraded,
            1_200,
        )
        .unwrap();

        let verdict = get_health(&env, &cid);
        assert_eq!(verdict.status, CompositeSystemStatus::Degraded);
        assert_eq!(verdict.degraded_count, 1);
        // Operations continue normally with warnings
        assert!(verdict.can_exit_funds);
        assert!(verdict.can_disburse_aid);
        assert!(verdict.can_accept_deposits);
    }

    #[test]
    fn test_retry_and_recovery_path() {
        let (env, cid, _, reporter, _) = setup();

        // Outage
        rep_hb(
            &env,
            &cid,
            &reporter,
            symbol_short!("oracle"),
            ComponentHealth::Down,
            9_999,
        )
        .unwrap();
        assert_eq!(
            get_health(&env, &cid).status,
            CompositeSystemStatus::EmergencyHalted
        );

        // Recovery heartbeat
        rep_hb(
            &env,
            &cid,
            &reporter,
            symbol_short!("oracle"),
            ComponentHealth::Healthy,
            120,
        )
        .unwrap();

        // System returns to Operational
        let recovered = get_health(&env, &cid);
        assert_eq!(recovered.status, CompositeSystemStatus::Operational);
        assert!(recovered.can_disburse_aid);
    }

    #[test]
    fn test_authorization_path_rejects_unprivileged() {
        let (env, cid, admin, _, unprivileged) = setup();

        // Unprivileged cannot report heartbeat
        let err1 = rep_hb(
            &env,
            &cid,
            &unprivileged,
            symbol_short!("oracle"),
            ComponentHealth::Down,
            100,
        )
        .unwrap_err();
        assert_eq!(err1, DependencyHealthError::Unauthorized);

        // Unprivileged cannot register dependency
        let err2 = reg_dep(
            &env,
            &cid,
            &unprivileged,
            symbol_short!("new_feed"),
            DependencyType::OraclePriceFeed,
            Criticality::Low,
        )
        .unwrap_err();
        assert_eq!(err2, DependencyHealthError::Unauthorized);

        // Unprivileged cannot register reporter
        let bot = Address::generate(&env);
        let err3 = reg_rep(&env, &cid, &unprivileged, &bot, true).unwrap_err();
        assert_eq!(err3, DependencyHealthError::Unauthorized);

        // Admin can register reporter
        reg_rep(&env, &cid, &admin, &bot, true).unwrap();
        assert!(chk_rep(&env, &cid, &bot));
    }
}
