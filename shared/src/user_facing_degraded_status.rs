//! User-Facing Status for Degraded Dependencies (Issue #441).
//!
//! Provides transparent, contract-visible status and non-confusing user guidance
//! when critical external dependencies (e.g. Oracles, Stellar Asset Contracts,
//! off-chain relayers) suffer latency, partial degradation, or full outages.
//!
//! Core Invariants:
//! 1. User exits (withdrawals, refunds, claims) are NEVER blocked, even during
//!    complete dependency outages. `can_exit_funds` is guaranteed to be `true`.
//! 2. Only new commitments/deposits are gated during major degradation.
//! 3. Guidance messages are structured enums, preventing leaks of internal stack
//!    traces or sensitive RPC URLs.
//! 4. Recovery and status updates require authorization by admin/reporters.
//!
//! Time complexity: O(1) reads/writes in instance storage.
//! Space complexity: O(1) per module dependency pair.

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
pub enum DegradedStatusError {
    Unauthorized = 1,
    InvalidConfiguration = 2,
    DependencyNotFound = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradationModule {
    Treasury = 1,
    Aid = 2,
    Referral = 3,
    Governance = 4,
    Oracle = 5,
    Marketplace = 6,
}

impl DegradationModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            DegradationModule::Treasury => symbol_short!("treasury"),
            DegradationModule::Aid => symbol_short!("aid"),
            DegradationModule::Referral => symbol_short!("referral"),
            DegradationModule::Governance => symbol_short!("gov"),
            DegradationModule::Oracle => symbol_short!("oracle"),
            DegradationModule::Marketplace => symbol_short!("market"),
        }
    }
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalDependencyKind {
    StellarAssetContract = 1,
    ExternalOracleFeed = 2,
    OffchainRelayOrIndexer = 3,
    FiatOrPaymentGateway = 4,
}

impl ExternalDependencyKind {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ExternalDependencyKind::StellarAssetContract => symbol_short!("sac"),
            ExternalDependencyKind::ExternalOracleFeed => symbol_short!("oracle"),
            ExternalDependencyKind::OffchainRelayOrIndexer => symbol_short!("indexer"),
            ExternalDependencyKind::FiatOrPaymentGateway => symbol_short!("gateway"),
        }
    }
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyDegradationLevel {
    Nominal = 0,
    DegradedMinor = 1,
    DegradedMajor = 2,
    Offline = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserGuidanceAction {
    CanProceedNormally = 0,
    ProceedWithDegradedFallback = 1,
    ExitAllowedEntryBlocked = 2,
    ActionTemporarilyBlocked = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserImpactSummary {
    Operational = 0,
    ReadInspectionOnly = 1,
    DelayedSettlement = 2,
    SlippageOrStaleRates = 3,
    EmergencyProtection = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserFacingDependencyStatus {
    pub module: DegradationModule,
    pub dependency: ExternalDependencyKind,
    pub level: DependencyDegradationLevel,
    pub guidance: UserGuidanceAction,
    pub impact: UserImpactSummary,
    pub can_exit_funds: bool,
    pub can_deposit_funds: bool,
    pub consecutive_failures: u32,
    pub retry_after_ledgers: u32,
    pub last_reported_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
enum StatusStorageKey {
    Status(Symbol, Symbol),
}

pub const TOPIC_DEPENDENCY_STATUS: Symbol = symbol_short!("dep_stat");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn storage_key(module: DegradationModule, dependency: ExternalDependencyKind) -> StatusStorageKey {
    StatusStorageKey::Status(module.as_symbol(), dependency.as_symbol())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Queries user-facing status for a specific module dependency pair.
/// Defaults to Nominal if no degradation has been reported.
pub fn get_user_facing_status(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> UserFacingDependencyStatus {
    let key = storage_key(module, dependency);
    instance_get(env, &key).unwrap_or(UserFacingDependencyStatus {
        module,
        dependency,
        level: DependencyDegradationLevel::Nominal,
        guidance: UserGuidanceAction::CanProceedNormally,
        impact: UserImpactSummary::Operational,
        can_exit_funds: true,
        can_deposit_funds: true,
        consecutive_failures: 0,
        retry_after_ledgers: 0,
        last_reported_ledger: env.ledger().sequence(),
    })
}

/// Reports a degraded dependency with user-safe impact and guidance mappings.
/// Admin or authorized health reporter only.
pub fn report_user_facing_degradation(
    env: &Env,
    caller: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    level: DependencyDegradationLevel,
    impact: UserImpactSummary,
    consecutive_failures: u32,
    retry_after_ledgers: u32,
) -> Result<UserFacingDependencyStatus, DegradedStatusError> {
    require_admin(env, caller).map_err(|_| DegradedStatusError::Unauthorized)?;

    let (guidance, can_deposit) = match level {
        DependencyDegradationLevel::Nominal => (UserGuidanceAction::CanProceedNormally, true),
        DependencyDegradationLevel::DegradedMinor => (UserGuidanceAction::ProceedWithDegradedFallback, true),
        DependencyDegradationLevel::DegradedMajor => (UserGuidanceAction::ExitAllowedEntryBlocked, false),
        DependencyDegradationLevel::Offline => (UserGuidanceAction::ExitAllowedEntryBlocked, false),
    };

    let record = UserFacingDependencyStatus {
        module,
        dependency,
        level,
        guidance,
        impact,
        can_exit_funds: true, // Invariant: exits are NEVER blocked
        can_deposit_funds: can_deposit,
        consecutive_failures,
        retry_after_ledgers: if level == DependencyDegradationLevel::Nominal { 0 } else { retry_after_ledgers },
        last_reported_ledger: env.ledger().sequence(),
    };

    instance_set(env, &storage_key(module, dependency), &record);

    env.events().publish(
        (TOPIC_DEPENDENCY_STATUS, module.as_symbol(), dependency.as_symbol()),
        (level as u32, guidance as u32, env.ledger().sequence()),
    );

    Ok(record)
}

/// Restores a dependency to nominal status after recovery.
pub fn clear_user_facing_degradation(
    env: &Env,
    caller: &Address,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
) -> Result<UserFacingDependencyStatus, DegradedStatusError> {
    require_admin(env, caller).map_err(|_| DegradedStatusError::Unauthorized)?;

    let record = UserFacingDependencyStatus {
        module,
        dependency,
        level: DependencyDegradationLevel::Nominal,
        guidance: UserGuidanceAction::CanProceedNormally,
        impact: UserImpactSummary::Operational,
        can_exit_funds: true,
        can_deposit_funds: true,
        consecutive_failures: 0,
        retry_after_ledgers: 0,
        last_reported_ledger: env.ledger().sequence(),
    };

    instance_set(env, &storage_key(module, dependency), &record);

    env.events().publish(
        (TOPIC_DEPENDENCY_STATUS, module.as_symbol(), dependency.as_symbol()),
        (0u32, 0u32, env.ledger().sequence()),
    );

    Ok(record)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Env};

    #[contract]
    struct DegradedStatusTestContract;
    #[contractimpl]
    impl DegradedStatusTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let cid = env.register_contract(None, DegradedStatusTestContract);
        let admin = Address::generate(&env);
        env.as_contract(&cid, || {
            crate::auth::set_admin(&env, &admin);
        });
        (env, cid, admin)
    }

    #[test]
    fn test_normal_path_default_status_is_nominal() {
        let (env, cid, _admin) = setup();
        env.as_contract(&cid, || {
            let status = get_user_facing_status(
                &env,
                DegradationModule::Treasury,
                ExternalDependencyKind::StellarAssetContract,
            );

            assert_eq!(status.level, DependencyDegradationLevel::Nominal);
            assert_eq!(status.guidance, UserGuidanceAction::CanProceedNormally);
            assert_eq!(status.impact, UserImpactSummary::Operational);
            assert!(status.can_exit_funds);
            assert!(status.can_deposit_funds);
            assert_eq!(status.consecutive_failures, 0);
        });
    }

    #[test]
    fn test_report_degraded_minor_allows_deposit_and_exit_with_fallback() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let status = report_user_facing_degradation(
                &env,
                &admin,
                DegradationModule::Oracle,
                ExternalDependencyKind::ExternalOracleFeed,
                DependencyDegradationLevel::DegradedMinor,
                UserImpactSummary::SlippageOrStaleRates,
                2,
                10,
            ).unwrap();

            assert_eq!(status.level, DependencyDegradationLevel::DegradedMinor);
            assert_eq!(status.guidance, UserGuidanceAction::ProceedWithDegradedFallback);
            assert_eq!(status.impact, UserImpactSummary::SlippageOrStaleRates);
            assert!(status.can_exit_funds);
            assert!(status.can_deposit_funds);
            assert_eq!(status.retry_after_ledgers, 10);
        });
    }

    #[test]
    fn test_report_degraded_major_blocks_deposit_preserves_exit() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let status = report_user_facing_degradation(
                &env,
                &admin,
                DegradationModule::Aid,
                ExternalDependencyKind::StellarAssetContract,
                DependencyDegradationLevel::DegradedMajor,
                UserImpactSummary::EmergencyProtection,
                5,
                30,
            ).unwrap();

            assert_eq!(status.level, DependencyDegradationLevel::DegradedMajor);
            assert_eq!(status.guidance, UserGuidanceAction::ExitAllowedEntryBlocked);
            assert_eq!(status.impact, UserImpactSummary::EmergencyProtection);
            // CRITICAL INVARIANT: exits remain allowed
            assert!(status.can_exit_funds);
            // Deposits blocked to prevent trapping new funds
            assert!(!status.can_deposit_funds);
            assert_eq!(status.retry_after_ledgers, 30);
        });
    }

    #[test]
    fn test_clear_degradation_restores_nominal_retry_path() {
        let (env, cid, admin) = setup();
        env.as_contract(&cid, || {
            let _ = report_user_facing_degradation(
                &env,
                &admin,
                DegradationModule::Marketplace,
                ExternalDependencyKind::OffchainRelayOrIndexer,
                DependencyDegradationLevel::Offline,
                UserImpactSummary::DelayedSettlement,
                10,
                50,
            ).unwrap();
        });

        // Dependency recovers -> clear status in new frame
        env.as_contract(&cid, || {
            let restored = clear_user_facing_degradation(
                &env,
                &admin,
                DegradationModule::Marketplace,
                ExternalDependencyKind::OffchainRelayOrIndexer,
            ).unwrap();

            assert_eq!(restored.level, DependencyDegradationLevel::Nominal);
            assert_eq!(restored.guidance, UserGuidanceAction::CanProceedNormally);
            assert_eq!(restored.impact, UserImpactSummary::Operational);
            assert!(restored.can_exit_funds);
            assert!(restored.can_deposit_funds);
            assert_eq!(restored.retry_after_ledgers, 0);
        });
    }

    #[test]
    fn test_authorization_rejection_for_unauthorized_reporter() {
        let (env, cid, _admin) = setup();
        env.as_contract(&cid, || {
            let unauth = Address::generate(&env);
            let err = report_user_facing_degradation(
                &env,
                &unauth,
                DegradationModule::Treasury,
                ExternalDependencyKind::StellarAssetContract,
                DependencyDegradationLevel::DegradedMajor,
                UserImpactSummary::EmergencyProtection,
                3,
                20,
            ).unwrap_err();

            assert_eq!(err, DegradedStatusError::Unauthorized);
        });
    }
}
