//! User-safe degraded mode for unavailable dependencies (Issue #265).
//!
//! `shared::degradation` derives a [`FallbackDecision`] for a
//! `(module, dependency)` pair, and `shared::health_guard` gates who may
//! report a dependency's health. Neither says what a contract entry point
//! should do with that decision, and `RejectOperation` blocks *every* call —
//! including a user withdrawing their own funds — so an outage, or a
//! misbehaving health reporter, could trap user funds.
//!
//! [`guard_operation`] closes that gap with one rule per [`OperationClass`],
//! evaluated **before** the entry point writes anything:
//!
//! | Class | Nominal | Fallback strategy keeps funds safe | Read-only / fail-safe / rejected |
//! |---|---|---|---|
//! | `Entry` (accepts new funds or commitments) | `Primary` | `Fallback(strategy)` | `Err(Error::DependencyDegraded)` |
//! | `Exit` (returns a user's own funds) | `Primary` | `Primary` | `Primary` |
//! | `Read` (inspection only) | `Primary` | `Fallback(strategy)` | `Fallback(ReadOnlyInspection)` |
//!
//! `ReadOnlyInspection` and `FailSafeRejection` are the strategies that block
//! entries; every other strategy is a documented safe fallback.
//!
//! Safety properties:
//!
//! 1. **No new exposure.** An `Entry` that needs an unavailable dependency is
//!    rejected before any storage write or token movement, so there is
//!    nothing to roll back and no partial state.
//! 2. **Exits are never blocked.** Soroban executes a transaction atomically:
//!    if an exit's token transfer fails because the dependency really is
//!    down, the whole invocation reverts and the user simply retries. The
//!    gate therefore never stands between a user and their own funds, and a
//!    compromised reporter can at most pause new entries.
//! 3. **Reads stay available**, flagged so clients can show stale data.
//!
//! The gate only reads storage (the matrix entry and the health record, O(1)
//! persistent reads); `Exit` reads nothing at all.
//!
//! ## Operational edge cases
//!
//! | Situation | Behavior |
//! |---|---|
//! | No health record for the dependency yet | Treated as nominal (existing `shared::degradation` policy); entries proceed. |
//! | Health record older than `max_staleness_ledgers` | Escalated to `DegradedMajor`, so entries switch to the fallback or are rejected even if the reporter went silent. |
//! | Failure recorded inside a call that then returns `Err` | Discarded: Soroban rolls back every write of a failed invocation. Report health from its own successful transaction via `shared::health_guard::report_health_check`. |
//! | Unregistered caller tries to report a failure | `Error::Unauthorized` from `health_guard`; the gate's inputs are unchanged. |
//! | Entry rejected while degraded | Stateless: nothing is queued or reserved, so retrying after recovery needs no cleanup. |
//!
//! ## Recovery / rollback
//!
//! 1. **Automatic:** once `recovery_success_threshold` consecutive healthy
//!    reports land (default 3), the matrix entry returns to `Nominal` and
//!    entries take the primary path again.
//! 2. **Manual:** an admin calls `shared::degradation::recover_dependency`
//!    after confirming the dependency is healthy.
//! 3. **Reporter compromised:** `shared::health_guard::revoke_reporter`, then
//!    step 2. Exits were never blocked, so no user funds need recovery.
//!
//! ## Compatibility
//!
//! Purely additive: no storage keys of its own and no change to
//! `shared::degradation` or `shared::health_guard`.

use soroban_sdk::{contracttype, Env};

use crate::degradation::{
    evaluate_dependency_decision, DegradationModule, ExternalDependencyKind, FallbackDecision,
    FallbackStrategy,
};
use crate::errors::Error;

/// How an entry point affects user funds, which decides how it degrades.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationClass {
    /// Inspection only; never mutates balances.
    Read,
    /// Returns funds the user already owns (claim, refund, withdrawal).
    Exit,
    /// Accepts new funds or commitments (deposit, create, purchase).
    Entry,
}

/// Path an entry point may take after [`guard_operation`] admits it.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedAccess {
    /// Dependency is nominal (or the operation is an exit): use the live path.
    Primary,
    /// Use this safe fallback behavior instead of the live path.
    Fallback(FallbackStrategy),
}

/// `true` for strategies under which no new funds may be accepted.
fn blocks_entry(strategy: FallbackStrategy) -> bool {
    matches!(
        strategy,
        FallbackStrategy::ReadOnlyInspection | FallbackStrategy::FailSafeRejection
    )
}

/// Decides how an operation of `class` proceeds while `dependency` may be
/// degraded. Call it first in the entry point, before any write.
///
/// # Errors
/// * [`Error::DependencyDegraded`] - an `Entry` while the dependency's
///   fallback is read-only, fail-safe rejection, or the dependency is down.
pub fn guard_operation(
    env: &Env,
    module: DegradationModule,
    dependency: ExternalDependencyKind,
    class: OperationClass,
) -> Result<DegradedAccess, Error> {
    if class == OperationClass::Exit {
        return Ok(DegradedAccess::Primary);
    }
    let strategy = match evaluate_dependency_decision(env, module, dependency) {
        FallbackDecision::ProceedPrimary => return Ok(DegradedAccess::Primary),
        FallbackDecision::ProceedFallback(strategy) => strategy,
        FallbackDecision::RejectOperation(_) => FallbackStrategy::FailSafeRejection,
    };
    match (class, blocks_entry(strategy)) {
        (OperationClass::Entry, true) => Err(Error::DependencyDegraded),
        (OperationClass::Read, true) => Ok(DegradedAccess::Fallback(
            FallbackStrategy::ReadOnlyInspection,
        )),
        _ => Ok(DegradedAccess::Fallback(strategy)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use crate::degradation::{record_dependency_check, DegradationLevel};
    use crate::health_guard::{register_reporter, report_health_check};
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{contract, contractimpl, symbol_short, Address};

    const MODULE: DegradationModule = DegradationModule::Treasury;
    const DEP: ExternalDependencyKind = ExternalDependencyKind::StellarAssetContract;

    /// Minimal vault whose entry points are invoked through the generated
    /// client, so rejected calls get real host rollback semantics.
    #[contract]
    struct Vault;

    #[contractimpl]
    impl Vault {
        pub fn init(env: Env, admin: Address) {
            initialize_admin(&env, &admin).unwrap();
        }

        pub fn add_reporter(env: Env, admin: Address, reporter: Address) -> Result<(), Error> {
            register_reporter(&env, &admin, &reporter)
        }

        pub fn report(env: Env, reporter: Address, ok: bool) -> Result<DegradationLevel, Error> {
            report_health_check(&env, &reporter, MODULE, DEP, ok, 0)
        }

        /// Records a failure, then fails: the record must not survive.
        pub fn failing_call(env: Env) -> Result<(), Error> {
            record_dependency_check(&env, MODULE, DEP, false, 1);
            Err(Error::DependencyDegraded)
        }

        pub fn deposit(env: Env, amount: i128) -> Result<DegradedAccess, Error> {
            let access = guard_operation(&env, MODULE, DEP, OperationClass::Entry)?;
            Self::adjust(&env, amount);
            Ok(access)
        }

        pub fn withdraw(env: Env, amount: i128) -> Result<DegradedAccess, Error> {
            let access = guard_operation(&env, MODULE, DEP, OperationClass::Exit)?;
            Self::adjust(&env, -amount);
            Ok(access)
        }

        pub fn quote(env: Env) -> Result<DegradedAccess, Error> {
            guard_operation(&env, MODULE, DEP, OperationClass::Read)
        }

        pub fn total(env: Env) -> i128 {
            env.storage().instance().get(&symbol_short!("total")).unwrap_or(0)
        }
    }

    impl Vault {
        fn adjust(env: &Env, delta: i128) {
            let total = Self::total(env.clone()) + delta;
            env.storage().instance().set(&symbol_short!("total"), &total);
        }
    }

    fn setup() -> (Env, VaultClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let client = VaultClient::new(&env, &env.register_contract(None, Vault));
        let admin = Address::generate(&env);
        let reporter = Address::generate(&env);
        client.init(&admin);
        client.add_reporter(&admin, &reporter);
        (env, client, admin, reporter)
    }

    #[test]
    fn nominal_dependency_takes_primary_path() {
        let (_env, client, _, _) = setup();
        assert_eq!(client.deposit(&100), DegradedAccess::Primary);
        assert_eq!(client.withdraw(&40), DegradedAccess::Primary);
        assert_eq!(client.quote(), DegradedAccess::Primary);
        assert_eq!(client.total(), 60);
    }

    #[test]
    fn degraded_dependency_blocks_entries_but_not_exits_or_reads() {
        let (_env, client, _, reporter) = setup();
        client.deposit(&100);
        client.report(&reporter, &false);

        assert_eq!(
            client.try_deposit(&50),
            Err(Ok(Error::DependencyDegraded))
        );
        assert_eq!(client.total(), 100);

        assert_eq!(client.withdraw(&30), DegradedAccess::Primary);
        assert_eq!(client.total(), 70);
        assert_eq!(
            client.quote(),
            DegradedAccess::Fallback(FallbackStrategy::ReadOnlyInspection)
        );
    }

    #[test]
    fn critical_failure_still_lets_users_exit() {
        let (_env, client, _, reporter) = setup();
        client.deposit(&100);
        for _ in 0..4 {
            client.report(&reporter, &false);
        }
        assert_eq!(
            client.try_deposit(&1),
            Err(Ok(Error::DependencyDegraded))
        );
        assert_eq!(client.withdraw(&100), DegradedAccess::Primary);
        assert_eq!(client.total(), 0);
    }

    #[test]
    fn safe_fallback_strategy_admits_entries_on_the_fallback_path() {
        let env = Env::default();
        let contract = env.register_contract(None, Vault);
        env.as_contract(&contract, || {
            let (module, dep) = (DegradationModule::Aid, ExternalDependencyKind::PaymentGateway);
            record_dependency_check(&env, module, dep, false, 1);
            let expected = DegradedAccess::Fallback(FallbackStrategy::EscrowHoldWithRefundGuarantee);
            assert_eq!(guard_operation(&env, module, dep, OperationClass::Entry), Ok(expected));
            assert_eq!(guard_operation(&env, module, dep, OperationClass::Read), Ok(expected));
        });
    }

    #[test]
    fn entries_retry_successfully_after_recovery_threshold() {
        let (_env, client, _, reporter) = setup();
        // Two failures reach the failure threshold: the matrix holds DegradedMajor.
        client.report(&reporter, &false);
        client.report(&reporter, &false);
        assert!(client.try_deposit(&10).is_err());

        // Below the recovery streak the entry is still refused.
        client.report(&reporter, &true);
        client.report(&reporter, &true);
        assert_eq!(
            client.try_deposit(&10),
            Err(Ok(Error::DependencyDegraded))
        );

        client.report(&reporter, &true);
        assert_eq!(client.deposit(&10), DegradedAccess::Primary);
        assert_eq!(client.total(), 10);
    }

    #[test]
    fn stale_health_record_degrades_entries() {
        let (env, client, _, reporter) = setup();
        client.report(&reporter, &true);
        env.ledger().with_mut(|l| l.sequence_number += 51);
        assert_eq!(
            client.try_deposit(&10),
            Err(Ok(Error::DependencyDegraded))
        );
    }

    #[test]
    fn only_registered_authenticated_reporters_can_degrade() {
        let (env, client, _, reporter) = setup();
        let intruder = Address::generate(&env);
        assert_eq!(
            client.try_report(&intruder, &false),
            Err(Ok(Error::Unauthorized))
        );

        // A registered reporter must still sign.
        env.set_auths(&[]);
        assert!(client.try_report(&reporter, &false).is_err());

        env.mock_all_auths();
        assert_eq!(client.deposit(&5), DegradedAccess::Primary);
    }

    #[test]
    fn failures_recorded_in_a_reverted_call_are_discarded() {
        let (_env, client, _, _) = setup();
        assert_eq!(
            client.try_failing_call(),
            Err(Ok(Error::DependencyDegraded))
        );
        assert_eq!(client.deposit(&5), DegradedAccess::Primary);
    }
}
