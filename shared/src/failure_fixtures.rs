//! Deterministic fixture generators for rare failure and recovery paths (Issue #285).
//!
//! Rare production failures — partial batch commits, orphaned lock expiries,
//! stale replica reads, concurrent nonce races, downstream rejections requiring
//! rollback, and mid-retry quota exhaustion — are difficult to reproduce reliably
//! in ad-hoc tests.
//!
//! This module provides a seeded, deterministic fixture generator built on
//! [`crate::chaos::DeterministicPrng`] and persisted recovery state so every
//! contract test or operator drill can:
//! 1. Deterministically generate a [`FailureFixture`] from `(seed, scenario)`.
//! 2. Inject the failure at a reproducible step (`inject_failure`).
//! 3. Exercise bounded, idempotent retries (`retry_fixture`).
//! 4. Roll back partial side effects when recovery cannot proceed (`rollback_fixture`).
//! 5. Enforce admin authorization on all mutating fixture lifecycle transitions.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

use crate::auth::require_admin;
use crate::chaos::DeterministicPrng;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_has, persistent_set};

/// Maximum number of steps a generated fixture may span.
pub const MAX_FIXTURE_STEPS: u32 = 32;

/// Maximum retry budget assigned to any generated fixture.
pub const MAX_FIXTURE_RETRY_BUDGET: u32 = 5;

/// Rare failure scenarios modeled by the fixture generator.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RareFailureScenario {
    /// A batch operation commits a subset of items before failing mid-flight.
    PartialBatchCommit,
    /// A temporary lock or reservation expires after an external side effect.
    OrphanedLockExpiry,
    /// A read replica lags behind canonical state during a retry attempt.
    StaleReplicaRead,
    /// Two actors race on the same nonce or idempotency key.
    ConcurrentNonceRace,
    /// A downstream contract rejects after local state mutation, requiring rollback.
    RollbackAfterDownstreamReject,
    /// Retry or rate quota is exhausted mid-recovery.
    QuotaExhaustionMidRetry,
}

impl RareFailureScenario {
    /// Short canonical symbol identifying the scenario.
    pub fn as_symbol(self) -> Symbol {
        match self {
            RareFailureScenario::PartialBatchCommit => symbol_short!("part_bat"),
            RareFailureScenario::OrphanedLockExpiry => symbol_short!("orph_lck"),
            RareFailureScenario::StaleReplicaRead => symbol_short!("stale_rd"),
            RareFailureScenario::ConcurrentNonceRace => symbol_short!("nonce_rc"),
            RareFailureScenario::RollbackAfterDownstreamReject => symbol_short!("rb_down"),
            RareFailureScenario::QuotaExhaustionMidRetry => symbol_short!("qta_exh"),
        }
    }

    /// Default error code associated with this rare failure scenario.
    pub fn default_error_code(self) -> u32 {
        match self {
            RareFailureScenario::PartialBatchCommit => Error::DependencyDegraded as u32,
            RareFailureScenario::OrphanedLockExpiry => Error::Expired as u32,
            RareFailureScenario::StaleReplicaRead => Error::StaleData as u32,
            RareFailureScenario::ConcurrentNonceRace => Error::AlreadyClaimed as u32,
            RareFailureScenario::RollbackAfterDownstreamReject => Error::InvalidArgument as u32,
            RareFailureScenario::QuotaExhaustionMidRetry => Error::QuotaExceeded as u32,
        }
    }

    /// Whether this scenario requires explicit rollback when recovery fails.
    pub fn default_requires_rollback(self) -> bool {
        matches!(
            self,
            RareFailureScenario::PartialBatchCommit
                | RareFailureScenario::OrphanedLockExpiry
                | RareFailureScenario::RollbackAfterDownstreamReject
        )
    }
}

/// Lifecycle state of a generated failure/recovery fixture.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureState {
    Generated,
    Injected,
    Retried,
    Recovered,
    RolledBack,
    Abandoned,
}

/// Deterministic fixture describing a rare failure and its recovery path.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureFixture {
    pub fixture_id: u64,
    pub seed: u64,
    pub scenario: RareFailureScenario,
    pub actor: Address,
    pub total_steps: u32,
    pub failing_step: u32,
    pub retry_budget: u32,
    pub retries_used: u32,
    pub expected_error_code: u32,
    pub requires_rollback: bool,
    pub state: FixtureState,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureFixtureKey {
    Fixture(u64),
}

/// Pure deterministic fixture builder (no storage side effects).
pub fn build_fixture(
    env: &Env,
    fixture_id: u64,
    seed: u64,
    scenario: RareFailureScenario,
    actor: Address,
) -> Result<FailureFixture, Error> {
    if fixture_id == 0 || seed == 0 {
        return Err(Error::InvalidArgument);
    }
    let mut prng = DeterministicPrng::new(seed ^ fixture_id);
    let total_steps = prng.next_range(3, MAX_FIXTURE_STEPS);
    let failing_step = prng.next_range(1, total_steps - 1);
    let retry_budget = if scenario == RareFailureScenario::QuotaExhaustionMidRetry {
        1
    } else {
        prng.next_range(1, MAX_FIXTURE_RETRY_BUDGET)
    };

    Ok(FailureFixture {
        fixture_id,
        seed,
        scenario,
        actor,
        total_steps,
        failing_step,
        retry_budget,
        retries_used: 0,
        expected_error_code: scenario.default_error_code(),
        requires_rollback: scenario.default_requires_rollback(),
        state: FixtureState::Generated,
        created_at: env.ledger().timestamp(),
    })
}

/// Generate and persist a rare failure fixture (admin-authorized).
pub fn generate_fixture(
    env: &Env,
    caller: &Address,
    fixture_id: u64,
    seed: u64,
    scenario: RareFailureScenario,
    actor: Address,
) -> Result<FailureFixture, Error> {
    require_admin(env, caller)?;
    let key = FailureFixtureKey::Fixture(fixture_id);
    if persistent_has(env, &key) {
        return Err(Error::AlreadyClaimed);
    }
    let fixture = build_fixture(env, fixture_id, seed, scenario, actor)?;
    persistent_set(env, &key, &fixture);
    Ok(fixture)
}

/// Read-only lookup for a persisted fixture.
pub fn get_fixture(env: &Env, fixture_id: u64) -> Option<FailureFixture> {
    persistent_get(env, &FailureFixtureKey::Fixture(fixture_id))
}

/// Inject the configured rare failure into the fixture lifecycle (admin-authorized).
pub fn inject_failure(
    env: &Env,
    caller: &Address,
    fixture_id: u64,
) -> Result<FailureFixture, Error> {
    require_admin(env, caller)?;
    let key = FailureFixtureKey::Fixture(fixture_id);
    let mut fixture: FailureFixture = persistent_get(env, &key).ok_or(Error::NotFound)?;
    if fixture.state != FixtureState::Generated {
        return Err(Error::InvalidArgument);
    }
    fixture.state = FixtureState::Injected;
    persistent_set(env, &key, &fixture);
    Ok(fixture)
}

/// Attempt recovery by retrying the failed fixture within its retry budget.
///
/// - When `succeeds` is `true` and `retries_used < retry_budget`, transitions to `Recovered`.
/// - When `succeeds` is `false` and budget remains, increments `retries_used` and moves to `Retried`.
/// - When `retries_used >= retry_budget`, transitions to `Abandoned` and returns `Error::QuotaExceeded`.
/// - Calling `retry_fixture` on an already `Recovered` fixture is idempotent and returns `Ok(fixture)`.
pub fn retry_fixture(
    env: &Env,
    caller: &Address,
    fixture_id: u64,
    succeeds: bool,
) -> Result<FailureFixture, Error> {
    require_admin(env, caller)?;
    let key = FailureFixtureKey::Fixture(fixture_id);
    let mut fixture: FailureFixture = persistent_get(env, &key).ok_or(Error::NotFound)?;

    match fixture.state {
        FixtureState::Recovered => return Ok(fixture),
        FixtureState::RolledBack | FixtureState::Abandoned | FixtureState::Generated => {
            return Err(Error::InvalidArgument);
        }
        FixtureState::Injected | FixtureState::Retried => {}
    }

    if fixture.retries_used >= fixture.retry_budget {
        fixture.state = FixtureState::Abandoned;
        persistent_set(env, &key, &fixture);
        return Err(Error::QuotaExceeded);
    }

    fixture.retries_used += 1;
    if succeeds {
        fixture.state = FixtureState::Recovered;
    } else if fixture.retries_used >= fixture.retry_budget {
        fixture.state = FixtureState::Abandoned;
        persistent_set(env, &key, &fixture);
        return Err(Error::QuotaExceeded);
    } else {
        fixture.state = FixtureState::Retried;
    }

    persistent_set(env, &key, &fixture);
    Ok(fixture)
}

/// Roll back a fixture that failed and cannot recover (admin-authorized).
pub fn rollback_fixture(
    env: &Env,
    caller: &Address,
    fixture_id: u64,
) -> Result<FailureFixture, Error> {
    require_admin(env, caller)?;
    let key = FailureFixtureKey::Fixture(fixture_id);
    let mut fixture: FailureFixture = persistent_get(env, &key).ok_or(Error::NotFound)?;

    if !fixture.requires_rollback {
        return Err(Error::InvalidArgument);
    }

    match fixture.state {
        FixtureState::RolledBack => return Ok(fixture),
        FixtureState::Injected | FixtureState::Retried | FixtureState::Abandoned => {
            fixture.state = FixtureState::RolledBack;
            persistent_set(env, &key, &fixture);
            Ok(fixture)
        }
        FixtureState::Generated | FixtureState::Recovered => Err(Error::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct MockContract;

    #[contractimpl]
    impl MockContract {
        pub fn ping() -> u32 {
            1
        }
    }

    #[test]
    fn deterministic_generation_is_reproducible() {
        let env = Env::default();
        env.ledger().set_timestamp(10_000);
        let actor = Address::generate(&env);

        let a = build_fixture(
            &env,
            1,
            0xDEAD_BEEF,
            RareFailureScenario::PartialBatchCommit,
            actor.clone(),
        )
        .unwrap();
        let b = build_fixture(
            &env,
            1,
            0xDEAD_BEEF,
            RareFailureScenario::PartialBatchCommit,
            actor,
        )
        .unwrap();
        assert_eq!(a, b);
        assert!(a.failing_step >= 1 && a.failing_step < a.total_steps);
        assert!(a.requires_rollback);
    }

    #[test]
    fn normal_inject_retry_and_idempotent_recovery_path() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let actor = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            let created = generate_fixture(
                &env,
                &admin,
                10,
                42,
                RareFailureScenario::StaleReplicaRead,
                actor,
            )
            .unwrap();
            assert_eq!(created.state, FixtureState::Generated);

            let injected = inject_failure(&env, &admin, 10).unwrap();
            assert_eq!(injected.state, FixtureState::Injected);

            let recovered = retry_fixture(&env, &admin, 10, true).unwrap();
            assert_eq!(recovered.state, FixtureState::Recovered);
            assert_eq!(recovered.retries_used, 1);

            // Idempotent retry on already-recovered fixture returns same state without incrementing.
            let retry_again = retry_fixture(&env, &admin, 10, true).unwrap();
            assert_eq!(retry_again, recovered);
        });
    }

    #[test]
    fn failure_retry_exhaustion_and_rollback_path() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let actor = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            // Invalid zero seed/id rejected.
            assert_eq!(
                generate_fixture(
                    &env,
                    &admin,
                    0,
                    99,
                    RareFailureScenario::PartialBatchCommit,
                    actor.clone(),
                ),
                Err(Error::InvalidArgument)
            );

            let f = generate_fixture(
                &env,
                &admin,
                20,
                99,
                RareFailureScenario::QuotaExhaustionMidRetry,
                actor,
            )
            .unwrap();
            assert_eq!(f.retry_budget, 1);
            inject_failure(&env, &admin, 20).unwrap();

            // Failing retry exhausts budget -> QuotaExceeded and Abandoned.
            assert_eq!(
                retry_fixture(&env, &admin, 20, false),
                Err(Error::QuotaExceeded)
            );
            let persisted = get_fixture(&env, 20).unwrap();
            assert_eq!(persisted.state, FixtureState::Abandoned);
        });
    }

    #[test]
    fn rollback_after_downstream_reject_and_authorization_checks() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let non_admin = Address::generate(&env);
        let actor = Address::generate(&env);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            // Unauthorized caller cannot generate.
            assert_eq!(
                generate_fixture(
                    &env,
                    &non_admin,
                    30,
                    777,
                    RareFailureScenario::RollbackAfterDownstreamReject,
                    actor.clone(),
                ),
                Err(Error::Unauthorized)
            );

            generate_fixture(
                &env,
                &admin,
                30,
                777,
                RareFailureScenario::RollbackAfterDownstreamReject,
                actor,
            )
            .unwrap();

            // Non-admin cannot inject or rollback.
            assert_eq!(
                inject_failure(&env, &non_admin, 30),
                Err(Error::Unauthorized)
            );
            inject_failure(&env, &admin, 30).unwrap();
            assert_eq!(
                rollback_fixture(&env, &non_admin, 30),
                Err(Error::Unauthorized)
            );

            let rolled = rollback_fixture(&env, &admin, 30).unwrap();
            assert_eq!(rolled.state, FixtureState::RolledBack);

            // Idempotent rollback returns Ok(rolled); retry after rollback is rejected.
            assert_eq!(rollback_fixture(&env, &admin, 30), Ok(rolled));
            assert_eq!(
                retry_fixture(&env, &admin, 30, true),
                Err(Error::InvalidArgument)
            );
        });
    }
}
