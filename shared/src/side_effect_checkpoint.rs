//! Recovery checkpoints around every external side effect (Issue #275).
//!
//! Guards each individual external side effect (token transfer, cross-contract
//! call, webhook dispatch, oracle publish, settlement payout) with a persisted
//! pre-effect / post-effect checkpoint so interrupted or retried invocations
//! resume safely without duplicating already-committed external side effects.

use soroban_sdk::{
    contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

/// Default maximum retry attempts permitted for a single external side effect.
pub const DEFAULT_MAX_EFFECT_RETRIES: u32 = 5;

/// Classification of the external side effect being checkpointed.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SideEffectKind {
    /// External token transfer (`token::Client::transfer`).
    TokenTransfer = 1,
    /// Synchronous cross-contract invocation.
    CrossContractCall = 2,
    /// Outbound webhook notification dispatch.
    WebhookDispatch = 3,
    /// External oracle feed publication.
    OraclePublish = 4,
    /// Settlement or escrow payout to an external recipient.
    SettlementPayout = 5,
}

/// Execution state of a checkpointed external side effect.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SideEffectState {
    /// Pre-effect checkpoint written; external call may be in flight.
    Prepared = 1,
    /// External side effect succeeded; subsequent retries must short-circuit.
    Committed = 2,
    /// External side effect failed with `last_error`; eligible for retry or rollback.
    Failed = 3,
    /// Compensated/rolled back by an administrator; terminal state.
    RolledBack = 4,
}

/// Outcome returned by [`begin_side_effect`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginEffectOutcome {
    /// First attempt; caller should execute the external side effect then call
    /// [`commit_side_effect`] or [`fail_side_effect`].
    Execute(SideEffectCheckpoint),
    /// Retry after a prior failure or interrupted `Prepared` state; caller
    /// should execute the external side effect.
    Retry(SideEffectCheckpoint),
    /// Side effect was already `Committed`; caller MUST NOT re-execute it.
    AlreadyCommitted(SideEffectCheckpoint),
}

/// Persisted checkpoint guarding one external side effect.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SideEffectCheckpoint {
    /// Deterministic identifier derived from `(op_id, step_index, kind, target, payload_hash)`.
    pub effect_id: BytesN<32>,
    /// Parent operation correlation identifier.
    pub op_id: Symbol,
    /// Step index within the parent operation.
    pub step_index: u32,
    /// Actor authorized to drive this side effect.
    pub actor: Address,
    /// Kind of external side effect.
    pub kind: SideEffectKind,
    /// External target contract or recipient address.
    pub target: Address,
    /// Digest of the external call parameters.
    pub payload_hash: BytesN<32>,
    /// Current checkpoint state.
    pub state: SideEffectState,
    /// Number of execution attempts started.
    pub attempts: u32,
    /// Last error code recorded via [`fail_side_effect`] (0 when none).
    pub last_error: u32,
    /// Ledger timestamp when first prepared.
    pub prepared_at: u64,
    /// Ledger timestamp of the latest state transition.
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EffectKey {
    ById(BytesN<32>),
}

/// Derives a deterministic `effect_id` using canonical Soroban XDR encoding.
pub fn derive_effect_id(
    env: &Env,
    op_id: &Symbol,
    step_index: u32,
    kind: SideEffectKind,
    target: &Address,
    payload_hash: &BytesN<32>,
) -> BytesN<32> {
    let payload = (
        symbol_short!("fx_chk"),
        env.current_contract_address(),
        op_id.clone(),
        step_index,
        kind,
        target.clone(),
        payload_hash.clone(),
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).into()
}

/// Loads a side-effect checkpoint by `effect_id`, if present.
pub fn get_side_effect_checkpoint(
    env: &Env,
    effect_id: &BytesN<32>,
) -> Option<SideEffectCheckpoint> {
    persistent_get(env, &EffectKey::ById(effect_id.clone()))
}

/// Acquires or resumes a recovery checkpoint before executing an external side
/// effect.
///
/// - If no checkpoint exists, creates one in [`SideEffectState::Prepared`] and
///   returns [`BeginEffectOutcome::Execute`].
/// - If the checkpoint is [`SideEffectState::Committed`], returns
///   [`BeginEffectOutcome::AlreadyCommitted`] so the caller skips duplicate
///   execution.
/// - If the checkpoint is [`SideEffectState::Failed`] or interrupted
///   [`SideEffectState::Prepared`], increments `attempts` (up to
///   `DEFAULT_MAX_EFFECT_RETRIES`) and returns [`BeginEffectOutcome::Retry`].
/// - If [`SideEffectState::RolledBack`], returns `Err(Error::AlreadyExecuted)`.
#[allow(clippy::too_many_arguments)]
pub fn begin_side_effect(
    env: &Env,
    actor: &Address,
    op_id: Symbol,
    step_index: u32,
    kind: SideEffectKind,
    target: &Address,
    payload_hash: BytesN<32>,
) -> Result<BeginEffectOutcome, Error> {
    actor.require_auth();

    let effect_id = derive_effect_id(env, &op_id, step_index, kind, target, &payload_hash);
    let now = env.ledger().timestamp();

    if let Some(mut existing) = get_side_effect_checkpoint(env, &effect_id) {
        if existing.actor != *actor {
            return Err(Error::Unauthorized);
        }
        return match existing.state {
            SideEffectState::Committed => Ok(BeginEffectOutcome::AlreadyCommitted(existing)),
            SideEffectState::RolledBack => Err(Error::AlreadyExecuted),
            SideEffectState::Prepared | SideEffectState::Failed => {
                if existing.attempts >= DEFAULT_MAX_EFFECT_RETRIES {
                    return Err(Error::QuotaExceeded);
                }
                existing.attempts = existing.attempts.saturating_add(1);
                existing.state = SideEffectState::Prepared;
                existing.updated_at = now;
                persistent_set(env, &EffectKey::ById(effect_id.clone()), &existing);
                env.events().publish(
                    (symbol_short!("fx_chk"), symbol_short!("retry")),
                    (effect_id, existing.attempts),
                );
                Ok(BeginEffectOutcome::Retry(existing))
            }
        };
    }

    let checkpoint = SideEffectCheckpoint {
        effect_id: effect_id.clone(),
        op_id,
        step_index,
        actor: actor.clone(),
        kind,
        target: target.clone(),
        payload_hash,
        state: SideEffectState::Prepared,
        attempts: 1,
        last_error: 0,
        prepared_at: now,
        updated_at: now,
    };

    persistent_set(env, &EffectKey::ById(effect_id.clone()), &checkpoint);
    env.events().publish(
        (symbol_short!("fx_chk"), symbol_short!("begin")),
        (effect_id, kind),
    );

    Ok(BeginEffectOutcome::Execute(checkpoint))
}

/// Marks a `Prepared` (or `Failed`) side effect as [`SideEffectState::Committed`]
/// after the external call succeeds. Idempotent if already `Committed`.
pub fn commit_side_effect(
    env: &Env,
    actor: &Address,
    effect_id: &BytesN<32>,
) -> Result<SideEffectCheckpoint, Error> {
    actor.require_auth();

    let mut checkpoint = get_side_effect_checkpoint(env, effect_id).ok_or(Error::NotFound)?;
    if checkpoint.actor != *actor {
        return Err(Error::Unauthorized);
    }

    match checkpoint.state {
        SideEffectState::Committed => return Ok(checkpoint),
        SideEffectState::RolledBack => return Err(Error::AlreadyExecuted),
        SideEffectState::Prepared | SideEffectState::Failed => {}
    }

    checkpoint.state = SideEffectState::Committed;
    checkpoint.last_error = 0;
    checkpoint.updated_at = env.ledger().timestamp();

    persistent_set(env, &EffectKey::ById(effect_id.clone()), &checkpoint);
    env.events().publish(
        (symbol_short!("fx_chk"), symbol_short!("commit")),
        (effect_id.clone(), checkpoint.attempts),
    );

    Ok(checkpoint)
}

/// Records an external call failure on a `Prepared` checkpoint so it can be
/// retried or rolled back.
pub fn fail_side_effect(
    env: &Env,
    actor: &Address,
    effect_id: &BytesN<32>,
    error_code: u32,
) -> Result<SideEffectCheckpoint, Error> {
    actor.require_auth();
    if error_code == 0 {
        return Err(Error::InvalidArgument);
    }

    let mut checkpoint = get_side_effect_checkpoint(env, effect_id).ok_or(Error::NotFound)?;
    if checkpoint.actor != *actor {
        return Err(Error::Unauthorized);
    }
    if checkpoint.state == SideEffectState::Committed
        || checkpoint.state == SideEffectState::RolledBack
    {
        return Err(Error::AlreadyExecuted);
    }

    checkpoint.state = SideEffectState::Failed;
    checkpoint.last_error = error_code;
    checkpoint.updated_at = env.ledger().timestamp();

    persistent_set(env, &EffectKey::ById(effect_id.clone()), &checkpoint);
    env.events().publish(
        (symbol_short!("fx_chk"), symbol_short!("fail")),
        (effect_id.clone(), error_code),
    );

    Ok(checkpoint)
}

/// Admin-gated compensation/rollback marker for a `Prepared` or `Failed`
/// side effect, preventing any future retry of that `effect_id`.
pub fn rollback_side_effect(
    env: &Env,
    admin: &Address,
    effect_id: &BytesN<32>,
    reason: Symbol,
) -> Result<SideEffectCheckpoint, Error> {
    require_admin(env, admin)?;

    let mut checkpoint = get_side_effect_checkpoint(env, effect_id).ok_or(Error::NotFound)?;
    if checkpoint.state == SideEffectState::Committed {
        return Err(Error::AlreadyExecuted);
    }
    if checkpoint.state == SideEffectState::RolledBack {
        return Ok(checkpoint);
    }

    checkpoint.state = SideEffectState::RolledBack;
    checkpoint.updated_at = env.ledger().timestamp();

    persistent_set(env, &EffectKey::ById(effect_id.clone()), &checkpoint);
    env.events().publish(
        (symbol_short!("fx_chk"), symbol_short!("rollback")),
        (effect_id.clone(), reason),
    );

    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Bytes, Env,
    };

    #[contract]
    struct SideEffectTestContract;

    #[contractimpl]
    impl SideEffectTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SideEffectTestContract);
        let admin = Address::generate(&env);
        let actor = Address::generate(&env);
        let target = Address::generate(&env);
        env.ledger().set_timestamp(2_000);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });
        (env, contract_id, admin, actor, target)
    }

    #[test]
    fn test_normal_commit_and_idempotent_retry_guard() {
        let (env, contract_id, _admin, actor, target) = setup();
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"pay_100")).into();

        env.as_contract(&contract_id, || {
            let outcome = begin_side_effect(
                &env,
                &actor,
                symbol_short!("payout"),
                0,
                SideEffectKind::TokenTransfer,
                &target,
                payload_hash.clone(),
            )
            .unwrap();
            let cp = match outcome {
                BeginEffectOutcome::Execute(cp) => cp,
                _ => panic!("expected Execute"),
            };
            assert_eq!(cp.state, SideEffectState::Prepared);

            let committed = commit_side_effect(&env, &actor, &cp.effect_id).unwrap();
            assert_eq!(committed.state, SideEffectState::Committed);

            // Retry after commit MUST return AlreadyCommitted without re-executing
            let retry_outcome = begin_side_effect(
                &env,
                &actor,
                symbol_short!("payout"),
                0,
                SideEffectKind::TokenTransfer,
                &target,
                payload_hash,
            )
            .unwrap();
            assert_eq!(retry_outcome, BeginEffectOutcome::AlreadyCommitted(committed));
        });
    }

    #[test]
    fn test_interrupted_prepared_checkpoint_resumes_with_same_id_and_skips_committed_effect() {
        let (env, contract_id, _admin, actor, target) = setup();
        let payload_hash: BytesN<32> =
            env.crypto().sha256(&Bytes::from_slice(&env, b"recovery_payout")).into();

        // The first invocation persists Prepared and is interrupted before the
        // external effect runs.
        let prepared = env.as_contract(&contract_id, || {
            match begin_side_effect(
                &env,
                &actor,
                symbol_short!("recover"),
                2,
                SideEffectKind::SettlementPayout,
                &target,
                payload_hash.clone(),
            )
            .unwrap()
            {
                BeginEffectOutcome::Execute(cp) => cp,
                _ => panic!("expected first attempt to execute"),
            }
        });
        assert_eq!(prepared.state, SideEffectState::Prepared);
        assert_eq!(prepared.attempts, 1);

        // A later invocation uses the exact same effect identity and safely
        // resumes the interrupted Prepared checkpoint.
        let resumed = env.as_contract(&contract_id, || {
            match begin_side_effect(
                &env,
                &actor,
                symbol_short!("recover"),
                2,
                SideEffectKind::SettlementPayout,
                &target,
                payload_hash.clone(),
            )
            .unwrap()
            {
                BeginEffectOutcome::Retry(cp) => cp,
                _ => panic!("expected interrupted attempt to be retried"),
            }
        });
        assert_eq!(resumed.effect_id, prepared.effect_id);
        assert_eq!(resumed.prepared_at, prepared.prepared_at);
        assert_eq!(resumed.attempts, 2);
        assert_eq!(resumed.state, SideEffectState::Prepared);

        // Simulate the caller executing the effect after Retry and recording
        // the commit, then restarting once more.
        let committed = env.as_contract(&contract_id, || {
            commit_side_effect(&env, &actor, &resumed.effect_id).unwrap()
        });
        assert_eq!(committed.state, SideEffectState::Committed);

        let after_commit = env.as_contract(&contract_id, || {
            begin_side_effect(
                &env,
                &actor,
                symbol_short!("recover"),
                2,
                SideEffectKind::SettlementPayout,
                &target,
                payload_hash,
            )
            .unwrap()
        });
        match after_commit {
            BeginEffectOutcome::AlreadyCommitted(cp) => assert_eq!(cp, committed),
            _ => panic!("committed effect must not be executed again"),
        }
    }

    #[test]
    fn test_failure_retry_and_admin_rollback_paths() {
        let (env, contract_id, admin, actor, target) = setup();
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"hook_1")).into();

        env.as_contract(&contract_id, || {
            let cp = match begin_side_effect(
                &env,
                &actor,
                symbol_short!("notify"),
                1,
                SideEffectKind::WebhookDispatch,
                &target,
                payload_hash.clone(),
            )
            .unwrap()
            {
                BeginEffectOutcome::Execute(cp) => cp,
                _ => panic!("expected Execute"),
            };

            let failed = fail_side_effect(&env, &actor, &cp.effect_id, 503).unwrap();
            assert_eq!(failed.state, SideEffectState::Failed);
            assert_eq!(failed.last_error, 503);

            // Retry succeeds in re-acquiring Prepared state
            let retried = match begin_side_effect(
                &env,
                &actor,
                symbol_short!("notify"),
                1,
                SideEffectKind::WebhookDispatch,
                &target,
                payload_hash.clone(),
            )
            .unwrap()
            {
                BeginEffectOutcome::Retry(cp) => cp,
                _ => panic!("expected Retry"),
            };
            assert_eq!(retried.attempts, 2);

            // Admin rolls back instead of committing
            let rolled = rollback_side_effect(
                &env,
                &admin,
                &retried.effect_id,
                symbol_short!("abort"),
            )
            .unwrap();
            assert_eq!(rolled.state, SideEffectState::RolledBack);

            // Cannot re-begin a rolled-back side effect
            assert_eq!(
                begin_side_effect(
                    &env,
                    &actor,
                    symbol_short!("notify"),
                    1,
                    SideEffectKind::WebhookDispatch,
                    &target,
                    payload_hash,
                ),
                Err(Error::AlreadyExecuted)
            );
        });
    }

    #[test]
    fn test_authorization_and_retry_limit_failures() {
        let (env, contract_id, _admin, actor, target) = setup();
        let attacker = Address::generate(&env);
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"oracle")).into();

        env.as_contract(&contract_id, || {
            let cp = match begin_side_effect(
                &env,
                &actor,
                symbol_short!("oracle"),
                0,
                SideEffectKind::OraclePublish,
                &target,
                payload_hash.clone(),
            )
            .unwrap()
            {
                BeginEffectOutcome::Execute(cp) => cp,
                _ => panic!("expected Execute"),
            };

            assert_eq!(
                commit_side_effect(&env, &attacker, &cp.effect_id),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                rollback_side_effect(&env, &attacker, &cp.effect_id, symbol_short!("hack")),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                fail_side_effect(&env, &actor, &cp.effect_id, 0),
                Err(Error::InvalidArgument)
            );

            // Exhaust retries
            for _ in 1..DEFAULT_MAX_EFFECT_RETRIES {
                begin_side_effect(
                    &env,
                    &actor,
                    symbol_short!("oracle"),
                    0,
                    SideEffectKind::OraclePublish,
                    &target,
                    payload_hash.clone(),
                )
                .unwrap();
            }
            assert_eq!(
                begin_side_effect(
                    &env,
                    &actor,
                    symbol_short!("oracle"),
                    0,
                    SideEffectKind::OraclePublish,
                    &target,
                    payload_hash,
                ),
                Err(Error::QuotaExceeded)
            );
        });
    }

    fn begin_execute(
        env: &Env,
        actor: &Address,
        target: &Address,
        payload_hash: &BytesN<32>,
    ) -> SideEffectCheckpoint {
        match begin_side_effect(
            env,
            actor,
            symbol_short!("edge"),
            0,
            SideEffectKind::SettlementPayout,
            target,
            payload_hash.clone(),
        )
        .unwrap()
        {
            BeginEffectOutcome::Execute(cp) => cp,
            _ => panic!("expected Execute"),
        }
    }

    #[test]
    fn test_rollback_after_commit_is_rejected_and_commit_is_preserved() {
        let (env, contract_id, admin, actor, target) = setup();
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"p")).into();

        env.as_contract(&contract_id, || {
            let cp = begin_execute(&env, &actor, &target, &payload_hash);
            commit_side_effect(&env, &actor, &cp.effect_id).unwrap();

            assert_eq!(
                rollback_side_effect(&env, &admin, &cp.effect_id, symbol_short!("late")),
                Err(Error::AlreadyExecuted)
            );
            // A late failure report must not downgrade a committed effect either.
            assert_eq!(
                fail_side_effect(&env, &actor, &cp.effect_id, 500),
                Err(Error::AlreadyExecuted)
            );
            let stored = get_side_effect_checkpoint(&env, &cp.effect_id).unwrap();
            assert_eq!(stored.state, SideEffectState::Committed);
            assert_eq!(stored.last_error, 0);
        });
    }

    #[test]
    fn test_rolled_back_effect_is_terminal_and_rollback_is_idempotent() {
        let (env, contract_id, admin, actor, target) = setup();
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"p")).into();

        env.as_contract(&contract_id, || {
            let cp = begin_execute(&env, &actor, &target, &payload_hash);
            let failed = fail_side_effect(&env, &actor, &cp.effect_id, 7).unwrap();
            let rolled =
                rollback_side_effect(&env, &admin, &cp.effect_id, symbol_short!("abort")).unwrap();
            assert_eq!(rolled.state, SideEffectState::RolledBack);
            // Rollback keeps the recorded failure for audit.
            assert_eq!(rolled.last_error, failed.last_error);

            assert_eq!(
                rollback_side_effect(&env, &admin, &cp.effect_id, symbol_short!("again")),
                Ok(rolled)
            );
            assert_eq!(
                commit_side_effect(&env, &actor, &cp.effect_id),
                Err(Error::AlreadyExecuted)
            );
            assert_eq!(
                fail_side_effect(&env, &actor, &cp.effect_id, 9),
                Err(Error::AlreadyExecuted)
            );
        });
    }

    #[test]
    fn test_begin_by_other_actor_is_unauthorized_and_leaves_checkpoint_unchanged() {
        let (env, contract_id, _admin, actor, target) = setup();
        let other = Address::generate(&env);
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"p")).into();

        env.as_contract(&contract_id, || {
            let cp = begin_execute(&env, &actor, &target, &payload_hash);

            assert_eq!(
                begin_side_effect(
                    &env,
                    &other,
                    symbol_short!("edge"),
                    0,
                    SideEffectKind::SettlementPayout,
                    &target,
                    payload_hash.clone(),
                ),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                fail_side_effect(&env, &other, &cp.effect_id, 1),
                Err(Error::Unauthorized)
            );
            assert_eq!(get_side_effect_checkpoint(&env, &cp.effect_id), Some(cp));
        });
    }

    #[test]
    fn test_unknown_effect_id_returns_not_found() {
        let (env, contract_id, admin, actor, _target) = setup();
        let missing = BytesN::from_array(&env, &[7u8; 32]);

        env.as_contract(&contract_id, || {
            assert_eq!(get_side_effect_checkpoint(&env, &missing), None);
            assert_eq!(
                commit_side_effect(&env, &actor, &missing),
                Err(Error::NotFound)
            );
            assert_eq!(
                fail_side_effect(&env, &actor, &missing, 1),
                Err(Error::NotFound)
            );
            assert_eq!(
                rollback_side_effect(&env, &admin, &missing, symbol_short!("x")),
                Err(Error::NotFound)
            );
        });
    }

    #[test]
    fn test_commit_after_failure_and_idempotent_commit_clear_error() {
        let (env, contract_id, _admin, actor, target) = setup();
        let payload_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"p")).into();

        env.as_contract(&contract_id, || {
            let cp = begin_execute(&env, &actor, &target, &payload_hash);
            fail_side_effect(&env, &actor, &cp.effect_id, 42).unwrap();

            // The external call actually landed after the failure was recorded.
            let committed = commit_side_effect(&env, &actor, &cp.effect_id).unwrap();
            assert_eq!(committed.state, SideEffectState::Committed);
            assert_eq!(committed.last_error, 0);

            // Repeating the commit returns the same checkpoint.
            assert_eq!(
                commit_side_effect(&env, &actor, &cp.effect_id),
                Ok(committed)
            );
        });
    }

    #[test]
    fn test_distinct_payloads_get_independent_checkpoints() {
        let (env, contract_id, _admin, actor, target) = setup();
        let h1: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"one")).into();
        let h2: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, b"two")).into();

        env.as_contract(&contract_id, || {
            let first = begin_execute(&env, &actor, &target, &h1);
            commit_side_effect(&env, &actor, &first.effect_id).unwrap();

            // Same op/step/target but another payload is a new effect, not AlreadyCommitted.
            let second = begin_execute(&env, &actor, &target, &h2);
            assert_ne!(first.effect_id, second.effect_id);
            assert_eq!(second.attempts, 1);
        });
    }
}
