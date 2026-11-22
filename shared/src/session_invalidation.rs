//! Security-Event Session Invalidation Engine (#491).
//!
//! Provides protocol-grade session authorization and atomic, security-event-driven
//! session invalidation for operators, relayers, keeper bots, and maintainers.
//!
//! When anomalous behavior, suspected key compromises, or emergency lockdowns occur,
//! sessions can be invalidated:
//! - By Actor: invalidates all active sessions held by a compromised address.
//! - By Scope: bumps the scope epoch, immediately invalidating all sessions under that capability.
//! - Globally: bumps the global security epoch, immediately invalidating every active session.

use soroban_sdk::{
    contracttype, symbol_short, Address, Env, Symbol,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionScope {
    Global,
    TreasuryOperations,
    DisbursementWorker,
    OracleFeed,
    MaintenanceKeeper,
    Custom(Symbol),
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SecurityEventType {
    KeyCompromise = 1,
    AnomalousActivity = 2,
    UnauthorizedAccessAttempt = 3,
    EmergencyLockdown = 4,
    RoutineRotation = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Active,
    InvalidatedBySecurityEvent,
    Expired,
    RevokedByAdmin,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SessionError {
    /// Caller is not authorized for the requested security operation.
    Unauthorized = 4101,
    /// Specified session ID does not exist.
    SessionNotFound = 4102,
    /// Session has passed its expiration timestamp.
    SessionExpired = 4103,
    /// Session was invalidated due to a security incident or epoch advancement.
    SessionInvalidated = 4104,
    /// Actor is currently blacklisted due to an active security investigation.
    ActorBlacklisted = 4105,
    /// Requested session validity duration is invalid (0 or exceeds maximum).
    InvalidDuration = 4106,
    /// Session is already in the requested terminal status.
    SessionAlreadyTerminated = 4107,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecuritySession {
    pub session_id: u64,
    pub actor: Address,
    pub scope: SessionScope,
    pub epoch_at_creation: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: SessionStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityInvalidationReceipt {
    pub invalidation_id: u64,
    pub event_type: SecurityEventType,
    pub target_actor: Option<Address>,
    pub target_scope: SessionScope,
    pub triggered_by: Address,
    pub timestamp: u64,
    pub reason: Symbol,
    pub new_epoch: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    Admin,
    SecurityOfficer(Address),
    GlobalSecurityEpoch,
    ScopeEpoch(SessionScope),
    BlacklistedActor(Address),
    Session(u64),
    NextSessionId,
    NextInvalidationId,
}

// ---------------------------------------------------------------------------
// Access Control & Administration
// ---------------------------------------------------------------------------

pub fn initialize_session_security(env: &Env, admin: &Address) {
    admin.require_auth();
    env.storage().instance().set(&DataKey::Admin, admin);
    if !env.storage().instance().has(&DataKey::GlobalSecurityEpoch) {
        env.storage().instance().set(&DataKey::GlobalSecurityEpoch, &1u32);
    }
}

pub fn get_security_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Admin)
}

pub fn register_security_officer(
    env: &Env,
    admin: &Address,
    officer: &Address,
) -> Result<(), SessionError> {
    let current_admin = get_security_admin(env).ok_or(SessionError::Unauthorized)?;
    if *admin != current_admin {
        return Err(SessionError::Unauthorized);
    }
    admin.require_auth();

    env.storage()
        .instance()
        .set(&DataKey::SecurityOfficer(officer.clone()), &true);
    Ok(())
}

pub fn is_authorized_officer(env: &Env, caller: &Address) -> bool {
    if let Some(admin) = get_security_admin(env) {
        if *caller == admin {
            return true;
        }
    }
    env.storage()
        .instance()
        .get(&DataKey::SecurityOfficer(caller.clone()))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Epoch & Blacklist Lookups
// ---------------------------------------------------------------------------

pub fn get_global_epoch(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::GlobalSecurityEpoch)
        .unwrap_or(1)
}

pub fn get_scope_epoch(env: &Env, scope: &SessionScope) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::ScopeEpoch(scope.clone()))
        .unwrap_or(1)
}

pub fn is_actor_blacklisted(env: &Env, actor: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::BlacklistedActor(actor.clone()))
        .unwrap_or(false)
}

fn next_session_id(env: &Env) -> u64 {
    let id: u64 = env.storage().instance().get(&DataKey::NextSessionId).unwrap_or(1);
    env.storage().instance().set(&DataKey::NextSessionId, &(id + 1));
    id
}

fn next_invalidation_id(env: &Env) -> u64 {
    let id: u64 = env.storage().instance().get(&DataKey::NextInvalidationId).unwrap_or(1);
    env.storage().instance().set(&DataKey::NextInvalidationId, &(id + 1));
    id
}

// ---------------------------------------------------------------------------
// Session Management & Invalidation Engine
// ---------------------------------------------------------------------------

/// Registers a new active session for an authorized actor under a specific scope.
pub fn create_session(
    env: &Env,
    caller: &Address,
    actor: &Address,
    scope: SessionScope,
    duration_seconds: u64,
) -> Result<SecuritySession, SessionError> {
    if !is_authorized_officer(env, caller) {
        return Err(SessionError::Unauthorized);
    }
    caller.require_auth();

    if is_actor_blacklisted(env, actor) {
        return Err(SessionError::ActorBlacklisted);
    }

    if duration_seconds == 0 || duration_seconds > 604_800 {
        return Err(SessionError::InvalidDuration);
    }

    let now = env.ledger().timestamp();
    let session_id = next_session_id(env);
    let epoch = get_global_epoch(env);

    let session = SecuritySession {
        session_id,
        actor: actor.clone(),
        scope,
        epoch_at_creation: epoch,
        created_at: now,
        expires_at: now + duration_seconds,
        status: SessionStatus::Active,
    };

    env.storage()
        .instance()
        .set(&DataKey::Session(session_id), &session);

    env.events().publish(
        (symbol_short!("sec_sess"), symbol_short!("created")),
        (session_id, actor.clone(), epoch),
    );

    Ok(session)
}

/// Validates an active session. Returns Ok(SecuritySession) if valid, or an explicit SessionError.
pub fn validate_session(
    env: &Env,
    session_id: u64,
) -> Result<SecuritySession, SessionError> {
    let session: SecuritySession = env
        .storage()
        .instance()
        .get(&DataKey::Session(session_id))
        .ok_or(SessionError::SessionNotFound)?;

    if session.status != SessionStatus::Active {
        return Err(SessionError::SessionInvalidated);
    }

    if is_actor_blacklisted(env, &session.actor) {
        return Err(SessionError::ActorBlacklisted);
    }

    let now = env.ledger().timestamp();
    if now > session.expires_at {
        return Err(SessionError::SessionExpired);
    }

    // Verify global epoch
    let current_global_epoch = get_global_epoch(env);
    if session.epoch_at_creation < current_global_epoch {
        return Err(SessionError::SessionInvalidated);
    }

    // Verify scope epoch
    let current_scope_epoch = get_scope_epoch(env, &session.scope);
    if session.epoch_at_creation < current_scope_epoch {
        return Err(SessionError::SessionInvalidated);
    }

    Ok(session)
}

/// Triggers security-event invalidation across actor, scope, or global domains.
pub fn trigger_security_invalidation(
    env: &Env,
    caller: &Address,
    event_type: SecurityEventType,
    target_actor: Option<Address>,
    target_scope: SessionScope,
    reason: Symbol,
) -> Result<SecurityInvalidationReceipt, SessionError> {
    if !is_authorized_officer(env, caller) {
        return Err(SessionError::Unauthorized);
    }
    caller.require_auth();

    let invalidation_id = next_invalidation_id(env);
    let now = env.ledger().timestamp();
    let mut new_epoch = get_global_epoch(env);

    if let Some(ref actor) = target_actor {
        // Invalidate by blacklisting actor
        env.storage()
            .instance()
            .set(&DataKey::BlacklistedActor(actor.clone()), &true);
    } else if target_scope != SessionScope::Global {
        // Invalidate scope by bumping scope epoch
        let cur = get_scope_epoch(env, &target_scope);
        new_epoch = cur + 1;
        env.storage()
            .instance()
            .set(&DataKey::ScopeEpoch(target_scope.clone()), &new_epoch);
    } else {
        // Global invalidation: bump global epoch
        new_epoch += 1;
        env.storage()
            .instance()
            .set(&DataKey::GlobalSecurityEpoch, &new_epoch);
    }

    let receipt = SecurityInvalidationReceipt {
        invalidation_id,
        event_type,
        target_actor: target_actor.clone(),
        target_scope: target_scope.clone(),
        triggered_by: caller.clone(),
        timestamp: now,
        reason,
        new_epoch,
    };

    env.events().publish(
        (symbol_short!("sec_sess"), symbol_short!("invalid")),
        (invalidation_id, event_type as u32, new_epoch),
    );

    Ok(receipt)
}

/// Clears blacklisted status for an actor after a security incident is resolved (Admin only).
pub fn reinstate_actor_after_investigation(
    env: &Env,
    admin: &Address,
    actor: &Address,
) -> Result<(), SessionError> {
    let current_admin = get_security_admin(env).ok_or(SessionError::Unauthorized)?;
    if *admin != current_admin {
        return Err(SessionError::Unauthorized);
    }
    admin.require_auth();

    env.storage()
        .instance()
        .remove(&DataKey::BlacklistedActor(actor.clone()));

    env.events().publish(
        (symbol_short!("sec_sess"), symbol_short!("reinst")),
        actor.clone(),
    );

    Ok(())
}

/// Explicitly revokes a single session by ID.
pub fn revoke_session(
    env: &Env,
    caller: &Address,
    session_id: u64,
) -> Result<(), SessionError> {
    if !is_authorized_officer(env, caller) {
        return Err(SessionError::Unauthorized);
    }
    caller.require_auth();

    let mut session: SecuritySession = env
        .storage()
        .instance()
        .get(&DataKey::Session(session_id))
        .ok_or(SessionError::SessionNotFound)?;

    if session.status != SessionStatus::Active {
        return Err(SessionError::SessionAlreadyTerminated);
    }

    session.status = SessionStatus::RevokedByAdmin;
    env.storage()
        .instance()
        .set(&DataKey::Session(session_id), &session);

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Env,
    };

    #[contract]
    pub struct SessionTestContract;

    #[contractimpl]
    impl SessionTestContract {}

    fn setup_test() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SessionTestContract);
        let admin = Address::generate(&env);
        let operator = Address::generate(&env);
        (env, contract_id, admin, operator)
    }

    fn init_sec(env: &Env, cid: &Address, admin: &Address) {
        env.as_contract(cid, || initialize_session_security(env, admin));
    }

    fn reg_officer(env: &Env, cid: &Address, admin: &Address, officer: &Address) -> Result<(), SessionError> {
        env.as_contract(cid, || register_security_officer(env, admin, officer))
    }

    fn create_sess(
        env: &Env,
        cid: &Address,
        caller: &Address,
        actor: &Address,
        scope: SessionScope,
        dur: u64,
    ) -> Result<SecuritySession, SessionError> {
        env.as_contract(cid, || create_session(env, caller, actor, scope, dur))
    }

    fn val_sess(env: &Env, cid: &Address, id: u64) -> Result<SecuritySession, SessionError> {
        env.as_contract(cid, || validate_session(env, id))
    }

    fn trig_inv(
        env: &Env,
        cid: &Address,
        caller: &Address,
        ev: SecurityEventType,
        actor: Option<Address>,
        scope: SessionScope,
        reason: Symbol,
    ) -> Result<SecurityInvalidationReceipt, SessionError> {
        env.as_contract(cid, || trigger_security_invalidation(env, caller, ev, actor, scope, reason))
    }

    fn reinstate(env: &Env, cid: &Address, admin: &Address, actor: &Address) -> Result<(), SessionError> {
        env.as_contract(cid, || reinstate_actor_after_investigation(env, admin, actor))
    }

    #[test]
    fn test_normal_session_creation_and_validation() {
        let (env, contract_id, admin, operator) = setup_test();
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        let session = create_sess(
            &env,
            &contract_id,
            &admin,
            &operator,
            SessionScope::TreasuryOperations,
            3600,
        )
        .expect("session created");

        assert_eq!(session.session_id, 1);
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.expires_at, 4600);

        let validated = val_sess(&env, &contract_id, 1).expect("session valid");
        assert_eq!(validated.actor, operator);
    }

    #[test]
    fn test_actor_security_invalidation_and_reinstatement() {
        let (env, contract_id, admin, operator) = setup_test();
        let other_op = Address::generate(&env);
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        let s1 = create_sess(&env, &contract_id, &admin, &operator, SessionScope::DisbursementWorker, 3600).unwrap();
        let s2 = create_sess(&env, &contract_id, &admin, &other_op, SessionScope::DisbursementWorker, 3600).unwrap();

        // Trigger security event for operator (suspected key compromise)
        let receipt = trig_inv(
            &env,
            &contract_id,
            &admin,
            SecurityEventType::KeyCompromise,
            Some(operator.clone()),
            SessionScope::Global,
            symbol_short!("comprom"),
        )
        .expect("invalidation triggered");

        assert_eq!(receipt.invalidation_id, 1);
        assert!(env.as_contract(&contract_id, || is_actor_blacklisted(&env, &operator)));

        // Operator session is now rejected with ActorBlacklisted
        assert_eq!(val_sess(&env, &contract_id, s1.session_id), Err(SessionError::ActorBlacklisted));

        // Other operator session is unaffected
        assert!(val_sess(&env, &contract_id, s2.session_id).is_ok());

        // Post-incident recovery: reinstate operator
        reinstate(&env, &contract_id, &admin, &operator).unwrap();
        assert!(!env.as_contract(&contract_id, || is_actor_blacklisted(&env, &operator)));

        // Re-creating session for reinstated operator succeeds
        let s3 = create_sess(&env, &contract_id, &admin, &operator, SessionScope::DisbursementWorker, 3600).unwrap();
        assert!(val_sess(&env, &contract_id, s3.session_id).is_ok());
    }

    #[test]
    fn test_scope_epoch_security_invalidation() {
        let (env, contract_id, admin, operator) = setup_test();
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        let s_treasury = create_sess(
            &env,
            &contract_id,
            &admin,
            &operator,
            SessionScope::TreasuryOperations,
            3600,
        )
        .unwrap();

        let s_oracle = create_sess(
            &env,
            &contract_id,
            &admin,
            &operator,
            SessionScope::OracleFeed,
            3600,
        )
        .unwrap();

        // Invalidate entire TreasuryOperations scope
        trig_inv(
            &env,
            &contract_id,
            &admin,
            SecurityEventType::AnomalousActivity,
            None,
            SessionScope::TreasuryOperations,
            symbol_short!("drain_att"),
        )
        .unwrap();

        // Treasury session is invalidated due to scope epoch bump
        assert_eq!(
            val_sess(&env, &contract_id, s_treasury.session_id),
            Err(SessionError::SessionInvalidated)
        );

        // Oracle session remains valid
        assert!(val_sess(&env, &contract_id, s_oracle.session_id).is_ok());
    }

    #[test]
    fn test_global_emergency_invalidation() {
        let (env, contract_id, admin, operator) = setup_test();
        let operator2 = Address::generate(&env);
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        let s1 = create_sess(&env, &contract_id, &admin, &operator, SessionScope::TreasuryOperations, 3600).unwrap();
        let s2 = create_sess(&env, &contract_id, &admin, &operator2, SessionScope::MaintenanceKeeper, 3600).unwrap();

        // Emergency protocol lockdown
        trig_inv(
            &env,
            &contract_id,
            &admin,
            SecurityEventType::EmergencyLockdown,
            None,
            SessionScope::Global,
            symbol_short!("global_lk"),
        )
        .unwrap();

        // All sessions contract-wide are invalidated
        assert_eq!(val_sess(&env, &contract_id, s1.session_id), Err(SessionError::SessionInvalidated));
        assert_eq!(val_sess(&env, &contract_id, s2.session_id), Err(SessionError::SessionInvalidated));
    }

    #[test]
    fn test_expiration_and_failure_paths() {
        let (env, contract_id, admin, operator) = setup_test();
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        // Invalid duration (0)
        let res = create_sess(&env, &contract_id, &admin, &operator, SessionScope::Global, 0);
        assert_eq!(res, Err(SessionError::InvalidDuration));

        // Unknown session validation
        let res_unknown = val_sess(&env, &contract_id, 9999);
        assert_eq!(res_unknown, Err(SessionError::SessionNotFound));

        // Create valid short session
        let s = create_sess(&env, &contract_id, &admin, &operator, SessionScope::Global, 100).unwrap();
        assert!(val_sess(&env, &contract_id, s.session_id).is_ok());

        // Fast forward past expiration
        env.ledger().set_timestamp(1101);
        assert_eq!(val_sess(&env, &contract_id, s.session_id), Err(SessionError::SessionExpired));
    }

    #[test]
    fn test_authorization_rejects_unprivileged_callers() {
        let (env, contract_id, admin, operator) = setup_test();
        let stranger = Address::generate(&env);
        env.ledger().set_timestamp(1000);

        init_sec(&env, &contract_id, &admin);

        // Stranger cannot create session
        let res1 = create_sess(&env, &contract_id, &stranger, &operator, SessionScope::Global, 3600);
        assert_eq!(res1, Err(SessionError::Unauthorized));

        // Stranger cannot trigger security invalidation
        let res2 = trig_inv(
            &env,
            &contract_id,
            &stranger,
            SecurityEventType::KeyCompromise,
            Some(operator.clone()),
            SessionScope::Global,
            symbol_short!("unauth"),
        );
        assert_eq!(res2, Err(SessionError::Unauthorized));

        // Stranger cannot register security officer
        let res3 = reg_officer(&env, &contract_id, &stranger, &operator);
        assert_eq!(res3, Err(SessionError::Unauthorized));
    }
}
