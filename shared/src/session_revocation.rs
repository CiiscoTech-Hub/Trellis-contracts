//! Stale session and token revocation after security events (Issue #283).
//!
//! Provides O(1) bulk invalidation of all pre-event sessions/tokens via a
//! per-subject security epoch (`min_valid_epoch`) and cutoff timestamp
//! (`last_revoked_at`), alongside explicit single-token revocation.

use soroban_sdk::{
    contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol,
};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

/// Security event reasons that invalidate stale sessions and tokens.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SecurityEventKind {
    /// Ownership or administrative control changed.
    AdminChanged = 1,
    /// A privileged role was revoked from the subject.
    RoleRevoked = 2,
    /// Signing key or credential compromise suspected.
    KeyCompromised = 3,
    /// Suspicious or anomalous activity detected.
    SuspiciousActivity = 4,
    /// Account locked or quarantined by an administrator.
    AccountLocked = 5,
    /// Explicit manual revocation by the subject or administrator.
    ManualRevocation = 6,
}

/// Lifecycle state of an individual session token.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TokenStatus {
    /// Token is active and valid if epoch, cutoff, and expiry checks pass.
    Active = 1,
    /// Token was explicitly revoked.
    Revoked = 2,
}

/// Per-subject revocation watermark.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectSecurityState {
    /// Minimum epoch a token must carry to remain valid.
    pub min_valid_epoch: u64,
    /// Any token issued strictly before this timestamp is stale.
    pub last_revoked_at: u64,
    /// Most recent security event kind recorded for this subject.
    pub last_event: SecurityEventKind,
    /// Total number of bulk security revocations triggered.
    pub revocation_count: u32,
}

/// Persisted session or token record bound to a subject and security epoch.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionToken {
    /// Deterministic token identifier.
    pub token_id: BytesN<32>,
    /// Account that owns the session/token.
    pub subject: Address,
    /// Security epoch at issuance time.
    pub epoch: u64,
    /// Ledger timestamp at issuance.
    pub issued_at: u64,
    /// Ledger timestamp after which the token expires.
    pub expires_at: u64,
    /// Current explicit status.
    pub status: TokenStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionKey {
    SubjectState(Address),
    Token(BytesN<32>),
}

/// Computes a deterministic token ID from `(subject, nonce, issued_at)` using
/// canonical Soroban XDR encoding.
pub fn derive_token_id(
    env: &Env,
    subject: &Address,
    nonce: u64,
    issued_at: u64,
) -> BytesN<32> {
    let payload = (
        symbol_short!("sess_tok"),
        env.current_contract_address(),
        subject.clone(),
        nonce,
        issued_at,
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).into()
}

/// Returns the current security watermark for `subject`, or a default epoch-0
/// state if no security event has been recorded yet.
pub fn get_subject_security_state(env: &Env, subject: &Address) -> SubjectSecurityState {
    persistent_get(env, &SessionKey::SubjectState(subject.clone())).unwrap_or(
        SubjectSecurityState {
            min_valid_epoch: 0,
            last_revoked_at: 0,
            last_event: SecurityEventKind::ManualRevocation,
            revocation_count: 0,
        },
    )
}

/// Returns a stored session token by `token_id`, if present.
pub fn get_session_token(env: &Env, token_id: &BytesN<32>) -> Option<SessionToken> {
    persistent_get(env, &SessionKey::Token(token_id.clone()))
}

/// Issues a new session token for `subject` bound to `subject`'s current
/// `min_valid_epoch`.
///
/// Only the contract admin or `subject` itself (with auth) may issue a token.
/// Rejects `expires_at <= now` or duplicate `token_id`.
pub fn issue_session_token(
    env: &Env,
    caller: &Address,
    subject: &Address,
    nonce: u64,
    expires_at: u64,
) -> Result<SessionToken, Error> {
    if *caller == *subject {
        caller.require_auth();
    } else {
        require_admin(env, caller)?;
    }

    let now = env.ledger().timestamp();
    if expires_at <= now {
        return Err(Error::InvalidArgument);
    }

    let token_id = derive_token_id(env, subject, nonce, now);
    if get_session_token(env, &token_id).is_some() {
        return Err(Error::AlreadyClaimed);
    }

    let sec = get_subject_security_state(env, subject);
    let token = SessionToken {
        token_id: token_id.clone(),
        subject: subject.clone(),
        epoch: sec.min_valid_epoch,
        issued_at: now,
        expires_at,
        status: TokenStatus::Active,
    };

    persistent_set(env, &SessionKey::Token(token_id.clone()), &token);

    env.events().publish(
        (symbol_short!("session"), symbol_short!("issued")),
        (subject.clone(), token_id, token.epoch, expires_at),
    );

    Ok(token)
}

/// Triggers a security event for `subject`, advancing `min_valid_epoch` and
/// updating `last_revoked_at` so all previously issued sessions and tokens are
/// immediately invalidated as stale.
///
/// Admin-gated via [`require_admin`].
pub fn trigger_security_revocation(
    env: &Env,
    admin: &Address,
    subject: &Address,
    event_kind: SecurityEventKind,
) -> Result<SubjectSecurityState, Error> {
    require_admin(env, admin)?;

    let now = env.ledger().timestamp();
    let mut state = get_subject_security_state(env, subject);
    state.min_valid_epoch = state
        .min_valid_epoch
        .checked_add(1)
        .ok_or(Error::Overflow)?;
    if now > state.last_revoked_at {
        state.last_revoked_at = now;
    }
    state.last_event = event_kind;
    state.revocation_count = state.revocation_count.saturating_add(1);

    persistent_set(env, &SessionKey::SubjectState(subject.clone()), &state);

    env.events().publish(
        (symbol_short!("session"), symbol_short!("sec_rvk")),
        (subject.clone(), state.min_valid_epoch, now, event_kind),
    );

    Ok(state)
}

/// Explicitly revokes a single `token_id`.
///
/// Authorized for either the contract admin or the token's `subject`.
/// Idempotent: revoking an already-revoked token returns `Ok(false)`; a new
/// revocation returns `Ok(true)`.
pub fn revoke_session_token(
    env: &Env,
    caller: &Address,
    token_id: &BytesN<32>,
    reason: Symbol,
) -> Result<bool, Error> {
    let mut token = get_session_token(env, token_id).ok_or(Error::NotFound)?;

    if *caller == token.subject {
        caller.require_auth();
    } else {
        require_admin(env, caller)?;
    }

    if token.status == TokenStatus::Revoked {
        return Ok(false);
    }

    token.status = TokenStatus::Revoked;
    persistent_set(env, &SessionKey::Token(token_id.clone()), &token);

    env.events().publish(
        (symbol_short!("session"), symbol_short!("tok_rvk")),
        (token.subject, token_id.clone(), reason),
    );

    Ok(true)
}

/// Validates that `token_id` exists, has not been explicitly revoked, has not
/// been invalidated by a newer security event (`epoch` and `issued_at`), and
/// has not expired.
pub fn validate_session_token(env: &Env, token_id: &BytesN<32>) -> Result<SessionToken, Error> {
    let token = get_session_token(env, token_id).ok_or(Error::NotFound)?;
    if token.status == TokenStatus::Revoked {
        return Err(Error::Unauthorized);
    }

    let sec = get_subject_security_state(env, &token.subject);
    if token.epoch < sec.min_valid_epoch || token.issued_at < sec.last_revoked_at {
        return Err(Error::StaleData);
    }

    let now = env.ledger().timestamp();
    if now > token.expires_at {
        return Err(Error::Expired);
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Env,
    };

    #[contract]
    struct SessionRevocationTestContract;

    #[contractimpl]
    impl SessionRevocationTestContract {}

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SessionRevocationTestContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        env.ledger().set_timestamp(1_000);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });
        (env, contract_id, admin, user)
    }

    #[test]
    fn test_normal_issue_validate_and_security_event_invalidation() {
        let (env, contract_id, admin, user) = setup();

        let (t1, t2) = env.as_contract(&contract_id, || {
            let t1 = issue_session_token(&env, &user, &user, 1, 2_000).unwrap();
            let t2 = issue_session_token(&env, &admin, &user, 2, 2_500).unwrap();
            assert_eq!(validate_session_token(&env, &t1.token_id), Ok(t1.clone()));
            assert_eq!(validate_session_token(&env, &t2.token_id), Ok(t2.clone()));

            // Security event invalidates all pre-event tokens
            let state = trigger_security_revocation(
                &env,
                &admin,
                &user,
                SecurityEventKind::KeyCompromised,
            )
            .unwrap();
            assert_eq!(state.min_valid_epoch, 1);
            assert_eq!(
                validate_session_token(&env, &t1.token_id),
                Err(Error::StaleData)
            );
            assert_eq!(
                validate_session_token(&env, &t2.token_id),
                Err(Error::StaleData)
            );
            (t1, t2)
        });

        // Re-issuing after the security event succeeds under the new epoch
        env.ledger().set_timestamp(1_100);
        env.as_contract(&contract_id, || {
            let t3 = issue_session_token(&env, &user, &user, 3, 3_000).unwrap();
            assert_eq!(t3.epoch, 1);
            assert_eq!(validate_session_token(&env, &t3.token_id), Ok(t3));
            // Old tokens remain stale
            assert_eq!(
                validate_session_token(&env, &t1.token_id),
                Err(Error::StaleData)
            );
            assert_eq!(
                validate_session_token(&env, &t2.token_id),
                Err(Error::StaleData)
            );
        });
    }

    #[test]
    fn test_single_token_revocation_idempotent_retry_and_expiry() {
        let (env, contract_id, _admin, user) = setup();

        env.as_contract(&contract_id, || {
            let tok = issue_session_token(&env, &user, &user, 10, 1_500).unwrap();
            assert_eq!(
                revoke_session_token(&env, &user, &tok.token_id, symbol_short!("logout")),
                Ok(true)
            );
            // Retry revocation is idempotent
            assert_eq!(
                revoke_session_token(&env, &user, &tok.token_id, symbol_short!("logout")),
                Ok(false)
            );
            assert_eq!(
                validate_session_token(&env, &tok.token_id),
                Err(Error::Unauthorized)
            );

            // Expiry path
            let tok2 = issue_session_token(&env, &user, &user, 11, 1_200).unwrap();
            env.ledger().set_timestamp(1_201);
            assert_eq!(
                validate_session_token(&env, &tok2.token_id),
                Err(Error::Expired)
            );
        });
    }

    #[test]
    fn test_authorization_and_invalid_argument_failures() {
        let (env, contract_id, _admin, user) = setup();
        let attacker = Address::generate(&env);

        env.as_contract(&contract_id, || {
            assert_eq!(
                issue_session_token(&env, &attacker, &user, 1, 2_000),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                issue_session_token(&env, &user, &user, 1, 1_000),
                Err(Error::InvalidArgument)
            );
            assert_eq!(
                trigger_security_revocation(
                    &env,
                    &attacker,
                    &user,
                    SecurityEventKind::SuspiciousActivity
                ),
                Err(Error::Unauthorized)
            );

            let tok = issue_session_token(&env, &user, &user, 1, 2_000).unwrap();
            assert_eq!(
                revoke_session_token(&env, &attacker, &tok.token_id, symbol_short!("hack")),
                Err(Error::Unauthorized)
            );
        });
    }
}
