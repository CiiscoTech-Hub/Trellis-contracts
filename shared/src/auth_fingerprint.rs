//! Replay-safe authorization payload fingerprints (Issue #325).
//!
//! A signer authorises an [`AuthPayload`] — an action, the sha256 of its
//! argument body, a per-signer nonce and an expiry ledger. The payload's
//! fingerprint is
//!
//! ```text
//! sha256(xdr(("auth_fp", FORMAT, network_id, contract_address, payload)))
//! ```
//!
//! so the same signed payload cannot be replayed on another network, another
//! contract, or with a different body. [`consume_authorization`] binds the
//! signer's `require_auth_for_args` to the fingerprint, checks it in this
//! order, and only then records it:
//!
//! 1. revoked → `Revoked`
//! 2. already consumed → `Replayed` (a retry after success is detectable)
//! 3. `ledger > expires_at_ledger` → `Expired`
//! 4. validity window larger than [`MAX_VALIDITY_LEDGERS`] → `ExpiryTooFar`
//! 5. `nonce != next_nonce(signer)` → `NonceMismatch`
//!
//! Consumed and revoked markers live in temporary storage. Their TTL
//! (`TEMPORARY_BUMP_AMOUNT`) always exceeds [`MAX_VALIDITY_LEDGERS`], so a
//! marker can only expire after the payload itself has expired; the strict
//! nonce sequence remains the long-term replay guard.

use soroban_sdk::{contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, Symbol};

use crate::storage::{persistent_read, persistent_set, temporary_has, temporary_set, TEMPORARY_BUMP_AMOUNT};

pub const AUTH_FINGERPRINT_FORMAT: u32 = 1;
/// ~12 hours at 5 s/ledger. Must stay below `TEMPORARY_BUMP_AMOUNT`.
pub const MAX_VALIDITY_LEDGERS: u32 = TEMPORARY_BUMP_AMOUNT / 2;

pub const TOPIC_AUTH_CONSUMED: Symbol = symbol_short!("afp_use");
pub const TOPIC_AUTH_REVOKED: Symbol = symbol_short!("afp_rev");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPayload {
    pub signer: Address,
    pub action: Symbol,
    pub body_hash: BytesN<32>,
    pub nonce: u64,
    pub expires_at_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedRecord {
    pub signer: Address,
    pub nonce: u64,
    pub consumed_at_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FingerprintStatus {
    Unknown,
    Consumed(ConsumedRecord),
    Revoked,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AuthFingerprintError {
    Unauthorized = 1,
    Expired = 2,
    ExpiryTooFar = 3,
    Replayed = 4,
    Revoked = 5,
    NonceMismatch = 6,
    BodyMismatch = 7,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AfpKey {
    Nonce(Address),
    Consumed(BytesN<32>),
    Revoked(BytesN<32>),
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

pub fn body_hash(env: &Env, body: &Bytes) -> BytesN<32> {
    env.crypto().sha256(body).into()
}

/// Domain-separated fingerprint, bound to network and calling contract.
pub fn payload_fingerprint(env: &Env, payload: &AuthPayload) -> BytesN<32> {
    let bytes = (
        symbol_short!("auth_fp"),
        AUTH_FINGERPRINT_FORMAT,
        env.ledger().network_id(),
        env.current_contract_address(),
        payload.clone(),
    )
        .to_xdr(env);
    env.crypto().sha256(&bytes).into()
}

pub fn next_nonce(env: &Env, signer: &Address) -> u64 {
    persistent_read(env, &AfpKey::Nonce(signer.clone())).unwrap_or(0)
}

pub fn fingerprint_status(env: &Env, fingerprint: &BytesN<32>) -> FingerprintStatus {
    if temporary_has(env, &AfpKey::Revoked(fingerprint.clone())) {
        return FingerprintStatus::Revoked;
    }
    match env.storage().temporary().get(&AfpKey::Consumed(fingerprint.clone())) {
        Some(rec) => FingerprintStatus::Consumed(rec),
        None => FingerprintStatus::Unknown,
    }
}

fn precheck(env: &Env, payload: &AuthPayload, fp: &BytesN<32>) -> Result<(), AuthFingerprintError> {
    match fingerprint_status(env, fp) {
        FingerprintStatus::Revoked => return Err(AuthFingerprintError::Revoked),
        FingerprintStatus::Consumed(_) => return Err(AuthFingerprintError::Replayed),
        FingerprintStatus::Unknown => {}
    }
    let now = env.ledger().sequence();
    if now > payload.expires_at_ledger {
        return Err(AuthFingerprintError::Expired);
    }
    if payload.expires_at_ledger - now > MAX_VALIDITY_LEDGERS {
        return Err(AuthFingerprintError::ExpiryTooFar);
    }
    Ok(())
}

/// Verify and consume a payload. Returns its fingerprint on success.
/// When `body` is supplied it must hash to `payload.body_hash`.
pub fn consume_authorization(
    env: &Env,
    payload: &AuthPayload,
    body: Option<Bytes>,
) -> Result<BytesN<32>, AuthFingerprintError> {
    if let Some(b) = body {
        if body_hash(env, &b) != payload.body_hash {
            return Err(AuthFingerprintError::BodyMismatch);
        }
    }
    let fp = payload_fingerprint(env, payload);
    precheck(env, payload, &fp)?;
    if payload.nonce != next_nonce(env, &payload.signer) {
        return Err(AuthFingerprintError::NonceMismatch);
    }
    payload
        .signer
        .require_auth_for_args((fp.clone(),).into_val(env));

    let rec = ConsumedRecord {
        signer: payload.signer.clone(),
        nonce: payload.nonce,
        consumed_at_ledger: env.ledger().sequence(),
    };
    temporary_set(env, &AfpKey::Consumed(fp.clone()), &rec);
    persistent_set(env, &AfpKey::Nonce(payload.signer.clone()), &(payload.nonce + 1));
    env.events().publish(
        (TOPIC_AUTH_CONSUMED, payload.signer.clone()),
        (fp.clone(), payload.action.clone(), payload.nonce),
    );
    Ok(fp)
}

/// Cancel a signed-but-unused payload. Callable by the signer or the admin.
/// Does not advance the nonce: the signer's next payload may reuse it, and
/// will have a different fingerprint as long as any field differs.
pub fn revoke_authorization(
    env: &Env,
    caller: &Address,
    payload: &AuthPayload,
) -> Result<BytesN<32>, AuthFingerprintError> {
    if *caller == payload.signer {
        caller.require_auth();
    } else {
        crate::auth::require_admin(env, caller).map_err(|_| AuthFingerprintError::Unauthorized)?;
    }
    let fp = payload_fingerprint(env, payload);
    match fingerprint_status(env, &fp) {
        FingerprintStatus::Consumed(_) => return Err(AuthFingerprintError::Replayed),
        FingerprintStatus::Revoked => return Ok(fp),
        FingerprintStatus::Unknown => {}
    }
    temporary_set(env, &AfpKey::Revoked(fp.clone()), &true);
    env.events().publish((TOPIC_AUTH_REVOKED, payload.signer.clone()), (fp.clone(), caller.clone()));
    Ok(fp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Address, Env,
    };

    #[contract]
    struct AuthFpTestContract;
    #[contractimpl]
    impl AuthFpTestContract {}

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|li| {
            li.sequence_number = 100;
            // Long enough that the contract instance survives the expiry tests'
            // jump past MAX_VALIDITY_LEDGERS.
            li.min_persistent_entry_ttl = 50_000;
            li.max_entry_ttl = 1_000_000;
        });
        let cid = env.register_contract(None, AuthFpTestContract);
        let admin = Address::generate(&env);
        let signer = Address::generate(&env);
        env.as_contract(&cid, || crate::auth::set_admin(&env, &admin));
        (env, cid, admin, signer)
    }

    // Each call runs in its own frame, as a real invocation would; Soroban
    // rejects a second `require_auth` for the same address within one frame.
    fn consume(env: &Env, cid: &Address, p: &AuthPayload, body: Option<Bytes>) -> Result<BytesN<32>, AuthFingerprintError> {
        env.as_contract(cid, || consume_authorization(env, p, body))
    }

    fn revoke(env: &Env, cid: &Address, caller: &Address, p: &AuthPayload) -> Result<BytesN<32>, AuthFingerprintError> {
        env.as_contract(cid, || revoke_authorization(env, caller, p))
    }

    fn status(env: &Env, cid: &Address, fp: &BytesN<32>) -> FingerprintStatus {
        env.as_contract(cid, || fingerprint_status(env, fp))
    }

    fn fingerprint(env: &Env, cid: &Address, p: &AuthPayload) -> BytesN<32> {
        env.as_contract(cid, || payload_fingerprint(env, p))
    }

    fn nonce(env: &Env, cid: &Address, signer: &Address) -> u64 {
        env.as_contract(cid, || next_nonce(env, signer))
    }

    fn payload(env: &Env, signer: &Address, nonce: u64, body: &[u8]) -> AuthPayload {
        AuthPayload {
            signer: signer.clone(),
            action: symbol_short!("withdraw"),
            body_hash: body_hash(env, &Bytes::from_slice(env, body)),
            nonce,
            expires_at_ledger: env.ledger().sequence() + 100,
        }
    }

    #[test]
    fn fingerprint_is_deterministic_and_field_sensitive() {
        let (env, cid, _, signer) = setup();
        let p = payload(&env, &signer, 0, b"amt=5");
        assert_eq!(fingerprint(&env, &cid, &p), fingerprint(&env, &cid, &p.clone()));
        let mut variants = [p.clone(), p.clone(), p.clone(), p.clone(), p.clone()];
        variants[0].nonce = 1;
        variants[1].action = symbol_short!("deposit");
        variants[2].body_hash = body_hash(&env, &Bytes::from_slice(&env, b"amt=6"));
        variants[3].expires_at_ledger += 1;
        variants[4].signer = Address::generate(&env);
        for v in variants.iter() {
            assert_ne!(fingerprint(&env, &cid, v), fingerprint(&env, &cid, &p));
        }
    }

    #[test]
    fn fingerprint_is_bound_to_contract() {
        let (env, cid, _, signer) = setup();
        let other = env.register_contract(None, AuthFpTestContract);
        let p = payload(&env, &signer, 0, b"x");
        let a = fingerprint(&env, &cid, &p);
        let b = fingerprint(&env, &other, &p);
        assert_ne!(a, b);
        // Consuming on one contract does not mark it consumed on the other;
        // each contract enforces its own replay protection.
        consume(&env, &cid, &p, None).unwrap();
        assert_eq!(status(&env, &other, &b), FingerprintStatus::Unknown);
    }

    #[test]
    fn normal_consume_advances_nonce_and_records_status() {
        let (env, cid, _, signer) = setup();
        let body = Bytes::from_slice(&env, b"amt=5");
        let p0 = payload(&env, &signer, 0, b"amt=5");
        let fp = consume(&env, &cid, &p0, Some(body)).unwrap();
        assert_eq!(nonce(&env, &cid, &signer), 1);
        match status(&env, &cid, &fp) {
            FingerprintStatus::Consumed(rec) => {
                assert_eq!(rec.nonce, 0);
                assert_eq!(rec.consumed_at_ledger, 100);
            }
            s => panic!("unexpected {s:?}"),
        }
        let p1 = payload(&env, &signer, 1, b"amt=7");
        consume(&env, &cid, &p1, None).unwrap();
        assert_eq!(nonce(&env, &cid, &signer), 2);
    }

    #[test]
    fn replay_and_retry_paths() {
        let (env, cid, _, signer) = setup();
        let p = payload(&env, &signer, 0, b"a");
        let fp = consume(&env, &cid, &p, None).unwrap();
        // A client retry after a timed-out success sees Replayed and can
        // confirm via fingerprint_status instead of double-executing.
        assert_eq!(consume(&env, &cid, &p, None), Err(AuthFingerprintError::Replayed));
        assert!(matches!(status(&env, &cid, &fp), FingerprintStatus::Consumed(_)));
        assert_eq!(nonce(&env, &cid, &signer), 1);

        // Stale nonce with a fresh body is not a replay but still rejected.
        let stale = payload(&env, &signer, 0, b"b");
        assert_eq!(consume(&env, &cid, &stale, None), Err(AuthFingerprintError::NonceMismatch));
        // Skipping ahead is rejected too (strict ordering).
        let ahead = payload(&env, &signer, 5, b"c");
        assert_eq!(consume(&env, &cid, &ahead, None), Err(AuthFingerprintError::NonceMismatch));
    }

    #[test]
    fn failure_expiry_window_and_body_checks() {
        let (env, cid, _, signer) = setup();
        let mut p = payload(&env, &signer, 0, b"a");
        assert_eq!(
            consume(&env, &cid, &p, Some(Bytes::from_slice(&env, b"tampered"))),
            Err(AuthFingerprintError::BodyMismatch)
        );
        p.expires_at_ledger = 100 + MAX_VALIDITY_LEDGERS + 1;
        assert_eq!(consume(&env, &cid, &p, None), Err(AuthFingerprintError::ExpiryTooFar));
        p.expires_at_ledger = 100 + MAX_VALIDITY_LEDGERS;
        let boundary = p.clone();

        let late = payload(&env, &signer, 0, b"late");
        env.ledger().set_sequence_number(late.expires_at_ledger + 1);
        assert_eq!(consume(&env, &cid, &late, None), Err(AuthFingerprintError::Expired));
        // Expiry exactly at the current ledger is still valid.
        env.ledger().set_sequence_number(boundary.expires_at_ledger);
        consume(&env, &cid, &boundary, None).unwrap();
        // Failures never advanced the nonce.
        assert_eq!(nonce(&env, &cid, &signer), 1);
    }

    #[test]
    fn revocation_and_authorization_paths() {
        let (env, cid, admin, signer) = setup();
        let intruder = Address::generate(&env);
        let p = payload(&env, &signer, 0, b"a");
        assert_eq!(revoke(&env, &cid, &intruder, &p), Err(AuthFingerprintError::Unauthorized));

        let fp = revoke(&env, &cid, &signer, &p).unwrap();
        assert_eq!(status(&env, &cid, &fp), FingerprintStatus::Revoked);
        // Revocation is idempotent and blocks consumption.
        assert_eq!(revoke(&env, &cid, &admin, &p), Ok(fp));
        assert_eq!(consume(&env, &cid, &p, None), Err(AuthFingerprintError::Revoked));
        assert_eq!(nonce(&env, &cid, &signer), 0);

        // Signer re-issues with the same nonce and a new body.
        let reissued = payload(&env, &signer, 0, b"a2");
        consume(&env, &cid, &reissued, None).unwrap();
        // Consumed payloads cannot be revoked after the fact.
        assert_eq!(revoke(&env, &cid, &admin, &reissued), Err(AuthFingerprintError::Replayed));
    }

    #[test]
    #[should_panic]
    fn consume_requires_signer_auth() {
        let env = Env::default();
        let cid = env.register_contract(None, AuthFpTestContract);
        let signer = Address::generate(&env);
        let p = payload(&env, &signer, 0, b"a");
        let _ = consume(&env, &cid, &p, None);
    }
}
