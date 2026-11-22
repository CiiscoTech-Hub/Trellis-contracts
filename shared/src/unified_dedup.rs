//! Unified Notification and Webhook Deduplication Framework (Issue #488).
//!
//! Provides high-throughput, replay-safe deduplication for inbound webhook
//! callbacks, outbound notification dispatches, and cross-contract event relays.
//!
//! Features:
//! 1. Atomic Check-and-Reserve: Prevents double-processing of identical events
//!    arriving simultaneously over distributed networks.
//! 2. Idempotent Outcome Caching: Completed requests return their cached response
//!    hash (`ReturnCached`), allowing external retry callers to receive consistent
//!    success confirmation without duplicate side effects.
//! 3. Resilient Retries & Dead-Letter Routing: Transient failures can be retried
//!    up to [`MAX_DEDUP_ATTEMPTS`] (3) times. Exhausted retries transition to
//!    [`DedupStatus::DeadLetter`], isolating toxic messages.
//! 4. Authorization & Pruning: Only the originating caller or protocol admin
//!    can update record lifecycles or prune expired entries.
//!
//! Time complexity: O(1) reads and writes in persistent storage.
//! Space complexity: O(1) per registered event key.

#![allow(dead_code)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, BytesN, Env};

use crate::auth::require_admin;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Constants & Error Codes
// ---------------------------------------------------------------------------

pub const MAX_DEDUP_ATTEMPTS: u32 = 3;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DedupError {
    Unauthorized = 1,
    InvalidTransition = 2,
    ConcurrentConflict = 3,
    RetryCapExceeded = 4,
    RecordNotFound = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DedupChannel {
    InboundWebhook = 1,
    OutboundNotification = 2,
    CrossContractCallback = 3,
    RelayerRelay = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DedupStatus {
    Processing = 1,
    Completed = 2,
    Failed = 3,
    DeadLetter = 4,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DedupAction {
    Proceed = 1,
    ReturnCached = 2,
    RejectInFlight = 3,
    RejectDeadLetter = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedupRecord {
    pub idempotency_key: BytesN<32>,
    pub channel: DedupChannel,
    pub caller: Address,
    pub status: DedupStatus,
    pub attempts: u32,
    pub response_hash: BytesN<32>,
    pub created_ledger: u32,
    pub completed_ledger: Option<u32>,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DedupKey {
    Record(BytesN<32>),
}

// ---------------------------------------------------------------------------
// Core Deduplication Logic
// ---------------------------------------------------------------------------

pub fn check_and_reserve(
    env: &Env,
    caller: &Address,
    channel: DedupChannel,
    idempotency_key: BytesN<32>,
) -> Result<DedupAction, DedupError> {
    caller.require_auth();

    let storage_key = DedupKey::Record(idempotency_key.clone());
    let existing: Option<DedupRecord> = persistent_get(env, &storage_key);

    match existing {
        None => {
            // Unseen event: reserve for processing
            let zero_hash = BytesN::from_array(env, &[0u8; 32]);
            let record = DedupRecord {
                idempotency_key: idempotency_key.clone(),
                channel,
                caller: caller.clone(),
                status: DedupStatus::Processing,
                attempts: 1,
                response_hash: zero_hash,
                created_ledger: env.ledger().sequence(),
                completed_ledger: None,
            };
            persistent_set(env, &storage_key, &record);

            env.events().publish(
                (symbol_short!("dedup"), symbol_short!("reserve")),
                (channel, idempotency_key),
            );

            Ok(DedupAction::Proceed)
        }
        Some(mut record) => {
            match record.status {
                DedupStatus::Completed => {
                    // Safe replay: return cached outcome without reprocessing
                    Ok(DedupAction::ReturnCached)
                }
                DedupStatus::Processing => {
                    // Concurrent execution in progress: prevent duplicate race
                    Ok(DedupAction::RejectInFlight)
                }
                DedupStatus::DeadLetter => {
                    // Poison pill message: permanently rejected
                    Ok(DedupAction::RejectDeadLetter)
                }
                DedupStatus::Failed => {
                    if record.attempts >= MAX_DEDUP_ATTEMPTS {
                        record.status = DedupStatus::DeadLetter;
                        persistent_set(env, &storage_key, &record);
                        Ok(DedupAction::RejectDeadLetter)
                    } else {
                        record.attempts += 1;
                        record.status = DedupStatus::Processing;
                        persistent_set(env, &storage_key, &record);

                        env.events().publish(
                            (symbol_short!("dedup"), symbol_short!("retry")),
                            (channel, idempotency_key, record.attempts),
                        );

                        Ok(DedupAction::Proceed)
                    }
                }
            }
        }
    }
}

pub fn finalize_success(
    env: &Env,
    caller: &Address,
    idempotency_key: BytesN<32>,
    response_hash: BytesN<32>,
) -> Result<(), DedupError> {
    caller.require_auth();

    let storage_key = DedupKey::Record(idempotency_key.clone());
    let mut record: DedupRecord =
        persistent_get(env, &storage_key).ok_or(DedupError::RecordNotFound)?;

    if &record.caller != caller && require_admin(env, caller).is_err() {
        return Err(DedupError::Unauthorized);
    }

    if record.status != DedupStatus::Processing {
        return Err(DedupError::InvalidTransition);
    }

    record.status = DedupStatus::Completed;
    record.response_hash = response_hash.clone();
    record.completed_ledger = Some(env.ledger().sequence());

    persistent_set(env, &storage_key, &record);

    env.events().publish(
        (symbol_short!("dedup"), symbol_short!("success")),
        (idempotency_key, response_hash),
    );

    Ok(())
}

pub fn finalize_failure(
    env: &Env,
    caller: &Address,
    idempotency_key: BytesN<32>,
) -> Result<(), DedupError> {
    caller.require_auth();

    let storage_key = DedupKey::Record(idempotency_key.clone());
    let mut record: DedupRecord =
        persistent_get(env, &storage_key).ok_or(DedupError::RecordNotFound)?;

    if &record.caller != caller && require_admin(env, caller).is_err() {
        return Err(DedupError::Unauthorized);
    }

    if record.status != DedupStatus::Processing {
        return Err(DedupError::InvalidTransition);
    }

    if record.attempts >= MAX_DEDUP_ATTEMPTS {
        record.status = DedupStatus::DeadLetter;
    } else {
        record.status = DedupStatus::Failed;
    }

    persistent_set(env, &storage_key, &record);

    env.events().publish(
        (symbol_short!("dedup"), symbol_short!("failure")),
        (idempotency_key, record.attempts, record.status),
    );

    Ok(())
}

pub fn get_dedup_record(env: &Env, idempotency_key: BytesN<32>) -> Option<DedupRecord> {
    let storage_key = DedupKey::Record(idempotency_key);
    persistent_get(env, &storage_key)
}

pub fn prune_dedup_record(
    env: &Env,
    admin: &Address,
    idempotency_key: BytesN<32>,
) -> Result<(), DedupError> {
    require_admin(env, admin).map_err(|_| DedupError::Unauthorized)?;

    let storage_key = DedupKey::Record(idempotency_key.clone());
    let record: DedupRecord =
        persistent_get(env, &storage_key).ok_or(DedupError::RecordNotFound)?;

    // Can only prune completed or dead-lettered entries
    if record.status == DedupStatus::Processing {
        return Err(DedupError::InvalidTransition);
    }

    // Soroban storage removal via setting or overwriting
    env.storage().persistent().remove(&storage_key);

    env.events().publish(
        (symbol_short!("dedup"), symbol_short!("pruned")),
        idempotency_key,
    );

    Ok(())
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
    struct DedupTestContract;
    #[contractimpl]
    impl DedupTestContract {}

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(20_000);
        let cid = env.register_contract(None, DedupTestContract);
        let admin = Address::generate(&env);
        let worker = Address::generate(&env);
        let unprivileged = Address::generate(&env);

        env.as_contract(&cid, || {
            crate::auth::set_admin(&env, &admin);
        });

        (env, cid, admin, worker, unprivileged)
    }

    fn reserve(
        env: &Env,
        cid: &Address,
        caller: &Address,
        ch: DedupChannel,
        key: BytesN<32>,
    ) -> Result<DedupAction, DedupError> {
        env.as_contract(cid, || check_and_reserve(env, caller, ch, key))
    }

    fn fin_succ(
        env: &Env,
        cid: &Address,
        caller: &Address,
        key: BytesN<32>,
        hash: BytesN<32>,
    ) -> Result<(), DedupError> {
        env.as_contract(cid, || finalize_success(env, caller, key, hash))
    }

    fn fin_fail(
        env: &Env,
        cid: &Address,
        caller: &Address,
        key: BytesN<32>,
    ) -> Result<(), DedupError> {
        env.as_contract(cid, || finalize_failure(env, caller, key))
    }

    fn get_rec(env: &Env, cid: &Address, key: BytesN<32>) -> Option<DedupRecord> {
        env.as_contract(cid, || get_dedup_record(env, key))
    }

    fn prune(env: &Env, cid: &Address, admin: &Address, key: BytesN<32>) -> Result<(), DedupError> {
        env.as_contract(cid, || prune_dedup_record(env, admin, key))
    }

    #[test]
    fn test_normal_idempotent_lifecycle() {
        let (env, cid, _, worker, _) = setup();

        let key = BytesN::from_array(&env, &[11u8; 32]);
        let response_hash = BytesN::from_array(&env, &[99u8; 32]);

        // 1. Initial reservation
        let action = reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::InboundWebhook,
            key.clone(),
        )
        .unwrap();
        assert_eq!(action, DedupAction::Proceed);

        // 2. Finalize success
        fin_succ(&env, &cid, &worker, key.clone(), response_hash.clone()).unwrap();

        let record = get_rec(&env, &cid, key.clone()).unwrap();
        assert_eq!(record.status, DedupStatus::Completed);
        assert_eq!(record.response_hash, response_hash);
        assert_eq!(record.completed_ledger, Some(20_000));

        // 3. Duplicate request returns cached outcome
        let dup_action = reserve(&env, &cid, &worker, DedupChannel::InboundWebhook, key).unwrap();
        assert_eq!(dup_action, DedupAction::ReturnCached);
    }

    #[test]
    fn test_concurrent_in_flight_rejection() {
        let (env, cid, _, worker, _) = setup();

        let key = BytesN::from_array(&env, &[12u8; 32]);

        // First worker reserves
        let action1 = reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::OutboundNotification,
            key.clone(),
        )
        .unwrap();
        assert_eq!(action1, DedupAction::Proceed);

        // Concurrent duplicate attempt while still processing
        let action2 =
            reserve(&env, &cid, &worker, DedupChannel::OutboundNotification, key).unwrap();
        assert_eq!(action2, DedupAction::RejectInFlight);
    }

    #[test]
    fn test_failure_retry_and_dead_letter() {
        let (env, cid, _, worker, _) = setup();

        let key = BytesN::from_array(&env, &[13u8; 32]);

        // Attempt 1: reserve and fail
        reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::CrossContractCallback,
            key.clone(),
        )
        .unwrap();
        fin_fail(&env, &cid, &worker, key.clone()).unwrap();
        assert_eq!(
            get_rec(&env, &cid, key.clone()).unwrap().status,
            DedupStatus::Failed
        );

        // Attempt 2: retry and fail
        let action2 = reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::CrossContractCallback,
            key.clone(),
        )
        .unwrap();
        assert_eq!(action2, DedupAction::Proceed);
        fin_fail(&env, &cid, &worker, key.clone()).unwrap();

        // Attempt 3: retry and fail -> reaches max attempts
        let action3 = reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::CrossContractCallback,
            key.clone(),
        )
        .unwrap();
        assert_eq!(action3, DedupAction::Proceed);
        fin_fail(&env, &cid, &worker, key.clone()).unwrap();
        assert_eq!(
            get_rec(&env, &cid, key.clone()).unwrap().status,
            DedupStatus::DeadLetter
        );

        // Attempt 4: routed to dead letter and rejected
        let action4 = reserve(
            &env,
            &cid,
            &worker,
            DedupChannel::CrossContractCallback,
            key,
        )
        .unwrap();
        assert_eq!(action4, DedupAction::RejectDeadLetter);
    }

    #[test]
    fn test_authorization_path_rejects_unprivileged() {
        let (env, cid, admin, worker, unprivileged) = setup();

        let key = BytesN::from_array(&env, &[14u8; 32]);
        let resp = BytesN::from_array(&env, &[100u8; 32]);

        reserve(&env, &cid, &worker, DedupChannel::RelayerRelay, key.clone()).unwrap();

        // Unprivileged cannot finalize worker's record
        let err1 = fin_succ(&env, &cid, &unprivileged, key.clone(), resp.clone()).unwrap_err();
        assert_eq!(err1, DedupError::Unauthorized);

        // Worker can finalize
        fin_succ(&env, &cid, &worker, key.clone(), resp).unwrap();

        // Unprivileged cannot prune
        let err2 = prune(&env, &cid, &unprivileged, key.clone()).unwrap_err();
        assert_eq!(err2, DedupError::Unauthorized);

        // Admin can prune
        prune(&env, &cid, &admin, key.clone()).unwrap();
        assert!(get_rec(&env, &cid, key).is_none());
    }
}
