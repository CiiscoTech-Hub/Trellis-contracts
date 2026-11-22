//! Duplicate suppression for outbound notifications and inbound/outbound webhooks (Issue #280).
//!
//! While [`crate::webhook`] authenticates and deduplicates raw inbound webhook
//! callbacks by `event_id`, Trellis also dispatches outbound notifications
//! (webhook, email, push, in-app, SMS) and processes retryable deliveries where
//! the same logical notification can be triggered multiple times across retries
//! or concurrent workers.
//!
//! This module provides:
//! - Deterministic `dedupe_key` derivation from `(channel, recipient, event_id)`.
//! - Conflict detection when the same `dedupe_key` is reused with a different `payload_hash`.
//! - Bounded retry tracking (`InFlight` -> `Retry(attempt)` up to `max_attempts`).
//! - Time-windowed duplicate suppression (`Delivered` -> `Suppress(count)` within `window_seconds`).
//! - Admin-authorized recovery (`reset_suppression`) for permanently failed or stuck deliveries.

use soroban_sdk::{contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_remove, persistent_set};

/// Delivery channel for notifications and webhooks.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeliveryChannel {
    Webhook,
    Email,
    Push,
    InApp,
    Sms,
}

impl DeliveryChannel {
    fn tag(self) -> u8 {
        match self {
            DeliveryChannel::Webhook => 1,
            DeliveryChannel::Email => 2,
            DeliveryChannel::Push => 3,
            DeliveryChannel::InApp => 4,
            DeliveryChannel::Sms => 5,
        }
    }
}

/// Configuration for duplicate suppression and retry bounds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuppressionPolicy {
    /// Time window (seconds) during which a completed delivery suppresses duplicates.
    pub window_seconds: u64,
    /// Maximum number of dispatch attempts allowed while `InFlight`.
    pub max_attempts: u32,
}

impl Default for SuppressionPolicy {
    fn default() -> Self {
        Self {
            window_seconds: 300,
            max_attempts: 3,
        }
    }
}

/// Lifecycle state of a deduplicated delivery.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuppressionState {
    InFlight,
    Delivered,
    FailedPermanent,
}

/// Persisted delivery record keyed by `dedupe_key`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    pub dedupe_key: BytesN<32>,
    pub channel: DeliveryChannel,
    pub recipient: Address,
    pub payload_hash: BytesN<32>,
    pub first_seen: u64,
    pub last_attempt: u64,
    pub attempts: u32,
    pub suppressed_count: u32,
    pub state: SuppressionState,
}

/// Decision returned by [`begin_delivery`].
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeliveryDecision {
    /// First time seeing this delivery (or suppression window expired); proceed to send.
    Dispatch,
    /// Previous attempt is still `InFlight`; proceed with retry attempt `u32`.
    Retry(u32),
    /// Delivery already completed within the suppression window; skip sending (total suppressed `u32`).
    Suppress(u32),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuppressionKey {
    Record(BytesN<32>),
}

/// Derive a deterministic 32-byte deduplication key from `(channel, recipient, event_id)`.
pub fn compute_dedupe_key(
    env: &Env,
    channel: DeliveryChannel,
    recipient: &Address,
    event_id: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.push_back(channel.tag());
    preimage.append(&recipient.to_xdr(env));
    preimage.append(&Bytes::from_slice(env, &event_id.to_array()));
    env.crypto().sha256(&preimage).to_bytes()
}

/// Read-only lookup for a delivery record.
pub fn get_delivery_record(env: &Env, dedupe_key: &BytesN<32>) -> Option<DeliveryRecord> {
    persistent_get(env, &SuppressionKey::Record(dedupe_key.clone()))
}

/// Evaluate whether a notification or webhook should be dispatched, retried, or suppressed.
///
/// - Calls `caller.require_auth()`.
/// - Rejects `policy.max_attempts == 0` with [`Error::InvalidArgument`].
/// - Rejects payload mismatches for an existing `dedupe_key` with [`Error::InvalidArgument`].
/// - Rejects permanently failed or retry-exhausted deliveries with [`Error::QuotaExceeded`].
pub fn begin_delivery(
    env: &Env,
    caller: &Address,
    policy: &SuppressionPolicy,
    channel: DeliveryChannel,
    recipient: &Address,
    event_id: &BytesN<32>,
    payload_hash: &BytesN<32>,
) -> Result<(BytesN<32>, DeliveryDecision), Error> {
    caller.require_auth();
    if policy.max_attempts == 0 {
        return Err(Error::InvalidArgument);
    }

    let now = env.ledger().timestamp();
    let dedupe_key = compute_dedupe_key(env, channel, recipient, event_id);
    let key = SuppressionKey::Record(dedupe_key.clone());

    if let Some(mut record) = persistent_get::<_, DeliveryRecord>(env, &key) {
        if record.payload_hash != *payload_hash {
            return Err(Error::InvalidArgument);
        }

        match record.state {
            SuppressionState::Delivered => {
                if now.saturating_sub(record.last_attempt) <= policy.window_seconds {
                    record.suppressed_count = record.suppressed_count.saturating_add(1);
                    persistent_set(env, &key, &record);
                    return Ok((
                        dedupe_key,
                        DeliveryDecision::Suppress(record.suppressed_count),
                    ));
                }
                // Window expired: start a fresh dispatch cycle.
                record.first_seen = now;
                record.last_attempt = now;
                record.attempts = 1;
                record.suppressed_count = 0;
                record.state = SuppressionState::InFlight;
                persistent_set(env, &key, &record);
                return Ok((dedupe_key, DeliveryDecision::Dispatch));
            }
            SuppressionState::InFlight => {
                if record.attempts >= policy.max_attempts {
                    record.state = SuppressionState::FailedPermanent;
                    persistent_set(env, &key, &record);
                    return Err(Error::QuotaExceeded);
                }
                record.attempts += 1;
                record.last_attempt = now;
                persistent_set(env, &key, &record);
                return Ok((dedupe_key, DeliveryDecision::Retry(record.attempts)));
            }
            SuppressionState::FailedPermanent => {
                return Err(Error::QuotaExceeded);
            }
        }
    }

    let record = DeliveryRecord {
        dedupe_key: dedupe_key.clone(),
        channel,
        recipient: recipient.clone(),
        payload_hash: payload_hash.clone(),
        first_seen: now,
        last_attempt: now,
        attempts: 1,
        suppressed_count: 0,
        state: SuppressionState::InFlight,
    };
    persistent_set(env, &key, &record);
    Ok((dedupe_key, DeliveryDecision::Dispatch))
}

/// Mark an `InFlight` delivery as `Delivered` so subsequent duplicates are suppressed.
pub fn complete_delivery(
    env: &Env,
    caller: &Address,
    dedupe_key: &BytesN<32>,
) -> Result<DeliveryRecord, Error> {
    caller.require_auth();
    let key = SuppressionKey::Record(dedupe_key.clone());
    let mut record: DeliveryRecord = persistent_get(env, &key).ok_or(Error::NotFound)?;
    if record.state == SuppressionState::FailedPermanent {
        return Err(Error::InvalidArgument);
    }
    record.state = SuppressionState::Delivered;
    record.last_attempt = env.ledger().timestamp();
    persistent_set(env, &key, &record);
    Ok(record)
}

/// Record a failed delivery attempt; marks `FailedPermanent` when `permanent` is `true`.
pub fn fail_delivery(
    env: &Env,
    caller: &Address,
    dedupe_key: &BytesN<32>,
    permanent: bool,
) -> Result<DeliveryRecord, Error> {
    caller.require_auth();
    let key = SuppressionKey::Record(dedupe_key.clone());
    let mut record: DeliveryRecord = persistent_get(env, &key).ok_or(Error::NotFound)?;
    if record.state == SuppressionState::Delivered {
        return Err(Error::AlreadyClaimed);
    }
    if permanent {
        record.state = SuppressionState::FailedPermanent;
    }
    record.last_attempt = env.ledger().timestamp();
    persistent_set(env, &key, &record);
    Ok(record)
}

/// Admin-authorized recovery: clear a suppression/failure record so delivery can be retried.
pub fn reset_suppression(
    env: &Env,
    admin: &Address,
    dedupe_key: &BytesN<32>,
) -> Result<(), Error> {
    require_admin(env, admin)?;
    let key = SuppressionKey::Record(dedupe_key.clone());
    if persistent_get::<_, DeliveryRecord>(env, &key).is_none() {
        return Err(Error::NotFound);
    }
    persistent_remove(env, &key);
    Ok(())
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
    fn normal_dispatch_and_duplicate_suppression_within_window() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(1_000);
        let contract_id = env.register_contract(None, MockContract);
        let caller = Address::generate(&env);
        let recipient = Address::generate(&env);
        let event_id = BytesN::from_array(&env, &[1u8; 32]);
        let payload_hash = BytesN::from_array(&env, &[2u8; 32]);
        let policy = SuppressionPolicy::default();

        env.as_contract(&contract_id, || {
            let (key, dec1) = begin_delivery(
                &env,
                &caller,
                &policy,
                DeliveryChannel::Webhook,
                &recipient,
                &event_id,
                &payload_hash,
            )
            .unwrap();
            assert_eq!(dec1, DeliveryDecision::Dispatch);

            complete_delivery(&env, &caller, &key).unwrap();

            // Duplicate within window is suppressed.
            env.ledger().set_timestamp(1_100);
            let (_, dec2) = begin_delivery(
                &env,
                &caller,
                &policy,
                DeliveryChannel::Webhook,
                &recipient,
                &event_id,
                &payload_hash,
            )
            .unwrap();
            assert_eq!(dec2, DeliveryDecision::Suppress(1));

            // After window expires, fresh dispatch is allowed.
            env.ledger().set_timestamp(1_500);
            let (_, dec3) = begin_delivery(
                &env,
                &caller,
                &policy,
                DeliveryChannel::Webhook,
                &recipient,
                &event_id,
                &payload_hash,
            )
            .unwrap();
            assert_eq!(dec3, DeliveryDecision::Dispatch);
        });
    }

    #[test]
    fn retry_exhaustion_and_payload_conflict_failures() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(5_000);
        let contract_id = env.register_contract(None, MockContract);
        let caller = Address::generate(&env);
        let recipient = Address::generate(&env);
        let event_id = BytesN::from_array(&env, &[9u8; 32]);
        let payload_a = BytesN::from_array(&env, &[10u8; 32]);
        let payload_b = BytesN::from_array(&env, &[11u8; 32]);
        let policy = SuppressionPolicy {
            window_seconds: 300,
            max_attempts: 2,
        };

        env.as_contract(&contract_id, || {
            let (key, dec1) = begin_delivery(
                &env,
                &caller,
                &policy,
                DeliveryChannel::Email,
                &recipient,
                &event_id,
                &payload_a,
            )
            .unwrap();
            assert_eq!(dec1, DeliveryDecision::Dispatch);

            // Conflicting payload for same dedupe_key is rejected.
            assert_eq!(
                begin_delivery(
                    &env,
                    &caller,
                    &policy,
                    DeliveryChannel::Email,
                    &recipient,
                    &event_id,
                    &payload_b,
                ),
                Err(Error::InvalidArgument)
            );

            // Second attempt is allowed as Retry(2).
            fail_delivery(&env, &caller, &key, false).unwrap();
            let (_, dec2) = begin_delivery(
                &env,
                &caller,
                &policy,
                DeliveryChannel::Email,
                &recipient,
                &event_id,
                &payload_a,
            )
            .unwrap();
            assert_eq!(dec2, DeliveryDecision::Retry(2));

            // Third attempt exceeds max_attempts -> QuotaExceeded and FailedPermanent.
            assert_eq!(
                begin_delivery(
                    &env,
                    &caller,
                    &policy,
                    DeliveryChannel::Email,
                    &recipient,
                    &event_id,
                    &payload_a,
                ),
                Err(Error::QuotaExceeded)
            );
            assert_eq!(
                get_delivery_record(&env, &key).unwrap().state,
                SuppressionState::FailedPermanent
            );
        });
    }

    #[test]
    fn reset_suppression_requires_admin_authorization() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MockContract);
        let admin = Address::generate(&env);
        let non_admin = Address::generate(&env);
        let recipient = Address::generate(&env);
        let event_id = BytesN::from_array(&env, &[3u8; 32]);
        let payload = BytesN::from_array(&env, &[4u8; 32]);

        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();

            let (key, _) = begin_delivery(
                &env,
                &non_admin,
                &SuppressionPolicy::default(),
                DeliveryChannel::Push,
                &recipient,
                &event_id,
                &payload,
            )
            .unwrap();
            fail_delivery(&env, &non_admin, &key, true).unwrap();

            // Non-admin cannot reset suppression.
            assert_eq!(
                reset_suppression(&env, &non_admin, &key),
                Err(Error::Unauthorized)
            );

            // Admin can reset and allow fresh dispatch.
            reset_suppression(&env, &admin, &key).unwrap();
            let (_, dec) = begin_delivery(
                &env,
                &non_admin,
                &SuppressionPolicy::default(),
                DeliveryChannel::Push,
                &recipient,
                &event_id,
                &payload,
            )
            .unwrap();
            assert_eq!(dec, DeliveryDecision::Dispatch);
        });
    }
}
