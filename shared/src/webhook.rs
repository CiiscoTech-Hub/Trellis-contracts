//! Signed webhook verification with replay-window enforcement (Issue #60).
//!
//! Inbound integration callbacks must be authenticated cryptographically and
//! refused when replayed or stale. This module provides:
//!
//! - [`sign_webhook`] — HMAC-SHA256 over `event_id || timestamp_be || payload`
//!   (the same construction webhook providers use).
//! - [`verify_and_consume`] — the single entry point contracts call. It checks
//!   the timestamp window, verifies the signature in constant time, rejects
//!   duplicate `event_id`s, and only then records the event as processed so a
//!   valid event cannot cause side effects twice.
//!
//! ## Ordering and errors
//!
//! | Condition | Result |
//! |---|---|
//! | Empty / oversized payload | [`Error::InvalidArgument`] |
//! | Timestamp outside `replay_window_seconds` (past or future) | [`Error::Expired`] |
//! | Signature mismatch | [`Error::Unauthorized`] |
//! | `event_id` already processed | [`Error::AlreadyClaimed`] |
//!
//! Processed ids are persisted so they survive ledger closures. Signature
//! comparison is constant-time to avoid leaking match length.

use soroban_sdk::{contracttype, Bytes, BytesN, Env};

use crate::errors::Error;
use crate::storage::{persistent_has, persistent_set};

/// Largest accepted webhook payload.
pub const MAX_PAYLOAD_BYTES: u32 = 4096;

/// Replay/timestamp configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookConfig {
    /// Maximum age (seconds) of an accepted event.
    pub replay_window_seconds: u64,
    /// Maximum tolerated future clock skew (seconds).
    pub max_future_skew_seconds: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            replay_window_seconds: 300,
            max_future_skew_seconds: 60,
        }
    }
}

/// Storage key for processed webhook event ids.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebhookKey {
    Processed(BytesN<32>),
}

/// A webhook event as received (without its signature).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookEvent {
    /// Stable event id, shared across retries.
    pub event_id: BytesN<32>,
    /// Unix seconds when the provider signed the event.
    pub timestamp: u64,
    /// Raw request body bytes.
    pub payload: Bytes,
}

/// The exact bytes that are signed: `event_id || timestamp_be || payload`.
pub fn webhook_message(env: &Env, event: &WebhookEvent) -> Bytes {
    let mut msg = Bytes::new(env);
    msg.append(&Bytes::from_slice(env, &event.event_id.to_array()));
    msg.append(&Bytes::from_slice(env, &event.timestamp.to_be_bytes()));
    msg.append(&event.payload);
    msg
}

/// HMAC-SHA256 (RFC 2104) built from the host `sha256` primitive.
pub fn hmac_sha256(env: &Env, key: &Bytes, message: &Bytes) -> BytesN<32> {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let digest = env.crypto().sha256(key).to_array();
        k[..32].copy_from_slice(&digest);
    } else {
        let mut i = 0u32;
        while i < key.len() {
            k[i as usize] = key.get(i).unwrap();
            i += 1;
        }
    }

    let mut inner = [0u8; 64];
    let mut outer = [0u8; 64];
    for (dst, src) in inner.iter_mut().zip(k.iter()) {
        *dst = *src ^ 0x36;
    }
    for (dst, src) in outer.iter_mut().zip(k.iter()) {
        *dst = *src ^ 0x5c;
    }

    let mut inner_input = Bytes::from_slice(env, &inner);
    inner_input.append(message);
    let inner_hash = env.crypto().sha256(&inner_input);

    let mut outer_input = Bytes::from_slice(env, &outer);
    outer_input.append(&Bytes::from_slice(env, &inner_hash.to_array()));
    env.crypto().sha256(&outer_input).to_bytes()
}

/// Compute the signature a provider would send for `event`.
pub fn sign_webhook(env: &Env, secret: &Bytes, event: &WebhookEvent) -> BytesN<32> {
    hmac_sha256(env, secret, &webhook_message(env, event))
}

fn constant_time_eq(a: &BytesN<32>, b: &BytesN<32>) -> bool {
    let x = a.to_array();
    let y = b.to_array();
    let mut diff = 0u8;
    for (p, q) in x.iter().zip(y.iter()) {
        diff |= *p ^ *q;
    }
    diff == 0
}

/// Verify only the signature (used by read-only validation paths).
pub fn verify_signature(
    env: &Env,
    secret: &Bytes,
    event: &WebhookEvent,
    signature: &BytesN<32>,
) -> Result<(), Error> {
    let expected = sign_webhook(env, secret, event);
    if constant_time_eq(&expected, signature) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

/// Enforce the replay window against the current ledger time.
pub fn check_timestamp(
    env: &Env,
    config: &WebhookConfig,
    event: &WebhookEvent,
) -> Result<(), Error> {
    let now = env.ledger().timestamp();
    if event.timestamp > now {
        if event.timestamp - now > config.max_future_skew_seconds {
            return Err(Error::Expired);
        }
        return Ok(());
    }
    if now - event.timestamp > config.replay_window_seconds {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Returns `true` when `event_id` was already consumed.
pub fn is_processed(env: &Env, event_id: &BytesN<32>) -> bool {
    persistent_has(env, &WebhookKey::Processed(event_id.clone()))
}

/// Record `event_id` as processed.
pub fn mark_processed(env: &Env, event_id: &BytesN<32>) {
    persistent_set(env, &WebhookKey::Processed(event_id.clone()), &true);
}

/// Full verification path: shape -> timestamp -> signature -> replay.
///
/// On success the event id is persisted, so a second call with the same id
/// returns [`Error::AlreadyClaimed`] and side effects must not repeat.
pub fn verify_and_consume(
    env: &Env,
    secret: &Bytes,
    config: &WebhookConfig,
    event: &WebhookEvent,
    signature: &BytesN<32>,
) -> Result<(), Error> {
    if event.payload.is_empty() || event.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::InvalidArgument);
    }
    check_timestamp(env, config, event)?;
    verify_signature(env, secret, event, signature)?;
    if is_processed(env, &event.event_id) {
        return Err(Error::AlreadyClaimed);
    }
    mark_processed(env, &event.event_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Ledger;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct MockContract;

    #[contractimpl]
    impl MockContract {
        pub fn ping() -> u32 {
            1
        }
    }

    fn event(env: &Env, id: u8, ts: u64, body: &[u8]) -> WebhookEvent {
        WebhookEvent {
            event_id: BytesN::from_array(env, &[id; 32]),
            timestamp: ts,
            payload: Bytes::from_slice(env, body),
        }
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        let env = Env::default();
        let key = Bytes::from_slice(&env, &[0x0bu8; 20]);
        let msg = Bytes::from_slice(&env, b"Hi There");
        let expected = BytesN::from_array(
            &env,
            &[
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ],
        );
        assert_eq!(hmac_sha256(&env, &key, &msg), expected);
    }

    #[test]
    fn valid_event_is_accepted_once() {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);
        let contract_id = env.register_contract(None, MockContract);
        let secret = Bytes::from_slice(&env, b"super-secret");
        let ev = event(&env, 1, 990, b"{\"ok\":true}");
        let sig = sign_webhook(&env, &secret, &ev);
        let cfg = WebhookConfig::default();

        env.as_contract(&contract_id, || {
            assert!(verify_and_consume(&env, &secret, &cfg, &ev, &sig).is_ok());
            // Replay of a valid, in-window event must not repeat side effects.
            assert_eq!(
                verify_and_consume(&env, &secret, &cfg, &ev, &sig),
                Err(Error::AlreadyClaimed)
            );
            assert!(is_processed(&env, &ev.event_id));
        });
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);
        let secret = Bytes::from_slice(&env, b"super-secret");
        let ev = event(&env, 2, 990, b"{}");
        let bad = BytesN::from_array(&env, &[0u8; 32]);
        assert_eq!(
            verify_and_consume(&env, &secret, &WebhookConfig::default(), &ev, &bad),
            Err(Error::Unauthorized)
        );

        // A different secret must not validate the original signature.
        let sig = sign_webhook(&env, &secret, &ev);
        let other = Bytes::from_slice(&env, b"other-secret");
        assert_eq!(
            verify_signature(&env, &other, &ev, &sig),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn stale_and_far_future_events_are_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(10_000);
        let secret = Bytes::from_slice(&env, b"secret");
        let cfg = WebhookConfig::default();

        let edge = event(&env, 6, 10_000 - cfg.replay_window_seconds, b"{}");
        assert!(check_timestamp(&env, &cfg, &edge).is_ok());
        let f_edge = event(&env, 7, 10_000 + cfg.max_future_skew_seconds, b"{}");
        assert!(check_timestamp(&env, &cfg, &f_edge).is_ok());

        let stale = event(&env, 3, 10_000 - cfg.replay_window_seconds - 1, b"{}");
        let stale_sig = sign_webhook(&env, &secret, &stale);
        assert_eq!(
            verify_and_consume(&env, &secret, &cfg, &stale, &stale_sig),
            Err(Error::Expired)
        );

        let future = event(&env, 4, 10_000 + cfg.max_future_skew_seconds + 1, b"{}");
        let future_sig = sign_webhook(&env, &secret, &future);
        assert_eq!(
            verify_and_consume(&env, &secret, &cfg, &future, &future_sig),
            Err(Error::Expired)
        );
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);
        let secret = Bytes::from_slice(&env, b"secret");
        let ev = event(&env, 5, 990, b"");
        let sig = sign_webhook(&env, &secret, &ev);
        assert_eq!(
            verify_and_consume(&env, &secret, &WebhookConfig::default(), &ev, &sig),
            Err(Error::InvalidArgument)
        );
    }
}
