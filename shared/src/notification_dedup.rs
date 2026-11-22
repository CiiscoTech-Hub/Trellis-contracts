//! Notification deduplication with delivery receipts (Issue #447).
//!
//! A notification is identified by `(recipient, notification_id, channel)`.
//! The first dispatch creates a [`DeliveryReceipt`]; repeating the dispatch
//! while it is in flight or after it was delivered returns the existing
//! receipt with `duplicate = true` instead of sending again. A failed delivery
//! can be retried up to [`MAX_DELIVERY_ATTEMPTS`] times.
//!
//! Authorization:
//! - the dispatcher signs [`record_dispatch`] and [`mark_failed`];
//! - only the recipient can confirm delivery with [`confirm_delivery`].
//!
//! See `docs/NOTIFICATION_DEDUP.md` for edge cases and recovery.

use soroban_sdk::{contracterror, contracttype, Address, BytesN, Env};

pub const MAX_DELIVERY_ATTEMPTS: u32 = 3;
pub const RECEIPT_TTL_LEDGERS: u32 = 120_960; // ~7 days

const RECEIPT_KEY: u32 = 0x4e44_5250; // "NDRP"

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum NotificationError {
    ReceiptNotFound = 1,
    InvalidTransition = 2,
    RetryLimitExceeded = 3,
    DispatcherMismatch = 4,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeliveryStatus {
    Dispatched,
    Delivered,
    Failed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    pub recipient: Address,
    pub notification_id: BytesN<32>,
    pub channel: u32,
    pub dispatcher: Address,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub dispatched_ledger: u32,
    pub delivered_ledger: Option<u32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchOutcome {
    pub receipt: DeliveryReceipt,
    /// `true` when no new delivery should be sent.
    pub duplicate: bool,
}

fn key(
    recipient: &Address,
    notification_id: &BytesN<32>,
    channel: u32,
) -> (u32, Address, BytesN<32>, u32) {
    (RECEIPT_KEY, recipient.clone(), notification_id.clone(), channel)
}

fn save(env: &Env, receipt: &DeliveryReceipt) {
    let k = key(&receipt.recipient, &receipt.notification_id, receipt.channel);
    env.storage().persistent().set(&k, receipt);
    env.storage()
        .persistent()
        .extend_ttl(&k, RECEIPT_TTL_LEDGERS, RECEIPT_TTL_LEDGERS);
}

pub fn get_receipt(
    env: &Env,
    recipient: &Address,
    notification_id: &BytesN<32>,
    channel: u32,
) -> Option<DeliveryReceipt> {
    env.storage()
        .persistent()
        .get(&key(recipient, notification_id, channel))
}

/// Records a dispatch attempt. Returns `duplicate = true` when the caller must
/// not send the notification again.
pub fn record_dispatch(
    env: &Env,
    dispatcher: &Address,
    recipient: &Address,
    notification_id: &BytesN<32>,
    channel: u32,
) -> Result<DispatchOutcome, NotificationError> {
    dispatcher.require_auth();
    let ledger = env.ledger().sequence();
    match get_receipt(env, recipient, notification_id, channel) {
        None => {
            let receipt = DeliveryReceipt {
                recipient: recipient.clone(),
                notification_id: notification_id.clone(),
                channel,
                dispatcher: dispatcher.clone(),
                status: DeliveryStatus::Dispatched,
                attempts: 1,
                dispatched_ledger: ledger,
                delivered_ledger: None,
            };
            save(env, &receipt);
            Ok(DispatchOutcome {
                receipt,
                duplicate: false,
            })
        }
        Some(mut receipt) => {
            let status = receipt.status;
            match status {
                DeliveryStatus::Dispatched | DeliveryStatus::Delivered => Ok(DispatchOutcome {
                    receipt,
                    duplicate: true,
                }),
                DeliveryStatus::Failed => {
                    if receipt.attempts >= MAX_DELIVERY_ATTEMPTS {
                        return Err(NotificationError::RetryLimitExceeded);
                    }
                    receipt.attempts += 1;
                    receipt.status = DeliveryStatus::Dispatched;
                    receipt.dispatcher = dispatcher.clone();
                    receipt.dispatched_ledger = ledger;
                    save(env, &receipt);
                    Ok(DispatchOutcome {
                        receipt,
                        duplicate: false,
                    })
                }
            }
        }
    }
}

/// Recipient-signed delivery receipt. Confirming twice is a no-op.
pub fn confirm_delivery(
    env: &Env,
    recipient: &Address,
    notification_id: &BytesN<32>,
    channel: u32,
) -> Result<DeliveryReceipt, NotificationError> {
    recipient.require_auth();
    let mut receipt = get_receipt(env, recipient, notification_id, channel)
        .ok_or(NotificationError::ReceiptNotFound)?;
    let status = receipt.status;
    match status {
        DeliveryStatus::Delivered => Ok(receipt),
        DeliveryStatus::Failed => Err(NotificationError::InvalidTransition),
        DeliveryStatus::Dispatched => {
            receipt.status = DeliveryStatus::Delivered;
            receipt.delivered_ledger = Some(env.ledger().sequence());
            save(env, &receipt);
            Ok(receipt)
        }
    }
}

/// Marks an in-flight dispatch as failed so it can be retried. Only the
/// dispatcher that made the attempt may fail it.
pub fn mark_failed(
    env: &Env,
    dispatcher: &Address,
    recipient: &Address,
    notification_id: &BytesN<32>,
    channel: u32,
) -> Result<DeliveryReceipt, NotificationError> {
    dispatcher.require_auth();
    let mut receipt = get_receipt(env, recipient, notification_id, channel)
        .ok_or(NotificationError::ReceiptNotFound)?;
    if receipt.dispatcher != *dispatcher {
        return Err(NotificationError::DispatcherMismatch);
    }
    if receipt.status != DeliveryStatus::Dispatched {
        return Err(NotificationError::InvalidTransition);
    }
    receipt.status = DeliveryStatus::Failed;
    save(env, &receipt);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct NotificationDedupFixture;

    #[contractimpl]
    impl NotificationDedupFixture {
        pub fn notification_dedup_ping() -> u32 {
            1
        }
    }

    struct Ctx {
        contract_id: Address,
        dispatcher: Address,
        recipient: Address,
        id: BytesN<32>,
    }

    fn setup(env: &Env) -> Ctx {
        env.mock_all_auths();
        Ctx {
            contract_id: env.register_contract(None, NotificationDedupFixture),
            dispatcher: Address::generate(env),
            recipient: Address::generate(env),
            id: BytesN::from_array(env, &[1; 32]),
        }
    }

    #[test]
    fn first_dispatch_is_sent_and_repeats_are_deduplicated() {
        let env = Env::default();
        let c = setup(&env);
        env.as_contract(&c.contract_id, || {
            let first = record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            assert!(!first.duplicate);
            assert_eq!(first.receipt.attempts, 1);

            let again = record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            assert!(again.duplicate);
            assert_eq!(again.receipt, first.receipt);

            // A different channel is a different notification.
            let other = record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 2).unwrap();
            assert!(!other.duplicate);
        });
    }

    #[test]
    fn delivery_receipt_is_recorded_and_blocks_resend() {
        let env = Env::default();
        let c = setup(&env);
        env.ledger().set_sequence_number(10);
        env.as_contract(&c.contract_id, || {
            record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            let delivered = confirm_delivery(&env, &c.recipient, &c.id, 1).unwrap();
            assert_eq!(delivered.status, DeliveryStatus::Delivered);
            assert_eq!(delivered.delivered_ledger, Some(10));

            // Confirming twice is idempotent.
            assert_eq!(confirm_delivery(&env, &c.recipient, &c.id, 1), Ok(delivered.clone()));

            let after = record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            assert!(after.duplicate);
            assert_eq!(after.receipt.status, DeliveryStatus::Delivered);
        });
    }

    #[test]
    fn failed_delivery_retries_until_limit() {
        let env = Env::default();
        let c = setup(&env);
        env.as_contract(&c.contract_id, || {
            record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            for attempt in 2..=MAX_DELIVERY_ATTEMPTS {
                mark_failed(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
                let retry = record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
                assert!(!retry.duplicate);
                assert_eq!(retry.receipt.attempts, attempt);
            }
            mark_failed(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            assert_eq!(
                record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1),
                Err(NotificationError::RetryLimitExceeded)
            );
            // A failed notification cannot be confirmed as delivered.
            assert_eq!(
                confirm_delivery(&env, &c.recipient, &c.id, 1),
                Err(NotificationError::InvalidTransition)
            );
        });
    }

    #[test]
    fn invalid_transitions_and_missing_receipts_are_rejected() {
        let env = Env::default();
        let c = setup(&env);
        env.as_contract(&c.contract_id, || {
            assert_eq!(
                confirm_delivery(&env, &c.recipient, &c.id, 1),
                Err(NotificationError::ReceiptNotFound)
            );
            assert_eq!(
                mark_failed(&env, &c.dispatcher, &c.recipient, &c.id, 1),
                Err(NotificationError::ReceiptNotFound)
            );
            record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            confirm_delivery(&env, &c.recipient, &c.id, 1).unwrap();
            assert_eq!(
                mark_failed(&env, &c.dispatcher, &c.recipient, &c.id, 1),
                Err(NotificationError::InvalidTransition)
            );
        });
    }

    #[test]
    fn only_the_dispatching_party_can_fail_a_dispatch() {
        let env = Env::default();
        let c = setup(&env);
        env.as_contract(&c.contract_id, || {
            record_dispatch(&env, &c.dispatcher, &c.recipient, &c.id, 1).unwrap();
            let other = Address::generate(&env);
            assert_eq!(
                mark_failed(&env, &other, &c.recipient, &c.id, 1),
                Err(NotificationError::DispatcherMismatch)
            );
        });
    }

    #[test]
    #[should_panic]
    fn confirm_requires_recipient_signature() {
        let env = Env::default();
        let contract_id = env.register_contract(None, NotificationDedupFixture);
        let recipient = Address::generate(&env);
        let id = BytesN::from_array(&env, &[2; 32]);
        env.as_contract(&contract_id, || {
            let _ = confirm_delivery(&env, &recipient, &id, 1);
        });
    }
}
