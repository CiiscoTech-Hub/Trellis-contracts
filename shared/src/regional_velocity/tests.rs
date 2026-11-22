//! Tests for regional disbursement quota + velocity breaker (Issue #539).
//!
//! Coverage map:
//! - normal: configure, disburse under both limits
//! - failure: volume over quota, velocity burst latches breaker, bad config,
//!   non-positive amount
//! - retry: window rollover re-admits traffic; rejected op leaves no state
//! - authorization: non-admin cannot configure or reset
//! - recovery: cooldown auto-recovery + manual reset / trip

use super::*;
use crate::auth;
use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, testutils::Ledger, Address, Env,
    Symbol,
};

fn region() -> Symbol {
    symbol_short!("sahel")
}

fn limit(max_amount: i128, max_ops: u32, cooldown: u64) -> RegionLimit {
    RegionLimit {
        quota_window_secs: 3_600,
        max_amount_per_window: max_amount,
        velocity_window_secs: 600,
        max_ops_per_velocity_window: max_ops,
        cooldown_secs: cooldown,
    }
}

#[contract]
struct Harness;

#[contractimpl]
impl Harness {
    pub fn set_admin(env: Env, admin: Address) {
        auth::set_admin(&env, &admin);
    }

    pub fn configure(env: Env, caller: Address, lim: RegionLimit) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        set_region_limit(&env, &region(), &lim)
    }

    pub fn disburse(env: Env, amount: i128) -> Result<GuardReceipt, Error> {
        guard_disbursement(&env, &region(), amount)
    }

    pub fn status(env: Env) -> RegionStatus {
        region_status(&env, &region())
    }

    pub fn reset(env: Env, caller: Address) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        reset_breaker(&env, &region())
    }
}

#[test]
fn invalid_config_rejected() {
    let env = Env::default();
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        let bad = RegionLimit {
            quota_window_secs: 0,
            ..limit(1_000, 5, 0)
        };
        assert_eq!(bad.validate().unwrap_err(), Error::ConfigInvalid);
        let bad2 = RegionLimit {
            max_ops_per_velocity_window: 0,
            ..limit(1_000, 5, 0)
        };
        assert_eq!(
            set_region_limit(&env, &region(), &bad2).unwrap_err(),
            Error::ConfigInvalid
        );
    });
}

#[test]
fn unconfigured_region_fails_open() {
    let env = Env::default();
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        let receipt = guard_disbursement(&env, &region(), 10_000).unwrap();
        assert!(!receipt.configured);
        assert!(!receipt.breaker_armed);
        // No state persisted for an unconfigured region.
        assert!(get_region_state(&env, &region()).is_none());
    });
}

#[test]
fn non_positive_amount_rejected() {
    let env = Env::default();
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        set_region_limit(&env, &region(), &limit(1_000, 5, 0)).unwrap();
        assert_eq!(
            guard_disbursement(&env, &region(), 0).unwrap_err(),
            Error::InvalidAmount
        );
        assert_eq!(
            guard_disbursement(&env, &region(), -5).unwrap_err(),
            Error::InvalidAmount
        );
    });
}

#[test]
fn normal_disbursement_records_state() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        set_region_limit(&env, &region(), &limit(1_000, 5, 0)).unwrap();
        let r = guard_disbursement(&env, &region(), 400).unwrap();
        assert!(r.configured);
        assert_eq!(r.quota_amount_after, 400);
        assert_eq!(r.vel_ops_after, 1);
        let st = region_status(&env, &region());
        assert_eq!(st.quota_remaining, 600);
        assert!(!st.breaker_active);
    });
}

#[test]
fn volume_quota_enforced_and_rolls_over() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        set_region_limit(&env, &region(), &limit(1_000, 100, 0)).unwrap();
        guard_disbursement(&env, &region(), 600).unwrap();
        // 600 + 600 = 1200 > 1000 cap: rejected, no surviving state change.
        assert_eq!(
            guard_disbursement(&env, &region(), 600).unwrap_err(),
            Error::QuotaExceeded
        );
        // The rejected op left the window total at 600 (retry with a fit works).
        let r = guard_disbursement(&env, &region(), 400).unwrap();
        assert_eq!(r.quota_amount_after, 1_000);

        // Advance past the quota window: the cap resets.
        env.ledger().with_mut(|l| l.timestamp += 3_601);
        let r2 = guard_disbursement(&env, &region(), 900).unwrap();
        assert_eq!(r2.quota_amount_after, 900);
    });
}

#[test]
fn velocity_breaker_latches_and_blocks() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        // max 3 ops / velocity window, generous volume cap, manual-reset breaker.
        set_region_limit(&env, &region(), &limit(1_000_000, 3, 0)).unwrap();
        let r1 = guard_disbursement(&env, &region(), 1).unwrap();
        assert!(!r1.breaker_armed);
        let r2 = guard_disbursement(&env, &region(), 1).unwrap();
        assert!(!r2.breaker_armed);
        // 3rd op reaches the threshold: allowed, and arms the breaker.
        let r3 = guard_disbursement(&env, &region(), 1).unwrap();
        assert!(r3.breaker_armed);
        assert_eq!(r3.vel_ops_after, 3);
        // 4th op is blocked by the latched breaker.
        assert_eq!(
            guard_disbursement(&env, &region(), 1).unwrap_err(),
            Error::OperationPaused
        );
        assert!(region_status(&env, &region()).breaker_active);
    });
}

#[test]
fn breaker_cooldown_auto_recovers() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        set_region_limit(&env, &region(), &limit(1_000_000, 2, 300)).unwrap();
        guard_disbursement(&env, &region(), 1).unwrap();
        let armed = guard_disbursement(&env, &region(), 1).unwrap();
        assert!(armed.breaker_armed);
        // Still cooling down.
        env.ledger().with_mut(|l| l.timestamp += 100);
        assert_eq!(
            guard_disbursement(&env, &region(), 1).unwrap_err(),
            Error::OperationPaused
        );
        // Cooldown elapsed: breaker auto-clears and a fresh velocity window opens.
        env.ledger().with_mut(|l| l.timestamp += 250);
        let recovered = guard_disbursement(&env, &region(), 1).unwrap();
        assert!(!recovered.breaker_armed);
        assert_eq!(recovered.vel_ops_after, 1);
    });
}

#[test]
fn manual_reset_and_trip() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        set_region_limit(&env, &region(), &limit(1_000_000, 2, 0)).unwrap();
        guard_disbursement(&env, &region(), 1).unwrap();
        guard_disbursement(&env, &region(), 1).unwrap(); // arms
        assert!(region_status(&env, &region()).breaker_active);
        reset_breaker(&env, &region()).unwrap();
        assert!(!region_status(&env, &region()).breaker_active);
        // Manual trip blocks again.
        trip_breaker(&env, &region()).unwrap();
        assert_eq!(
            guard_disbursement(&env, &region(), 1).unwrap_err(),
            Error::OperationPaused
        );
    });
}

#[test]
fn reset_and_trip_require_configured_region() {
    let env = Env::default();
    let id = env.register_contract(None, Harness);
    env.as_contract(&id, || {
        assert_eq!(reset_breaker(&env, &region()).unwrap_err(), Error::NotFound);
        assert_eq!(trip_breaker(&env, &region()).unwrap_err(), Error::NotFound);
    });
}

// ----- Authorization path (via the contract harness) -----------------------

#[test]
fn admin_may_configure_and_reset() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    let client = HarnessClient::new(&env, &id);
    let admin = Address::generate(&env);

    client.set_admin(&admin);
    client.configure(&admin, &limit(1_000_000, 2, 0));
    client.disburse(&1);
    client.disburse(&1); // arms breaker
    assert!(client.status().breaker_active);
    client.reset(&admin);
    assert!(!client.status().breaker_active);
}

#[test]
fn non_admin_cannot_configure_or_reset() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, Harness);
    let client = HarnessClient::new(&env, &id);
    let admin = Address::generate(&env);
    let intruder = Address::generate(&env);

    client.set_admin(&admin);
    assert_eq!(
        client.try_configure(&intruder, &limit(1_000, 2, 0)),
        Err(Ok(Error::Unauthorized))
    );
    // Configure legitimately, then a non-admin reset is refused.
    client.configure(&admin, &limit(1_000_000, 2, 0));
    assert_eq!(client.try_reset(&intruder), Err(Ok(Error::Unauthorized)));
}
