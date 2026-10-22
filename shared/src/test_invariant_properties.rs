#![cfg(test)]

//! Property tests for financial and ownership invariants (Issue #350).
//!
//! Randomised inputs come from a fixed-seed generator, so every failure is
//! reproducible from the seed printed in the assertion message. No external
//! property-testing crate is needed.

extern crate std;

use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    Address, Env,
};

use crate::auth::{
    accept_ownership_transfer, cancel_ownership_transfer, get_admin,
    get_pending_ownership_transfer, has_role, initialize_admin, propose_ownership_transfer,
    PendingOwnershipTransfer, Role,
};
use crate::errors::Error;
use crate::payments::{calculate_fee, calculate_fee_split};

const CASES: usize = 512;
const WALK_STEPS: usize = 300;
const BASE_TIME: u64 = 1_000;
const MAX_FEE_BPS: i128 = 10_000;

/// Deterministic xorshift64* generator.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `0..n`. `n` must be non-zero.
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Inclusive range `lo..=hi`. Both bounds must be non-negative.
    fn next_i128_in(&mut self, lo: i128, hi: i128) -> i128 {
        let span = (hi - lo) as u128 + 1;
        let wide = ((self.next_u64() as u128) << 64) | self.next_u64() as u128;
        lo + (wide % span) as i128
    }
}

// ---------------------------------------------------------------------------
// Financial invariants: fee split
// ---------------------------------------------------------------------------

#[test]
fn fee_split_conserves_the_full_amount_across_random_inputs() {
    let env = Env::default();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    // Largest amount whose fee multiplication cannot overflow.
    let max_amount = i128::MAX / MAX_FEE_BPS;
    for case in 0..CASES {
        let amount = rng.next_i128_in(1, max_amount);
        let rate = rng.next_i128_in(0, MAX_FEE_BPS);
        let (fee, net) = calculate_fee_split(&env, amount, rate).unwrap();
        assert_eq!(
            fee + net,
            amount,
            "case {case}: conservation failed for amount={amount} rate={rate}"
        );
        assert!(
            fee >= 0 && net >= 0 && fee <= amount,
            "case {case}: fee or net out of bounds"
        );
        assert_eq!(fee, calculate_fee(&env, amount, rate).unwrap());
    }
}

#[test]
fn fee_is_monotonic_in_rate_for_a_fixed_amount() {
    let env = Env::default();
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let max_amount = i128::MAX / MAX_FEE_BPS;
    for case in 0..CASES {
        let amount = rng.next_i128_in(1, max_amount);
        let low = rng.next_i128_in(0, MAX_FEE_BPS);
        let high = rng.next_i128_in(low, MAX_FEE_BPS);
        let fee_low = calculate_fee(&env, amount, low).unwrap();
        let fee_high = calculate_fee(&env, amount, high).unwrap();
        assert!(
            fee_low <= fee_high,
            "case {case}: fee fell from {fee_low} to {fee_high} as rate rose {low}->{high}"
        );
    }
}

#[test]
fn fee_boundary_rates_take_nothing_or_everything() {
    let env = Env::default();
    let amount = 1_234_567_i128;
    assert_eq!(calculate_fee_split(&env, amount, 0), Ok((0, amount)));
    assert_eq!(
        calculate_fee_split(&env, amount, MAX_FEE_BPS),
        Ok((amount, 0))
    );
}

#[test]
fn fee_calculation_is_pure_so_retries_return_identical_results() {
    let env = Env::default();
    for _ in 0..3 {
        assert_eq!(
            calculate_fee_split(&env, 7_777, 250),
            Ok((194, 7_583))
        );
    }
}

// ---------------------------------------------------------------------------
// Failure paths: fee validation
// ---------------------------------------------------------------------------

#[test]
fn non_positive_amounts_are_rejected_before_rate_is_checked() {
    let env = Env::default();
    for amount in [0_i128, -1, i128::MIN] {
        // A bad rate must not change which error is reported.
        assert_eq!(
            calculate_fee_split(&env, amount, -5),
            Err(Error::PaymentInvalidAmount)
        );
        assert_eq!(
            calculate_fee_split(&env, amount, 250),
            Err(Error::PaymentInvalidAmount)
        );
    }
}

#[test]
fn out_of_range_rates_are_rejected() {
    let env = Env::default();
    for rate in [-1_i128, MAX_FEE_BPS + 1, i128::MAX] {
        assert_eq!(
            calculate_fee_split(&env, 1_000, rate),
            Err(Error::PaymentInvalidFeeRate),
            "rate {rate} must be rejected"
        );
    }
}

#[test]
fn fee_overflow_is_reported_rather_than_wrapped() {
    let env = Env::default();
    assert_eq!(
        calculate_fee_split(&env, i128::MAX, 2),
        Err(Error::PaymentFeeOverflow)
    );
    // With a zero rate the product is zero, so the whole amount is net.
    assert_eq!(calculate_fee_split(&env, i128::MAX, 0), Ok((0, i128::MAX)));
}

// ---------------------------------------------------------------------------
// Ownership invariants
// ---------------------------------------------------------------------------

#[contract]
pub struct OwnershipHarness;

#[contractimpl]
impl OwnershipHarness {
    pub fn noop(_env: Env) {}
}

/// A registered contract with an admin and two other actors.
struct Harness {
    env: Env,
    contract_id: Address,
    /// `actors[0]` is the initial admin.
    actors: [Address; 3],
}

impl Harness {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(BASE_TIME);
        let actors = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];
        let contract_id = env.register_contract(None, OwnershipHarness);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &actors[0]).unwrap();
        });
        Self {
            env,
            contract_id,
            actors,
        }
    }

    fn propose(&self, caller: &Address, target: &Address, expiry: u64) -> Result<(), Error> {
        self.env.as_contract(&self.contract_id, || {
            propose_ownership_transfer(&self.env, caller, target, expiry)
        })
    }

    fn accept(&self, caller: &Address) -> Result<(), Error> {
        self.env
            .as_contract(&self.contract_id, || accept_ownership_transfer(&self.env, caller))
    }

    fn cancel(&self, caller: &Address) -> Result<(), Error> {
        self.env
            .as_contract(&self.contract_id, || cancel_ownership_transfer(&self.env, caller))
    }

    fn admin(&self) -> Address {
        self.env
            .as_contract(&self.contract_id, || get_admin(&self.env))
    }

    fn pending(&self) -> Option<PendingOwnershipTransfer> {
        self.env
            .as_contract(&self.contract_id, || get_pending_ownership_transfer(&self.env))
    }

    fn holds_admin_role(&self, who: &Address) -> bool {
        self.env.as_contract(&self.contract_id, || {
            has_role(&self.env, who, Role::Admin)
        })
    }

    fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    fn set_time(&self, timestamp: u64) {
        self.env.ledger().set_timestamp(timestamp);
    }

    /// Checked after every operation in the random walk.
    fn assert_ownership_invariants(&self) {
        let admin = self.admin();
        assert!(
            self.actors.contains(&admin),
            "admin must be one of the known actors"
        );
        assert!(
            self.holds_admin_role(&admin),
            "the admin must hold the Admin role"
        );
        for actor in self.actors.iter().filter(|a| **a != admin) {
            assert!(
                !self.holds_admin_role(actor),
                "only the current admin may hold the Admin role"
            );
        }
        if let Some(pending) = self.pending() {
            assert_ne!(
                pending.target_owner, pending.current_owner,
                "a pending transfer must change the owner"
            );
        }
    }
}

#[test]
fn ownership_invariants_hold_across_random_operation_sequences() {
    for seed in [1_u64, 0xDEAD_BEEF, 0x0123_4567_89AB_CDEF, 42] {
        let harness = Harness::new();
        let mut rng = Rng(seed);
        for step in 0..WALK_STEPS {
            let actor = harness.actors[rng.below(3) as usize].clone();
            let other = harness.actors[rng.below(3) as usize].clone();
            match rng.below(4) {
                0 => {
                    let expiry = harness.now() + 1 + rng.below(500);
                    let result = harness.propose(&actor, &other, expiry);
                    assert!(
                        matches!(
                            result,
                            Ok(())
                                | Err(Error::Unauthorized)
                                | Err(Error::InvalidArgument)
                                | Err(Error::TransferAlreadyPending)
                        ),
                        "seed {seed} step {step}: unexpected propose result {result:?}"
                    );
                }
                1 => {
                    let result = harness.accept(&actor);
                    assert!(
                        matches!(
                            result,
                            Ok(())
                                | Err(Error::NoPendingTransfer)
                                | Err(Error::NotPendingOwner)
                                | Err(Error::TransferExpired)
                        ),
                        "seed {seed} step {step}: unexpected accept result {result:?}"
                    );
                }
                2 => {
                    let result = harness.cancel(&actor);
                    assert!(
                        matches!(
                            result,
                            Ok(()) | Err(Error::Unauthorized) | Err(Error::NoPendingTransfer)
                        ),
                        "seed {seed} step {step}: unexpected cancel result {result:?}"
                    );
                }
                _ => harness.set_time(harness.now() + rng.below(300)),
            }
            harness.assert_ownership_invariants();
        }
    }
}

#[test]
fn non_admin_cannot_propose_and_nothing_is_recorded() {
    let h = Harness::new();
    let target = h.actors[1].clone();
    let intruder = h.actors[2].clone();
    assert_eq!(
        h.propose(&intruder, &target, h.now() + 100),
        Err(Error::Unauthorized)
    );
    assert!(h.pending().is_none());
    h.assert_ownership_invariants();
}

#[test]
fn proposals_to_self_or_with_past_expiry_are_rejected() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    assert_eq!(
        h.propose(&admin, &admin, h.now() + 100),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        h.propose(&admin, &target, h.now()),
        Err(Error::InvalidArgument)
    );
    assert!(h.pending().is_none());
}

#[test]
fn only_the_designated_target_can_accept_and_acceptance_transfers_admin() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    let intruder = h.actors[2].clone();
    h.propose(&admin, &target, h.now() + 100).unwrap();

    assert_eq!(h.accept(&intruder), Err(Error::NotPendingOwner));
    assert!(h.pending().is_some(), "a rejected accept must not clear the pending transfer");

    assert_eq!(h.accept(&target), Ok(()));
    assert_eq!(h.admin(), target);
    assert!(h.holds_admin_role(&target));
    assert!(!h.holds_admin_role(&admin), "the old admin must lose the role");
    assert!(h.pending().is_none());
    h.assert_ownership_invariants();
}

#[test]
fn acceptance_at_the_exact_expiry_timestamp_is_still_valid() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    let expiry = h.now() + 100;
    h.propose(&admin, &target, expiry).unwrap();
    h.set_time(expiry);
    assert_eq!(h.accept(&target), Ok(()));
}

#[test]
fn accept_without_a_pending_transfer_fails_and_retries_are_harmless() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    assert_eq!(h.accept(&target), Err(Error::NoPendingTransfer));

    h.propose(&admin, &target, h.now() + 100).unwrap();
    assert_eq!(h.accept(&target), Ok(()));
    // A retried accept after success must not re-apply the transfer.
    assert_eq!(h.accept(&target), Err(Error::NoPendingTransfer));
    assert_eq!(h.admin(), target);
    h.assert_ownership_invariants();
}

#[test]
fn second_proposal_is_blocked_until_the_first_expires() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let first = h.actors[1].clone();
    let second = h.actors[2].clone();
    let expiry = h.now() + 100;
    h.propose(&admin, &first, expiry).unwrap();

    assert_eq!(
        h.propose(&admin, &second, expiry + 100),
        Err(Error::TransferAlreadyPending)
    );

    h.set_time(expiry + 1);
    h.propose(&admin, &second, expiry + 200).unwrap();
    assert_eq!(h.pending().unwrap().target_owner, second);
    h.assert_ownership_invariants();
}

#[test]
fn expired_transfer_is_refused_and_cleared() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    let expiry = h.now() + 10;
    h.propose(&admin, &target, expiry).unwrap();

    h.set_time(expiry + 1);
    assert_eq!(h.accept(&target), Err(Error::TransferExpired));
    assert!(h.pending().is_none(), "an expired transfer must be cleared");
    assert_eq!(h.admin(), admin);
    h.assert_ownership_invariants();
}

#[test]
fn only_the_admin_can_cancel_and_cancel_clears_the_transfer() {
    let h = Harness::new();
    let admin = h.actors[0].clone();
    let target = h.actors[1].clone();
    h.propose(&admin, &target, h.now() + 100).unwrap();

    assert_eq!(h.cancel(&target), Err(Error::Unauthorized));
    assert!(h.pending().is_some());

    assert_eq!(h.cancel(&admin), Ok(()));
    assert!(h.pending().is_none());
    assert_eq!(h.accept(&target), Err(Error::NoPendingTransfer));
    h.assert_ownership_invariants();
}
