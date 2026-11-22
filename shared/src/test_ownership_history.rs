//! Ownership transfer expiry and audit history tests (Issue #450).
//!
//! Covers the normal path (propose → accept), failure paths (expired accept,
//! premature expiry), the retry path (re-proposing after a proposal lapses)
//! and authorization (strangers cannot propose, cancel or accept).

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    Address, Env,
};

use crate::{
    auth::{
        accept_ownership_transfer, cancel_ownership_transfer, get_admin,
        get_pending_ownership_transfer, has_role, initialize_admin, propose_ownership_transfer,
        Role,
    },
    errors::Error,
    ownership_history::{
        expire_ownership_transfer, get_ownership_history_entry, ownership_history,
        ownership_history_len, OwnershipAction, MAX_OWNERSHIP_HISTORY_PAGE,
    },
};

#[contract]
pub struct DummyOwnershipContract;

#[contractimpl]
impl DummyOwnershipContract {
    pub fn noop(_env: Env) {}
}

/// Fresh env with an initialized admin. Returns (env, contract_id, admin).
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, DummyOwnershipContract);
    env.ledger().set_timestamp(100);
    env.as_contract(&contract_id, || {
        initialize_admin(&env, &admin).unwrap();
    });
    (env, contract_id, admin)
}

#[test]
fn accepted_transfer_writes_proposed_then_accepted() {
    let (env, id, admin) = setup();
    let new_owner = Address::generate(&env);

    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &new_owner, 200).unwrap();
    });
    env.ledger().set_timestamp(150);
    env.as_contract(&id, || {
        accept_ownership_transfer(&env, &new_owner).unwrap();

        assert_eq!(ownership_history_len(&env), 2);
        let history = ownership_history(&env, 0, 10).unwrap();
        let proposed = history.get(0).unwrap();
        let accepted = history.get(1).unwrap();

        assert_eq!(proposed.seq, 0);
        assert_eq!(proposed.action, OwnershipAction::Proposed);
        assert_eq!(proposed.actor, admin);
        assert_eq!(proposed.previous_owner, admin);
        assert_eq!(proposed.target_owner, new_owner);
        assert_eq!(proposed.expiry, 200);
        assert_eq!(proposed.timestamp, 100);

        assert_eq!(accepted.seq, 1);
        assert_eq!(accepted.action, OwnershipAction::Accepted);
        assert_eq!(accepted.actor, new_owner);
        assert_eq!(accepted.previous_owner, admin);
        assert_eq!(accepted.timestamp, 150);

        assert_eq!(get_admin(&env), new_owner);
    });
}

#[test]
fn cancelled_transfer_is_recorded_and_ownership_is_unchanged() {
    let (env, id, admin) = setup();
    let target = Address::generate(&env);

    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &target, 200).unwrap();
    });
    env.as_contract(&id, || {
        cancel_ownership_transfer(&env, &admin).unwrap();

        let entry = get_ownership_history_entry(&env, 1).unwrap();
        assert_eq!(entry.action, OwnershipAction::Cancelled);
        assert_eq!(entry.actor, admin);
        assert_eq!(entry.target_owner, target);
        assert_eq!(get_admin(&env), admin);
        assert_eq!(get_pending_ownership_transfer(&env), None);
    });
}

#[test]
fn expire_clears_a_lapsed_proposal_and_records_it() {
    let (env, id, admin) = setup();
    let target = Address::generate(&env);
    let keeper = Address::generate(&env);

    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &target, 200).unwrap();
    });
    env.ledger().set_timestamp(201);
    env.as_contract(&id, || {
        let entry = expire_ownership_transfer(&env, &keeper).unwrap();
        assert_eq!(entry.action, OwnershipAction::Expired);
        assert_eq!(entry.actor, keeper);
        assert_eq!(entry.previous_owner, admin);
        assert_eq!(entry.target_owner, target);
        assert_eq!(entry.expiry, 200);

        assert_eq!(get_pending_ownership_transfer(&env), None);
        assert_eq!(get_admin(&env), admin);
        assert!(has_role(&env, &admin, Role::Admin));
        assert!(!has_role(&env, &target, Role::Admin));
    });
}

#[test]
fn expire_rejects_an_unexpired_or_missing_proposal() {
    let (env, id, admin) = setup();
    let target = Address::generate(&env);
    let keeper = Address::generate(&env);

    env.as_contract(&id, || {
        assert_eq!(
            expire_ownership_transfer(&env, &keeper),
            Err(Error::NoPendingTransfer)
        );
    });
    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &target, 200).unwrap();
    });
    // Expiry is inclusive: at exactly `expiry` the proposal is still live.
    env.ledger().set_timestamp(200);
    env.as_contract(&id, || {
        assert_eq!(
            expire_ownership_transfer(&env, &keeper),
            Err(Error::InvalidArgument)
        );
        assert!(get_pending_ownership_transfer(&env).is_some());
        assert_eq!(ownership_history_len(&env), 1);
    });
}

#[test]
fn accepting_after_expiry_fails_and_records_expired() {
    let (env, id, admin) = setup();
    let target = Address::generate(&env);

    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &target, 200).unwrap();
    });
    env.ledger().set_timestamp(201);
    env.as_contract(&id, || {
        assert_eq!(
            accept_ownership_transfer(&env, &target),
            Err(Error::TransferExpired)
        );
        let entry = get_ownership_history_entry(&env, 1).unwrap();
        assert_eq!(entry.action, OwnershipAction::Expired);
        assert_eq!(entry.actor, target);
        assert_eq!(get_admin(&env), admin);
    });
}

#[test]
fn reproposing_after_lapse_records_the_replaced_proposal() {
    let (env, id, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &first, 200).unwrap();
    });
    env.ledger().set_timestamp(300);
    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &second, 400).unwrap();

        let history = ownership_history(&env, 0, 10).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history.get(0).unwrap().action, OwnershipAction::Proposed);
        let replaced = history.get(1).unwrap();
        assert_eq!(replaced.action, OwnershipAction::Expired);
        assert_eq!(replaced.target_owner, first);
        let current = history.get(2).unwrap();
        assert_eq!(current.action, OwnershipAction::Proposed);
        assert_eq!(current.target_owner, second);
        assert_eq!(current.expiry, 400);
    });
}

#[test]
fn unauthorized_attempts_leave_no_history() {
    let (env, id, admin) = setup();
    let target = Address::generate(&env);
    let stranger = Address::generate(&env);

    env.as_contract(&id, || {
        assert_eq!(
            propose_ownership_transfer(&env, &stranger, &target, 200),
            Err(Error::Unauthorized)
        );
        assert_eq!(ownership_history_len(&env), 0);
    });
    env.as_contract(&id, || {
        propose_ownership_transfer(&env, &admin, &target, 200).unwrap();
    });
    env.as_contract(&id, || {
        assert_eq!(
            cancel_ownership_transfer(&env, &stranger),
            Err(Error::Unauthorized)
        );
    });
    env.as_contract(&id, || {
        assert_eq!(
            accept_ownership_transfer(&env, &stranger),
            Err(Error::NotPendingOwner)
        );
        assert_eq!(ownership_history_len(&env), 1);
        assert_eq!(get_admin(&env), admin);
    });
}

#[test]
fn history_pages_are_bounded() {
    let (env, id, _admin) = setup();
    env.as_contract(&id, || {
        assert_eq!(ownership_history(&env, 0, 0), Err(Error::InvalidArgument));
        assert_eq!(
            ownership_history(&env, 0, MAX_OWNERSHIP_HISTORY_PAGE + 1),
            Err(Error::InvalidArgument)
        );
        assert_eq!(ownership_history(&env, 5, 10).unwrap().len(), 0);
    });
}
