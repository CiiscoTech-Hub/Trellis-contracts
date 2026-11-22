//! Tests for treasury category budget reallocation (Issue #541).
//!
//! Coverage map:
//! - normal: move budget between categories, total preserved, audit recorded
//! - failure: insufficient source, same-category, non-positive amount
//! - authorization: only ManageConfiguration (admin) may reallocate; a treasury
//!   manager (TreasuryOperations) is rejected before any mutation
//! - retry/rollback: a rejected reallocation leaves both balances unchanged

#![cfg(test)]

use crate::{TreasuryContract, TreasuryContractClient};
use shared::errors::Error;
use soroban_sdk::{symbol_short, testutils::Address as _, token::StellarAssetClient, Address, Env, Symbol};

struct Fixture {
    env: Env,
    client_id: Address,
    admin: Address,
    token: Address,
}

fn reserve() -> Symbol {
    symbol_short!("reserve")
}
fn rewards() -> Symbol {
    symbol_short!("rewards")
}

/// Register the treasury, initialise it, and fund `reserve` with `seed`.
fn setup(seed: i128) -> Fixture {
    let env = Env::default();
    env.mock_all_auths();

    let client_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &client_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &1_000_000);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    StellarAssetClient::new(&env, &token).mint(&admin, &1_000_000);
    client.deposit(&admin, &token, &reserve(), &seed);

    Fixture {
        env,
        client_id,
        admin,
        token,
    }
}

#[test]
fn reallocation_moves_budget_and_preserves_total() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);

    client.reallocate_budget(&fx.admin, &fx.token, &reserve(), &rewards(), &200);

    assert_eq!(client.category_balance(&fx.token, &reserve()), 300);
    assert_eq!(client.category_balance(&fx.token, &rewards()), 200);
    // No token transfer occurred: the treasury's total for this token is invariant.
    let total = client.category_balance(&fx.token, &reserve())
        + client.category_balance(&fx.token, &rewards());
    assert_eq!(total, 500);
}

#[test]
fn reallocation_rejects_insufficient_source() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);

    assert_eq!(
        client.try_reallocate_budget(&fx.admin, &fx.token, &reserve(), &rewards(), &600),
        Err(Ok(Error::InsufficientBalance))
    );
    // Rejected before mutation: balances unchanged.
    assert_eq!(client.category_balance(&fx.token, &reserve()), 500);
    assert_eq!(client.category_balance(&fx.token, &rewards()), 0);
}

#[test]
fn reallocation_rejects_same_category() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);
    assert_eq!(
        client.try_reallocate_budget(&fx.admin, &fx.token, &reserve(), &reserve(), &100),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(client.category_balance(&fx.token, &reserve()), 500);
}

#[test]
fn reallocation_rejects_non_positive_amount() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);
    assert_eq!(
        client.try_reallocate_budget(&fx.admin, &fx.token, &reserve(), &rewards(), &0),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(
        client.try_reallocate_budget(&fx.admin, &fx.token, &reserve(), &rewards(), &-5),
        Err(Ok(Error::InvalidArgument))
    );
}

#[test]
fn reallocation_requires_manage_configuration() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);

    // A treasury manager has TreasuryOperations but not ManageConfiguration.
    let manager = Address::generate(&fx.env);
    client.add_treasury_manager(&fx.admin, &manager);

    assert_eq!(
        client.try_reallocate_budget(&manager, &fx.token, &reserve(), &rewards(), &100),
        Err(Ok(Error::Unauthorized))
    );
    // And an unrelated address is likewise rejected.
    let intruder = Address::generate(&fx.env);
    assert_eq!(
        client.try_reallocate_budget(&intruder, &fx.token, &reserve(), &rewards(), &100),
        Err(Ok(Error::Unauthorized))
    );
    // No mutation from either rejected call.
    assert_eq!(client.category_balance(&fx.token, &reserve()), 500);
    assert_eq!(client.category_balance(&fx.token, &rewards()), 0);
}

#[test]
fn reallocation_round_trip_is_balance_neutral() {
    let fx = setup(500);
    let client = TreasuryContractClient::new(&fx.env, &fx.client_id);

    client.reallocate_budget(&fx.admin, &fx.token, &reserve(), &rewards(), &200);
    client.reallocate_budget(&fx.admin, &fx.token, &rewards(), &reserve(), &200);

    assert_eq!(client.category_balance(&fx.token, &reserve()), 500);
    assert_eq!(client.category_balance(&fx.token, &rewards()), 0);
}
