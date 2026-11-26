//! Strict input size and cardinality limits (Issue #448).
//!
//! Contracts call [`enforce_bytes`], [`enforce_items`] and
//! [`enforce_cardinality`] at their entry points before doing any work, so an
//! oversized payload fails fast and costs the caller, not the contract.
//!
//! Every scope (for example `batch` or `metadata`) has an [`InputLimitPolicy`].
//! When no policy is stored, [`DEFAULT_INPUT_LIMITS`] applies, so existing
//! contracts keep working without a migration. The admin may tighten or relax
//! a policy with [`set_input_limits`]; removing it with [`clear_input_limits`]
//! rolls back to the defaults. See `docs/INPUT_LIMITS.md`.

use soroban_sdk::{
    contracterror, contracttype, Address, Bytes, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};

use crate::auth;

/// Hard ceilings no policy may exceed.
pub const ABSOLUTE_MAX_BYTES: u32 = 64 * 1024;
pub const ABSOLUTE_MAX_ITEMS: u32 = 1_000;

pub const DEFAULT_INPUT_LIMITS: InputLimitPolicy = InputLimitPolicy {
    max_bytes: 4 * 1024,
    max_items: 100,
    max_distinct: 100,
};

const POLICY_KEY: u32 = 0x494c_4d54; // "ILMT"

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum InputLimitError {
    InputTooLarge = 1,
    TooManyItems = 2,
    CardinalityExceeded = 3,
    InvalidPolicy = 4,
    Unauthorized = 5,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputLimitPolicy {
    pub max_bytes: u32,
    pub max_items: u32,
    /// Maximum number of distinct keys in one call.
    pub max_distinct: u32,
}

impl InputLimitPolicy {
    pub fn validate(&self) -> Result<(), InputLimitError> {
        if self.max_bytes == 0
            || self.max_items == 0
            || self.max_distinct == 0
            || self.max_bytes > ABSOLUTE_MAX_BYTES
            || self.max_items > ABSOLUTE_MAX_ITEMS
            || self.max_distinct > self.max_items
        {
            return Err(InputLimitError::InvalidPolicy);
        }
        Ok(())
    }
}

fn policy_key(scope: &Symbol) -> (u32, Symbol) {
    (POLICY_KEY, scope.clone())
}

pub fn get_input_limits(env: &Env, scope: &Symbol) -> InputLimitPolicy {
    env.storage()
        .instance()
        .get(&policy_key(scope))
        .unwrap_or(DEFAULT_INPUT_LIMITS)
}

/// Stores a policy for `scope`. Admin only. Setting the same policy twice is a
/// no-op, so retries are safe.
pub fn set_input_limits(
    env: &Env,
    caller: &Address,
    scope: &Symbol,
    policy: &InputLimitPolicy,
) -> Result<(), InputLimitError> {
    auth::require_admin(env, caller).map_err(|_| InputLimitError::Unauthorized)?;
    policy.validate()?;
    env.storage().instance().set(&policy_key(scope), policy);
    Ok(())
}

/// Removes the policy for `scope`, falling back to the defaults.
pub fn clear_input_limits(
    env: &Env,
    caller: &Address,
    scope: &Symbol,
) -> Result<(), InputLimitError> {
    auth::require_admin(env, caller).map_err(|_| InputLimitError::Unauthorized)?;
    env.storage().instance().remove(&policy_key(scope));
    Ok(())
}

pub fn check_bytes(policy: &InputLimitPolicy, input: &Bytes) -> Result<(), InputLimitError> {
    if input.len() > policy.max_bytes {
        return Err(InputLimitError::InputTooLarge);
    }
    Ok(())
}

pub fn check_items(policy: &InputLimitPolicy, count: u32) -> Result<(), InputLimitError> {
    if count > policy.max_items {
        return Err(InputLimitError::TooManyItems);
    }
    Ok(())
}

/// Counts distinct keys, stopping as soon as the limit is exceeded so a
/// hostile input cannot force a full quadratic scan.
pub fn check_cardinality<T>(policy: &InputLimitPolicy, keys: &Vec<T>) -> Result<(), InputLimitError>
where
    T: Clone + PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    check_items(policy, keys.len())?;
    let mut distinct: u32 = 0;
    for i in 0..keys.len() {
        let current = keys.get_unchecked(i);
        let mut seen = false;
        for j in 0..i {
            if keys.get_unchecked(j) == current {
                seen = true;
                break;
            }
        }
        if !seen {
            distinct += 1;
            if distinct > policy.max_distinct {
                return Err(InputLimitError::CardinalityExceeded);
            }
        }
    }
    Ok(())
}

pub fn enforce_bytes(env: &Env, scope: &Symbol, input: &Bytes) -> Result<(), InputLimitError> {
    check_bytes(&get_input_limits(env, scope), input)
}

pub fn enforce_items(env: &Env, scope: &Symbol, count: u32) -> Result<(), InputLimitError> {
    check_items(&get_input_limits(env, scope), count)
}

pub fn enforce_cardinality<T>(
    env: &Env,
    scope: &Symbol,
    keys: &Vec<T>,
) -> Result<(), InputLimitError>
where
    T: Clone + PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    check_cardinality(&get_input_limits(env, scope), keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, symbol_short, vec};

    #[contract]
    pub struct InputLimitsFixture;

    #[contractimpl]
    impl InputLimitsFixture {
        pub fn input_limits_ping() -> u32 {
            1
        }
    }

    fn policy(max_bytes: u32, max_items: u32, max_distinct: u32) -> InputLimitPolicy {
        InputLimitPolicy {
            max_bytes,
            max_items,
            max_distinct,
        }
    }

    #[test]
    fn byte_limit_accepts_boundary_and_rejects_one_over() {
        let env = Env::default();
        let p = policy(4, 10, 10);
        assert_eq!(check_bytes(&p, &Bytes::from_slice(&env, &[0; 4])), Ok(()));
        assert_eq!(
            check_bytes(&p, &Bytes::from_slice(&env, &[0; 5])),
            Err(InputLimitError::InputTooLarge)
        );
        assert_eq!(check_bytes(&p, &Bytes::new(&env)), Ok(()));
    }

    #[test]
    fn item_limit_accepts_boundary_and_rejects_one_over() {
        let p = policy(4, 3, 3);
        assert_eq!(check_items(&p, 3), Ok(()));
        assert_eq!(check_items(&p, 4), Err(InputLimitError::TooManyItems));
    }

    #[test]
    fn cardinality_counts_distinct_keys_only() {
        let env = Env::default();
        let p = policy(4, 10, 2);
        let repeated = vec![&env, 1u32, 1, 2, 2, 1];
        assert_eq!(check_cardinality(&p, &repeated), Ok(()));
        let too_many = vec![&env, 1u32, 2, 3];
        assert_eq!(
            check_cardinality(&p, &too_many),
            Err(InputLimitError::CardinalityExceeded)
        );
        let too_long = vec![&env, 1u32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(check_cardinality(&p, &too_long), Err(InputLimitError::TooManyItems));
    }

    #[test]
    fn invalid_policies_are_rejected() {
        assert_eq!(policy(0, 1, 1).validate(), Err(InputLimitError::InvalidPolicy));
        assert_eq!(policy(1, 0, 1).validate(), Err(InputLimitError::InvalidPolicy));
        assert_eq!(policy(1, 1, 0).validate(), Err(InputLimitError::InvalidPolicy));
        assert_eq!(policy(1, 1, 2).validate(), Err(InputLimitError::InvalidPolicy));
        assert_eq!(
            policy(ABSOLUTE_MAX_BYTES + 1, 1, 1).validate(),
            Err(InputLimitError::InvalidPolicy)
        );
        assert_eq!(
            policy(1, ABSOLUTE_MAX_ITEMS + 1, 1).validate(),
            Err(InputLimitError::InvalidPolicy)
        );
        assert_eq!(DEFAULT_INPUT_LIMITS.validate(), Ok(()));
    }

    #[test]
    fn stored_policy_is_admin_only_and_clear_restores_defaults() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, InputLimitsFixture);
        let admin = Address::generate(&env);
        let stranger = Address::generate(&env);
        let scope = symbol_short!("batch");
        env.as_contract(&contract_id, || {
            auth::set_admin(&env, &admin);
            assert_eq!(get_input_limits(&env, &scope), DEFAULT_INPUT_LIMITS);

            let tight = policy(2, 2, 2);
            assert_eq!(
                set_input_limits(&env, &stranger, &scope, &tight),
                Err(InputLimitError::Unauthorized)
            );
            assert_eq!(set_input_limits(&env, &admin, &scope, &tight), Ok(()));
            // Retrying the same update is harmless.
            assert_eq!(set_input_limits(&env, &admin, &scope, &tight), Ok(()));
            assert_eq!(
                enforce_bytes(&env, &scope, &Bytes::from_slice(&env, &[0; 3])),
                Err(InputLimitError::InputTooLarge)
            );
            assert_eq!(enforce_items(&env, &scope, 3), Err(InputLimitError::TooManyItems));
            assert_eq!(
                enforce_cardinality(&env, &scope, &vec![&env, 1u32, 2]),
                Ok(())
            );

            // Other scopes are unaffected.
            assert_eq!(enforce_items(&env, &symbol_short!("meta"), 3), Ok(()));

            assert_eq!(
                clear_input_limits(&env, &stranger, &scope),
                Err(InputLimitError::Unauthorized)
            );
            assert_eq!(clear_input_limits(&env, &admin, &scope), Ok(()));
            assert_eq!(get_input_limits(&env, &scope), DEFAULT_INPUT_LIMITS);
        });
    }
}
