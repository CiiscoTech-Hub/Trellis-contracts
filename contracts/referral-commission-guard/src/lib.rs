#![no_std]

//! Referral Multi-Tier Commission Cap & Self-Referral Guard Contract.
//!
//! Provides a focused vertical slice for enforcing multi-tier referral
//! commission caps (per-tier, per-transaction, and per-referrer lifetime),
//! blocking direct and indirect (cyclic) self-referrals, supporting
//! idempotent accrual retries, and enabling admin rollback/recovery.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Basis points denominator (100%).
pub const BPS_DENOMINATOR: i128 = 10_000;

/// Maximum supported referral tiers.
pub const MAX_TIERS: u32 = 5;

/// Maximum ancestor traversal depth for cycle detection.
pub const MAX_CYCLE_DEPTH: u32 = 16;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    InvalidConfig = 4,
    InvalidAmount = 5,
    SelfReferral = 6,
    ReferralCycle = 7,
    CycleDepthExceeded = 8,
    AlreadyRegistered = 9,
    NotRegistered = 10,
    EventNotFound = 11,
    EventRolledBack = 12,
    InvalidState = 13,
    InsufficientBalance = 14,
}

// ---------------------------------------------------------------------------
// Domain Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissionConfig {
    /// Basis points per tier (index 0 = Tier 1 direct referrer).
    pub tier_bps: Vec<u32>,
    /// Maximum aggregate BPS allowed across all tiers.
    pub max_total_bps: u32,
    /// Hard cap on total commission distributed across all tiers in one accrual.
    pub per_tx_commission_cap: i128,
    /// Hard cap on commission for any single tier in one accrual.
    pub per_tier_cap: i128,
    /// Hard lifetime cumulative commission cap per referrer.
    pub lifetime_cap: i128,
    /// Maximum ancestor hops checked for indirect self-referral cycles.
    pub cycle_check_depth: u32,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccrualStatus {
    Completed,
    RolledBack,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierPayout {
    pub tier: u32,
    pub referrer: Address,
    pub amount: i128,
    pub capped: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccrualReceipt {
    pub event_id: Symbol,
    pub referee: Address,
    pub base_amount: i128,
    pub total_distributed: i128,
    pub payouts: Vec<TierPayout>,
    pub status: AccrualStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageKey {
    Admin,
    Operator,
    Config,
    Referrer(Address),
    Accrued(Address),
    LifetimeAccrued(Address),
    Receipt(Symbol),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ReferralCommissionGuardContract;

#[contractimpl]
impl ReferralCommissionGuardContract {
    /// Initialize contract roles and default commission config. Can only be called once.
    pub fn init(
        env: Env,
        admin: Address,
        operator: Address,
        config: CommissionConfig,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&StorageKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        validate_config(&config)?;
        env.storage().instance().set(&StorageKey::Admin, &admin);
        env.storage().instance().set(&StorageKey::Operator, &operator);
        env.storage().instance().set(&StorageKey::Config, &config);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Admin Role & Config Management
    // -----------------------------------------------------------------------

    pub fn set_operator(env: Env, admin: Address, new_operator: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&StorageKey::Operator, &new_operator);
        Ok(())
    }

    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage().instance().set(&StorageKey::Admin, &new_admin);
        Ok(())
    }

    pub fn set_config(env: Env, admin: Address, config: CommissionConfig) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        validate_config(&config)?;
        env.storage().instance().set(&StorageKey::Config, &config);
        Ok(())
    }

    pub fn get_config(env: Env) -> Result<CommissionConfig, Error> {
        env.storage()
            .instance()
            .get(&StorageKey::Config)
            .ok_or(Error::NotInitialized)
    }

    // -----------------------------------------------------------------------
    // Referral Registration & Self-Referral / Cycle Guard
    // -----------------------------------------------------------------------

    /// Register `referee` under `referrer`.
    ///
    /// Enforces:
    /// - Caller must be `referee`, `Admin`, or `Operator`.
    /// - Direct self-referral (`referee == referrer`) is rejected.
    /// - Indirect self-referral cycles (`referee` in `referrer`'s ancestor chain)
    ///   are rejected; exceeding `cycle_check_depth` fails closed.
    pub fn register_referral(
        env: Env,
        caller: Address,
        referee: Address,
        referrer: Address,
    ) -> Result<(), Error> {
        require_referee_or_privileged(&env, &caller, &referee)?;

        if referee == referrer {
            return Err(Error::SelfReferral);
        }

        let key = StorageKey::Referrer(referee.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyRegistered);
        }

        let config = get_config_internal(&env)?;

        // Walk ancestor chain from `referrer` to detect indirect self-referral cycles.
        let mut cursor = referrer.clone();
        for _ in 0..config.cycle_check_depth {
            match env
                .storage()
                .persistent()
                .get::<_, Address>(&StorageKey::Referrer(cursor.clone()))
            {
                Some(parent) => {
                    if parent == referee {
                        return Err(Error::ReferralCycle);
                    }
                    cursor = parent;
                }
                None => {
                    // Reached root of referral tree safely.
                    env.storage().persistent().set(&key, &referrer);
                    return Ok(());
                }
            }
        }

        // If the chain is still continuing past `cycle_check_depth`, fail closed.
        if env
            .storage()
            .persistent()
            .has(&StorageKey::Referrer(cursor))
        {
            return Err(Error::CycleDepthExceeded);
        }

        env.storage().persistent().set(&key, &referrer);
        Ok(())
    }

    /// Admin-only recovery: remove a referral link.
    pub fn revoke_referral(env: Env, admin: Address, referee: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        let key = StorageKey::Referrer(referee);
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotRegistered);
        }
        env.storage().persistent().remove(&key);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Multi-Tier Commission Accrual (Capped & Idempotent)
    // -----------------------------------------------------------------------

    /// Accrue multi-tier commissions for a transaction `event_id` by `referee`.
    ///
    /// - Authorized for `Admin` or `Operator`.
    /// - Idempotent: re-submitting a completed `event_id` returns the existing receipt.
    /// - Enforces per-tier cap, per-transaction aggregate cap, and per-referrer lifetime cap.
    /// - Defense-in-depth: skips `referee` or any duplicate ancestor in the payout chain.
    pub fn accrue_commission(
        env: Env,
        caller: Address,
        event_id: Symbol,
        referee: Address,
        base_amount: i128,
    ) -> Result<AccrualReceipt, Error> {
        require_operator_or_admin(&env, &caller)?;
        if base_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let receipt_key = StorageKey::Receipt(event_id.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, AccrualReceipt>(&receipt_key)
        {
            return match existing.status {
                AccrualStatus::Completed => Ok(existing),
                AccrualStatus::RolledBack => Err(Error::EventRolledBack),
            };
        }

        let config = get_config_internal(&env)?;
        let mut payouts: Vec<TierPayout> = Vec::new(&env);
        let mut paid_addresses: Vec<Address> = Vec::new(&env);
        let mut total_distributed: i128 = 0;
        let mut remaining_tx_cap = config.per_tx_commission_cap;

        let mut current = referee.clone();
        let tier_count = config.tier_bps.len();

        for tier_idx in 0..tier_count {
            if remaining_tx_cap <= 0 {
                break;
            }
            let Some(ancestor) = env
                .storage()
                .persistent()
                .get::<_, Address>(&StorageKey::Referrer(current.clone()))
            else {
                break;
            };

            // Defense-in-depth self-referral & cycle guard during accrual.
            if ancestor == referee || contains_address(&paid_addresses, &ancestor) {
                break;
            }

            let bps = config.tier_bps.get(tier_idx).unwrap_or(0) as i128;
            let raw = base_amount
                .saturating_mul(bps)
                .checked_div(BPS_DENOMINATOR)
                .unwrap_or(0);

            let lifetime_key = StorageKey::LifetimeAccrued(ancestor.clone());
            let current_lifetime: i128 = env.storage().persistent().get(&lifetime_key).unwrap_or(0);
            let remaining_lifetime = config.lifetime_cap.saturating_sub(current_lifetime).max(0);

            let mut amount = raw;
            let mut capped = false;

            if amount > config.per_tier_cap {
                amount = config.per_tier_cap;
                capped = true;
            }
            if amount > remaining_tx_cap {
                amount = remaining_tx_cap;
                capped = true;
            }
            if amount > remaining_lifetime {
                amount = remaining_lifetime;
                capped = true;
            }

            if amount > 0 {
                let accrued_key = StorageKey::Accrued(ancestor.clone());
                let prev_accrued: i128 = env.storage().persistent().get(&accrued_key).unwrap_or(0);
                env.storage()
                    .persistent()
                    .set(&accrued_key, &(prev_accrued.saturating_add(amount)));
                env.storage()
                    .persistent()
                    .set(&lifetime_key, &(current_lifetime.saturating_add(amount)));

                total_distributed = total_distributed.saturating_add(amount);
                remaining_tx_cap = remaining_tx_cap.saturating_sub(amount);
            }

            paid_addresses.push_back(ancestor.clone());
            payouts.push_back(TierPayout {
                tier: tier_idx + 1,
                referrer: ancestor.clone(),
                amount,
                capped,
            });

            current = ancestor;
        }

        let receipt = AccrualReceipt {
            event_id,
            referee,
            base_amount,
            total_distributed,
            payouts,
            status: AccrualStatus::Completed,
        };
        env.storage().persistent().set(&receipt_key, &receipt);
        Ok(receipt)
    }

    /// Admin-only rollback of a completed accrual event.
    /// Reverses accrued and lifetime balances for all payouts in the receipt.
    pub fn rollback_accrual(
        env: Env,
        admin: Address,
        event_id: Symbol,
    ) -> Result<AccrualReceipt, Error> {
        require_admin(&env, &admin)?;
        let receipt_key = StorageKey::Receipt(event_id);
        let mut receipt: AccrualReceipt = env
            .storage()
            .persistent()
            .get(&receipt_key)
            .ok_or(Error::EventNotFound)?;

        if receipt.status != AccrualStatus::Completed {
            return Err(Error::InvalidState);
        }

        for i in 0..receipt.payouts.len() {
            let Some(payout) = receipt.payouts.get(i) else {
                continue;
            };
            if payout.amount <= 0 {
                continue;
            }
            let accrued_key = StorageKey::Accrued(payout.referrer.clone());
            let prev_accrued: i128 = env.storage().persistent().get(&accrued_key).unwrap_or(0);
            if prev_accrued < payout.amount {
                return Err(Error::InsufficientBalance);
            }
            let lifetime_key = StorageKey::LifetimeAccrued(payout.referrer.clone());
            let prev_lifetime: i128 = env.storage().persistent().get(&lifetime_key).unwrap_or(0);

            env.storage()
                .persistent()
                .set(&accrued_key, &(prev_accrued - payout.amount));
            env.storage()
                .persistent()
                .set(&lifetime_key, &(prev_lifetime.saturating_sub(payout.amount)));
        }

        receipt.status = AccrualStatus::RolledBack;
        env.storage().persistent().set(&receipt_key, &receipt);
        Ok(receipt)
    }

    /// Claim accrued commission balance. Referrer-authenticated.
    pub fn claim_commission(env: Env, referrer: Address, amount: i128) -> Result<i128, Error> {
        referrer.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let key = StorageKey::Accrued(referrer);
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if amount > balance {
            return Err(Error::InsufficientBalance);
        }
        let remaining = balance - amount;
        env.storage().persistent().set(&key, &remaining);
        Ok(remaining)
    }

    // -----------------------------------------------------------------------
    // Read-Only Queries
    // -----------------------------------------------------------------------

    pub fn get_referrer(env: Env, referee: Address) -> Option<Address> {
        env.storage().persistent().get(&StorageKey::Referrer(referee))
    }

    pub fn get_accrued_balance(env: Env, referrer: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&StorageKey::Accrued(referrer))
            .unwrap_or(0)
    }

    pub fn get_lifetime_accrued(env: Env, referrer: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&StorageKey::LifetimeAccrued(referrer))
            .unwrap_or(0)
    }

    pub fn get_accrual_receipt(env: Env, event_id: Symbol) -> Option<AccrualReceipt> {
        env.storage().persistent().get(&StorageKey::Receipt(event_id))
    }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

fn validate_config(config: &CommissionConfig) -> Result<(), Error> {
    let len = config.tier_bps.len();
    if len == 0 || len > MAX_TIERS {
        return Err(Error::InvalidConfig);
    }
    if config.max_total_bps == 0 || (config.max_total_bps as i128) > BPS_DENOMINATOR {
        return Err(Error::InvalidConfig);
    }
    if config.per_tx_commission_cap <= 0
        || config.per_tier_cap <= 0
        || config.lifetime_cap <= 0
    {
        return Err(Error::InvalidConfig);
    }
    if config.cycle_check_depth == 0 || config.cycle_check_depth > MAX_CYCLE_DEPTH {
        return Err(Error::InvalidConfig);
    }
    let mut sum_bps: u32 = 0;
    for i in 0..len {
        let bps = config.tier_bps.get(i).unwrap_or(0);
        if bps == 0 || (bps as i128) > BPS_DENOMINATOR {
            return Err(Error::InvalidConfig);
        }
        sum_bps = sum_bps.saturating_add(bps);
    }
    if sum_bps > config.max_total_bps {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

fn get_config_internal(env: &Env) -> Result<CommissionConfig, Error> {
    env.storage()
        .instance()
        .get(&StorageKey::Config)
        .ok_or(Error::NotInitialized)
}

fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn require_operator_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    let operator: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Operator)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin && caller != &operator {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn require_referee_or_privileged(
    env: &Env,
    caller: &Address,
    referee: &Address,
) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    let operator: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Operator)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != referee && caller != &admin && caller != &operator {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn contains_address(list: &Vec<Address>, target: &Address) -> bool {
    for i in 0..list.len() {
        if let Some(addr) = list.get(i) {
            if &addr == target {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Automated Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, vec};

    struct Fixture {
        env: Env,
        client: ReferralCommissionGuardContractClient<'static>,
        admin: Address,
        operator: Address,
        outsider: Address,
    }

    fn default_config(env: &Env) -> CommissionConfig {
        CommissionConfig {
            tier_bps: vec![env, 500, 300, 200], // 5%, 3%, 2% = 10% total
            max_total_bps: 1_000,
            per_tx_commission_cap: 800,
            per_tier_cap: 500,
            lifetime_cap: 1_000,
            cycle_check_depth: 5,
        }
    }

    fn setup() -> Fixture {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ReferralCommissionGuardContract);
        let client = ReferralCommissionGuardContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let operator = Address::generate(&env);
        let outsider = Address::generate(&env);

        client.init(&admin, &operator, &default_config(&env));

        Fixture {
            env,
            client,
            admin,
            operator,
            outsider,
        }
    }

    #[test]
    fn normal_path_multi_tier_accrual_caps_and_claim() {
        let f = setup();
        let a = Address::generate(&f.env); // Tier 3
        let b = Address::generate(&f.env); // Tier 2
        let c = Address::generate(&f.env); // Tier 1
        let d = Address::generate(&f.env); // Referee

        f.client.register_referral(&b, &b, &a);
        f.client.register_referral(&c, &c, &b);
        f.client.register_referral(&d, &d, &c);

        // Base = 10_000: raw Tier 1 = 500, Tier 2 = 300, Tier 3 = 200 (sum = 1000).
        // per_tx_commission_cap = 800 -> Tier 1 gets 500, Tier 2 gets 300, Tier 3 gets 0 (stopped).
        let receipt = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("ev_1"), &d, &10_000);
        assert_eq!(receipt.total_distributed, 800);
        assert_eq!(receipt.payouts.len(), 2);
        assert_eq!(f.client.get_accrued_balance(&c), 500);
        assert_eq!(f.client.get_accrued_balance(&b), 300);
        assert_eq!(f.client.get_accrued_balance(&a), 0);

        // Claim partial balance
        let remaining = f.client.claim_commission(&c, &200);
        assert_eq!(remaining, 300);
        assert_eq!(f.client.get_accrued_balance(&c), 300);
        assert_eq!(f.client.get_lifetime_accrued(&c), 500);
    }

    #[test]
    fn self_referral_and_indirect_cycle_guards() {
        let f = setup();
        let a = Address::generate(&f.env);
        let b = Address::generate(&f.env);
        let c = Address::generate(&f.env);

        // Direct self-referral rejected
        assert_eq!(
            f.client.try_register_referral(&a, &a, &a),
            Err(Ok(Error::SelfReferral))
        );

        // Build chain: c -> b -> a
        f.client.register_referral(&b, &b, &a);
        f.client.register_referral(&c, &c, &b);

        // Indirect cycle: a -> c would create a -> c -> b -> a
        assert_eq!(
            f.client.try_register_referral(&a, &a, &c),
            Err(Ok(Error::ReferralCycle))
        );

        // Duplicate registration rejected
        assert_eq!(
            f.client.try_register_referral(&b, &b, &c),
            Err(Ok(Error::AlreadyRegistered))
        );
    }

    #[test]
    fn lifetime_cap_and_per_tier_cap_enforced() {
        let f = setup();
        let referrer = Address::generate(&f.env);
        let referee = Address::generate(&f.env);
        f.client.register_referral(&referee, &referee, &referrer);

        // Base = 20_000: raw Tier 1 = 1000, clamped by per_tier_cap = 500
        let r1 = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("cap_1"), &referee, &20_000);
        assert_eq!(r1.total_distributed, 500);
        assert!(r1.payouts.get(0).unwrap().capped);

        // Second accrual: another 500 -> reaches lifetime_cap = 1000
        let r2 = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("cap_2"), &referee, &20_000);
        assert_eq!(r2.total_distributed, 500);
        assert_eq!(f.client.get_lifetime_accrued(&referrer), 1_000);

        // Third accrual: lifetime cap reached -> 0 distributed
        let r3 = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("cap_3"), &referee, &20_000);
        assert_eq!(r3.total_distributed, 0);
        assert!(r3.payouts.get(0).unwrap().capped);
    }

    #[test]
    fn idempotent_retry_and_admin_rollback_recovery() {
        let f = setup();
        let referrer = Address::generate(&f.env);
        let referee = Address::generate(&f.env);
        f.client.register_referral(&referee, &referee, &referrer);

        let r1 = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("idem_1"), &referee, &4_000);
        assert_eq!(r1.total_distributed, 200);

        // Retrying the same event_id returns existing receipt without double-crediting
        let r1_retry = f
            .client
            .accrue_commission(&f.operator, &symbol_short!("idem_1"), &referee, &4_000);
        assert_eq!(r1_retry, r1);
        assert_eq!(f.client.get_accrued_balance(&referrer), 200);

        // Admin rolls back accrual
        let rolled = f
            .client
            .rollback_accrual(&f.admin, &symbol_short!("idem_1"));
        assert_eq!(rolled.status, AccrualStatus::RolledBack);
        assert_eq!(f.client.get_accrued_balance(&referrer), 0);
        assert_eq!(f.client.get_lifetime_accrued(&referrer), 0);

        // Replaying a rolled-back event_id is rejected
        assert_eq!(
            f.client
                .try_accrue_commission(&f.operator, &symbol_short!("idem_1"), &referee, &4_000),
            Err(Ok(Error::EventRolledBack))
        );

        // Admin can revoke referral link for recovery
        f.client.revoke_referral(&f.admin, &referee);
        assert_eq!(f.client.get_referrer(&referee), None);
    }

    #[test]
    fn authorization_and_invalid_config_paths() {
        let f = setup();
        let a = Address::generate(&f.env);
        let b = Address::generate(&f.env);

        // Outsider cannot set config
        assert_eq!(
            f.client.try_set_config(&f.outsider, &default_config(&f.env)),
            Err(Ok(Error::Unauthorized))
        );

        // Operator cannot set config
        assert_eq!(
            f.client.try_set_config(&f.operator, &default_config(&f.env)),
            Err(Ok(Error::Unauthorized))
        );

        // Invalid config (sum of tier_bps > max_total_bps) rejected
        let mut bad_cfg = default_config(&f.env);
        bad_cfg.max_total_bps = 500;
        assert_eq!(
            f.client.try_set_config(&f.admin, &bad_cfg),
            Err(Ok(Error::InvalidConfig))
        );

        // Outsider cannot register referral on behalf of another user
        assert_eq!(
            f.client.try_register_referral(&f.outsider, &a, &b),
            Err(Ok(Error::Unauthorized))
        );

        // Outsider cannot accrue commissions
        assert_eq!(
            f.client
                .try_accrue_commission(&f.outsider, &symbol_short!("unauth"), &a, &1_000),
            Err(Ok(Error::Unauthorized))
        );

        // Operator cannot rollback accruals (admin-only)
        f.client.register_referral(&a, &a, &b);
        f.client
            .accrue_commission(&f.operator, &symbol_short!("ok_ev"), &a, &1_000);
        assert_eq!(
            f.client
                .try_rollback_accrual(&f.operator, &symbol_short!("ok_ev")),
            Err(Ok(Error::Unauthorized))
        );
    }
}
