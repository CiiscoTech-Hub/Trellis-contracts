//! Quota management for expensive operations and storage growth (Issue #65).
//!
//! Expensive operations (storage writes, compute-heavy loops, external index
//! fan-out) need quota controls to prevent abuse, runaway costs, and
//! accidental resource exhaustion.
//!
//! ## Design
//!
//! - Quotas are keyed by `(actor, resource)` where `resource` is a short
//!   symbol such as `aid_crt`, `wdraw`, or `reward`.
//! - Each resource has a [`QuotaConfig`] (max ops per window, ledger window
//!   length, max storage entries, max amount per op). Absent config means
//!   **fail-open** (allowed) so existing contracts keep working until a
//!   maintainer sets limits.
//! - [`check_and_consume`] is called at the top of state-changing entry
//!   points (cheap-first: amount check, window rollover, limit check, then
//!   persist). Over-limit calls return [`Error::QuotaExceeded`], a user-safe
//!   error that reveals no internals.
//! - Maintainers inspect usage via [`get_usage`] / [`get_quota_status`] and
//!   reset or override via [`reset_quota`] / [`set_quota_config`].
//!
//! ## Resource budgets and worst-case behavior
//!
//! - Worst-case per-call cost of [`check_and_consume`] is bounded: one config
//!   read, at most one usage read, at most one usage write. No loops and no
//!   unbounded storage scans, so cost is O(1) regardless of how many actors
//!   or operations exist.
//! - Normal path: under-limit call consumes one unit and persists.
//! - Failure path: negative amount, per-op cap exceeded, or window budget
//!   exhausted returns an error *before* any write (cheap-first ordering),
//!   so rejected calls cost reads only.
//! - Retry path: a retried over-limit call is idempotent with respect to
//!   state (no write occurs). A retried successful call does consume again;
//!   callers needing exactly-once semantics must dedupe above this layer.
//! - Authorization path: this module does not authenticate callers. Config
//!   mutation via [`set_quota_config`] and [`reset_quota`] must be gated by
//!   the caller's admin check. Non-admin misuse is rejected at that layer.
//! - Rollback: a failed host call after `check_and_consume` persists usage
//!   in the same transaction; Soroban reverts storage on transaction
//!   failure, so no partial consumption survives a failed invocation.
//!
//! See `docs/QUOTA.md` for limit tables and maintainer runbook.

use soroban_sdk::{contracttype, Address, Env, Symbol};

use crate::errors::Error;
use crate::telemetry::{emit_failure, emit_success, ActorType, OP_QUOTA_CONSUME};
use crate::storage::{instance_get, instance_set, persistent_get, persistent_set};

/// Per-resource quota limits.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaConfig {
    /// Max operations per window for each actor.
    pub max_ops_per_window: u32,
    /// Window length in ledgers. Usage resets when the window rolls over.
    pub window_ledgers: u32,
    /// Soft cap on tracked storage entries per actor (advisory for now).
    pub max_storage_entries: u32,
    /// Max `amount` per single operation (0 = no per-op amount cap).
    pub max_amount_per_op: i128,
    /// When `true`, maintainers may bypass via [`reset_quota`] workflows.
    /// Enforcement still applies; this only documents override support.
    pub allow_override: bool,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_ops_per_window: 100,
            window_ledgers: 17_280, // ~1 day at 5s/ledger
            max_storage_entries: 1_000,
            max_amount_per_op: 0,
            allow_override: true,
        }
    }
}

/// Tracked usage for one `(actor, resource)` pair.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaUsage {
    pub count: u32,
    pub window_start: u32,
    pub total_amount: i128,
}

/// Maintainer-facing snapshot for one `(actor, resource)` pair.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaStatus {
    pub actor: Address,
    pub resource: Symbol,
    pub has_config: bool,
    pub config: QuotaConfig,
    pub usage: QuotaUsage,
    pub remaining: u32,
    pub over_limit: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum QuotaKey {
    Config(Symbol),
    Usage(Address, Symbol),
}

fn config_key(resource: &Symbol) -> QuotaKey {
    QuotaKey::Config(resource.clone())
}

fn usage_key(actor: &Address, resource: &Symbol) -> QuotaKey {
    QuotaKey::Usage(actor.clone(), resource.clone())
}

/// Set (or replace) quota limits for a resource. Caller must enforce admin
/// authorization; this helper only persists.
pub fn set_quota_config(env: &Env, resource: &Symbol, config: &QuotaConfig) -> Result<(), Error> {
    if config.max_ops_per_window == 0 || config.window_ledgers == 0 {
        return Err(Error::ConfigInvalid);
    }
    if config.max_amount_per_op < 0 || config.max_storage_entries == 0 {
        return Err(Error::ConfigInvalid);
    }
    instance_set(env, &config_key(resource), config);
    Ok(())
}

/// Fetch quota limits for a resource, or `None` when unset (fail-open).
pub fn get_quota_config(env: &Env, resource: &Symbol) -> Option<QuotaConfig> {
    instance_get(env, &config_key(resource))
}

/// Fetch raw usage for an actor/resource pair (zeroed when never used).
pub fn get_usage(env: &Env, actor: &Address, resource: &Symbol) -> QuotaUsage {
    persistent_get(env, &usage_key(actor, resource)).unwrap_or(QuotaUsage {
        count: 0,
        window_start: env.ledger().sequence(),
        total_amount: 0,
    })
}

/// Maintainer diagnostics: config + usage + remaining budget.
pub fn get_quota_status(env: &Env, actor: &Address, resource: &Symbol) -> QuotaStatus {
    let config = get_quota_config(env, resource);
    let mut usage = get_usage(env, actor, resource);
    // Project window rollover without mutating (diagnostic view).
    if let Some(cfg) = &config {
        if env.ledger().sequence().saturating_sub(usage.window_start) >= cfg.window_ledgers {
            usage.count = 0;
            usage.total_amount = 0;
        }
    }
    let (has_config, cfg_val, remaining, over_limit) = match &config {
        None => (false, QuotaConfig::default(), u32::MAX, false),
        Some(cfg) => (
            true,
            cfg.clone(),
            cfg.max_ops_per_window.saturating_sub(usage.count),
            usage.count >= cfg.max_ops_per_window,
        ),
    };
    QuotaStatus {
        actor: actor.clone(),
        resource: resource.clone(),
        has_config,
        config: cfg_val,
        usage,
        remaining,
        over_limit,
    }
}

/// Reset usage for an actor/resource pair (window reset + override path).
///
/// Maintainers call this to clear a window early or to override a blocked
/// actor after review. Resets are idempotent.
pub fn reset_quota(env: &Env, actor: &Address, resource: &Symbol) {
    persistent_set(
        env,
        &usage_key(actor, resource),
        &QuotaUsage {
            count: 0,
            window_start: env.ledger().sequence(),
            total_amount: 0,
        },
    );
}

/// Enforce quota and consume one unit of budget.
///
/// - No config for `resource` -> allowed (fail-open), usage still tracked
///   against a zero-window marker so a later-set config starts clean.
/// - Window rolled over -> counters reset automatically.
/// - Over-limit or over-amount -> [`Error::QuotaExceeded`].
pub fn check_and_consume(
    env: &Env,
    actor: &Address,
    resource: &Symbol,
    amount: i128,
) -> Result<QuotaUsage, Error> {
    if amount < 0 {
        emit_failure(env, OP_QUOTA_CONSUME, ActorType::User, 0);
        return Err(Error::InvalidAmount);
    }
    // Emergency kill switch: maintainers can enable the quota-bypass feature
    // flag to skip enforcement during an incident. A missing flag config falls
    // back to enforcing quotas (the safer behavior).
    if matches!(
        crate::feature_flags::decide(env, &crate::feature_flags::FeatureFlag::QuotaBypass),
        crate::feature_flags::GateDecision::Enabled
    ) {
        return Ok(get_usage(env, actor, resource));
    }
    let Some(cfg) = get_quota_config(env, resource) else {
        emit_success(env, OP_QUOTA_CONSUME, ActorType::User, 0);
        return Ok(get_usage(env, actor, resource));
    };
    // Cheap-first: per-op amount cap before any storage write.
    if cfg.max_amount_per_op > 0 && amount > cfg.max_amount_per_op {
        emit_failure(env, OP_QUOTA_CONSUME, ActorType::User, 0);
        return Err(Error::QuotaExceeded);
    }
    let key = usage_key(actor, resource);
    let mut usage: QuotaUsage =
        persistent_get(env, &key).unwrap_or(QuotaUsage {
            count: 0,
            window_start: env.ledger().sequence(),
            total_amount: 0,
        });
    let now = env.ledger().sequence();
    if now.saturating_sub(usage.window_start) >= cfg.window_ledgers {
        usage.count = 0;
        usage.total_amount = 0;
        usage.window_start = now;
    }
    if usage.count >= cfg.max_ops_per_window {
        emit_failure(env, OP_QUOTA_CONSUME, ActorType::User, 0);
        return Err(Error::QuotaExceeded);
    }
    usage.count = usage.count.saturating_add(1);
    usage.total_amount = usage.total_amount.saturating_add(amount);
    persistent_set(env, &key, &usage);
    emit_success(env, OP_QUOTA_CONSUME, ActorType::User, 0);
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, symbol_short, testutils::Address as _, testutils::Ledger};

    #[contract]
    struct DummyContract;
    #[contractimpl]
    impl DummyContract {}

    fn setup() -> (Env, Address, Symbol, Address) {
        let env = Env::default();
        let actor = Address::generate(&env);
        let contract = env.register_contract(None, DummyContract);
        (env, actor, symbol_short!("aid_crt"), contract)
    }

    fn cfg(max_ops: u32, window: u32, max_amount: i128) -> QuotaConfig {
        QuotaConfig {
            max_ops_per_window: max_ops,
            window_ledgers: window,
            max_storage_entries: 10,
            max_amount_per_op: max_amount,
            allow_override: true,
        }
    }

    #[test]
    fn within_limit_consumes_budget() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(2, 100, 1000)).unwrap();
            assert!(check_and_consume(&env, &actor, &resource, 100).is_ok());
            assert!(check_and_consume(&env, &actor, &resource, 100).is_ok());
            let status = get_quota_status(&env, &actor, &resource);
            assert_eq!(status.remaining, 0);
            assert!(status.over_limit);
        });
    }

    #[test]
    fn over_limit_is_blocked() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(1, 100, 0)).unwrap();
            assert!(check_and_consume(&env, &actor, &resource, 0).is_ok());
            assert_eq!(
                check_and_consume(&env, &actor, &resource, 0),
                Err(Error::QuotaExceeded)
            );
        });
        // Per-op amount cap also maps to QuotaExceeded (user-safe).
        let (env2, actor2, resource2, contract2) = setup();
        env2.as_contract(&contract2, || {
            set_quota_config(&env2, &resource2, &cfg(10, 100, 50)).unwrap();
            assert_eq!(
                check_and_consume(&env2, &actor2, &resource2, 51),
                Err(Error::QuotaExceeded)
            );
        });
    }

    #[test]
    fn negative_amount_rejected_without_write() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(5, 100, 0)).unwrap();
            assert_eq!(
                check_and_consume(&env, &actor, &resource, -1),
                Err(Error::InvalidAmount)
            );
            assert_eq!(get_usage(&env, &actor, &resource).count, 0);
        });
    }

    #[test]
    fn rejected_call_does_not_consume_budget() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(10, 100, 50)).unwrap();
            let _ = check_and_consume(&env, &actor, &resource, 51);
            assert_eq!(get_usage(&env, &actor, &resource).count, 0);
        });
    }

    #[test]
    fn no_config_fails_open() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            assert!(check_and_consume(&env, &actor, &resource, 1_000_000).is_ok());
        });
    }

    #[test]
    fn invalid_config_rejected() {
        let (env, _actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            assert_eq!(
                set_quota_config(&env, &resource, &cfg(0, 100, 0)),
                Err(Error::ConfigInvalid)
            );
            assert_eq!(
                set_quota_config(&env, &resource, &cfg(1, 0, 0)),
                Err(Error::ConfigInvalid)
            );
            assert_eq!(
                set_quota_config(&env, &resource, &cfg(1, 10, -5)),
                Err(Error::ConfigInvalid)
            );
        });
    }

    #[test]
    fn worst_case_saturation_stays_bounded() {
        // Load test: drive the budget to exhaustion and confirm every further
        // call fails cheaply without growing usage state.
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(50, 100_000, 0)).unwrap();
            let mut ok = 0u32;
            let mut blocked = 0u32;
            for _ in 0..500 {
                match check_and_consume(&env, &actor, &resource, 1) {
                    Ok(_) => ok += 1,
                    Err(Error::QuotaExceeded) => blocked += 1,
                    Err(e) => panic!("unexpected error: {:?}", e),
                }
            }
            assert_eq!(ok, 50);
            assert_eq!(blocked, 450);
            assert_eq!(get_usage(&env, &actor, &resource).count, 50);
        });
    }

    #[test]
    fn window_reset_and_manual_reset_reopen_budget() {
        let (env, actor, resource, contract) = setup();
        env.as_contract(&contract, || {
            set_quota_config(&env, &resource, &cfg(1, 10, 0)).unwrap();
            assert!(check_and_consume(&env, &actor, &resource, 0).is_ok());
            assert_eq!(
                check_and_consume(&env, &actor, &resource, 0),
                Err(Error::QuotaExceeded)
            );
            // Maintainer override: manual reset reopens budget.
            reset_quota(&env, &actor, &resource);
            assert!(check_and_consume(&env, &actor, &resource, 0).is_ok());

            // Ledger-window rollover reopens budget after window_ledgers.
            let seq = env.ledger().sequence();
            env.ledger().with_mut(|l| l.sequence_number = seq + 10);
            assert!(check_and_consume(&env, &actor, &resource, 0).is_ok());
        });
    }
}
