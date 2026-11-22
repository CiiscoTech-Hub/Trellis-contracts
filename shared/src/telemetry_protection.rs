#![no_std]

//! High-cardinality telemetry redaction and sampling protection (Issue #428).
//!
//! Observability pipelines in blockchain smart contracts are vulnerable to:
//! 1. **PII and Secret Leakage**: Accidental inclusion of sensitive keys (Stellar secrets,
//!    private keys, authorization tokens, plaintext passwords) in telemetry events.
//! 2. **Cardinality Explosion**: Emitting unbounded labels (such as unique account addresses,
//!    raw amounts, or transaction hashes) degrades indexer databases and monitoring backends.
//! 3. **Telemetry Flooding / DoS**: Adversarial or high-frequency invocations exhausting
//!    event emission budgets and indexing pipeline bandwidth.
//!
//! This module provides:
//! - **Bounded Label Validation**: `is_safe_label` verifies label bounds and catches high-cardinality values.
//! - **Automated Redaction**: `redact_label` masks sensitive values (secrets, wallets, amounts) with stable placeholders.
//! - **Deterministic Sampling**: `SamplingConfig` and `sample_decision` throttle high-volume events while
//!   guaranteeing error events and baseline bursts are never dropped.
//! - **Lifecycle & Authorization**: Admin-gated controls for telemetry policy tuning.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

use soroban_sdk::{
    contracttype, symbol_short, Address, Env,
};

use crate::auth::require_admin;
use crate::errors::Error;

/// Maximum allowed length in characters for any telemetry label.
pub const MAX_LABEL_LEN: usize = 64;

/// Stable placeholder emitted in place of sensitive label values.
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Configuration for deterministic telemetry sampling.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplingConfig {
    /// Number of events admitted per burst without applying sampling.
    pub burst_threshold: u32,
    /// Sampling rate denominator: 1 in `sample_rate_denominator` events is emitted
    /// once the burst threshold is exceeded.
    pub sample_rate_denominator: u32,
}

impl SamplingConfig {
    /// Creates a new sampling configuration.
    pub fn new(burst_threshold: u32, sample_rate_denominator: u32) -> Self {
        Self {
            burst_threshold,
            sample_rate_denominator,
        }
    }
}

/// Evaluates whether a label is safe to emit without risk of cardinality explosion
/// or sensitive data leakage.
pub fn is_safe_label(label: &str) -> bool {
    let len = label.len();
    if len == 0 || len > MAX_LABEL_LEN {
        return false;
    }

    // High-cardinality / sensitive label patterns to reject:
    if label.starts_with("user:G") || label.starts_with("wallet:") {
        return false;
    }
    if label.starts_with("amount:") {
        return false;
    }
    if label.starts_with("secret:") || label.starts_with("priv_key:") || label.starts_with("seed:") {
        return false;
    }
    if label.starts_with("auth:") || label.starts_with("token:") || label.starts_with("api_key:") {
        return false;
    }

    true
}

/// Redacts a label by replacing sensitive substrings or high-cardinality values
/// with a safe `<redacted>` placeholder while preserving the classification prefix.
pub fn redact_label(label: &str) -> String {
    if is_safe_label(label) {
        return label.to_string();
    }

    if let Some(rest) = label.strip_prefix("user:") {
        if !rest.is_empty() {
            return format!("user:{REDACTED_PLACEHOLDER}");
        }
    }
    if let Some(rest) = label.strip_prefix("amount:") {
        if !rest.is_empty() {
            return format!("amount:{REDACTED_PLACEHOLDER}");
        }
    }
    if let Some(rest) = label.strip_prefix("secret:") {
        if !rest.is_empty() {
            return format!("secret:{REDACTED_PLACEHOLDER}");
        }
    }
    if let Some(rest) = label.strip_prefix("wallet:") {
        if !rest.is_empty() {
            return format!("wallet:{REDACTED_PLACEHOLDER}");
        }
    }
    if let Some(rest) = label.strip_prefix("token:") {
        if !rest.is_empty() {
            return format!("token:{REDACTED_PLACEHOLDER}");
        }
    }

    REDACTED_PLACEHOLDER.to_string()
}

/// Evaluates whether an event should be retained based on its volume, sampling configuration,
/// and event index. Error events (index 0) are always retained.
pub fn sample_decision(config: &SamplingConfig, event_index: u32, current_volume: u32) -> bool {
    // Baseline burst protection: admit all events under threshold
    if current_volume <= config.burst_threshold {
        return true;
    }

    // Critical invariant: Errors or primary priority events (index 0) are NEVER dropped
    if event_index == 0 {
        return true;
    }

    if config.sample_rate_denominator <= 1 {
        return true;
    }

    // Deterministic sampling above threshold
    (event_index % config.sample_rate_denominator) == 0
}

/// Admin-authorized update of sampling policy parameters.
pub fn update_sampling_policy(
    env: &Env,
    admin: &Address,
    burst_threshold: u32,
    sample_rate_denominator: u32,
) -> Result<SamplingConfig, Error> {
    require_admin(env, admin)?;

    if sample_rate_denominator == 0 {
        return Err(Error::InvalidArgument);
    }

    let config = SamplingConfig::new(burst_threshold, sample_rate_denominator);
    env.events().publish(
        (symbol_short!("telemetry"), symbol_short!("cfg_upd")),
        (burst_threshold, sample_rate_denominator),
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::Address as _,
        Env,
    };

    #[contract]
    struct TelemetryProtectionTestContract;

    #[contractimpl]
    impl TelemetryProtectionTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TelemetryProtectionTestContract);
        let admin = Address::generate(&env);
        let caller = Address::generate(&env);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });
        (env, admin, caller)
    }

    #[test]
    fn test_normal_label_safety_and_redaction() {
        assert!(is_safe_label("op:transfer"));
        assert!(is_safe_label("actor:user"));
        assert!(is_safe_label("status:ok"));

        assert_eq!(redact_label("op:transfer"), "op:transfer");
        assert_eq!(
            redact_label("user:GD6W56ZDF7..."),
            "user:<redacted>"
        );
        assert_eq!(redact_label("amount:9999999"), "amount:<redacted>");
        assert_eq!(redact_label("secret:SABC..."), "secret:<redacted>");
        assert_eq!(redact_label("wallet:GXYZ..."), "wallet:<redacted>");
    }

    #[test]
    fn test_failure_paths_and_boundary_checks() {
        // Empty labels are unsafe
        assert!(!is_safe_label(""));

        // Oversized labels are unsafe
        let oversized = "a".repeat(MAX_LABEL_LEN + 1);
        assert!(!is_safe_label(&oversized));
        assert_eq!(redact_label(&oversized), "<redacted>");
    }

    #[test]
    fn test_deterministic_sampling_decisions() {
        let config = SamplingConfig::new(5, 10);

        // Within burst threshold: all pass
        for i in 0..5 {
            assert!(sample_decision(&config, i, 3));
        }

        // Above threshold: error (0) always passes
        assert!(sample_decision(&config, 0, 500));

        // Sampled decisions
        assert!(sample_decision(&config, 10, 500));
        assert!(sample_decision(&config, 20, 500));
        assert!(!sample_decision(&config, 11, 500));
        assert!(!sample_decision(&config, 13, 500));
    }

    #[test]
    fn test_retry_idempotency_and_policy_updates() {
        let (env, admin, caller) = setup();

        // Admin can update sampling policy
        let config = update_sampling_policy(&env, &admin, 20, 50).unwrap();
        assert_eq!(config.burst_threshold, 20);
        assert_eq!(config.sample_rate_denominator, 50);

        // Retrying with same valid parameters succeeds idempotently
        let config2 = update_sampling_policy(&env, &admin, 20, 50).unwrap();
        assert_eq!(config, config2);

        // Denominator of 0 is rejected
        assert_eq!(
            update_sampling_policy(&env, &admin, 20, 0),
            Err(Error::InvalidArgument)
        );

        // Non-admin is unauthorized
        assert_eq!(
            update_sampling_policy(&env, &caller, 20, 50),
            Err(Error::Unauthorized)
        );
    }
}
