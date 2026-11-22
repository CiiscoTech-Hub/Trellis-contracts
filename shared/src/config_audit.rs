//! # Audit Evidence for Sensitive Configuration Changes (Issue #436)
//!
//! Provides verifiable, tamper-evident audit trails and cryptographic proof bundles
//! for mutations to sensitive protocol configuration parameters across the Trellis
//! Soroban contract suite.
//!
//! ## Overview
//!
//! Critical configuration parameters—such as Treasury withdrawal limits, Governance
//! approval thresholds, Oracle staleness windows, Marketplace platform fee rates,
//! and emergency pause flags—can alter the security and economic guarantees of the
//! protocol.
//!
//! This module guarantees:
//! 1. **Mandatory Audit Evidence**: Any sensitive parameter change must supply an
//!    authenticated operator, a salted rationale digest (`rationale_hash`), and a
//!    tracing `correlation_id`.
//! 2. **Tamper-Evident Hash Chaining**: Every configuration change is hashed with the
//!    previous evidence digest into an immutable, verifiable chain.
//! 3. **Parameter Bounds Enforcement**: Production range checks prevent accidental or
//!    malicious misconfiguration (e.g., fee rates > 10% or negative withdrawal limits).
//! 4. **Deterministic Rollback & Compensatory Logging**: Config changes can be
//!    reverted to any prior valid state, logging a compensatory evidence record into
//!    the chain.
//! 5. **Access Control**: Administrative role enforcement (`Role::Admin`) and
//!    cryptographic signature verification via Soroban auth tree.
//!
//! ## Time and Space Complexity
//!
//! - **Time Complexity**:
//!   - Apply change: `O(1)` constant-time cryptographic hash and storage update.
//!   - Rollback change: `O(1)` constant-time reversal with compensatory record.
//!   - Verify chain: `O(M)` linear scan over `M` historical configuration records.
//! - **Space Complexity**:
//!   - `O(1)` storage footprint per configuration change record.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol,
};

use crate::auth::require_admin;
use crate::storage::{persistent_get, persistent_set};

// ---------------------------------------------------------------------------
// Error Codes
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ConfigAuditError {
    /// Caller is not an authorized administrator.
    Unauthorized = 960,
    /// The supplied configuration value is outside safe parameter bounds.
    InvalidParameterBounds = 961,
    /// Rationale hash is missing or zeroed.
    MissingRationale = 962,
    /// Requested evidence record was not found.
    EvidenceNotFound = 963,
    /// Cryptographic hash chain verification failed (tampering detected).
    HashChainBroken = 964,
    /// Target parameter is not currently configured.
    ParameterNotConfigured = 965,
    /// Target evidence ID for rollback is invalid.
    InvalidRollbackTarget = 966,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Tamper-evident audit record for a single sensitive configuration change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigAuditEvidence {
    pub evidence_id: u64,
    pub timestamp: u64,
    pub module: Symbol,
    pub parameter: Symbol,
    pub old_value: i128,
    pub new_value: i128,
    pub actor: Address,
    pub rationale_hash: BytesN<32>,
    pub correlation_id: BytesN<32>,
    pub prev_evidence_hash: BytesN<32>,
    pub evidence_digest: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

const CFG_VAL: Symbol = symbol_short!("cfg_val");
const CFG_HEAD: Symbol = symbol_short!("cfg_head");
const CFG_EVID: Symbol = symbol_short!("cfg_evid");

fn val_key(module: &Symbol, param: &Symbol) -> (Symbol, Symbol, Symbol) {
    (CFG_VAL, module.clone(), param.clone())
}

fn head_key(module: &Symbol, param: &Symbol) -> (Symbol, Symbol, Symbol) {
    (CFG_HEAD, module.clone(), param.clone())
}

fn evidence_key(module: &Symbol, param: &Symbol, id: u64) -> (Symbol, Symbol, Symbol, u64) {
    (CFG_EVID, module.clone(), param.clone(), id)
}

// ---------------------------------------------------------------------------
// Cryptographic Digest Calculation
// ---------------------------------------------------------------------------

fn compute_evidence_digest(
    env: &Env,
    evidence_id: u64,
    timestamp: u64,
    module: &Symbol,
    parameter: &Symbol,
    old_value: i128,
    new_value: i128,
    actor: &Address,
    rationale_hash: &BytesN<32>,
    correlation_id: &BytesN<32>,
    prev_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.append(&to_bytes_u64(env, evidence_id));
    payload.append(&to_bytes_u64(env, timestamp));
    payload.append(&module.clone().to_xdr(env));
    payload.append(&parameter.clone().to_xdr(env));
    payload.append(&actor.clone().to_xdr(env));
    payload.append(&to_bytes_i128(env, old_value));
    payload.append(&to_bytes_i128(env, new_value));
    payload.append(&rationale_hash.clone().into());
    payload.append(&correlation_id.clone().into());
    payload.append(&prev_hash.clone().into());
    env.crypto().sha256(&payload).into()
}

fn to_bytes_u64(env: &Env, val: u64) -> Bytes {
    let mut b = Bytes::new(env);
    for &byte in val.to_be_bytes().iter() {
        b.push_back(byte);
    }
    b
}

fn to_bytes_i128(env: &Env, val: i128) -> Bytes {
    let mut b = Bytes::new(env);
    for &byte in val.to_be_bytes().iter() {
        b.push_back(byte);
    }
    b
}

// ---------------------------------------------------------------------------
// Boundary Validations
// ---------------------------------------------------------------------------

fn validate_parameter_bounds(param: &Symbol, value: i128) -> Result<(), ConfigAuditError> {
    // Treasury max withdrawal limit: must be strictly positive
    if *param == symbol_short!("max_wd") {
        if value <= 0 {
            return Err(ConfigAuditError::InvalidParameterBounds);
        }
    }
    // Marketplace platform fee basis points: max 10% (1,000 bps)
    else if *param == symbol_short!("fee_bps") {
        if !(0..=1000).contains(&value) {
            return Err(ConfigAuditError::InvalidParameterBounds);
        }
    }
    // Governance quorum / threshold: minimum 1
    else if *param == symbol_short!("threshold") || *param == symbol_short!("quorum") {
        if value < 1 {
            return Err(ConfigAuditError::InvalidParameterBounds);
        }
    }
    // Oracle max skew in seconds: 10 to 300 seconds
    else if *param == symbol_short!("skew_secs") {
        if !(10..=300).contains(&value) {
            return Err(ConfigAuditError::InvalidParameterBounds);
        }
    }
    // Emergency pause flag: boolean 0 or 1
    else if *param == symbol_short!("paused") {
        if value != 0 && value != 1 {
            return Err(ConfigAuditError::InvalidParameterBounds);
        }
    }
    Ok(())
}

fn is_empty_hash(hash: &BytesN<32>) -> bool {
    let zero = [0u8; 32];
    hash.to_array() == zero
}

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Apply a sensitive configuration change, validating bounds, enforcing admin authorization,
/// and generating an immutable, hash-chained audit evidence record.
pub fn apply_sensitive_config_change(
    env: &Env,
    admin: &Address,
    module: &Symbol,
    parameter: &Symbol,
    new_value: i128,
    rationale_hash: &BytesN<32>,
    correlation_id: &BytesN<32>,
) -> Result<ConfigAuditEvidence, ConfigAuditError> {
    require_admin(env, admin).map_err(|_| ConfigAuditError::Unauthorized)?;

    if is_empty_hash(rationale_hash) {
        return Err(ConfigAuditError::MissingRationale);
    }

    validate_parameter_bounds(parameter, new_value)?;

    let old_value = persistent_get::<_, i128>(env, &val_key(module, parameter)).unwrap_or(0);

    let (prev_id, prev_hash) = persistent_get::<_, (u64, BytesN<32>)>(env, &head_key(module, parameter))
        .unwrap_or_else(|| (0u64, BytesN::from_array(env, &[0u8; 32])));

    let evidence_id = prev_id + 1;
    let timestamp = env.ledger().timestamp();

    let evidence_digest = compute_evidence_digest(
        env,
        evidence_id,
        timestamp,
        module,
        parameter,
        old_value,
        new_value,
        admin,
        rationale_hash,
        correlation_id,
        &prev_hash,
    );

    let evidence = ConfigAuditEvidence {
        evidence_id,
        timestamp,
        module: module.clone(),
        parameter: parameter.clone(),
        old_value,
        new_value,
        actor: admin.clone(),
        rationale_hash: rationale_hash.clone(),
        correlation_id: correlation_id.clone(),
        prev_evidence_hash: prev_hash,
        evidence_digest: evidence_digest.clone(),
    };

    persistent_set(env, &val_key(module, parameter), &new_value);
    persistent_set(env, &head_key(module, parameter), &(evidence_id, evidence_digest));
    persistent_set(env, &evidence_key(module, parameter, evidence_id), &evidence);

    Ok(evidence)
}

/// Retrieve the active configuration value for a sensitive parameter.
pub fn get_sensitive_config_value(env: &Env, module: &Symbol, parameter: &Symbol) -> Option<i128> {
    persistent_get(env, &val_key(module, parameter))
}

/// Retrieve a specific configuration audit evidence record by ID.
pub fn get_config_audit_evidence(
    env: &Env,
    module: &Symbol,
    parameter: &Symbol,
    evidence_id: u64,
) -> Option<ConfigAuditEvidence> {
    persistent_get(env, &evidence_key(module, parameter, evidence_id))
}

/// Verify the entire cryptographic hash chain for a configuration parameter.
/// Returns the total number of verified records.
pub fn verify_config_audit_chain(
    env: &Env,
    module: &Symbol,
    parameter: &Symbol,
) -> Result<u64, ConfigAuditError> {
    let (head_id, head_digest) = match persistent_get::<_, (u64, BytesN<32>)>(env, &head_key(module, parameter)) {
        Some(h) => h,
        None => return Ok(0),
    };

    let mut current_id = head_id;
    let mut expected_digest = head_digest;

    while current_id > 0 {
        let evidence = get_config_audit_evidence(env, module, parameter, current_id)
            .ok_or(ConfigAuditError::EvidenceNotFound)?;

        if evidence.evidence_digest != expected_digest {
            return Err(ConfigAuditError::HashChainBroken);
        }

        let computed = compute_evidence_digest(
            env,
            evidence.evidence_id,
            evidence.timestamp,
            &evidence.module,
            &evidence.parameter,
            evidence.old_value,
            evidence.new_value,
            &evidence.actor,
            &evidence.rationale_hash,
            &evidence.correlation_id,
            &evidence.prev_evidence_hash,
        );

        if computed != evidence.evidence_digest {
            return Err(ConfigAuditError::HashChainBroken);
        }

        expected_digest = evidence.prev_evidence_hash;
        current_id -= 1;
    }

    Ok(head_id)
}

/// Rollback a configuration parameter to a target historical value, recording
/// an explicit compensatory evidence record into the audit trail.
pub fn rollback_config_change(
    env: &Env,
    admin: &Address,
    module: &Symbol,
    parameter: &Symbol,
    target_evidence_id: u64,
    rationale_hash: &BytesN<32>,
    correlation_id: &BytesN<32>,
) -> Result<ConfigAuditEvidence, ConfigAuditError> {
    let target_evidence = get_config_audit_evidence(env, module, parameter, target_evidence_id)
        .ok_or(ConfigAuditError::InvalidRollbackTarget)?;

    // Roll back to target's old_value (apply_sensitive_config_change verifies admin authorization)
    apply_sensitive_config_change(
        env,
        admin,
        module,
        parameter,
        target_evidence.old_value,
        rationale_hash,
        correlation_id,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _};
    use crate::auth::set_admin;

    #[contract]
    struct ConfigAuditTestContract;

    #[contractimpl]
    impl ConfigAuditTestContract {}

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ConfigAuditTestContract);
        let admin = Address::generate(&env);
        env.as_contract(&contract_id, || {
            set_admin(&env, &admin);
        });
        (env, contract_id, admin)
    }

    fn sample_hash(env: &Env, val: u8) -> BytesN<32> {
        let arr = [val; 32];
        BytesN::from_array(env, &arr)
    }

    #[test]
    fn test_normal_config_mutation_with_evidence_chain() {
        let (env, contract_id, admin) = setup();
        let module = symbol_short!("treasury");
        let param = symbol_short!("max_wd");
        let rat1 = sample_hash(&env, 1);
        let corr1 = sample_hash(&env, 10);

        let e1 = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 5000, &rat1, &corr1).unwrap()
        });

        assert_eq!(e1.evidence_id, 1);
        assert_eq!(e1.old_value, 0);
        assert_eq!(e1.new_value, 5000);
        assert_eq!(e1.actor, admin);

        let val1 = env.as_contract(&contract_id, || {
            get_sensitive_config_value(&env, &module, &param).unwrap()
        });
        assert_eq!(val1, 5000);

        // Second update: 5000 -> 10000
        let rat2 = sample_hash(&env, 2);
        let corr2 = sample_hash(&env, 20);

        let e2 = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 10000, &rat2, &corr2).unwrap()
        });

        assert_eq!(e2.evidence_id, 2);
        assert_eq!(e2.old_value, 5000);
        assert_eq!(e2.new_value, 10000);
        assert_eq!(e2.prev_evidence_hash, e1.evidence_digest);

        // Verify cryptographic chain
        let verified_count = env.as_contract(&contract_id, || {
            verify_config_audit_chain(&env, &module, &param).unwrap()
        });
        assert_eq!(verified_count, 2);
    }

    #[test]
    fn test_parameter_bounds_rejection_and_retry() {
        let (env, contract_id, admin) = setup();
        let module = symbol_short!("mkt");
        let param = symbol_short!("fee_bps");
        let rat = sample_hash(&env, 3);
        let corr = sample_hash(&env, 30);

        // Value 1500 bps (15%) exceeds max allowed 10% (1000 bps)
        let err = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 1500, &rat, &corr)
        });
        assert_eq!(err, Err(ConfigAuditError::InvalidParameterBounds));

        // State remains unconfigured
        let current = env.as_contract(&contract_id, || {
            get_sensitive_config_value(&env, &module, &param)
        });
        assert_eq!(current, None);

        // Retry with valid fee 500 bps (5%) succeeds
        let e_retry = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 500, &rat, &corr).unwrap()
        });
        assert_eq!(e_retry.new_value, 500);
    }

    #[test]
    fn test_missing_rationale_hash_rejected() {
        let (env, contract_id, admin) = setup();
        let module = symbol_short!("gov");
        let param = symbol_short!("threshold");
        let empty_rat = sample_hash(&env, 0);
        let corr = sample_hash(&env, 40);

        let err = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 3, &empty_rat, &corr)
        });
        assert_eq!(err, Err(ConfigAuditError::MissingRationale));
    }

    #[test]
    fn test_unauthorized_mutation_rejected() {
        let (env, contract_id, _admin) = setup();
        let unauthorized = Address::generate(&env);
        let module = symbol_short!("oracle");
        let param = symbol_short!("skew_secs");
        let rat = sample_hash(&env, 5);
        let corr = sample_hash(&env, 50);

        let err = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &unauthorized, &module, &param, 60, &rat, &corr)
        });
        assert_eq!(err, Err(ConfigAuditError::Unauthorized));
    }

    #[test]
    fn test_rollback_and_compensatory_evidence() {
        let (env, contract_id, admin) = setup();
        let module = symbol_short!("treasury");
        let param = symbol_short!("max_wd");
        let rat = sample_hash(&env, 6);
        let corr = sample_hash(&env, 60);

        // Baseline: set max_wd to 10000
        env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 10000, &rat, &corr).unwrap()
        });

        // Mistaken change: set max_wd to 50000 (evidence_id 2, old_value 10000)
        let e2 = env.as_contract(&contract_id, || {
            apply_sensitive_config_change(&env, &admin, &module, &param, 50000, &rat, &corr).unwrap()
        });
        assert_eq!(e2.evidence_id, 2);

        // Rollback change 2 -> reverts parameter to 10000 and writes evidence_id 3
        let rat_rb = sample_hash(&env, 7);
        let corr_rb = sample_hash(&env, 70);

        let e_rb = env.as_contract(&contract_id, || {
            rollback_config_change(&env, &admin, &module, &param, 2, &rat_rb, &corr_rb).unwrap()
        });

        assert_eq!(e_rb.evidence_id, 3);
        assert_eq!(e_rb.old_value, 50000);
        assert_eq!(e_rb.new_value, 10000);

        // Current active value restored to 10000
        let restored = env.as_contract(&contract_id, || {
            get_sensitive_config_value(&env, &module, &param).unwrap()
        });
        assert_eq!(restored, 10000);

        // Chain is complete and intact across 3 records
        let chain_len = env.as_contract(&contract_id, || {
            verify_config_audit_chain(&env, &module, &param).unwrap()
        });
        assert_eq!(chain_len, 3);
    }
}
