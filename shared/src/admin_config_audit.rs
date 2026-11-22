//! Audit evidence for administrative configuration changes (Issue #278).
//!
//! Binds every administrative configuration mutation to a versioned,
//! tamper-evident [`AdminConfigEvidence`] record backed by both a canonical
//! XDR SHA-256 `evidence_hash` and an immutable [`AdminChangeReceipt`] in
//! [`crate::audit_ledger`].

use soroban_sdk::{
    contracttype, symbol_short, xdr::ToXdr, Address, BytesN, Env, Symbol,
};

use crate::audit_ledger::{
    record_admin_change, verify_admin_receipt, AdminChangeReceipt, AdminReceiptStatus,
    AuditEventKind,
};
use crate::auth::require_admin;
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

/// Verification outcome for a stored [`AdminConfigEvidence`] record.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ConfigEvidenceStatus {
    /// Both the canonical XDR evidence hash and the audit-ledger receipt match.
    Verified = 1,
    /// No evidence record exists for the requested `(config_key, version)`.
    Missing = 2,
    /// Recomputed `evidence_hash` does not match the stored digest.
    HashMismatch = 3,
    /// The underlying audit-ledger receipt failed verification.
    ReceiptInvalid = 4,
}

/// Tamper-evident record of a single administrative configuration change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminConfigEvidence {
    /// Configuration key that was mutated.
    pub config_key: Symbol,
    /// Monotonic 1-based version for `config_key`.
    pub version: u32,
    /// Administrator who authorized the change.
    pub actor: Address,
    /// SHA-256 digest of the previous configuration value.
    pub before_hash: BytesN<32>,
    /// SHA-256 digest of the new configuration value.
    pub after_hash: BytesN<32>,
    /// Short reason/change-ticket symbol.
    pub reason: Symbol,
    /// Ledger sequence when recorded.
    pub ledger: u32,
    /// Ledger timestamp when recorded.
    pub timestamp: u64,
    /// Canonical XDR SHA-256 digest over all evidence fields above.
    pub evidence_hash: BytesN<32>,
    /// Receipt linking this change into the append-only audit ledger.
    pub receipt: AdminChangeReceipt,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfigAuditKey {
    LatestVersion(Symbol),
    Evidence(Symbol, u32),
}

/// Computes the deterministic SHA-256 evidence digest over canonical XDR fields.
pub fn compute_evidence_hash(
    env: &Env,
    config_key: &Symbol,
    version: u32,
    actor: &Address,
    before_hash: &BytesN<32>,
    after_hash: &BytesN<32>,
    reason: &Symbol,
    ledger: u32,
    timestamp: u64,
) -> BytesN<32> {
    let payload = (
        symbol_short!("cfg_evid"),
        env.current_contract_address(),
        config_key.clone(),
        version,
        actor.clone(),
        before_hash.clone(),
        after_hash.clone(),
        reason.clone(),
        ledger,
        timestamp,
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).into()
}

/// Returns the latest recorded version number for `config_key` (0 if never set).
pub fn latest_config_version(env: &Env, config_key: &Symbol) -> u32 {
    persistent_get(env, &ConfigAuditKey::LatestVersion(config_key.clone())).unwrap_or(0)
}

/// Returns the stored [`AdminConfigEvidence`] for `(config_key, version)`.
pub fn get_config_evidence(
    env: &Env,
    config_key: &Symbol,
    version: u32,
) -> Option<AdminConfigEvidence> {
    persistent_get(env, &ConfigAuditKey::Evidence(config_key.clone(), version))
}

/// Records an administrative configuration change with full audit evidence.
///
/// Admin-gated via [`require_admin`]. Rejects no-op changes where
/// `before_hash == after_hash` with `Err(Error::NoChangeDetected)`.
pub fn record_config_change(
    env: &Env,
    admin: &Address,
    module: Symbol,
    config_key: Symbol,
    before_hash: BytesN<32>,
    after_hash: BytesN<32>,
    reason: Symbol,
) -> Result<AdminConfigEvidence, Error> {
    require_admin(env, admin)?;

    if before_hash == after_hash {
        return Err(Error::NoChangeDetected);
    }

    let prev_version = latest_config_version(env, &config_key);
    let version = prev_version.checked_add(1).ok_or(Error::Overflow)?;
    let ledger = env.ledger().sequence();
    let timestamp = env.ledger().timestamp();

    let evidence_hash = compute_evidence_hash(
        env,
        &config_key,
        version,
        admin,
        &before_hash,
        &after_hash,
        &reason,
        ledger,
        timestamp,
    );

    let receipt = record_admin_change(
        env,
        AuditEventKind::ConfigChanged,
        module,
        admin.clone(),
        None,
        Some(config_key.clone()),
        Some(reason.clone()),
    )?;

    let evidence = AdminConfigEvidence {
        config_key: config_key.clone(),
        version,
        actor: admin.clone(),
        before_hash,
        after_hash,
        reason,
        ledger,
        timestamp,
        evidence_hash: evidence_hash.clone(),
        receipt,
    };

    persistent_set(
        env,
        &ConfigAuditKey::Evidence(config_key.clone(), version),
        &evidence,
    );
    persistent_set(env, &ConfigAuditKey::LatestVersion(config_key.clone()), &version);

    env.events().publish(
        (symbol_short!("cfg_aud"), config_key),
        (version, evidence_hash),
    );

    Ok(evidence)
}

/// Records an administrative rollback to `target_version`'s `after_hash` as a
/// new append-only audit evidence entry, preserving prior history.
pub fn rollback_config_change(
    env: &Env,
    admin: &Address,
    module: Symbol,
    config_key: Symbol,
    target_version: u32,
    reason: Symbol,
) -> Result<AdminConfigEvidence, Error> {
    require_admin(env, admin)?;

    let latest_ver = latest_config_version(env, &config_key);
    if latest_ver == 0 {
        return Err(Error::NotFound);
    }
    let current = get_config_evidence(env, &config_key, latest_ver).ok_or(Error::NotFound)?;
    let target = get_config_evidence(env, &config_key, target_version).ok_or(Error::NotFound)?;

    record_config_change(
        env,
        admin,
        module,
        config_key,
        current.after_hash,
        target.after_hash,
        reason,
    )
}

/// Verifies both the canonical `evidence_hash` and the underlying
/// [`AdminChangeReceipt`] against the live audit ledger.
pub fn verify_config_evidence(
    env: &Env,
    config_key: &Symbol,
    version: u32,
) -> ConfigEvidenceStatus {
    let evidence = match get_config_evidence(env, config_key, version) {
        Some(ev) => ev,
        None => return ConfigEvidenceStatus::Missing,
    };

    let expected = compute_evidence_hash(
        env,
        &evidence.config_key,
        evidence.version,
        &evidence.actor,
        &evidence.before_hash,
        &evidence.after_hash,
        &evidence.reason,
        evidence.ledger,
        evidence.timestamp,
    );
    if expected != evidence.evidence_hash {
        return ConfigEvidenceStatus::HashMismatch;
    }

    match verify_admin_receipt(env, &evidence.receipt) {
        AdminReceiptStatus::Valid => ConfigEvidenceStatus::Verified,
        _ => ConfigEvidenceStatus::ReceiptInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::initialize_admin;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Ledger as _},
        Bytes, Env,
    };

    #[contract]
    struct ConfigAuditTestContract;

    #[contractimpl]
    impl ConfigAuditTestContract {}

    fn hash_byte(env: &Env, b: u8) -> BytesN<32> {
        env.crypto().sha256(&Bytes::from_slice(env, &[b])).into()
    }

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ConfigAuditTestContract);
        let admin = Address::generate(&env);
        env.ledger().set_sequence_number(10);
        env.ledger().set_timestamp(5_000);
        env.as_contract(&contract_id, || {
            initialize_admin(&env, &admin).unwrap();
        });
        (env, contract_id, admin)
    }

    #[test]
    fn test_record_verify_and_rollback_config_evidence() {
        let (env, contract_id, admin) = setup();
        let key = symbol_short!("fee_bps");
        let module = symbol_short!("treasury");

        env.as_contract(&contract_id, || {
            let h0 = hash_byte(&env, 0);
            let h1 = hash_byte(&env, 1);
            let h2 = hash_byte(&env, 2);

            let ev1 = record_config_change(
                &env,
                &admin,
                module.clone(),
                key.clone(),
                h0.clone(),
                h1.clone(),
                symbol_short!("init_fee"),
            )
            .unwrap();
            assert_eq!(ev1.version, 1);
            assert_eq!(
                verify_config_evidence(&env, &key, 1),
                ConfigEvidenceStatus::Verified
            );

            env.ledger().set_sequence_number(11);
            env.ledger().set_timestamp(5_010);
            let ev2 = record_config_change(
                &env,
                &admin,
                module.clone(),
                key.clone(),
                h1.clone(),
                h2.clone(),
                symbol_short!("raise"),
            )
            .unwrap();
            assert_eq!(ev2.version, 2);

            // Rollback to v1 appends v3 rather than mutating v1/v2
            env.ledger().set_sequence_number(12);
            env.ledger().set_timestamp(5_020);
            let ev3 = rollback_config_change(
                &env,
                &admin,
                module,
                key.clone(),
                1,
                symbol_short!("revert"),
            )
            .unwrap();
            assert_eq!(ev3.version, 3);
            assert_eq!(ev3.before_hash, h2);
            assert_eq!(ev3.after_hash, h1);
            assert_eq!(latest_config_version(&env, &key), 3);
            assert_eq!(
                verify_config_evidence(&env, &key, 1),
                ConfigEvidenceStatus::Verified
            );
            assert_eq!(
                verify_config_evidence(&env, &key, 2),
                ConfigEvidenceStatus::Verified
            );
            assert_eq!(
                verify_config_evidence(&env, &key, 3),
                ConfigEvidenceStatus::Verified
            );
        });
    }

    #[test]
    fn test_tamper_detection_noop_and_missing_failures() {
        let (env, contract_id, admin) = setup();
        let key = symbol_short!("cap");
        let module = symbol_short!("aid");

        env.as_contract(&contract_id, || {
            assert_eq!(
                verify_config_evidence(&env, &key, 1),
                ConfigEvidenceStatus::Missing
            );

            let h1 = hash_byte(&env, 1);
            // No-op change rejected
            assert_eq!(
                record_config_change(
                    &env,
                    &admin,
                    module.clone(),
                    key.clone(),
                    h1.clone(),
                    h1.clone(),
                    symbol_short!("noop"),
                ),
                Err(Error::NoChangeDetected)
            );

            let h2 = hash_byte(&env, 2);
            let mut ev = record_config_change(
                &env,
                &admin,
                module,
                key.clone(),
                h1,
                h2,
                symbol_short!("set_cap"),
            )
            .unwrap();

            // Simulate storage tampering on after_hash
            ev.after_hash = hash_byte(&env, 99);
            persistent_set(&env, &ConfigAuditKey::Evidence(key.clone(), 1), &ev);
            assert_eq!(
                verify_config_evidence(&env, &key, 1),
                ConfigEvidenceStatus::HashMismatch
            );
        });
    }

    #[test]
    fn test_non_admin_rejected() {
        let (env, contract_id, _admin) = setup();
        let attacker = Address::generate(&env);
        let key = symbol_short!("cap");
        let module = symbol_short!("aid");

        env.as_contract(&contract_id, || {
            let h1 = hash_byte(&env, 1);
            let h2 = hash_byte(&env, 2);
            assert_eq!(
                record_config_change(
                    &env,
                    &attacker,
                    module.clone(),
                    key.clone(),
                    h1,
                    h2,
                    symbol_short!("hack"),
                ),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                rollback_config_change(&env, &attacker, module, key, 1, symbol_short!("hack")),
                Err(Error::Unauthorized)
            );
        });
    }
}
