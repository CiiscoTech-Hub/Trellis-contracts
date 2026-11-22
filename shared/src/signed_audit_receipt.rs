//! Signed audit receipts for privileged actions (Issue #424).
//!
//! Wraps the existing hash-chained audit ledger to issue a tamper-evident
//! receipt every time a privileged action is recorded.  Verification reads
//! the live chain — no extra storage is needed.

use soroban_sdk::{contracttype, BytesN, Env, Symbol};

use crate::{
    audit_ledger::{
        append_event, entry_hash, get_entry, record_admin_change, AuditEventClass,
        AdminChangeReceipt, AuditEventParams, AuditLedgerEntry, AUDIT_LEDGER_SCHEMA_VERSION,
    },
    errors::Error,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Tamper-evident receipt pinning a privileged action to its chain position.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAuditReceipt {
    pub schema_version: u32,
    pub seq: u64,
    /// Stable numeric code of the recorded event kind.
    pub kind_code: u32,
    pub module: Symbol,
    /// SHA-256 of the recorded entry (the "signature").
    pub entry_hash: BytesN<32>,
    /// Hash of the preceding entry — anchors this receipt in the chain.
    pub prev_hash: BytesN<32>,
    pub ledger: u32,
    pub timestamp: u64,
}

/// Outcome of verifying a receipt against the live chain.
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptStatus {
    Valid = 0,
    Missing = 1,
    HashMismatch = 2,
    ChainBroken = 3,
    ModuleMismatch = 4,
    KindMismatch = 5,
    MetadataMismatch = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptVerification {
    pub valid: bool,
    pub status: ReceiptStatus,
    pub seq: u64,
    pub live_hash: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// Append a privileged event and return a [`SignedAuditReceipt`].
pub fn issue_privileged_receipt(env: &Env, params: AuditEventParams) -> Result<SignedAuditReceipt, Error> {
    // `append_privileged` takes individual fields and drops amount/resource/
    // correlation; apply its class rule here and keep the full params.
    if params.kind.class() != AuditEventClass::Privileged {
        return Err(Error::InvalidArgument);
    }
    append_event(env, params)?;
    let seq = crate::audit_ledger::head(env).length;
    let entry = get_entry(env, seq).ok_or(Error::NotFound)?;
    Ok(build_receipt(env, &entry))
}

/// Append an admin-change event and return both receipt types.
pub fn issue_admin_change_receipt(
    env: &Env,
    params: AuditEventParams,
) -> Result<(SignedAuditReceipt, AdminChangeReceipt), Error> {
    let admin = record_admin_change(
        env,
        params.kind,
        params.module,
        params.actor,
        params.subject,
        params.attribute,
        params.note,
    )?;
    let entry = get_entry(env, admin.seq).ok_or(Error::NotFound)?;
    Ok((build_receipt(env, &entry), admin))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a receipt against the live chain (read-only, no auth required).
pub fn verify_receipt(env: &Env, receipt: &SignedAuditReceipt) -> ReceiptVerification {
    let zero = BytesN::from_array(env, &[0u8; 32]);

    let entry = match get_entry(env, receipt.seq) {
        Some(e) => e,
        None => return ReceiptVerification { valid: false, status: ReceiptStatus::Missing, seq: receipt.seq, live_hash: zero },
    };

    let live = entry_hash(env, &entry);

    if live          != receipt.entry_hash { return bad(ReceiptStatus::HashMismatch,    receipt.seq, live); }
    if entry.prev_hash != receipt.prev_hash { return bad(ReceiptStatus::ChainBroken,     receipt.seq, live); }
    if entry.module    != receipt.module    { return bad(ReceiptStatus::ModuleMismatch,  receipt.seq, live); }
    if entry.kind.code() != receipt.kind_code { return bad(ReceiptStatus::KindMismatch, receipt.seq, live); }
    if entry.ledger    != receipt.ledger
    || entry.timestamp != receipt.timestamp { return bad(ReceiptStatus::MetadataMismatch, receipt.seq, live); }

    ReceiptVerification { valid: true, status: ReceiptStatus::Valid, seq: receipt.seq, live_hash: live }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_receipt(env: &Env, entry: &AuditLedgerEntry) -> SignedAuditReceipt {
    SignedAuditReceipt {
        schema_version: AUDIT_LEDGER_SCHEMA_VERSION,
        seq:        entry.seq,
        kind_code:  entry.kind.code(),
        module:     entry.module.clone(),
        entry_hash: entry_hash(env, entry),
        prev_hash:  entry.prev_hash.clone(),
        ledger:     entry.ledger,
        timestamp:  entry.timestamp,
    }
}

fn bad(status: ReceiptStatus, seq: u64, live_hash: BytesN<32>) -> ReceiptVerification {
    ReceiptVerification { valid: false, status, seq, live_hash }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _, LedgerInfo},
        symbol_short, Address, BytesN, Env,
    };
    use crate::audit_ledger::{AuditEventKind, AuditEventParams};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_000, protocol_version: 21, sequence_number: 100,
            network_id: Default::default(), base_reserve: 10,
            min_temp_entry_ttl: 1, min_persistent_entry_ttl: 1, max_entry_ttl: 10_000,
        });
        crate::audit_ledger::checkpoint(&env);
        let caller = Address::generate(&env);
        (env, caller)
    }

    fn params(env: &Env, actor: &Address) -> AuditEventParams {
        AuditEventParams {
            kind: AuditEventKind::ConfigChanged,
            module: symbol_short!("test"),
            actor: actor.clone(),
            subject: None, resource: None, attribute: None,
            amount: None, previous_amount: None, note: None,
            correlation_id: BytesN::from_array(env, &[0u8; 32]),
        }
    }

    // normal path
    #[test]
    fn receipt_issued_with_correct_seq_and_kind() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        assert_eq!(r.seq, 1);
        assert_eq!(r.kind_code, AuditEventKind::ConfigChanged.code());
    }

    #[test]
    fn receipt_verified_immediately_after_issuance() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let v = verify_receipt(&env, &r);
        assert!(v.valid);
        assert_eq!(v.status, ReceiptStatus::Valid);
    }

    #[test]
    fn sequential_receipts_form_hash_chain() {
        let (env, actor) = setup();
        let r1 = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let r2 = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        assert_eq!(r2.prev_hash, r1.entry_hash);
        assert!(verify_receipt(&env, &r1).valid);
        assert!(verify_receipt(&env, &r2).valid);
    }

    #[test]
    fn admin_change_receipt_both_types_match_seq_and_hash() {
        let (env, actor) = setup();
        let p = AuditEventParams { kind: AuditEventKind::RoleGranted, ..params(&env, &actor) };
        let (s, a) = issue_admin_change_receipt(&env, p).unwrap();
        assert_eq!(s.seq, a.seq);
        assert_eq!(s.entry_hash, a.entry_hash);
    }

    // failure paths
    #[test]
    fn missing_seq_returns_missing_status() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let fake = SignedAuditReceipt { seq: 999, ..r };
        assert_eq!(verify_receipt(&env, &fake).status, ReceiptStatus::Missing);
    }

    #[test]
    fn tampered_entry_hash_returns_hash_mismatch() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let mut raw = r.entry_hash.to_array(); raw[0] ^= 0xFF;
        let fake = SignedAuditReceipt { entry_hash: BytesN::from_array(&env, &raw), ..r };
        assert_eq!(verify_receipt(&env, &fake).status, ReceiptStatus::HashMismatch);
    }

    #[test]
    fn wrong_module_returns_module_mismatch() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let fake = SignedAuditReceipt { module: symbol_short!("wrong"), ..r };
        assert_eq!(verify_receipt(&env, &fake).status, ReceiptStatus::ModuleMismatch);
    }

    #[test]
    fn wrong_kind_code_returns_kind_mismatch() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let fake = SignedAuditReceipt { kind_code: AuditEventKind::ContractUpgraded.code(), ..r };
        assert_eq!(verify_receipt(&env, &fake).status, ReceiptStatus::KindMismatch);
    }

    #[test]
    fn wrong_timestamp_returns_metadata_mismatch() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        let fake = SignedAuditReceipt { timestamp: r.timestamp + 1, ..r };
        assert_eq!(verify_receipt(&env, &fake).status, ReceiptStatus::MetadataMismatch);
    }

    // retry/idempotency
    #[test]
    fn re_verifying_same_receipt_is_idempotent() {
        let (env, actor) = setup();
        let r = issue_privileged_receipt(&env, params(&env, &actor)).unwrap();
        assert_eq!(verify_receipt(&env, &r).status, verify_receipt(&env, &r).status);
    }

    // authorization path
    #[test]
    fn all_privileged_kinds_produce_valid_receipts() {
        let (env, actor) = setup();
        for kind in [AuditEventKind::RoleGranted, AuditEventKind::RoleRevoked,
                     AuditEventKind::ContractPaused, AuditEventKind::EmergencyAction] {
            let p = AuditEventParams { kind, ..params(&env, &actor) };
            let r = issue_privileged_receipt(&env, p).unwrap();
            assert!(verify_receipt(&env, &r).valid);
        }
    }
}
