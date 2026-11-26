#![no_std]
//! Cryptographically signed audit receipts for administrative changes.
//!
//! This contract provides a focused, self-contained vertical slice for
//! **Ed25519-signed, hash-chained admin audit receipts**:
//!
//! 1. **Admin & Signer Registry**: An initialized admin registers and revokes
//!    32-byte Ed25519 public keys authorized to countersign admin change
//!    receipts. Revocation is monotonic and records `revoked_ledger` /
//!    `revoked_at` so historical receipts remain auditable.
//! 2. **Idempotent Pending Receipt Issuance**: `issue_pending_receipt` records
//!    an admin change in an append-only, SHA-256 hash-chained ledger under a
//!    caller-supplied `change_id: BytesN<32>` idempotency key. Retrying with
//!    identical parameters returns the existing pending receipt without
//!    duplicating the chain entry; conflicting parameters return
//!    `IdempotencyConflict`.
//! 3. **Canonical Signing Digest**: `receipt_signing_digest` computes a
//!    domain-separated SHA-256 digest over canonical Soroban XDR encoding of
//!    the schema version, `change_id`, ledger-pinned receipt fields, and
//!    `signer_key`.
//! 4. **Ed25519 Signature Attachment**: `attach_receipt_signature` checks that
//!    `signer_key` is registered and active, then verifies the Ed25519
//!    signature via Soroban's host `ed25519_verify` (which aborts the
//!    transaction on invalid signatures, preventing any partial write).
//!    Retrying with the exact same `(change_id, signer_key, signature)` is
//!    idempotent.
//! 5. **End-to-End Verification**: `verify_signed_receipt` checks schema
//!    version, signer registration & revocation timing, digest integrity,
//!    Ed25519 signature validity, and forward hash-chain linkage to head.
//!
//! See `docs/SIGNED_AUDIT_RECEIPTS.md` for architecture, edge cases, recovery
//! procedures, and migration guidance.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    BytesN, Env, IntoVal, Symbol, Val, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator mixed into every hash-chained admin change entry.
pub const AUDIT_CHAIN_DOMAIN: &str = "trellis_admin_audit_chain";

/// Domain separator mixed into every signed audit receipt digest.
pub const SIGNED_AUDIT_RECEIPT_DOMAIN: &str = "trellis_signed_audit_receipt";

/// Current schema version for signed admin audit receipts.
pub const SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Maximum number of chain links scanned in a single verification call.
pub const MAX_VERIFY_ENTRIES: u64 = 10_000;

// ---------------------------------------------------------------------------
// Errors & Verification Status
// ---------------------------------------------------------------------------

/// Error returned by signed audit receipt contract entry points.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SignedReceiptError {
    /// Contract has not been initialized yet.
    NotInitialized = 1,
    /// Contract is already initialized.
    AlreadyInitialized = 2,
    /// Caller lacks the required administrative authority.
    Unauthorized = 3,
    /// Input parameter is invalid.
    InvalidInput = 4,
    /// The supplied `signer_key` is not registered.
    UnknownSigner = 5,
    /// The supplied `signer_key` has been revoked.
    SignerRevoked = 6,
    /// No pending or signed receipt exists for `change_id`.
    ReceiptNotFound = 7,
    /// `change_id` was already used with different change parameters.
    IdempotencyConflict = 8,
    /// The receipt was already signed with a different signer or signature.
    AlreadySigned = 9,
    /// Sequence counter overflowed.
    Overflow = 10,
}

/// Result of verifying a [`SignedAdminAuditReceipt`] against signer registry,
/// Ed25519 cryptography, and the live hash-chained audit ledger.
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedReceiptVerificationStatus {
    /// Signature, digest, active signer, and live audit chain all verify.
    Valid = 0,
    /// Receipt was validly signed while the signer was active, and the chain
    /// verifies, though the signer was revoked at a later ledger.
    ValidSignerRevokedLater = 1,
    /// Receipt schema version is unsupported.
    UnsupportedSchema = 2,
    /// Signer key was never registered.
    UnknownSigner = 3,
    /// Signer key was already revoked at or before `signed_ledger`.
    SignerRevokedBeforeSigning = 4,
    /// Recomputed signing digest does not match `receipt.digest`.
    DigestMismatch = 5,
    /// Underlying audit chain entry is missing.
    LedgerMissing = 6,
    /// Underlying audit chain entry does not match the receipt or is tampered.
    LedgerMismatch = 7,
    /// Underlying audit chain does not link forward to head.
    LedgerUnlinked = 8,
    /// Underlying audit chain verification exceeded `MAX_VERIFY_ENTRIES`.
    LedgerScanLimitExceeded = 9,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Privileged administrative event categories covered by signed receipts.
#[contracttype]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminChangeKind {
    ConfigChanged = 1,
    RoleGranted = 2,
    RoleRevoked = 3,
    ContractPaused = 4,
    ContractResumed = 5,
    ContractUpgraded = 6,
    AdminTransferred = 7,
}

/// Head pointer of the append-only admin audit hash chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditChainHead {
    pub length: u64,
    pub head_hash: BytesN<32>,
}

/// Immutable hash-chained audit entry for an admin change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAuditEntry {
    pub seq: u64,
    pub kind: AdminChangeKind,
    pub module: Symbol,
    pub actor: Address,
    pub subject: Option<Address>,
    pub attribute: Option<Symbol>,
    pub note: Option<Symbol>,
    pub ledger: u32,
    pub timestamp: u64,
    pub prev_hash: BytesN<32>,
    pub entry_hash: BytesN<32>,
}

/// Ledger-pinned receipt for an admin change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangeReceipt {
    pub seq: u64,
    pub kind: AdminChangeKind,
    pub actor: Address,
    pub entry_hash: BytesN<32>,
    pub prev_hash: BytesN<32>,
    pub ledger: u32,
    pub timestamp: u64,
}

/// Persistent registration record for an authorized Ed25519 receipt signer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptSignerRecord {
    pub public_key: BytesN<32>,
    pub registered_by: Address,
    pub registered_ledger: u32,
    pub registered_at: u64,
    pub active: bool,
    pub revoked_ledger: Option<u32>,
    pub revoked_at: Option<u64>,
}

/// Fingerprint of the admin change parameters used to enforce idempotency on
/// retries of `issue_pending_receipt`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangeRequestFingerprint {
    pub kind: AdminChangeKind,
    pub module: Symbol,
    pub actor: Address,
    pub subject: Option<Address>,
    pub attribute: Option<Symbol>,
    pub note: Option<Symbol>,
}

/// An admin change recorded in the audit chain that is awaiting an Ed25519
/// signature from an authorized receipt signer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAdminReceipt {
    pub schema_version: u32,
    pub change_id: BytesN<32>,
    pub fingerprint: AdminChangeRequestFingerprint,
    pub receipt: AdminChangeReceipt,
}

/// A cryptographically signed, ledger-pinned audit receipt for an admin change.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAdminAuditReceipt {
    pub schema_version: u32,
    pub change_id: BytesN<32>,
    pub receipt: AdminChangeReceipt,
    pub signer_key: BytesN<32>,
    pub digest: BytesN<32>,
    pub signature: BytesN<64>,
    pub signed_ledger: u32,
    pub signed_at: u64,
}

/// Isolated storage keys for the signed audit receipts contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageKey {
    Admin,
    ChainHead,
    ChainEntry(u64),
    Signer(BytesN<32>),
    Pending(BytesN<32>),
    Signed(BytesN<32>),
    BySeq(u64),
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

fn genesis_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn require_admin_auth(env: &Env, caller: &Address) -> Result<(), SignedReceiptError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(SignedReceiptError::NotInitialized)?;
    if *caller != admin {
        return Err(SignedReceiptError::Unauthorized);
    }
    caller.require_auth();
    Ok(())
}

fn get_chain_head(env: &Env) -> AuditChainHead {
    env.storage()
        .instance()
        .get(&StorageKey::ChainHead)
        .unwrap_or_else(|| AuditChainHead {
            length: 0,
            head_hash: genesis_hash(env),
        })
}

fn compute_entry_hash(env: &Env, entry: &AdminAuditEntry) -> BytesN<32> {
    let mut fields: Vec<Val> = Vec::new(env);
    fields.push_back(Symbol::new(env, AUDIT_CHAIN_DOMAIN).into_val(env));
    fields.push_back(SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION.into_val(env));
    fields.push_back(entry.seq.into_val(env));
    fields.push_back(entry.kind.into_val(env));
    fields.push_back(entry.module.clone().into_val(env));
    fields.push_back(entry.actor.clone().into_val(env));
    fields.push_back(entry.subject.clone().into_val(env));
    fields.push_back(entry.attribute.clone().into_val(env));
    fields.push_back(entry.note.clone().into_val(env));
    fields.push_back(entry.ledger.into_val(env));
    fields.push_back(entry.timestamp.into_val(env));
    fields.push_back(entry.prev_hash.clone().into_val(env));

    let encoded: Bytes = fields.to_xdr(env);
    env.crypto().sha256(&encoded).into()
}

fn compute_signing_digest(
    env: &Env,
    change_id: &BytesN<32>,
    receipt: &AdminChangeReceipt,
    signer_key: &BytesN<32>,
) -> BytesN<32> {
    let mut fields: Vec<Val> = Vec::new(env);
    fields.push_back(Symbol::new(env, SIGNED_AUDIT_RECEIPT_DOMAIN).into_val(env));
    fields.push_back(SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION.into_val(env));
    fields.push_back(change_id.clone().into_val(env));
    fields.push_back(receipt.seq.into_val(env));
    fields.push_back(receipt.kind.into_val(env));
    fields.push_back(receipt.actor.clone().into_val(env));
    fields.push_back(receipt.entry_hash.clone().into_val(env));
    fields.push_back(receipt.prev_hash.clone().into_val(env));
    fields.push_back(receipt.ledger.into_val(env));
    fields.push_back(receipt.timestamp.into_val(env));
    fields.push_back(signer_key.clone().into_val(env));

    let encoded: Bytes = fields.to_xdr(env);
    env.crypto().sha256(&encoded).into()
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SignedAuditReceiptsContract;

#[contractimpl]
impl SignedAuditReceiptsContract {
    /// Initializes the contract with the controlling administrator address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), SignedReceiptError> {
        if env.storage().instance().has(&StorageKey::Admin) {
            return Err(SignedReceiptError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&StorageKey::Admin, &admin);
        env.storage().instance().set(
            &StorageKey::ChainHead,
            &AuditChainHead {
                length: 0,
                head_hash: genesis_hash(&env),
            },
        );
        Ok(())
    }

    /// Registers an Ed25519 public key as an authorized receipt signer.
    ///
    /// Idempotent for an already-active key. Re-activating a revoked key is
    /// disallowed; rotate to a fresh Ed25519 keypair instead.
    pub fn register_receipt_signer(
        env: Env,
        admin: Address,
        signer_key: BytesN<32>,
    ) -> Result<(), SignedReceiptError> {
        require_admin_auth(&env, &admin)?;

        let key = StorageKey::Signer(signer_key.clone());
        if let Some(existing) = env.storage().persistent().get::<_, ReceiptSignerRecord>(&key) {
            if existing.active {
                return Ok(());
            }
            return Err(SignedReceiptError::SignerRevoked);
        }

        let record = ReceiptSignerRecord {
            public_key: signer_key.clone(),
            registered_by: admin.clone(),
            registered_ledger: env.ledger().sequence(),
            registered_at: env.ledger().timestamp(),
            active: true,
            revoked_ledger: None,
            revoked_at: None,
        };
        env.storage().persistent().set(&key, &record);
        env.events().publish(
            (symbol_short!("rcpt_sig"), symbol_short!("reg")),
            (admin, signer_key),
        );
        Ok(())
    }

    /// Revokes a registered Ed25519 receipt signer.
    ///
    /// Idempotent if already revoked. Preserves the record with revocation
    /// ledger/timestamp so historical receipts remain verifiable.
    pub fn revoke_receipt_signer(
        env: Env,
        admin: Address,
        signer_key: BytesN<32>,
    ) -> Result<(), SignedReceiptError> {
        require_admin_auth(&env, &admin)?;

        let key = StorageKey::Signer(signer_key.clone());
        let mut record: ReceiptSignerRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(SignedReceiptError::UnknownSigner)?;

        if !record.active {
            return Ok(());
        }

        record.active = false;
        record.revoked_ledger = Some(env.ledger().sequence());
        record.revoked_at = Some(env.ledger().timestamp());
        env.storage().persistent().set(&key, &record);
        env.events().publish(
            (symbol_short!("rcpt_sig"), symbol_short!("rev")),
            (admin, signer_key),
        );
        Ok(())
    }

    /// Returns the signer registration record, if any.
    pub fn get_receipt_signer(env: Env, signer_key: BytesN<32>) -> Option<ReceiptSignerRecord> {
        env.storage()
            .persistent()
            .get(&StorageKey::Signer(signer_key))
    }

    /// Returns `true` if `signer_key` is registered and currently active.
    pub fn is_active_receipt_signer(env: Env, signer_key: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get::<_, ReceiptSignerRecord>(&StorageKey::Signer(signer_key))
            .map(|r| r.active)
            .unwrap_or(false)
    }

    /// Computes the canonical 32-byte SHA-256 signing digest for an admin
    /// change receipt bound to `change_id` and `signer_key`.
    pub fn receipt_signing_digest(
        env: Env,
        change_id: BytesN<32>,
        receipt: AdminChangeReceipt,
        signer_key: BytesN<32>,
    ) -> BytesN<32> {
        compute_signing_digest(&env, &change_id, &receipt, &signer_key)
    }

    /// Records an administrative change in the hash-chained audit ledger and
    /// issues a pending receipt keyed by `change_id`.
    ///
    /// Idempotent on retries with identical parameters; returns
    /// `IdempotencyConflict` if `change_id` was used with different parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_pending_receipt(
        env: Env,
        change_id: BytesN<32>,
        kind: AdminChangeKind,
        module: Symbol,
        actor: Address,
        subject: Option<Address>,
        attribute: Option<Symbol>,
        note: Option<Symbol>,
    ) -> Result<PendingAdminReceipt, SignedReceiptError> {
        require_admin_auth(&env, &actor)?;

        let fingerprint = AdminChangeRequestFingerprint {
            kind,
            module: module.clone(),
            actor: actor.clone(),
            subject: subject.clone(),
            attribute: attribute.clone(),
            note: note.clone(),
        };

        let pending_key = StorageKey::Pending(change_id.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, PendingAdminReceipt>(&pending_key)
        {
            if existing.fingerprint == fingerprint {
                return Ok(existing);
            }
            return Err(SignedReceiptError::IdempotencyConflict);
        }

        let head = get_chain_head(&env);
        let seq = head
            .length
            .checked_add(1)
            .ok_or(SignedReceiptError::Overflow)?;
        let ledger = env.ledger().sequence();
        let timestamp = env.ledger().timestamp();

        let mut entry = AdminAuditEntry {
            seq,
            kind,
            module,
            actor: actor.clone(),
            subject,
            attribute,
            note,
            ledger,
            timestamp,
            prev_hash: head.head_hash.clone(),
            entry_hash: genesis_hash(&env),
        };
        let hash = compute_entry_hash(&env, &entry);
        entry.entry_hash = hash.clone();

        env.storage()
            .persistent()
            .set(&StorageKey::ChainEntry(seq), &entry);
        env.storage().instance().set(
            &StorageKey::ChainHead,
            &AuditChainHead {
                length: seq,
                head_hash: hash.clone(),
            },
        );

        let receipt = AdminChangeReceipt {
            seq,
            kind,
            actor,
            entry_hash: hash.clone(),
            prev_hash: head.head_hash,
            ledger,
            timestamp,
        };
        let pending = PendingAdminReceipt {
            schema_version: SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION,
            change_id: change_id.clone(),
            fingerprint,
            receipt,
        };
        env.storage().persistent().set(&pending_key, &pending);
        env.events().publish(
            (symbol_short!("rcpt_aud"), symbol_short!("pend")),
            (change_id, seq, hash),
        );
        Ok(pending)
    }

    /// Attaches an Ed25519 signature from an active registered signer to a
    /// pending admin change receipt.
    ///
    /// Invalid signatures abort inside Soroban's host `ed25519_verify` with no
    /// partial state written. Retrying with the exact same
    /// `(change_id, signer_key, signature)` is idempotent.
    pub fn attach_receipt_signature(
        env: Env,
        change_id: BytesN<32>,
        signer_key: BytesN<32>,
        signature: BytesN<64>,
    ) -> Result<SignedAdminAuditReceipt, SignedReceiptError> {
        let signed_key = StorageKey::Signed(change_id.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, SignedAdminAuditReceipt>(&signed_key)
        {
            if existing.signer_key == signer_key && existing.signature == signature {
                return Ok(existing);
            }
            return Err(SignedReceiptError::AlreadySigned);
        }

        let signer_record: ReceiptSignerRecord = env
            .storage()
            .persistent()
            .get(&StorageKey::Signer(signer_key.clone()))
            .ok_or(SignedReceiptError::UnknownSigner)?;
        if !signer_record.active {
            return Err(SignedReceiptError::SignerRevoked);
        }

        let pending: PendingAdminReceipt = env
            .storage()
            .persistent()
            .get(&StorageKey::Pending(change_id.clone()))
            .ok_or(SignedReceiptError::ReceiptNotFound)?;

        let digest = compute_signing_digest(&env, &change_id, &pending.receipt, &signer_key);
        let message = Bytes::from_slice(&env, &digest.to_array());
        env.crypto()
            .ed25519_verify(&signer_key, &message, &signature);

        let signed = SignedAdminAuditReceipt {
            schema_version: SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION,
            change_id: change_id.clone(),
            receipt: pending.receipt,
            signer_key: signer_key.clone(),
            digest: digest.clone(),
            signature,
            signed_ledger: env.ledger().sequence(),
            signed_at: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&signed_key, &signed);
        env.storage()
            .persistent()
            .set(&StorageKey::BySeq(signed.receipt.seq), &signed);
        env.events().publish(
            (symbol_short!("rcpt_aud"), symbol_short!("sign")),
            (change_id, signed.receipt.seq, signer_key, digest),
        );
        Ok(signed)
    }

    /// Verifies a signed admin audit receipt against schema version, signer
    /// registry & revocation timing, digest integrity, Ed25519 signature, and
    /// live hash-chain linkage to head.
    pub fn verify_signed_receipt(
        env: Env,
        signed: SignedAdminAuditReceipt,
    ) -> SignedReceiptVerificationStatus {
        if signed.schema_version != SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION {
            return SignedReceiptVerificationStatus::UnsupportedSchema;
        }

        let signer_record: ReceiptSignerRecord = match env
            .storage()
            .persistent()
            .get(&StorageKey::Signer(signed.signer_key.clone()))
        {
            Some(r) => r,
            None => return SignedReceiptVerificationStatus::UnknownSigner,
        };

        let mut revoked_later = false;
        if !signer_record.active {
            match signer_record.revoked_ledger {
                Some(rev_ledger) if rev_ledger <= signed.signed_ledger => {
                    return SignedReceiptVerificationStatus::SignerRevokedBeforeSigning;
                }
                Some(_) => revoked_later = true,
                None => return SignedReceiptVerificationStatus::SignerRevokedBeforeSigning,
            }
        }

        let expected_digest = compute_signing_digest(
            &env,
            &signed.change_id,
            &signed.receipt,
            &signed.signer_key,
        );
        if expected_digest != signed.digest {
            return SignedReceiptVerificationStatus::DigestMismatch;
        }

        let message = Bytes::from_slice(&env, &expected_digest.to_array());
        env.crypto()
            .ed25519_verify(&signed.signer_key, &message, &signed.signature);

        let current = get_chain_head(&env);
        if signed.receipt.seq == 0 || signed.receipt.seq > current.length {
            return SignedReceiptVerificationStatus::LedgerMissing;
        }
        if current.length - signed.receipt.seq > MAX_VERIFY_ENTRIES {
            return SignedReceiptVerificationStatus::LedgerScanLimitExceeded;
        }

        let entry: AdminAuditEntry = match env
            .storage()
            .persistent()
            .get(&StorageKey::ChainEntry(signed.receipt.seq))
        {
            Some(e) => e,
            None => return SignedReceiptVerificationStatus::LedgerMissing,
        };
        if entry.seq != signed.receipt.seq
            || entry.kind != signed.receipt.kind
            || entry.actor != signed.receipt.actor
            || entry.entry_hash != signed.receipt.entry_hash
            || entry.prev_hash != signed.receipt.prev_hash
            || compute_entry_hash(&env, &entry) != entry.entry_hash
        {
            return SignedReceiptVerificationStatus::LedgerMismatch;
        }

        let mut expected_prev = entry.entry_hash;
        for seq in (signed.receipt.seq + 1)..=current.length {
            let next: AdminAuditEntry = match env
                .storage()
                .persistent()
                .get(&StorageKey::ChainEntry(seq))
            {
                Some(n) => n,
                None => return SignedReceiptVerificationStatus::LedgerMissing,
            };
            if next.prev_hash != expected_prev || compute_entry_hash(&env, &next) != next.entry_hash
            {
                return SignedReceiptVerificationStatus::LedgerUnlinked;
            }
            expected_prev = next.entry_hash;
        }

        if expected_prev != current.head_hash {
            return SignedReceiptVerificationStatus::LedgerUnlinked;
        }

        if revoked_later {
            SignedReceiptVerificationStatus::ValidSignerRevokedLater
        } else {
            SignedReceiptVerificationStatus::Valid
        }
    }

    /// Fetches a pending admin receipt by `change_id`.
    pub fn get_pending_receipt(env: Env, change_id: BytesN<32>) -> Option<PendingAdminReceipt> {
        env.storage()
            .persistent()
            .get(&StorageKey::Pending(change_id))
    }

    /// Fetches a signed admin audit receipt by `change_id`.
    pub fn get_signed_receipt(env: Env, change_id: BytesN<32>) -> Option<SignedAdminAuditReceipt> {
        env.storage()
            .persistent()
            .get(&StorageKey::Signed(change_id))
    }

    /// Fetches a signed admin audit receipt by audit chain sequence number.
    pub fn get_signed_receipt_by_seq(env: Env, seq: u64) -> Option<SignedAdminAuditReceipt> {
        env.storage().persistent().get(&StorageKey::BySeq(seq))
    }

    /// Returns the current head of the admin audit hash chain.
    pub fn chain_head(env: Env) -> AuditChainHead {
        get_chain_head(&env)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Env,
    };

    fn setup() -> (Env, SignedAuditReceiptsContractClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| {
            l.sequence_number = 100;
            l.timestamp = 1_700_000_000;
        });
        let contract_id = env.register_contract(None, SignedAuditReceiptsContract);
        let client = SignedAuditReceiptsContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, contract_id, admin)
    }

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sign_digest(env: &Env, sk: &SigningKey, digest: &BytesN<32>) -> BytesN<64> {
        let sig = sk.sign(&digest.to_array());
        BytesN::from_array(env, &sig.to_bytes())
    }

    fn change_id(env: &Env, tag: u8) -> BytesN<32> {
        BytesN::from_array(env, &[tag; 32])
    }

    #[test]
    fn normal_path_issue_sign_and_verify() {
        let (env, client, _cid, admin) = setup();
        let (sk, pk_bytes) = keypair(7);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 1);

        client.register_receipt_signer(&admin, &pk);
        assert!(client.is_active_receipt_signer(&pk));

        let pending = client.issue_pending_receipt(
            &id,
            &AdminChangeKind::ConfigChanged,
            &symbol_short!("treasury"),
            &admin,
            &None,
            &Some(symbol_short!("fee_bps")),
            &Some(symbol_short!("set_50")),
        );
        assert_eq!(pending.receipt.seq, 1);
        assert_eq!(client.chain_head().length, 1);

        let digest = client.receipt_signing_digest(&id, &pending.receipt, &pk);
        let sig = sign_digest(&env, &sk, &digest);

        let signed = client.attach_receipt_signature(&id, &pk, &sig);
        assert_eq!(signed.digest, digest);
        assert_eq!(signed.receipt.seq, 1);

        assert_eq!(
            client.verify_signed_receipt(&signed),
            SignedReceiptVerificationStatus::Valid
        );
        assert_eq!(client.get_signed_receipt(&id), Some(signed.clone()));
        assert_eq!(client.get_signed_receipt_by_seq(&1), Some(signed));
    }

    #[test]
    fn authorization_non_admin_rejected() {
        let (env, client, _cid, _admin) = setup();
        let attacker = Address::generate(&env);
        let (_sk, pk_bytes) = keypair(9);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 2);

        assert_eq!(
            client.try_register_receipt_signer(&attacker, &pk),
            Err(Ok(SignedReceiptError::Unauthorized))
        );
        assert_eq!(
            client.try_revoke_receipt_signer(&attacker, &pk),
            Err(Ok(SignedReceiptError::Unauthorized))
        );
        assert_eq!(
            client.try_issue_pending_receipt(
                &id,
                &AdminChangeKind::RoleGranted,
                &symbol_short!("access"),
                &attacker,
                &None,
                &None,
                &None,
            ),
            Err(Ok(SignedReceiptError::Unauthorized))
        );
    }

    #[test]
    fn authorization_unknown_or_revoked_signer_rejected() {
        let (env, client, _cid, admin) = setup();
        let (sk, pk_bytes) = keypair(11);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 3);

        let pending = client.issue_pending_receipt(
            &id,
            &AdminChangeKind::ContractPaused,
            &symbol_short!("aid"),
            &admin,
            &None,
            &None,
            &None,
        );
        let digest = client.receipt_signing_digest(&id, &pending.receipt, &pk);
        let sig = sign_digest(&env, &sk, &digest);

        assert_eq!(
            client.try_attach_receipt_signature(&id, &pk, &sig),
            Err(Ok(SignedReceiptError::UnknownSigner))
        );

        client.register_receipt_signer(&admin, &pk);
        client.revoke_receipt_signer(&admin, &pk);
        assert!(!client.is_active_receipt_signer(&pk));

        assert_eq!(
            client.try_attach_receipt_signature(&id, &pk, &sig),
            Err(Ok(SignedReceiptError::SignerRevoked))
        );

        // Re-activating a revoked signer is disallowed
        assert_eq!(
            client.try_register_receipt_signer(&admin, &pk),
            Err(Ok(SignedReceiptError::SignerRevoked))
        );
    }

    #[test]
    fn retry_and_idempotency_paths() {
        let (env, client, _cid, admin) = setup();
        let (sk, pk_bytes) = keypair(13);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 4);

        // Idempotent signer registration
        client.register_receipt_signer(&admin, &pk);
        client.register_receipt_signer(&admin, &pk);

        // First issue
        let p1 = client.issue_pending_receipt(
            &id,
            &AdminChangeKind::ConfigChanged,
            &symbol_short!("oracle"),
            &admin,
            &None,
            &Some(symbol_short!("quorum")),
            &None,
        );
        assert_eq!(client.chain_head().length, 1);

        // Exact retry returns existing pending receipt without duplicating entry
        let p2 = client.issue_pending_receipt(
            &id,
            &AdminChangeKind::ConfigChanged,
            &symbol_short!("oracle"),
            &admin,
            &None,
            &Some(symbol_short!("quorum")),
            &None,
        );
        assert_eq!(p1, p2);
        assert_eq!(client.chain_head().length, 1);

        // Conflicting parameters for same change_id rejected
        assert_eq!(
            client.try_issue_pending_receipt(
                &id,
                &AdminChangeKind::ConfigChanged,
                &symbol_short!("oracle"),
                &admin,
                &None,
                &Some(symbol_short!("diff")),
                &None,
            ),
            Err(Ok(SignedReceiptError::IdempotencyConflict))
        );

        // Sign and retry with exact same signature (idempotent)
        let digest = client.receipt_signing_digest(&id, &p1.receipt, &pk);
        let sig = sign_digest(&env, &sk, &digest);
        let s1 = client.attach_receipt_signature(&id, &pk, &sig);
        let s2 = client.attach_receipt_signature(&id, &pk, &sig);
        assert_eq!(s1, s2);

        // Retrying with a different signer/signature fails with AlreadySigned
        let (sk2, pk2_bytes) = keypair(14);
        let pk2 = BytesN::from_array(&env, &pk2_bytes);
        client.register_receipt_signer(&admin, &pk2);
        let digest2 = client.receipt_signing_digest(&id, &p1.receipt, &pk2);
        let sig2 = sign_digest(&env, &sk2, &digest2);
        assert_eq!(
            client.try_attach_receipt_signature(&id, &pk2, &sig2),
            Err(Ok(SignedReceiptError::AlreadySigned))
        );
    }

    #[test]
    fn failure_missing_receipt_and_double_init() {
        let (env, client, _cid, admin) = setup();
        let (_sk, pk_bytes) = keypair(15);
        let pk = BytesN::from_array(&env, &pk_bytes);

        assert_eq!(
            client.try_initialize(&admin),
            Err(Ok(SignedReceiptError::AlreadyInitialized))
        );

        client.register_receipt_signer(&admin, &pk);
        assert_eq!(
            client.try_attach_receipt_signature(
                &change_id(&env, 99),
                &pk,
                &BytesN::from_array(&env, &[0u8; 64]),
            ),
            Err(Ok(SignedReceiptError::ReceiptNotFound))
        );
    }

    #[test]
    #[should_panic]
    fn failure_invalid_ed25519_signature_aborts() {
        let (env, client, _cid, admin) = setup();
        let (_sk, pk_bytes) = keypair(17);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 5);

        client.register_receipt_signer(&admin, &pk);
        client.issue_pending_receipt(
            &id,
            &AdminChangeKind::ContractUpgraded,
            &symbol_short!("core"),
            &admin,
            &None,
            &None,
            &None,
        );

        let bad_sig = BytesN::from_array(&env, &[0xAAu8; 64]);
        client.attach_receipt_signature(&id, &pk, &bad_sig);
    }

    #[test]
    fn recovery_key_rotation_and_historical_auditability() {
        let (env, client, _cid, admin) = setup();
        let (sk1, pk1_bytes) = keypair(21);
        let (sk2, pk2_bytes) = keypair(22);
        let pk1 = BytesN::from_array(&env, &pk1_bytes);
        let pk2 = BytesN::from_array(&env, &pk2_bytes);
        let id1 = change_id(&env, 10);
        let id2 = change_id(&env, 11);

        client.register_receipt_signer(&admin, &pk1);

        let p1 = client.issue_pending_receipt(
            &id1,
            &AdminChangeKind::RoleGranted,
            &symbol_short!("access"),
            &admin,
            &None,
            &None,
            &None,
        );
        let d1 = client.receipt_signing_digest(&id1, &p1.receipt, &pk1);
        let s1 = client.attach_receipt_signature(&id1, &pk1, &sign_digest(&env, &sk1, &d1));

        let p2 = client.issue_pending_receipt(
            &id2,
            &AdminChangeKind::ConfigChanged,
            &symbol_short!("access"),
            &admin,
            &None,
            &None,
            &None,
        );

        // Advance ledger and rotate signer: revoke pk1, register pk2
        env.ledger().with_mut(|l| {
            l.sequence_number = 105;
            l.timestamp = 1_700_000_500;
        });
        client.revoke_receipt_signer(&admin, &pk1);
        client.register_receipt_signer(&admin, &pk2);

        // Historical receipt 1 remains verifiable as ValidSignerRevokedLater
        assert_eq!(
            client.verify_signed_receipt(&s1),
            SignedReceiptVerificationStatus::ValidSignerRevokedLater
        );

        // Pending receipt 2 can be signed by the new key pk2
        let d2 = client.receipt_signing_digest(&id2, &p2.receipt, &pk2);
        let s2 = client.attach_receipt_signature(&id2, &pk2, &sign_digest(&env, &sk2, &d2));
        assert_eq!(
            client.verify_signed_receipt(&s2),
            SignedReceiptVerificationStatus::Valid
        );
    }

    #[test]
    fn tamper_detection_digest_and_ledger_mismatch() {
        let (env, client, cid, admin) = setup();
        let (sk, pk_bytes) = keypair(25);
        let pk = BytesN::from_array(&env, &pk_bytes);
        let id = change_id(&env, 12);

        client.register_receipt_signer(&admin, &pk);
        let pending = client.issue_pending_receipt(
            &id,
            &AdminChangeKind::AdminTransferred,
            &symbol_short!("access"),
            &admin,
            &None,
            &None,
            &None,
        );
        let digest = client.receipt_signing_digest(&id, &pending.receipt, &pk);
        let sig = sign_digest(&env, &sk, &digest);
        let signed = client.attach_receipt_signature(&id, &pk, &sig);

        // Tamper with digest field
        let mut bad_digest = signed.clone();
        bad_digest.digest = BytesN::from_array(&env, &[0xFFu8; 32]);
        assert_eq!(
            client.verify_signed_receipt(&bad_digest),
            SignedReceiptVerificationStatus::DigestMismatch
        );

        // Tamper with underlying audit chain entry in storage
        env.as_contract(&cid, || {
            let mut entry: AdminAuditEntry = env
                .storage()
                .persistent()
                .get(&StorageKey::ChainEntry(1))
                .unwrap();
            entry.note = Some(symbol_short!("tampered"));
            env.storage()
                .persistent()
                .set(&StorageKey::ChainEntry(1), &entry);
        });

        assert_eq!(
            client.verify_signed_receipt(&signed),
            SignedReceiptVerificationStatus::LedgerMismatch
        );
    }
}
