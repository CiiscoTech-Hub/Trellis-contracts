#![no_std]

//! Retention Enforcement & Deletion Verification Contract.
//!
//! Provides a focused vertical slice for enforcing data retention policies,
//! managing legal/audit holds, executing idempotent and retryable deletion
//! jobs, and issuing cryptographically verifiable deletion certificates.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    Symbol,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ledgers per day at ~5 s/ledger cadence.
pub const LEDGERS_PER_DAY: u32 = 17_280;

/// Maximum configurable retention window (10 years).
pub const MAX_RETAIN_LEDGERS: u32 = LEDGERS_PER_DAY * 3_650;

/// Sentinel `until_ledger` meaning "hold indefinitely".
pub const HOLD_INDEFINITE: u32 = 0;

/// Default maximum retry attempts per deletion job.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Convert whole days into ledgers, saturating at [`MAX_RETAIN_LEDGERS`].
pub const fn days_to_ledgers(days: u32) -> u32 {
    let ledgers = days.saturating_mul(LEDGERS_PER_DAY);
    if ledgers > MAX_RETAIN_LEDGERS {
        MAX_RETAIN_LEDGERS
    } else {
        ledgers
    }
}

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
    InvalidInput = 4,
    InvalidPolicy = 5,
    InvalidHold = 6,
    RecordNotFound = 7,
    AlreadyExists = 8,
    AlreadyDeleted = 9,
    NotExpired = 10,
    ActiveHold = 11,
    ClassFrozen = 12,
    ArchiveRequired = 13,
    HoldNotFound = 14,
    JobNotFound = 15,
    InvalidJobState = 16,
    MaxRetriesExceeded = 17,
    PendingDeletionExists = 18,
}

// ---------------------------------------------------------------------------
// Domain Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    Audit,
    Telemetry,
    Export,
    SupportEvidence,
    FinancialSettlement,
    Dispute,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    Dispute,
    Audit,
    Settlement,
    Legal,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordStatus {
    Active,
    PendingDeletion,
    Deleted,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementDecision {
    Eligible,
    Retained,
    Held,
    Frozen,
    ArchiveRequired,
    AlreadyDeleted,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStatus {
    Pending,
    Completed,
    Failed,
    Exhausted,
    Aborted,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub retain_ledgers: u32,
    pub archive_before_delete: bool,
    pub honor_holds: bool,
    pub deletion_frozen: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackedRecord {
    pub id: Symbol,
    pub class: DataClass,
    pub content_hash: BytesN<32>,
    pub created_ledger: u32,
    pub size_bytes: u32,
    pub archived: bool,
    pub archive_digest: BytesN<32>,
    pub status: RecordStatus,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionHold {
    pub record_id: Symbol,
    pub reason: HoldReason,
    pub until_ledger: u32,
    pub placed_ledger: u32,
    pub placed_by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionJob {
    pub job_id: u64,
    pub record_id: Symbol,
    pub idempotency_key: Symbol,
    pub status: JobStatus,
    pub attempts: u32,
    pub max_retries: u32,
    pub requested_ledger: u32,
    pub updated_ledger: u32,
    pub requested_by: Address,
    pub last_error_code: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionCertificate {
    pub record_id: Symbol,
    pub job_id: u64,
    pub class: DataClass,
    pub content_hash: BytesN<32>,
    pub deletion_proof_hash: BytesN<32>,
    pub deleted_ledger: u32,
    pub executed_by: Address,
    pub certificate_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub verified: bool,
    pub reason: Symbol,
    pub certificate_hash: BytesN<32>,
    pub deleted_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageKey {
    Admin,
    Enforcer,
    Auditor,
    NextJobId,
    Policy(DataClass),
    Record(Symbol),
    Hold(Symbol),
    Job(u64),
    Idempotency(Symbol, Symbol),
    Certificate(Symbol),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct RetentionEnforcementContract;

#[contractimpl]
impl RetentionEnforcementContract {
    /// Initialize contract roles. Can only be called once.
    pub fn init(
        env: Env,
        admin: Address,
        enforcer: Address,
        auditor: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&StorageKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&StorageKey::Admin, &admin);
        env.storage().instance().set(&StorageKey::Enforcer, &enforcer);
        env.storage().instance().set(&StorageKey::Auditor, &auditor);
        env.storage().instance().set(&StorageKey::NextJobId, &1u64);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Role Management (Admin-only)
    // -----------------------------------------------------------------------

    pub fn set_enforcer(env: Env, admin: Address, new_enforcer: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&StorageKey::Enforcer, &new_enforcer);
        Ok(())
    }

    pub fn set_auditor(env: Env, admin: Address, new_auditor: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&StorageKey::Auditor, &new_auditor);
        Ok(())
    }

    pub fn transfer_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.storage().instance().set(&StorageKey::Admin, &new_admin);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Policy & Record Management
    // -----------------------------------------------------------------------

    /// Set a retention policy override for a `DataClass`. Admin-only.
    pub fn set_policy(
        env: Env,
        admin: Address,
        class: DataClass,
        policy: RetentionPolicy,
    ) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        if policy.retain_ledgers == 0 || policy.retain_ledgers > MAX_RETAIN_LEDGERS {
            return Err(Error::InvalidPolicy);
        }
        env.storage()
            .instance()
            .set(&StorageKey::Policy(class), &policy);
        Ok(())
    }

    /// Return the effective policy for a `DataClass` (stored override or fail-safe default).
    pub fn get_policy(env: Env, class: DataClass) -> RetentionPolicy {
        effective_policy(&env, class)
    }

    /// Register a tracked record for retention enforcement. Admin or Enforcer.
    pub fn register_record(
        env: Env,
        caller: Address,
        record_id: Symbol,
        class: DataClass,
        content_hash: BytesN<32>,
        created_ledger: u32,
        size_bytes: u32,
    ) -> Result<TrackedRecord, Error> {
        require_enforcer_or_admin(&env, &caller)?;
        if created_ledger == 0 || size_bytes == 0 {
            return Err(Error::InvalidInput);
        }
        let key = StorageKey::Record(record_id.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        let record = TrackedRecord {
            id: record_id,
            class,
            content_hash,
            created_ledger,
            size_bytes,
            archived: false,
            archive_digest: BytesN::from_array(&env, &[0u8; 32]),
            status: RecordStatus::Active,
        };
        env.storage().persistent().set(&key, &record);
        Ok(record)
    }

    /// Mark a record as archived with an archive digest. Admin or Enforcer.
    pub fn mark_archived(
        env: Env,
        caller: Address,
        record_id: Symbol,
        archive_digest: BytesN<32>,
    ) -> Result<TrackedRecord, Error> {
        require_enforcer_or_admin(&env, &caller)?;
        let key = StorageKey::Record(record_id);
        let mut record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::RecordNotFound)?;
        if record.status == RecordStatus::Deleted {
            return Err(Error::AlreadyDeleted);
        }
        record.archived = true;
        record.archive_digest = archive_digest;
        env.storage().persistent().set(&key, &record);
        Ok(record)
    }

    // -----------------------------------------------------------------------
    // Hold Management (Admin or Auditor)
    // -----------------------------------------------------------------------

    /// Place or update a retention hold on a record. Admin or Auditor.
    pub fn place_hold(
        env: Env,
        caller: Address,
        record_id: Symbol,
        reason: HoldReason,
        until_ledger: u32,
    ) -> Result<RetentionHold, Error> {
        require_auditor_or_admin(&env, &caller)?;
        let now = env.ledger().sequence();
        if until_ledger != HOLD_INDEFINITE && until_ledger <= now {
            return Err(Error::InvalidHold);
        }
        let record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&StorageKey::Record(record_id.clone()))
            .ok_or(Error::RecordNotFound)?;
        if record.status == RecordStatus::Deleted {
            return Err(Error::AlreadyDeleted);
        }
        let hold = RetentionHold {
            record_id: record_id.clone(),
            reason,
            until_ledger,
            placed_ledger: now,
            placed_by: caller,
        };
        env.storage()
            .persistent()
            .set(&StorageKey::Hold(record_id), &hold);
        Ok(hold)
    }

    /// Release an existing hold. Admin or Auditor.
    pub fn release_hold(env: Env, caller: Address, record_id: Symbol) -> Result<(), Error> {
        require_auditor_or_admin(&env, &caller)?;
        let key = StorageKey::Hold(record_id);
        if !env.storage().persistent().has(&key) {
            return Err(Error::HoldNotFound);
        }
        env.storage().persistent().remove(&key);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Retention Evaluation & Deletion Enforcement
    // -----------------------------------------------------------------------

    /// Read-only evaluation of a record's retention status at the current ledger.
    pub fn evaluate_record(env: Env, record_id: Symbol) -> Result<EnforcementDecision, Error> {
        let record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&StorageKey::Record(record_id))
            .ok_or(Error::RecordNotFound)?;
        Ok(evaluate_internal(&env, &record, env.ledger().sequence()))
    }

    /// Request a deletion job for an eligible record. Idempotent per `(record_id, idempotency_key)`.
    /// Admin or Enforcer.
    pub fn request_deletion(
        env: Env,
        caller: Address,
        record_id: Symbol,
        idempotency_key: Symbol,
    ) -> Result<DeletionJob, Error> {
        require_enforcer_or_admin(&env, &caller)?;

        // Idempotency check: return existing job if already created with this key.
        let idem_key = StorageKey::Idempotency(record_id.clone(), idempotency_key.clone());
        if let Some(existing_job_id) = env.storage().persistent().get::<_, u64>(&idem_key) {
            let job: DeletionJob = env
                .storage()
                .persistent()
                .get(&StorageKey::Job(existing_job_id))
                .ok_or(Error::JobNotFound)?;
            return Ok(job);
        }

        let rec_key = StorageKey::Record(record_id.clone());
        let mut record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&rec_key)
            .ok_or(Error::RecordNotFound)?;

        if record.status == RecordStatus::PendingDeletion {
            return Err(Error::PendingDeletionExists);
        }

        let now = env.ledger().sequence();
        ensure_eligible(&env, &record, now)?;

        let job_id: u64 = env
            .storage()
            .instance()
            .get(&StorageKey::NextJobId)
            .unwrap_or(1);
        env.storage()
            .instance()
            .set(&StorageKey::NextJobId, &(job_id + 1));

        let job = DeletionJob {
            job_id,
            record_id: record_id.clone(),
            idempotency_key,
            status: JobStatus::Pending,
            attempts: 0,
            max_retries: DEFAULT_MAX_RETRIES,
            requested_ledger: now,
            updated_ledger: now,
            requested_by: caller,
            last_error_code: 0,
        };

        record.status = RecordStatus::PendingDeletion;
        env.storage().persistent().set(&rec_key, &record);
        env.storage().persistent().set(&StorageKey::Job(job_id), &job);
        env.storage().persistent().set(&idem_key, &job_id);

        Ok(job)
    }

    /// Execute a `Pending` deletion job, re-checking all retention protections
    /// and issuing a cryptographic [`DeletionCertificate`]. Admin or Enforcer.
    pub fn execute_deletion(
        env: Env,
        caller: Address,
        job_id: u64,
        deletion_proof_hash: BytesN<32>,
    ) -> Result<DeletionCertificate, Error> {
        require_enforcer_or_admin(&env, &caller)?;

        let job_key = StorageKey::Job(job_id);
        let mut job: DeletionJob = env
            .storage()
            .persistent()
            .get(&job_key)
            .ok_or(Error::JobNotFound)?;

        if job.status != JobStatus::Pending {
            return Err(Error::InvalidJobState);
        }

        let rec_key = StorageKey::Record(job.record_id.clone());
        let mut record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&rec_key)
            .ok_or(Error::RecordNotFound)?;

        let now = env.ledger().sequence();
        // Re-check all protections at execution time (handles late holds or newly frozen classes).
        ensure_eligible(&env, &record, now)?;

        let cert_hash = compute_certificate_hash(
            &env,
            job.job_id,
            &record.content_hash,
            &deletion_proof_hash,
            now,
        );

        let certificate = DeletionCertificate {
            record_id: record.id.clone(),
            job_id: job.job_id,
            class: record.class,
            content_hash: record.content_hash.clone(),
            deletion_proof_hash,
            deleted_ledger: now,
            executed_by: caller,
            certificate_hash: cert_hash,
        };

        record.status = RecordStatus::Deleted;
        job.status = JobStatus::Completed;
        job.attempts = job.attempts.saturating_add(1);
        job.updated_ledger = now;
        job.last_error_code = 0;

        env.storage().persistent().set(&rec_key, &record);
        env.storage().persistent().set(&job_key, &job);
        env.storage()
            .persistent()
            .set(&StorageKey::Certificate(record.id), &certificate);

        Ok(certificate)
    }

    /// Record a transient execution failure for a `Pending` job.
    /// Transitions to `Failed` (retryable) or `Exhausted` once `max_retries` is reached.
    /// Admin or Enforcer.
    pub fn record_deletion_failure(
        env: Env,
        caller: Address,
        job_id: u64,
        error_code: u32,
    ) -> Result<DeletionJob, Error> {
        require_enforcer_or_admin(&env, &caller)?;
        if error_code == 0 {
            return Err(Error::InvalidInput);
        }

        let job_key = StorageKey::Job(job_id);
        let mut job: DeletionJob = env
            .storage()
            .persistent()
            .get(&job_key)
            .ok_or(Error::JobNotFound)?;

        if job.status != JobStatus::Pending {
            return Err(Error::InvalidJobState);
        }

        job.attempts = job.attempts.saturating_add(1);
        job.last_error_code = error_code;
        job.updated_ledger = env.ledger().sequence();
        job.status = if job.attempts >= job.max_retries {
            JobStatus::Exhausted
        } else {
            JobStatus::Failed
        };

        env.storage().persistent().set(&job_key, &job);
        Ok(job)
    }

    /// Re-queue a `Failed` job back to `Pending` for retry. Admin or Enforcer.
    pub fn retry_deletion(env: Env, caller: Address, job_id: u64) -> Result<DeletionJob, Error> {
        require_enforcer_or_admin(&env, &caller)?;

        let job_key = StorageKey::Job(job_id);
        let mut job: DeletionJob = env
            .storage()
            .persistent()
            .get(&job_key)
            .ok_or(Error::JobNotFound)?;

        if job.status == JobStatus::Exhausted {
            return Err(Error::MaxRetriesExceeded);
        }
        if job.status != JobStatus::Failed {
            return Err(Error::InvalidJobState);
        }

        job.status = JobStatus::Pending;
        job.updated_ledger = env.ledger().sequence();
        env.storage().persistent().set(&job_key, &job);
        Ok(job)
    }

    /// Abort a `Pending`, `Failed`, or `Exhausted` deletion job and roll back
    /// the record status to `Active`. Admin or Enforcer.
    pub fn abort_deletion(env: Env, caller: Address, job_id: u64) -> Result<DeletionJob, Error> {
        require_enforcer_or_admin(&env, &caller)?;

        let job_key = StorageKey::Job(job_id);
        let mut job: DeletionJob = env
            .storage()
            .persistent()
            .get(&job_key)
            .ok_or(Error::JobNotFound)?;

        if job.status == JobStatus::Completed || job.status == JobStatus::Aborted {
            return Err(Error::InvalidJobState);
        }

        let rec_key = StorageKey::Record(job.record_id.clone());
        let mut record: TrackedRecord = env
            .storage()
            .persistent()
            .get(&rec_key)
            .ok_or(Error::RecordNotFound)?;

        record.status = RecordStatus::Active;
        job.status = JobStatus::Aborted;
        job.updated_ledger = env.ledger().sequence();

        env.storage().persistent().set(&rec_key, &record);
        env.storage().persistent().set(&job_key, &job);
        Ok(job)
    }

    // -----------------------------------------------------------------------
    // Deletion Verification & Queries
    // -----------------------------------------------------------------------

    /// Verify that a record has been deleted and its certificate is intact and
    /// matches `expected_content_hash`.
    pub fn verify_deletion(
        env: Env,
        record_id: Symbol,
        expected_content_hash: BytesN<32>,
    ) -> VerificationResult {
        let zero_hash = BytesN::from_array(&env, &[0u8; 32]);

        let Some(record) = env
            .storage()
            .persistent()
            .get::<_, TrackedRecord>(&StorageKey::Record(record_id.clone()))
        else {
            return VerificationResult {
                verified: false,
                reason: symbol_short!("no_rec"),
                certificate_hash: zero_hash,
                deleted_ledger: 0,
            };
        };

        if record.status != RecordStatus::Deleted {
            return VerificationResult {
                verified: false,
                reason: symbol_short!("not_del"),
                certificate_hash: zero_hash,
                deleted_ledger: 0,
            };
        }

        let Some(cert) = env
            .storage()
            .persistent()
            .get::<_, DeletionCertificate>(&StorageKey::Certificate(record_id))
        else {
            return VerificationResult {
                verified: false,
                reason: symbol_short!("no_cert"),
                certificate_hash: zero_hash,
                deleted_ledger: 0,
            };
        };

        if cert.content_hash != expected_content_hash {
            return VerificationResult {
                verified: false,
                reason: symbol_short!("hash_mis"),
                certificate_hash: cert.certificate_hash,
                deleted_ledger: cert.deleted_ledger,
            };
        }

        let recomputed = compute_certificate_hash(
            &env,
            cert.job_id,
            &cert.content_hash,
            &cert.deletion_proof_hash,
            cert.deleted_ledger,
        );

        if recomputed != cert.certificate_hash {
            return VerificationResult {
                verified: false,
                reason: symbol_short!("tampered"),
                certificate_hash: cert.certificate_hash,
                deleted_ledger: cert.deleted_ledger,
            };
        }

        VerificationResult {
            verified: true,
            reason: symbol_short!("verified"),
            certificate_hash: cert.certificate_hash,
            deleted_ledger: cert.deleted_ledger,
        }
    }

    pub fn get_record(env: Env, record_id: Symbol) -> Option<TrackedRecord> {
        env.storage()
            .persistent()
            .get(&StorageKey::Record(record_id))
    }

    pub fn get_hold(env: Env, record_id: Symbol) -> Option<RetentionHold> {
        env.storage().persistent().get(&StorageKey::Hold(record_id))
    }

    pub fn get_job(env: Env, job_id: u64) -> Option<DeletionJob> {
        env.storage().persistent().get(&StorageKey::Job(job_id))
    }

    pub fn get_deletion_certificate(env: Env, record_id: Symbol) -> Option<DeletionCertificate> {
        env.storage()
            .persistent()
            .get(&StorageKey::Certificate(record_id))
    }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

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

fn require_enforcer_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    let enforcer: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Enforcer)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin && caller != &enforcer {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn require_auditor_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .ok_or(Error::NotInitialized)?;
    let auditor: Address = env
        .storage()
        .instance()
        .get(&StorageKey::Auditor)
        .ok_or(Error::NotInitialized)?;
    caller.require_auth();
    if caller != &admin && caller != &auditor {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn default_policy(class: DataClass) -> RetentionPolicy {
    match class {
        DataClass::Audit => RetentionPolicy {
            retain_ledgers: days_to_ledgers(365),
            archive_before_delete: true,
            honor_holds: true,
            deletion_frozen: false,
        },
        DataClass::Telemetry => RetentionPolicy {
            retain_ledgers: days_to_ledgers(30),
            archive_before_delete: false,
            honor_holds: true,
            deletion_frozen: false,
        },
        DataClass::Export => RetentionPolicy {
            retain_ledgers: days_to_ledgers(180),
            archive_before_delete: true,
            honor_holds: true,
            deletion_frozen: false,
        },
        DataClass::SupportEvidence => RetentionPolicy {
            retain_ledgers: days_to_ledgers(90),
            archive_before_delete: false,
            honor_holds: true,
            deletion_frozen: false,
        },
        DataClass::FinancialSettlement => RetentionPolicy {
            retain_ledgers: days_to_ledgers(2_555),
            archive_before_delete: true,
            honor_holds: true,
            deletion_frozen: true,
        },
        DataClass::Dispute => RetentionPolicy {
            retain_ledgers: days_to_ledgers(365),
            archive_before_delete: true,
            honor_holds: true,
            deletion_frozen: true,
        },
    }
}

fn effective_policy(env: &Env, class: DataClass) -> RetentionPolicy {
    env.storage()
        .instance()
        .get(&StorageKey::Policy(class))
        .unwrap_or_else(|| default_policy(class))
}

fn has_active_hold(env: &Env, record_id: &Symbol, now: u32) -> bool {
    match env
        .storage()
        .persistent()
        .get::<_, RetentionHold>(&StorageKey::Hold(record_id.clone()))
    {
        Some(hold) => hold.until_ledger == HOLD_INDEFINITE || hold.until_ledger > now,
        None => false,
    }
}

fn evaluate_internal(env: &Env, record: &TrackedRecord, now: u32) -> EnforcementDecision {
    if record.status == RecordStatus::Deleted {
        return EnforcementDecision::AlreadyDeleted;
    }
    let policy = effective_policy(env, record.class);
    if policy.deletion_frozen {
        return EnforcementDecision::Frozen;
    }
    if now.saturating_sub(record.created_ledger) < policy.retain_ledgers {
        return EnforcementDecision::Retained;
    }
    if policy.honor_holds && has_active_hold(env, &record.id, now) {
        return EnforcementDecision::Held;
    }
    if policy.archive_before_delete && !record.archived {
        return EnforcementDecision::ArchiveRequired;
    }
    EnforcementDecision::Eligible
}

fn ensure_eligible(env: &Env, record: &TrackedRecord, now: u32) -> Result<(), Error> {
    match evaluate_internal(env, record, now) {
        EnforcementDecision::Eligible => Ok(()),
        EnforcementDecision::AlreadyDeleted => Err(Error::AlreadyDeleted),
        EnforcementDecision::Frozen => Err(Error::ClassFrozen),
        EnforcementDecision::Retained => Err(Error::NotExpired),
        EnforcementDecision::Held => Err(Error::ActiveHold),
        EnforcementDecision::ArchiveRequired => Err(Error::ArchiveRequired),
    }
}

fn compute_certificate_hash(
    env: &Env,
    job_id: u64,
    content_hash: &BytesN<32>,
    deletion_proof_hash: &BytesN<32>,
    deleted_ledger: u32,
) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    payload.extend_from_slice(&job_id.to_be_bytes());
    payload.extend_from_slice(&content_hash.to_array());
    payload.extend_from_slice(&deletion_proof_hash.to_array());
    payload.extend_from_slice(&deleted_ledger.to_be_bytes());
    env.crypto().sha256(&payload).into()
}

// ---------------------------------------------------------------------------
// Automated Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    struct Fixture {
        env: Env,
        client: RetentionEnforcementContractClient<'static>,
        admin: Address,
        enforcer: Address,
        auditor: Address,
        outsider: Address,
    }

    fn setup() -> Fixture {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|li| {
            li.sequence_number = 100;
            li.max_entry_ttl = 100_000_000;
            li.min_persistent_entry_ttl = 100_000_000;
        });

        let contract_id = env.register_contract(None, RetentionEnforcementContract);
        let client = RetentionEnforcementContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let enforcer = Address::generate(&env);
        let auditor = Address::generate(&env);
        let outsider = Address::generate(&env);

        client.init(&admin, &enforcer, &auditor);

        Fixture {
            env,
            client,
            admin,
            enforcer,
            auditor,
            outsider,
        }
    }

    fn hash(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    #[test]
    fn normal_path_retention_enforcement_and_deletion_verification() {
        let f = setup();
        let rec_id = symbol_short!("tel_001");
        let content_hash = hash(&f.env, 0xAA);
        let proof_hash = hash(&f.env, 0xBB);

        f.client.register_record(
            &f.enforcer,
            &rec_id,
            &DataClass::Telemetry,
            &content_hash,
            &100,
            &512,
        );

        // Before expiry: Retained
        assert_eq!(f.client.evaluate_record(&rec_id), EnforcementDecision::Retained);

        // Advance past 30-day Telemetry retention window
        f.env
            .ledger()
            .set_sequence_number(100 + days_to_ledgers(30));
        assert_eq!(f.client.evaluate_record(&rec_id), EnforcementDecision::Eligible);

        // Request and execute deletion
        let job = f
            .client
            .request_deletion(&f.enforcer, &rec_id, &symbol_short!("req_1"));
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.job_id, 1);

        let cert = f
            .client
            .execute_deletion(&f.enforcer, &job.job_id, &proof_hash);
        assert_eq!(cert.record_id, rec_id);
        assert_eq!(cert.content_hash, content_hash);
        assert_eq!(cert.deletion_proof_hash, proof_hash);

        // Verify deletion
        let verification = f.client.verify_deletion(&rec_id, &content_hash);
        assert!(verification.verified);
        assert_eq!(verification.reason, symbol_short!("verified"));
        assert_eq!(verification.certificate_hash, cert.certificate_hash);

        // Verify fails with wrong content hash
        let wrong_verification = f.client.verify_deletion(&rec_id, &hash(&f.env, 0xCC));
        assert!(!wrong_verification.verified);
        assert_eq!(wrong_verification.reason, symbol_short!("hash_mis"));

        // Re-evaluating deleted record returns AlreadyDeleted
        assert_eq!(
            f.client.evaluate_record(&rec_id),
            EnforcementDecision::AlreadyDeleted
        );
    }

    #[test]
    fn failure_paths_not_expired_frozen_archive_and_holds() {
        let f = setup();

        // 1. Not expired
        let tel_id = symbol_short!("tel_early");
        f.client.register_record(
            &f.enforcer,
            &tel_id,
            &DataClass::Telemetry,
            &hash(&f.env, 1),
            &100,
            &100,
        );
        assert_eq!(
            f.client
                .try_request_deletion(&f.enforcer, &tel_id, &symbol_short!("k1")),
            Err(Ok(Error::NotExpired))
        );

        // 2. Frozen class (FinancialSettlement)
        let fin_id = symbol_short!("fin_001");
        f.client.register_record(
            &f.enforcer,
            &fin_id,
            &DataClass::FinancialSettlement,
            &hash(&f.env, 2),
            &100,
            &256,
        );
        f.env
            .ledger()
            .set_sequence_number(100 + days_to_ledgers(3_000));
        assert_eq!(f.client.evaluate_record(&fin_id), EnforcementDecision::Frozen);
        assert_eq!(
            f.client
                .try_request_deletion(&f.enforcer, &fin_id, &symbol_short!("k2")),
            Err(Ok(Error::ClassFrozen))
        );

        // 3. Archive required (Audit)
        let aud_id = symbol_short!("aud_001");
        f.client.register_record(
            &f.enforcer,
            &aud_id,
            &DataClass::Audit,
            &hash(&f.env, 3),
            &100,
            &512,
        );
        assert_eq!(
            f.client.evaluate_record(&aud_id),
            EnforcementDecision::ArchiveRequired
        );
        assert_eq!(
            f.client
                .try_request_deletion(&f.enforcer, &aud_id, &symbol_short!("k3")),
            Err(Ok(Error::ArchiveRequired))
        );

        // Mark archived -> now eligible
        f.client
            .mark_archived(&f.enforcer, &aud_id, &hash(&f.env, 0x99));
        assert_eq!(f.client.evaluate_record(&aud_id), EnforcementDecision::Eligible);

        // 4. Active hold blocks deletion; releasing hold unblocks
        f.client.place_hold(
            &f.auditor,
            &aud_id,
            &HoldReason::Legal,
            &HOLD_INDEFINITE,
        );
        assert_eq!(f.client.evaluate_record(&aud_id), EnforcementDecision::Held);
        assert_eq!(
            f.client
                .try_request_deletion(&f.enforcer, &aud_id, &symbol_short!("k4")),
            Err(Ok(Error::ActiveHold))
        );

        f.client.release_hold(&f.auditor, &aud_id);
        assert_eq!(f.client.evaluate_record(&aud_id), EnforcementDecision::Eligible);
    }

    #[test]
    fn late_hold_placed_after_request_blocks_execution() {
        let f = setup();
        let rec_id = symbol_short!("late_h");
        f.client.register_record(
            &f.enforcer,
            &rec_id,
            &DataClass::Telemetry,
            &hash(&f.env, 5),
            &100,
            &128,
        );
        f.env
            .ledger()
            .set_sequence_number(100 + days_to_ledgers(31));

        let job = f
            .client
            .request_deletion(&f.enforcer, &rec_id, &symbol_short!("k_late"));

        // Auditor places a hold after job was requested
        f.client.place_hold(
            &f.auditor,
            &rec_id,
            &HoldReason::Dispute,
            &HOLD_INDEFINITE,
        );

        // Execution must be blocked
        assert_eq!(
            f.client
                .try_execute_deletion(&f.enforcer, &job.job_id, &hash(&f.env, 6)),
            Err(Ok(Error::ActiveHold))
        );

        // Operator can abort the job to roll back record status to Active
        let aborted = f.client.abort_deletion(&f.enforcer, &job.job_id);
        assert_eq!(aborted.status, JobStatus::Aborted);
        assert_eq!(
            f.client.get_record(&rec_id).unwrap().status,
            RecordStatus::Active
        );
    }

    #[test]
    fn idempotency_retry_exhaustion_and_recovery_paths() {
        let f = setup();
        let rec_id = symbol_short!("retry_1");
        let content_hash = hash(&f.env, 0x11);
        f.client.register_record(
            &f.enforcer,
            &rec_id,
            &DataClass::Telemetry,
            &content_hash,
            &100,
            &64,
        );
        f.env
            .ledger()
            .set_sequence_number(100 + days_to_ledgers(35));

        // Idempotent request_deletion returns same job
        let job1 = f
            .client
            .request_deletion(&f.enforcer, &rec_id, &symbol_short!("idem_a"));
        let job1_dup = f
            .client
            .request_deletion(&f.enforcer, &rec_id, &symbol_short!("idem_a"));
        assert_eq!(job1.job_id, job1_dup.job_id);

        // Record failure #1 -> Failed -> retry -> Pending
        let failed1 = f
            .client
            .record_deletion_failure(&f.enforcer, &job1.job_id, &503);
        assert_eq!(failed1.status, JobStatus::Failed);
        assert_eq!(failed1.attempts, 1);
        assert_eq!(failed1.last_error_code, 503);

        let retried1 = f.client.retry_deletion(&f.enforcer, &job1.job_id);
        assert_eq!(retried1.status, JobStatus::Pending);

        // Record failure #2 -> Failed -> retry -> Pending
        let failed2 = f
            .client
            .record_deletion_failure(&f.enforcer, &job1.job_id, &504);
        assert_eq!(failed2.status, JobStatus::Failed);
        assert_eq!(failed2.attempts, 2);
        f.client.retry_deletion(&f.enforcer, &job1.job_id);

        // Record failure #3 -> Exhausted (reaches DEFAULT_MAX_RETRIES = 3)
        let exhausted = f
            .client
            .record_deletion_failure(&f.enforcer, &job1.job_id, &500);
        assert_eq!(exhausted.status, JobStatus::Exhausted);
        assert_eq!(exhausted.attempts, 3);

        // Retrying an exhausted job fails with MaxRetriesExceeded
        assert_eq!(
            f.client.try_retry_deletion(&f.enforcer, &job1.job_id),
            Err(Ok(Error::MaxRetriesExceeded))
        );

        // Recovery: abort exhausted job, then start a fresh job and succeed
        let aborted = f.client.abort_deletion(&f.enforcer, &job1.job_id);
        assert_eq!(aborted.status, JobStatus::Aborted);

        let job2 = f
            .client
            .request_deletion(&f.enforcer, &rec_id, &symbol_short!("idem_b"));
        assert_eq!(job2.job_id, 2);
        f.client
            .execute_deletion(&f.enforcer, &job2.job_id, &hash(&f.env, 0x22));

        let ver = f.client.verify_deletion(&rec_id, &content_hash);
        assert!(ver.verified);
    }

    #[test]
    fn authorization_paths_enforced_per_role() {
        let f = setup();
        let rec_id = symbol_short!("auth_1");

        // Outsider cannot set policy
        let custom_policy = RetentionPolicy {
            retain_ledgers: days_to_ledgers(10),
            archive_before_delete: false,
            honor_holds: true,
            deletion_frozen: false,
        };
        assert_eq!(
            f.client
                .try_set_policy(&f.outsider, &DataClass::Telemetry, &custom_policy),
            Err(Ok(Error::Unauthorized))
        );
        // Enforcer cannot set policy
        assert_eq!(
            f.client
                .try_set_policy(&f.enforcer, &DataClass::Telemetry, &custom_policy),
            Err(Ok(Error::Unauthorized))
        );
        // Admin can set policy
        f.client
            .set_policy(&f.admin, &DataClass::Telemetry, &custom_policy);

        // Auditor cannot register records
        assert_eq!(
            f.client.try_register_record(
                &f.auditor,
                &rec_id,
                &DataClass::Telemetry,
                &hash(&f.env, 9),
                &100,
                &64,
            ),
            Err(Ok(Error::Unauthorized))
        );

        // Enforcer registers record
        f.client.register_record(
            &f.enforcer,
            &rec_id,
            &DataClass::Telemetry,
            &hash(&f.env, 9),
            &100,
            &64,
        );

        // Enforcer cannot place or release holds
        assert_eq!(
            f.client
                .try_place_hold(&f.enforcer, &rec_id, &HoldReason::Audit, &HOLD_INDEFINITE),
            Err(Ok(Error::Unauthorized))
        );

        // Auditor places hold; outsider cannot release it
        f.client
            .place_hold(&f.auditor, &rec_id, &HoldReason::Audit, &HOLD_INDEFINITE);
        assert_eq!(
            f.client.try_release_hold(&f.outsider, &rec_id),
            Err(Ok(Error::Unauthorized))
        );
        f.client.release_hold(&f.auditor, &rec_id);

        // Advance past custom 10-day policy
        f.env
            .ledger()
            .set_sequence_number(100 + days_to_ledgers(10));

        // Auditor cannot request deletion
        assert_eq!(
            f.client
                .try_request_deletion(&f.auditor, &rec_id, &symbol_short!("a_req")),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn verification_reports_non_deleted_and_missing_records() {
        let f = setup();
        let rec_id = symbol_short!("active_1");
        let h = hash(&f.env, 0x44);

        // Missing record
        let missing = f.client.verify_deletion(&rec_id, &h);
        assert!(!missing.verified);
        assert_eq!(missing.reason, symbol_short!("no_rec"));

        // Active (not yet deleted) record
        f.client
            .register_record(&f.enforcer, &rec_id, &DataClass::Telemetry, &h, &100, &32);
        let active = f.client.verify_deletion(&rec_id, &h);
        assert!(!active.verified);
        assert_eq!(active.reason, symbol_short!("not_del"));
    }
}
