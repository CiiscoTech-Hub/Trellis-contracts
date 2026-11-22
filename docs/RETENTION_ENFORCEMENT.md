# Retention Enforcement & Deletion Verification

This document describes the `retention-enforcement` Soroban contract ([`contracts/retention-enforcement/src/lib.rs`](../contracts/retention-enforcement/src/lib.rs)), which implements a focused vertical slice for on-chain retention policy enforcement, retryable deletion jobs, and cryptographic deletion verification.

## Overview

The contract separates operational concerns across three roles:

| Role | Permitted Operations |
|---|---|
| **Admin** | Initialize contract, rotate roles (`set_enforcer`, `set_auditor`, `transfer_admin`), configure retention policies (`set_policy`), plus all Enforcer and Auditor actions. |
| **Enforcer** | Register tracked records (`register_record`), record off-chain archive digests (`mark_archived`), request/execute/retry/abort deletion jobs (`request_deletion`, `execute_deletion`, `record_deletion_failure`, `retry_deletion`, `abort_deletion`). |
| **Auditor** | Place and release legal/audit/dispute/settlement holds (`place_hold`, `release_hold`). Cannot execute deletions or mutate policies. |

Read-only queries (`get_policy`, `evaluate_record`, `verify_deletion`, `get_record`, `get_hold`, `get_job`, `get_deletion_certificate`) are publicly accessible for transparent compliance verification.

## Enforcement Lifecycle

1. **Registration**: `register_record` stores record metadata (`class`, `content_hash`, `created_ledger`, `size_bytes`) in `RecordStatus::Active`.
2. **Evaluation**: `evaluate_record` deterministically classifies a record at the current ledger:
   - `AlreadyDeleted` — record has already been deleted.
   - `Frozen` — class has `deletion_frozen == true` (`FinancialSettlement`, `Dispute` by default).
   - `Retained` — current ledger has not yet reached `created_ledger + retain_ledgers`.
   - `Held` — an active hold (`until_ledger == 0` or `until_ledger > now`) protects the record.
   - `ArchiveRequired` — policy sets `archive_before_delete == true` and `mark_archived` has not been called.
   - `Eligible` — safe to schedule for deletion.
3. **Request (`request_deletion`)**: Enforces eligibility, transitions record to `RecordStatus::PendingDeletion`, and creates a `DeletionJob` (`JobStatus::Pending`). Idempotent per `(record_id, idempotency_key)`.
4. **Execution (`execute_deletion`)**: Re-checks all protections at execution time, transitions record to `RecordStatus::Deleted`, marks job `JobStatus::Completed`, and persists a `DeletionCertificate` with a `sha256` commitment over `(job_id, content_hash, deletion_proof_hash, deleted_ledger)`.
5. **Verification (`verify_deletion`)**: Confirms the record is `Deleted`, a certificate exists, `content_hash` matches the caller's expected hash, and the recomputed `sha256` commitment matches `certificate_hash`.

## Edge Cases

- **Late holds / mid-flight policy freezes**: If an Auditor places a hold or Admin freezes the class *after* `request_deletion` but *before* `execute_deletion`, `execute_deletion` re-evaluates protections and fails atomically with `Error::ActiveHold` or `Error::ClassFrozen`.
- **Duplicate / replayed deletion requests**: Repeating `request_deletion` with the same `(record_id, idempotency_key)` returns the existing `DeletionJob` without creating duplicate jobs or mutating state.
- **Concurrent deletion requests with different keys**: Rejected with `Error::PendingDeletionExists` while a record is in `RecordStatus::PendingDeletion`.
- **Invalid holds**: Holds with `until_ledger != 0` and `until_ledger <= current_ledger` are rejected (`Error::InvalidHold`) to prevent silently placing already-lapsed holds.
- **Invalid policies**: Policies with `retain_ledgers == 0` or `> MAX_RETAIN_LEDGERS` (10 years) are rejected (`Error::InvalidPolicy`).
- **Missing or un-deleted verification**: `verify_deletion` returns `verified: false` with explicit machine-readable reasons (`no_rec`, `not_del`, `no_cert`, `hash_mis`, `tampered`).

## Recovery & Rollback Behavior

- **Transient execution failures**: When an off-chain deletion worker encounters a transient failure, it calls `record_deletion_failure(job_id, error_code)`. This increments `attempts` and transitions the job to `JobStatus::Failed`.
- **Retry**: `retry_deletion(job_id)` transitions a `Failed` job back to `Pending` so execution can be retried.
- **Retry exhaustion**: Once `attempts >= max_retries` (`DEFAULT_MAX_RETRIES = 3`), the job transitions to `JobStatus::Exhausted` and further `retry_deletion` calls return `Error::MaxRetriesExceeded`.
- **Rollback (`abort_deletion`)**: Any `Pending`, `Failed`, or `Exhausted` job can be aborted via `abort_deletion(job_id)`. This transitions the job to `JobStatus::Aborted` and restores the record from `RecordStatus::PendingDeletion` back to `RecordStatus::Active` so it can be held, re-evaluated, or scheduled under a new job. Completed jobs cannot be aborted.

## Migration Plan & Backwards Compatibility

- **Existing contracts preserved**: `retention-enforcement` is deployed as a standalone Soroban contract crate (`contracts/retention-enforcement`) with its own isolated storage namespace. No existing contracts or shared libraries are modified.
- **Incremental adoption**:
  1. Deploy and initialize `RetentionEnforcementContract` with `admin`, `enforcer`, and `auditor` addresses.
  2. Configure any non-default `RetentionPolicy` overrides via `set_policy` (defaults match `shared/src/retention.rs`).
  3. Have off-chain indexers or contract keepers register operational records via `register_record` and verify deletions via `verify_deletion`.
  4. Existing contracts using `shared::retention` continue operating unchanged until migrated to invoke `RetentionEnforcementContract`.

## Verification

Run the automated test suite:

```bash
cargo test -p retention-enforcement
```
