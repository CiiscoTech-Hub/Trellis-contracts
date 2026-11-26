# Signed Audit Receipts for Admin Changes

This document describes the **signed audit receipts** contract (`contracts/signed-audit-receipts` — `SignedAuditReceiptsContract`) that provides Ed25519 cryptographic attestation over a hash-chained administrative audit ledger.

## Overview

Hash-chained audit receipts pin an administrative change to a specific sequence number and digest on-chain, but without a detached cryptographic signature they cannot prove off-chain countersignature by an authorized audit signer.

`SignedAuditReceiptsContract` provides a focused, self-contained vertical slice that binds every admin change to:
1. An immutable, append-only SHA-256 hash-chained `AdminAuditEntry` (`seq`, `entry_hash`, `prev_hash`, `ledger`, `timestamp`).
2. A caller-supplied idempotency key (`change_id: BytesN<32>`).
3. A domain-separated, canonical XDR SHA-256 signing digest (`SIGNED_AUDIT_RECEIPT_DOMAIN = "trellis_signed_audit_receipt"`, `SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION = 1`).
4. An Ed25519 signature verified on-chain via Soroban's host `env.crypto().ed25519_verify` against a registered, active audit signer public key.

## Architecture & Flow

### 1. Initialization & Signer Registry (Admin-only)
- `initialize(env, admin)` sets the controlling admin once (`AlreadyInitialized` on repeat).
- `register_receipt_signer(env, admin, signer_key)` registers a 32-byte Ed25519 public key. Requires admin authentication.
- `revoke_receipt_signer(env, admin, signer_key)` marks the signer inactive and records `revoked_ledger` and `revoked_at` without deleting the record.
- Revocation is monotonic: a revoked key cannot be re-activated (`SignerRevoked`). Operators must rotate to a new Ed25519 keypair.

### 2. Two-Phase Idempotent Issuance & Signing
1. **Phase 1 — Issue Pending Receipt (`issue_pending_receipt`)**:
   - Verifies `actor` is the initialized admin and authenticates (`actor.require_auth()`).
   - Appends an `AdminAuditEntry` to the hash chain and persists a `PendingAdminReceipt` keyed by `change_id`.
2. **Phase 2 — Attach Signature (`attach_receipt_signature`)**:
   - The off-chain audit signer computes `receipt_signing_digest(env, change_id, pending.receipt, signer_key)` and signs the 32-byte digest with Ed25519.
   - `attach_receipt_signature` checks that `signer_key` is registered and active, verifies the Ed25519 signature via `env.crypto().ed25519_verify`, and persists `SignedAdminAuditReceipt` indexed by both `change_id` and `seq`.

### 3. End-to-End Verification (`verify_signed_receipt`)
Checks in order:
1. `schema_version == SIGNED_AUDIT_RECEIPT_SCHEMA_VERSION` (`UnsupportedSchema`).
2. `signer_key` exists in registry (`UnknownSigner`) and was not revoked at or before `signed_ledger` (`SignerRevokedBeforeSigning`).
3. Recomputed `receipt_signing_digest` matches `signed.digest` (`DigestMismatch`).
4. `env.crypto().ed25519_verify` succeeds (traps on invalid signature).
5. The audit chain entry at `receipt.seq` matches and links forward to `chain_head` within `MAX_VERIFY_ENTRIES` (`LedgerMissing`, `LedgerMismatch`, `LedgerUnlinked`, `LedgerScanLimitExceeded`).
6. Returns `Valid`, or `ValidSignerRevokedLater` if the signer was validly active at `signed_ledger` and revoked at a later ledger.

## Covered Paths

| Path | Behavior |
|---|---|
| **Normal** | Admin initializes -> registers signer -> issues pending receipt -> signer signs digest -> attaches signature -> `verify_signed_receipt` returns `Valid`. |
| **Authorization** | Non-admin calls to `register_receipt_signer`, `revoke_receipt_signer`, or `issue_pending_receipt` return `Err(Unauthorized)`. Unregistered signers return `Err(UnknownSigner)`; revoked signers return `Err(SignerRevoked)`. |
| **Retry / Idempotency** | Re-registering an active signer returns `Ok(())`. Re-issuing a pending receipt with the same `change_id` and identical parameters returns the existing pending receipt without duplicating the chain entry; conflicting parameters return `Err(IdempotencyConflict)`. Re-attaching the exact same `(change_id, signer_key, signature)` returns the existing signed receipt; a different signer/signature returns `Err(AlreadySigned)`. |
| **Failure** | Invalid Ed25519 signatures trap inside `ed25519_verify` with no partial state written. Unknown `change_id` returns `Err(ReceiptNotFound)`. Double initialization returns `Err(AlreadyInitialized)`. |

## Edge Cases, Recovery & Rollback Behavior

- **Compromised Signer Key**:
  1. Admin immediately calls `revoke_receipt_signer(env, admin, compromised_key)` and `register_receipt_signer(env, admin, new_key)`.
  2. Any future `attach_receipt_signature` call using `compromised_key` is rejected with `SignerRevoked`.
  3. Receipts already signed *before* `revoked_ledger` remain historically auditable and verify as `ValidSignerRevokedLater`.
  4. Any receipts still in `PendingAdminReceipt` state can be signed by `new_key` without re-executing the admin change.
- **Transient Signing Failure / Network Timeout**:
  - Because Phase 1 (`issue_pending_receipt`) and Phase 2 (`attach_receipt_signature`) are both idempotent on `change_id`, clients and signing services can safely retry either step without duplicating audit chain entries or corrupting receipts.
- **Invalid Signature Rollback**:
  - Soroban's `env.crypto().ed25519_verify` aborts the entire transaction on signature verification failure, guaranteeing atomic rollback with zero partial storage writes.
- **Audit Chain Tampering**:
  - If the underlying `AdminAuditEntry` is altered or unlinked after signing, `verify_signed_receipt` detects it and returns `LedgerMismatch` or `LedgerUnlinked`.

## Compatibility & Migration Plan

- **100% Additive**: Implemented as a standalone Soroban contract (`contracts/signed-audit-receipts`) with no modifications to any existing contract or `shared` module.
- **Existing Contracts Preserved**: All existing contract interfaces, storage layouts, and event topics remain completely untouched.
- **Opt-In Adoption**: Deploy `SignedAuditReceiptsContract` alongside existing contracts and invoke `issue_pending_receipt` / `attach_receipt_signature` for privileged administrative workflows.

## Verification

Run the automated test suite:

```bash
cargo test -p signed-audit-receipts
```
