# Audit Evidence for Administrative Configuration Changes (Issue #278)

## Overview

`shared::admin_config_audit` binds every administrative configuration mutation to a versioned, tamper-evident `AdminConfigEvidence` record backed by:
1. A canonical Soroban XDR SHA-256 `evidence_hash` covering `(contract, config_key, version, actor, before_hash, after_hash, reason, ledger, timestamp)`.
2. An immutable `AdminChangeReceipt` anchored in `shared::audit_ledger` (`AuditEventKind::ConfigChanged`).

## Public Surface

| Function | Purpose |
|---|---|
| `record_config_change(env, admin, module, config_key, before_hash, after_hash, reason)` | Admin-gated (`require_admin`); rejects no-ops (`Error::NoChangeDetected`); stores versioned `AdminConfigEvidence` and emits `("cfg_aud", config_key)`. |
| `verify_config_evidence(env, config_key, version)` | Recomputes `evidence_hash` and runs `audit_ledger::verify_admin_receipt`, returning `ConfigEvidenceStatus`. |
| `rollback_config_change(env, admin, module, config_key, target_version, reason)` | Admin-gated rollback that appends a **new** version restoring `target_version.after_hash` without mutating or deleting prior evidence. |
| `get_config_evidence(env, config_key, version)` | Reads stored evidence for a version. |
| `latest_config_version(env, config_key)` | Returns the latest version number (0 if unset). |

## Operational Edge Cases

1. **No-op mutations:** If `before_hash == after_hash`, `record_config_change` returns `Err(Error::NoChangeDetected)` so the audit log is not polluted with empty changes.
2. **Storage tampering:** Modifying any field in `AdminConfigEvidence` causes `verify_config_evidence` to return `ConfigEvidenceStatus::HashMismatch`. Modifying the underlying audit ledger causes `ConfigEvidenceStatus::ReceiptInvalid`.
3. **Long ledger chains:** `verify_admin_receipt` bounds forward verification to `MAX_VERIFY_ENTRIES`; if exceeded, `verify_config_evidence` returns `ConfigEvidenceStatus::ReceiptInvalid`.

## Recovery and Rollback Behavior

- **Bad configuration change:** Never delete or overwrite historical `AdminConfigEvidence` entries. Call `rollback_config_change(..., target_version, reason)` to append a new monotonic version whose `before_hash` is the current value and `after_hash` is `target_version.after_hash`.
- **Verification failure:** If `verify_config_evidence` returns `HashMismatch` or `ReceiptInvalid`, pause affected configuration consumers and reconcile against off-chain event logs (`("cfg_aud", config_key)` and `("audit", "head")`).

## Contract Preservation

`shared::admin_config_audit` is purely additive and composes `shared::audit_ledger::record_admin_change` and `shared::auth::require_admin` without altering existing `config.rs`, `config_version.rs`, or `audit_ledger.rs` APIs.
