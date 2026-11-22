# Versioned Migration Notes & Compatibility Runbook (Issue #435)

## 1. Overview & Purpose

This document provides definitive, versioned migration notes and operational runbooks for ledger record transitions across the Trellis Soroban smart contract suite.

In decentralized environments running on Stellar, contract WASM upgrades and on-chain state migrations execute in separate transactions. A schema change must support:
- **Zero-downtime coexistence**: Old records created in earlier versions remain decodable and functional.
- **Lazy read-time migration**: Legacy records are converted to the current canonical schema upon access.
- **Outbound backward compatibility**: Legacy client APIs can request downgraded envelopes without mutating storage.
- **Guaranteed failure recovery**: Failed migration transactions revert cleanly without leaving corrupted or mixed-version state.

---

## 2. Schema Evolution History

| Version | Lifecycle Status | Core Changes | Storage Footprint | Target Module |
|---|---|---|---|---|
| **V1** | **Deprecated** (Read-Only) | `(id, donor, recipient, amount, expiry_ledger, status)`. No token binding; implicit single contract token. | ~120 bytes | `contracts/aid-contract` |
| **V2** | **Current** (Active Read/Write) | Adds explicit `token: Address` binding and `schema_version: u32 = 2`. All new writes enforce this shape. | ~160 bytes | `contracts/aid-contract`, `shared::compat` |
| **V3** | **Preview** (Forward-Compatible) | Adds cryptographic `metadata_digest: BytesN<32>` for compliance and external verification. | ~192 bytes | `contracts/aid-contract`, `shared::compat` |

---

## 3. Migration Paths & Lifecycle Guarantees

### 3.1 Normal Migration Path (V1 $\to$ V2)

1. **Detection**: Upon read invocation (`to_latest` or contract read queries), storage inspects the envelope discriminant (`VersionedAidRecord::V1` vs `V2`).
2. **Transformation**:
   - `id`, `donor`, `recipient`, `amount`, `expiry_ledger`, and `status` are copied losslessly.
   - The contract resolves the authoritative token binding from contract instance configuration.
   - `schema_version` is stamped as `CURRENT_RECORD_SCHEMA_VERSION` (2).
3. **Re-persistence**: Mutating transactions (e.g. `claim_aid`, `refund_aid`) write back the canonical V2 envelope, progressively upgrading the ledger without requiring an expensive all-at-once storage migration.

### 3.2 Failure & Invariant Violation Paths

- **Unsupported Versions**: If an envelope carries `schema_version < MIN_SUPPORTED (1)` or `schema_version > MAX_SUPPORTED (2)` on a write or strict read, the call immediately halts with `Error::UnsupportedSchemaVersion`.
- **Negative / Zero Amount**: If a legacy record contains `amount <= 0`, migration aborts with `Error::SchemaMigrationFailed`, protecting asset conservation invariants.
- **Malformed Envelopes**: Records failing XDR decoding or validation boundaries reject at the host layer before state mutation.

### 3.3 Retry & Idempotency Path

- **Idempotent Application**: Executing `migrate_v1_to_v2` or `to_latest` multiple times on the same record produces identical, deterministic output.
- **Round-Trip Consistency**: A V2 record downgraded to V1 via `downgrade_v2_to_v1` and re-migrated with the same token binding produces a record strictly identical to the original V2 record.

### 3.4 Authorization Path

- **Lazy Migrations**: Executed automatically during authorized transactional calls (`donor` creating, `recipient` claiming).
- **Bulk Storage Migrations**: Bulk migrations using `shared::migration` or `scripts/backfill.sh` strictly require administrator authentication (`Role::Admin` / `require_admin`). Unauthorized invocations reject immediately with `Error::Unauthorized`.

---

## 4. Operator Runbook: Performing Schema Migrations

### Step 1: Preflight Verification
Verify that test fixtures validate cleanly before deploying any upgrade:
```bash
cargo test --package shared test_compat_fixtures
```

### Step 2: WASM Upgrade
Deploy the new contract bytecode via the Trellis Upgradeability Coordinator:
```bash
./scripts/upgrade.sh --contract aid-contract --wasm target/wasm32-unknown-unknown/release/aid_contract.wasm
```

### Step 3: Migration Plan Dry-Run
Execute `dry_run(&plan)` to inspect record counts and potential destructive steps without altering storage:
```rust
let report = shared::migration::dry_run(&migration_plan);
assert!(report.plan_valid);
```

### Step 4: Stepwise Execution & Rollback
If any migration step fails partway through:
1. `MigrationJournal` records the failed step index and halts.
2. Operator assesses the failure cause (e.g., storage budget exhausted).
3. To recover: either forward-fix via `resume_migration` or execute the documented `RollbackStrategy` specified on the plan.

---

## 5. Compatibility Fixtures Reference

Test fixtures located at `fixtures/compatibility/`:
- `v1_legacy_record.json`: Legacy records for backward-compatibility assertions.
- `v2_current_record.json`: Active production format fixtures.
- `v3_forward_record.json`: Forward-compatibility preview fixtures.
- `malformed_record.json`: Failure-mode validation fixtures.

