# Deterministic Upgrade Compatibility Snapshots (Issue #322)

Module: `shared/src/upgrade_compat_snapshot.rs`

## What it does

A `CompatSnapshot` records the public surface of one contract version:

- entrypoint signatures (`name`, argument type names, return type name)
- storage key families
- event topics
- `storage_schema` version

`build_snapshot` sorts every list and rejects duplicates before hashing, so the
`surface_hash` depends only on the surface, never on input order. `version` is
stored but not hashed, so two versions with an unchanged surface share a hash.

## Lifecycle

| Step | Call | Auth |
|------|------|------|
| Register the deployed surface | `record_baseline` | admin |
| Dry-run a candidate | `check_upgrade` → `CompatReport` | none (read-only) |
| Promote the candidate | `approve_upgrade(candidate, migration_acknowledged)` | admin |
| Undo the last promotion | `rollback_upgrade` | admin |

## Verdicts

| Change | Verdict | `approve_upgrade` |
|--------|---------|-------------------|
| nothing | `Identical` | allowed |
| additions only | `Compatible` | allowed |
| storage key family removed, or schema bumped | `RequiresMigration` | needs `migration_acknowledged = true` |
| entrypoint removed/signature changed, event topic removed, schema decreased | `Breaking` | always rejected (`BreakingChange`) |

## Failure, retry and authorization paths

- **Tampered or unsorted snapshot**: `verify_snapshot` rebuilds it and returns
  `FingerprintMismatch`. Every stateful call verifies its input first.
- **Retry**: calling `record_baseline` or `approve_upgrade` again with the
  snapshot that is already the baseline returns success and changes nothing.
  A different snapshot for an existing baseline returns `BaselineConflict`.
- **Downgrade**: a candidate whose `version` is not above the baseline's returns
  `VersionNotIncreasing`.
- **Authorization**: any mutation from a non-admin returns `Unauthorized`.
  Callers also go through `require_auth`.
- Every rejected approval leaves the baseline and rollback slot unchanged.

## Operational edge cases

- **Rollback depth is one.** `approve_upgrade` saves the replaced baseline in a
  single `Previous` slot. A second rollback in a row returns `NoRollbackTarget`.
  To roll back further, re-approve the older snapshot under a new higher
  `version`. It still has to pass the compatibility check.
- **Rollback only restores the snapshot record.** It does not redeploy WASM or
  reverse a storage migration. Run `scripts/upgrade.sh` with the previous WASM
  hash first, then call `rollback_upgrade` so the snapshot matches what is
  deployed.
- **Type names are opaque.** Pick one naming convention per contract (for
  example `addr`, `i128`, `sym`) and keep it. Renaming a type label shows up as
  a `Breaking` signature change.
- **Bounds**: there is a limit of 64 entrypoints, 64 storage keys and 64 event
  topics, and 16 arguments per entrypoint. Larger inputs return `TooManyItems`.

## Migration plan

This change only adds a new module. No existing contract storage, entrypoint
or event changes. To adopt it:

1. Build a snapshot for each deployed contract from its current interface.
2. Call `record_baseline` once per contract.
3. Add `check_upgrade` to the release checklist before `scripts/upgrade.sh`, and
   call `approve_upgrade` after the WASM upgrade lands.
