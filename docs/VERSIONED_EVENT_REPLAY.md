# Versioned Event Replay Tool for Rebuilding Projections (Issue #276)

`shared::versioned_replay` provides a checkpointed, schema-versioned event replay engine for rebuilding derived projections safely.

## Replay Workflow

1. **Plan (`plan_replay`)**: Validates `target_version` in `[MIN_SUPPORTED_REPLAY_VERSION, MAX_SUPPORTED_REPLAY_VERSION]` (`1..=2`), snapshots `current_projection` as `pre_replay_snapshot`, and initializes `current_projection` at `target_version`.
2. **Apply (`apply_replay_batch`)**: Processes bounded batches (up to `MAX_REPLAY_BATCH = 50` events), upgrades v1 events to v2 semantics, updates `cursor_seq`, and recomputes the SHA-256 `checksum`.
3. **Complete (`complete_replay`)**: Transitions the session to `ReplayStatus::Completed`.

## Edge Cases & Recovery / Rollback Behavior

- **Unsupported Schema Version**: Out-of-range `target_version` or `ev.schema_version` fails with `Error::UnsupportedSchemaVersion`.
- **Idempotent Batch Retry**: Events with `seq <= cursor_seq` are safely skipped without double-applying, allowing interrupted batches to be retried.
- **Invariant Failure**: Negative amounts, underflow on `Debit`, or overflow on `Credit` mark the session `ReplayStatus::Failed` and return `Error::SchemaMigrationFailed` or `Error::Overflow` while preserving `pre_replay_snapshot`.
- **Rollback (`rollback_replay`)**: Restores `current_projection = pre_replay_snapshot` and sets `ReplayStatus::RolledBack` (idempotent on repeated calls).
- **Authorization**: All replay lifecycle functions enforce `require_admin`.

## Contract Preservation

This module is additive in `shared` (`shared::versioned_replay`) and complements `shared::projection_repair` and `shared::replay` without altering existing storage keys or contract interfaces.
