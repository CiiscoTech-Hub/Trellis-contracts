# Schema migration compatibility matrix fixtures (Issue #470)

Each CSV row is one cell of the schema migration compatibility matrix: a stored
state, an operation, and the outcome the current build must produce.
`shared/src/test_schema_migration_matrix.rs` loads these files with
`include_str!` and replays every row against the real code.

| File | Covers |
|---|---|
| `storage_read.csv` | `guard_storage_read`, `validate_storage_schema_read(env, true)` and `ensure_storage_schema_version` for every stored storage schema version |
| `schema_migration.csv` | `check_schema_migration` and `commit_schema_migration` across stored version, plan, journal state and caller |
| `record_read.csv` | `shared::compat` read (`to_latest`), downgrade (`downgrade_v2_to_v1`) and write (`from_latest`) paths per record envelope and version |

Format: comma-separated, one header row starting with `id,`, lines starting
with `#` are comments, `-` means "not applicable". Each file's comment block
explains its columns.

## Running

```bash
cargo test -p shared test_schema_migration_matrix
```

A failing row names its id (for example `M05: commit_schema_migration`), so
the cell that changed is obvious.

## When a schema version changes

The fixtures are written for a build that reads storage schema versions
`1..=2` and record schema version `2`.
`matrix_matches_this_builds_supported_versions` fails as soon as either
changes. To introduce V3:

1. Bump the constants in `storage_version.rs` / `compat.rs`.
2. Update the rows whose outcome changes. For storage schema V3, for example,
   `R13`–`R15` become `ok:3`, `M11` becomes `Compatible` / `ok:3`, and
   `M12` (stored 3) becomes `TargetUnsupported`; move it to stored 4 to keep a
   source-unsupported row.
3. Add rows for the new hop (`2 -> 3`) covering the same journal states and
   callers as the `1 -> 2` rows (`M01`–`M08`).
4. Update `MATRIX_*` in the test and the tables in
   `docs/SCHEMA_MIGRATION_MATRIX.md`.
