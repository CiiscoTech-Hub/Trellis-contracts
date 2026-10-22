# On-Chain Protocol Changelog

`shared::protocol_changelog` (Issue #340) is the on-chain complement to the
machine-readable changelog this workspace already has
(`changelog/entries.json` + `changelog/schema.json`, Issue #126; see
`docs/CHANGELOG_SCHEMA.md`), not a replacement for it.

## Why this is additive, not a duplicate

`changelog/entries.json` is validated in CI and gives any tool that can
clone this repo a structured record of protocol-facing changes. It is
deliberately a **git-repo artifact** — a contract cannot read it (no
filesystem access from WASM), and neither can an indexer or client SDK
without fetching the file out-of-band. There was no way for a deployed
contract, or a caller of one, to ask "what protocol-affecting changes have
shipped since version N" on-chain at all.

`shared::protocol_changelog` closes that gap: an append-only, admin-recorded
log using the exact same fields `changelog/schema.json` already defines
(`impact`, `summary`, `migration_notes`, `issue`), queryable directly from
the deployed contract.

## Design in one paragraph

`record_protocol_change` enforces the identical rule
`changelog/schema.json`'s conditional enforces off-chain: `summary` must be
non-empty, and `migration_notes` must be non-empty when `impact` is
`ChangeImpact::Breaking`. Admin-gated. Entries are immutable and
append-only, the same guarantee `shared::audit_ledger` gives its own
entries — there is no update or delete path. A wrong or incomplete entry is
corrected by recording a new one with `supersedes` pointing at the original,
never by editing history. `list_protocol_changes_since` and
`has_breaking_change_since` are bounded through `shared::scan_guard`, so
neither can scan unbounded as the log grows; `latest_protocol_change_for_module`
gives an O(1) lookup of the newest entry per module via a secondary index.

## Public surface

| Item | Purpose |
|---|---|
| `record_protocol_change` | Admin-gated; enforces the breaking-needs-migration-notes rule. |
| `get_protocol_change` | Read one entry by `seq`. |
| `latest_protocol_change` / `latest_protocol_change_for_module` | Read the newest entry overall or per module. |
| `list_protocol_changes_since` | Bounded listing since a cursor `seq`. |
| `has_breaking_change_since` | Bounded existence check for a breaking change since a cursor `seq`. |

Re-exported from the crate root as `protocol_changelog_length` — the
unaliased `length` is already taken by `shared::audit_ledger`.

## Who can do what

| Action | Required condition |
|---|---|
| Record an entry | `Role::Admin`, authenticated |
| Read any entry, list, or query | Anyone (read-only, no auth required) |

## Operational edge cases

| Situation | Behavior |
|---|---|
| Non-admin calls `record_protocol_change` | `Error::Unauthorized`, before anything is validated or stored. |
| `summary` is empty | `Error::InvalidArgument`. |
| `impact == Breaking` and `migration_notes` is empty | `Error::InvalidArgument` — the same rule `changelog/schema.json` enforces off-chain. |
| `supersedes` names a `seq` that does not exist | `Error::NotFound`, before the new entry is written. |
| `get_protocol_change(0)` or any `seq` beyond the current length | `None`, not an error. |
| `has_breaking_change_since` asked about a window with more than `ABSOLUTE_MAX_SCAN` entries | Scans only up to the ceiling; a breaking change further back than that can be missed. Use `list_protocol_changes_since` in explicit ranges for a window that large. |
| Two entries recorded for the same module | `latest_protocol_change_for_module` always reflects the most recent; older entries remain readable by `seq`. |

## Rollback and recovery

Entries are never edited or deleted — correcting one means recording a new
entry that references it:

1. **Wrong `impact`, or missing/wrong `migration_notes`**: record a new
   entry describing the correction, with `supersedes` set to the original's
   `seq`. The original stays exactly as recorded.
2. **An entry should never have been recorded**: record a correcting entry
   (`impact: Internal`, `summary` explaining why) with `supersedes` pointing
   at it. There is no delete path, by design.
3. **Retry after a validation failure**: `record_protocol_change` performs
   no partial writes — a rejected call changes nothing, so correct the
   input and call it again.

## Compatibility

Purely additive: new storage keys, no changes to `changelog/entries.json`,
its schema, `scripts/validate-changelog.cjs`, or any contract interface.
The two logs stay in sync by convention, not by code: a PR that adds a
`changelog/entries.json` entry for a deployed change should also call
`record_protocol_change` once that change ships.
