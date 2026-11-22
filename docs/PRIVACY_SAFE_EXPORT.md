# Privacy-safe export with field-level authorization (Issues #294, #502)

Code: `shared::export::{generate_field_scoped_export, field_visible_to, is_personal_field}`
Tests: `cargo test -p shared export`

`generate_export` already authorizes the **scope** (who may export which
records) and drops any field that is not on the safe-field allow-list. Every
caller who could see a record saw all of its allow-listed fields, though. A
support operator exporting under `Operational` received other users'
`amount`, `region`, `role` and `tier` values.

`generate_field_scoped_export` runs `generate_export` unchanged, then applies a
per-field decision for each record:

| Field class | Owner of the record | `Operational` (someone else's record) | `Full` (admin) |
|---|:---:|:---:|:---:|
| Forbidden (`priv_key`, `ssn`, `ip_addr`, …) | never | never | never |
| Not allow-listed (`wallet`, `email`, …) | never | never | never |
| Personal (`amount`, `region`, `role`, `tier`) | yes | **withheld** | yes |
| Other safe fields (`id`, `type`, `status`, `created`, `expiry`, `version`, `network`, `count`) | yes | yes | yes |

The result is a `FieldScopedExport { artifact, withheld_fields }`.
`artifact.report.redacted_fields` still counts allow-list drops;
`withheld_fields` counts fields hidden by field-level authorization.

## Paths

- **Normal:** owners get every safe field of their own records, admins every
  safe field of every record.
- **Authorization:** scope authorization (`ScopeDenied`), own-records filtering
  and restricted-record filtering are inherited from `generate_export` and run
  first. Field policy can only remove data, never add it.
- **Failure:** validation, size (`ExportTooLarge`) and TTL errors are those of
  `generate_export`; nothing is partially exported.
- **Retry:** generation is a pure function of the request, records and ledger,
  so retrying a failed delivery produces an identical artifact (tested).

## Edge cases

- An operator's **own** record keeps its personal fields under `Operational`:
  ownership is checked per record, not per export.
- A record whose every field is withheld is still exported, with its id, type,
  owner and created ledger, so record counts stay consistent with
  `metadata.record_count`.
- Adding a new allow-listed field: decide whether it is personal and update
  `is_personal_field` in the same change. Fields default to non-personal, so
  review is required.

## Migration plan

`generate_export` and `create_export` are unchanged, so existing callers and
stored artifacts are unaffected. Contract entry points that export on behalf of
operators should switch to `generate_field_scoped_export`. The artifact type is
the same, wrapped in `FieldScopedExport`. Rolling back means switching the
entry point back to `generate_export`; there is no stored state to migrate.
