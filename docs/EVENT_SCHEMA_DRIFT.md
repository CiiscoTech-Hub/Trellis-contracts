# Cross-Service Event Schema Drift Detection (Issue #449)

Module: `shared/src/event_schema_drift.rs`. It builds on `domain_events::EventSchema`.

`detect_drift(baseline, observed)` returns a `DriftReport { kind, added, removed, breaking }`:

| Kind | Meaning | Breaking |
|---|---|---|
| `None` | same field set (order ignored) | no |
| `FieldsAdded` | new fields with a version bump | no |
| `FieldsRemoved` | fields removed (even with a bump) | yes |
| `UnversionedChange` | fields changed, version unchanged | yes |
| `VersionRegressed` | observed version older than baseline | yes |
| `NameMismatch` | different events | yes |

## Registry

- `register_baseline` (admin only) stores the agreed schema for an event name.
  - Re-registering the current baseline is a no-op.
  - A non-breaking upgrade replaces it and keeps the old one as the rollback target.
  - A breaking change is refused with `BreakingDrift`, and the baseline is left as it was.
- `check_drift` compares a producer's or consumer's schema with the baseline. It returns `BaselineMissing` when none is registered.
- `rollback_baseline` (admin only) restores the previous baseline. It returns `NoPreviousBaseline` when there is none.

## Paths

| Path | Behaviour |
|---|---|
| Normal | a matching schema gives `None` |
| Failure | breaking drift is reported, and refused on registration |
| Retry | registering the same schema twice is safe |
| Authorization | only the admin can register or roll back; checking is public |

## Recovery

If an upgrade breaks consumers, call `rollback_baseline`. Ship the breaking change later as a new event name, or with a coordinated consumer upgrade.

## Compatibility

This is a new module. `EventSchema` is reused unchanged.
