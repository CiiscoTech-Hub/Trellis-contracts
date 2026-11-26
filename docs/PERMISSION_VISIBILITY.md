# Permission changes and hidden records

Contract tests: `shared/src/test_permission_visibility.rs` (Issue #445).

The timeline decides visibility at read time (`timeline::can_view`), using a
`Viewer` that `viewer_for` builds from on-chain roles. These tests pin down how
hidden records behave when roles change.

| Scenario | Expected behaviour |
|---|---|
| `Upgrader` or `Admin` granted | The address becomes a maintainer and sees participant-only and redacted entries |
| That role revoked | Access goes away on the next read |
| A non-maintainer role granted (e.g. `TreasuryManager`) | No extra visibility |
| Redacted public entry | Hidden from anonymous readers and from its own author; visible to maintainers |
| Admin ownership transfer accepted | The new owner gains maintainer visibility; the old owner loses it |
| `Admin` role revoked | That address can no longer redact (`Unauthorized`) |
| Hidden entries on a page | Skipped without shifting other viewers' pages or cursors |
| Deleted entry | Gone for everyone, maintainers included; the deletion stays in the audit trail |

## Permission-diff report (pre-change review)

Before a role or policy change is applied, operators should produce a
permission-diff report that lists exactly which addresses gain or lose
visibility into hidden records. The report is computed by comparing the
`Viewer` that `viewer_for` would build under the current role set against the
`Viewer` it would build under the proposed role set, for every affected address.

The report contains, per address:

- `before`: current `is_maintainer` and visible hidden-record classes
- `after`: the same fields under the proposed roles
- `change`: one of `gained`, `lost`, or `unchanged`

Normal path: a proposed change produces a report; reviewers approve it and the
change is applied in a separate invocation.

Failure path: if a proposed address is unknown or a role name is not recognised,
the report is rejected with `InvalidInput` and nothing is computed or applied.

Retry path: the report is a pure read over role state. Re-running it with the
same inputs and an unchanged role set yields an identical report, so retries are
safe. If roles change between report generation and application, the report is
stale and must be regenerated; applying a stale report is rejected.

Authorization path: only an `Admin` may request a permission-diff report or
apply the change it describes. Non-admin callers receive `Unauthorized` and
receive no diff contents.

Operational edge cases:

- Empty proposal: produces a report with all addresses `unchanged`; applying it
  is a no-op.
- Self-revocation of `Admin`: the report flags the caller as `lost`; the change
  is still allowed but reviewers should confirm a second admin exists first.
- Ownership transfer pending: the report reflects only roles currently on-chain;
  the pending owner is shown as `unchanged` until the transfer is accepted.

Rollback: because the report is read-only, no rollback is needed for the report
itself. To undo an applied change, apply the inverse role change, generating a
new report for it. Past visibility is not restored retroactively; the audit
trail records both the original and the reversing change.

## Edge case: stale viewers

A `Viewer` is a value snapshot. A copy held across a role change still reports
the old `is_maintainer`. Contract code must build the viewer with `viewer_for`
in the same invocation as the read. It must never cache a viewer in storage or
accept one as an argument. The `a_viewer_must_be_rebuilt_after_a_role_change`
test documents this.

## Recovery

Revoking a role is enough to remove access; nothing has to be cleaned up on the
records themselves. Only a maintainer can undo a redaction, by rewriting the
record. Deletion is permanent apart from the audit entry.
