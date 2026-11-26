# Permission-Aware Export with Field Redaction

## Overview

The aid contract now provides permission-aware export APIs that automatically redact sensitive fields based on the caller's role and permissions. This ensures that recipients, donors, and other stakeholders only see data they are authorized to access.

## Authorization Model

The export system recognizes four caller roles:

| Role | Permission Check | Can Export |
|------|------------------|-----------|
| **Admin** | Has `ManageConfiguration` permission | ✓ All aids, all fields |
| **Donor** | Created the aid record (`aid.donor == caller`) | ✓ Own aids, all fields |
| **Recipient** | Receiving the aid (`aid.recipient == caller`) | ✓ Own aids, **redacted fields** |
| **Inspector** | Registered in `Inspector` storage | ✓ All aids, all fields |
| **Other** | No match | ✗ Returns `None` |

### Field Redaction Matrix

This table shows which fields are visible to each role:

| Field | Admin | Donor | Recipient | Inspector |
|-------|-------|-------|-----------|-----------|
| `id` | ✓ | ✓ | ✓ | ✓ |
| `donor` | ✓ | ✓ | **✗** | ✓ |
| `recipient` | ✓ | ✓ | ✓ | ✓ |
| `token` | ✓ | ✓ | **✗** | ✓ |
| `amount` | ✓ | ✓ | ✓ | ✓ |
| `expiry_ledger` | ✓ | ✓ | **✗** | ✓ |
| `status` | ✓ | ✓ | ✓ | ✓ |
| `milestone_count` | ✓ | ✓ | ✓ | ✓ |
| `milestone.verified` | ✓ | ✓ | **✗** | ✓ |

Redacted fields are returned as `None` for optional fields in the `ExportedAidRecord` response.

## API Reference

### `export_aid(env, caller, aid_id) -> Option<ExportedAidRecord>`

Export a single aid record with permission-aware field redaction.

**Returns:**
- `Some(record)` if the caller is authorized to view the aid
- `None` if the caller is unauthorized or the aid does not exist

**Example:**
```rust
let exported = export_aid(&env, &caller, aid_id)?;
assert_eq!(exported.id, aid_id);
```

### `export_aid_with_milestones(env, caller, aid_id) -> Option<(ExportedAidRecord, Vec<ExportedMilestone>)>`

Export an aid record along with all its milestone tranches.

**Returns:**
- `Some((aid, milestones))` if authorized
- `None` if unauthorized or aid not found

**Behavior:**
- Milestones are redacted according to the same rules
- Recipients do **not** see `milestone.verified`
- The response is paginated implicitly (all milestones are returned)

### `export_aids_by_donor(env, caller, donor, limit, cursor) -> ExportedAidPage`

Export all aid records created by a specific donor, with pagination.

**Returns:**
- A paginated response with up to `limit` records
- Records the caller cannot view are **silently skipped**
- `next_cursor` indicates whether more results are available

**Example:**
```rust
let page1 = export_aids_by_donor(&env, &caller, &donor, 10, None);
let page2 = export_aids_by_donor(&env, &caller, &donor, 10, page1.next_cursor);
```

### `export_aids_by_recipient(env, caller, recipient, limit, cursor) -> ExportedAidPage`

Export all aid records assigned to a specific recipient, with pagination.

**Same behavior as `export_aids_by_donor`.**

## Normal Path Examples

### Admin exports all data for an aid

```rust
let exported = api.export_aid(env, admin, aid_id)?;
// exported.donor = Some(donor_addr)
// exported.token = Some(token_addr)
// exported.expiry_ledger = Some(100)
```

### Recipient exports their own aid

```rust
let exported = api.export_aid(env, recipient, aid_id)?;
// exported.donor = None (redacted)
// exported.token = None (redacted)
// exported.amount = 1000 (visible)
// exported.status = Pending (visible)
```

### Donor exports aid with milestones

```rust
let (aid, milestones) = api.export_aid_with_milestones(env, donor, aid_id)?;
// milestones[0].verified = Some(true) (visible)
```

## Authorization Failure Paths

### Unauthorized caller attempts export

```rust
let exported = api.export_aid(env, unauthorized_user, aid_id);
// Returns None (authorization denied)
```

**No error is thrown.** The API gracefully returns `None` to avoid leaking whether a record exists.

### Non-existent aid export

```rust
let exported = api.export_aid(env, admin, 999);
// Returns None (record not found)
```

**Same behavior as authorization failure.** Storage reads safely return `None` when the key does not exist.

## Retry and Idempotency

All export operations are **fully idempotent**:

- Multiple calls with the same parameters return identical results
- No state is modified during export
- No side effects occur (no events emitted, no storage changes)
- Exports can be safely retried without risk of duplication or inconsistency

**Recovery:** If an export fails due to a transient network error, simply retry with the same parameters.

## Edge Cases and Recovery

### Edge Case 1: Aid Record Exists But Milestones Are Empty

**Behavior:** The export returns an `AidRecord` with `milestone_count = 0` and an empty milestones vector.

**Recovery:** This is normal for non-milestone-based aids. Check `milestone_count` to determine if milestones are expected.

### Edge Case 2: Pagination Cursor Out of Range

**Behavior:** If `cursor` points beyond the current result set, the API starts from the cursor position. If no records remain, an empty page is returned with `next_cursor = None`.

**Recovery:** Check `next_cursor` before issuing subsequent requests. When it is `None`, all records have been returned.

### Edge Case 3: Concurrent Aid Creation During Export

**Behavior:** New aids created during export are included in subsequent pages if pagination is in use. The snapshot is taken per-page, not across the entire result set.

**Recovery:** Accept that pagination is eventually consistent. For a frozen snapshot, export all IDs first, then export each record independently.

### Edge Case 4: Caller Role Changes Mid-Export

**Behavior:** If the caller's role or permissions change between paginated requests, subsequent pages may include/exclude different records or show different field redactions.

**Recovery:** For a consistent view, fetch all data in a single request or use a fixed snapshot of aid IDs.

### Edge Case 5: Storage Schema Version Mismatch

**Behavior:** If the contract storage schema is upgraded but aid records are not migrated, the export may fail to read legacy records. This is prevented by the `guard_storage_read()` check in the storage layer.

**Recovery:** Ensure storage schema migrations complete before enabling exports. See the migration guide in `UPGRADEABILITY.md`.

### Edge Case 6: One Address Holds Two Roles

**Behavior:** The role is resolved in the order admin, donor, recipient, inspector, and the first match wins. An inspector who is also the recipient of an aid gets the recipient's redacted view of that aid, not the inspector's full view.

**Recovery:** None needed; this keeps the narrower view. To see the full record, export it from an address that is only an inspector, or as the admin.

## Rollback and Backwards Compatibility

### Existing Contracts

Existing contracts that do not have the export module remain unaffected:

- The export module is **opt-in** — older versions do not include it
- No changes to `AidRecord` or `AidStatus` types
- Existing aid creation and claiming flows are unchanged
- **Migration:** No migration plan needed; exports are purely additive

### New Deployments

New contracts include the export APIs by default. The `ExportedAidRecord` and `ExportedMilestone` types are separate from the canonical storage types, so:

- No breaking changes to stored data
- Exports are best-effort — if a record cannot be exported due to authorization, `None` is returned gracefully
- Storage TTL management is unchanged

### Version Safety

The export module uses the shared permission framework (`shared::auth::Permission`, `shared::auth::Role`). If roles or permissions are added in the future:

1. New roles are handled gracefully (default to `Unauthorized`)
2. Existing caller roles are not affected
3. The redaction matrix can be extended without breaking existing exports

## Testing Coverage

The export module includes comprehensive tests in `aid_export_test.rs`:

- ✓ Admin can export all fields
- ✓ Donor can export all fields of own aids
- ✓ Recipient sees redacted fields
- ✓ Inspector can export all fields
- ✓ Unauthorized users get `None`
- ✓ Non-existent aids return `None`
- ✓ Milestone redaction (recipient does not see `verified`)
- ✓ Export idempotency
- ✓ Pagination with multiple records
- ✓ All aid statuses (Pending, Settled, Refunded, PartiallyClaimed)
- ✓ Recipients cannot view others' aids

**Run tests:**
```bash
cargo test --package aid-contract aid_export
```

## Performance Considerations

- **Single export:** O(1) storage read + redaction
- **Paginated export:** O(limit) storage reads (one per record on the page)
- **Field redaction:** O(1) per record (boolean role check + field masking)
- **No indexing overhead:** Redaction happens at query time, not on storage

## Security Considerations

1. **Authorization is enforced on every call.** Role checks happen before field redaction.
2. **Non-authorization returns `None`, not an error.** This prevents attackers from probing for record existence.
3. **Milestone verification is redacted for recipients.** Prevents recipients from inferring verification state they should not know.
4. **Donor address is redacted for recipients.** Prevents privacy leaks.
5. **Token address is redacted for recipients.** Prevents information disclosure.
6. **Expiry ledger is redacted for recipients.** Prevents timing attacks.

## Support and Debugging

If an export returns unexpected results:

1. **Verify caller role:** Check if the caller is admin, donor, recipient, or inspector
2. **Check aid existence:** Call `get_aid()` directly to confirm the record exists
3. **Inspect permissions:** Use `shared::auth::has_permission()` to verify caller permissions
4. **Review redaction matrix:** Ensure field visibility matches expectations for the role
5. **Check milestone count:** For milestone-based aids, verify `milestone_count > 0`

See `aid_export_test.rs` for runnable examples of all paths.
