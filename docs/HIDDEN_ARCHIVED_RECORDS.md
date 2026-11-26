# Hidden and Archived Aid Records — Authorization Model (Issue #480)

This document defines who may see and change **hidden** and **archived** aid
records in [`contracts/aid-contract`](../contracts/aid-contract/src/lib.rs),
lists the edge cases, and gives the recovery / rollback procedure for each
state. The behaviour is pinned by
[`hidden_archived_auth_test.rs`](../contracts/aid-contract/src/hidden_archived_auth_test.rs):

```bash
cargo test -p aid-contract hidden_archived_auth_test
```

## Record states

| State | How a record gets there | Canonical record | In discovery index |
|-------|-------------------------|------------------|--------------------|
| **Visible** | `create_aid` / `batch_create_aid` | `Pending` | yes |
| **Hidden** | admin `set_aid_search_visibility(.., false)` | unchanged (any status) | no |
| **Archived** | `claim_aid` → `Settled`, `refund_aid` → `Refunded` | terminal status, retained | no |
| **Purged** | admin `delete_aid` on an archived record | removed | no |
| **Evicted** | canonical entry lost (TTL expiry) | missing | possibly a dangling entry |

Hidden and archived are independent. A record can be hidden *and* archived (for
example, hidden while pending and then claimed). The hidden flag survives
archival.

## Access matrix

`✓` = allowed, `✗` = `AidError::Unauthorized`. Every call also requires the
named address's signature (`require_auth`). Passing an admin or participant
address without that signature fails at the host auth layer, before any state
is touched.

| Operation | Admin | Donor | Recipient | Delegate (granted) | Outsider |
|-----------|:-----:|:-----:|:---------:|:------------------:|:--------:|
| Discover **hidden** record (`search_aids`, `search_aids_cursor`) | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) |
| Discover **archived** record | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) | ✗ (filtered) |
| Owner listing (`list_aids_by_donor*` / `list_aids_by_recipient*`) | — | ✓ own | ✓ own | — | — |
| Hide / unhide (`set_aid_search_visibility`) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Grant / revoke discovery (`*_search_access`) | ✗ | ✓ | ✗ | ✗ | ✗ |
| Claim hidden pending record | — | — | ✓ | — | — |
| Refund hidden expired record | ✓ | ✓ | — | — | — |
| Purge archived record (`delete_aid`) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Purge pending / partially-claimed record | `CannotDeletePending` | ✗ | ✗ | ✗ | ✗ |
| Rebuild index (`repair_search_index`) | ✓ | ✗ | ✗ | ✗ | ✗ |

"Filtered" means the call succeeds but the record is left out of the results.
Filtering happens at read time in `can_discover`, so it holds even when the
derived index is stale or corrupt.

## Edge cases

1. **Hiding is a discovery control, not a confidentiality control.** A hidden
   record stays in its donor's and recipient's listings, and `get_aid` returns
   it to anyone because it is public ledger state. Do not use hiding to protect
   sensitive data. Use the redacting export path (`aid-contract::export`) for
   that.
2. **Hiding never locks funds.** A hidden pending record can still be claimed
   by its recipient and refunded by its donor or the admin after expiry.
   Moderation cannot strand escrow.
3. **Discovery grants are inert while hidden or archived.** The donor may grant
   or revoke access on a hidden or archived record. The grant only takes effect
   if the admin later unhides a record that is still pending.
4. **The admin moderates but does not own grants.** The admin can hide records
   but cannot grant discovery on the donor's behalf.
5. **Admin rotation is immediate.** As soon as `shared::auth::set_admin`
   changes the admin, the former admin loses both the moderation right and the
   admin discovery bypass.
6. **Unhiding an archived record does not bring it back.** It clears the flag,
   but a `Settled` / `Refunded` record never re-enters the index.
7. **Partially claimed milestone programs cannot be purged**, even when hidden,
   because they still hold escrow.
8. **Retries are safe.**
   - Hide and unhide are idempotent: repeated calls never duplicate index rows.
   - Claim or refund on an archived record returns `AlreadyClaimed` /
     `AlreadyRefunded` with no balance change.
   - Any operation on a purged record returns `NotFound`.
   - A call rejected for authorization or because the contract is paused leaves
     nothing behind, so a correctly authorized retry succeeds.
9. **The index stays sorted.** `search_aids_cursor` binary-searches the derived
   index, so `index_aid` inserts in ascending order. Before #480 an un-hidden
   older record was appended behind newer IDs, and cursor pages silently
   skipped it.

## Recovery and rollback

| Situation | Recovery | Reversible? |
|-----------|----------|-------------|
| Record hidden by mistake | Admin calls `set_aid_search_visibility(id, true)`. A pending record goes back into the index at its sorted position. | Yes |
| Record hidden, then archived | Unhiding clears the flag only. An archived record stays out of discovery by design. | Flag only |
| Stale, duplicate, or corrupt index (interrupted write, bad migration) | Reads are already safe because of the read-time filter. The admin runs `repair_search_index` to rebuild from canonical storage. It is idempotent, and a second run reports `added = removed = 0`. | Yes |
| Index unsorted by the pre-#480 unhide bug | Run `repair_search_index` once. It rebuilds in ascending ID order. | Yes |
| Canonical record evicted (TTL) | Cursor reads skip the dangling entry. Visibility changes return `NotFound`. `repair_search_index` drops the entry. Funds tied to an evicted record need the ledger restore procedure in [`RECOVERY.md`](RECOVERY.md). | Index: yes |
| Archived record purged by mistake | **Not reversible on-chain.** Rebuild it from events (`aid_claimed` / `aid_refunded`) and the audit ledger off-chain. Purge only after export / retention sign-off; see [`RETENTION.md`](RETENTION.md). | No |

## Compatibility and migration

- No entrypoint signature, error code, event, or storage key changed.
- The `SearchHidden(id)` flag keeps its meaning. A missing flag still means
  visible.
- The only behaviour change is that `index_aid` keeps the derived index sorted.
  Indexes already left unsorted by the earlier append behaviour are not
  rewritten automatically. Run `repair_search_index(admin)` once after
  upgrading to normalise them. Until then, the offset-based `search_aids` keeps
  working, and `search_aids_cursor` may skip the affected records.
