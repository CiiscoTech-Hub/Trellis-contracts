# Strict allow-list validation (Issue #277)

`shared::allowlist` validates external URLs, the file types they reference,
and settlement destination addresses against admin-managed allow-lists. It
composes with the existing `shared::sanitize::validate_external_url` scheme
check rather than replacing it, and reuses `Permission::ManageConfiguration`
for authorization, matching the pattern `nft-marketplace`'s currency
whitelist already established for addresses.

## Model

`AllowlistPolicy` holds three independent dimensions, each with its own list
and `*_enforced` flag:

| Dimension      | List                   | Flag                   |
|----------------|------------------------|-------------------------|
| Hosts          | `allowed_hosts`        | `hosts_enforced`        |
| File types     | `allowed_extensions`   | `extensions_enforced`   |
| Destinations   | `allowed_destinations` | `destinations_enforced` |

A dimension that has never been touched (`*_enforced == false`) is a no-op:
`validate_url` / `validate_destination` return `Ok(())` regardless of value.
This is what makes the module additive — a contract can call
`shared::allowlist::validate_url` today with zero behavior change, and an
admin opts a dimension in later by adding its first entry.

## Operational edge cases

- **Enabling is implicit, one-directional, and fail-closed.** The first
  successful `add_allowed_*` call for a dimension flips its `*_enforced` flag
  to `true`. Removing entries **never** clears the flag. This means emptying
  a list by removing its last entry makes that dimension reject *everything*,
  not fall back to pass-through. A fail-open fallback on removal would let an
  admin accidentally reopen an allow-list they meant to keep locked down —
  for a contract moving donor funds, "reject until reconfigured" is the safer
  failure mode than "silently accept again."
- **Data already stored under a since-removed entry is unaffected.**
  Allow-list checks run only at submission time (e.g. inside
  `register_collection`). Removing a host, extension, or destination does
  not retroactively invalidate records already accepted while it was listed;
  there is no re-validation pass over historical storage. If a previously
  allowed value is later found to be unsafe, treat already-stored records as
  a separate incident-response problem (e.g. the collection/record-specific
  moderation or freeze tooling for that contract), not something this module
  can undo.
- **Retry is just resubmission.** `validate_url` / `validate_destination` are
  pure reads with no side effects, so a caller whose request was rejected can
  simply resubmit the exact same request after an admin updates the
  allow-list; no special retry path or nonce is needed. `nft-marketplace`
  exposes `is_metadata_url_allowed` so a client can check this before
  resubmitting a full transaction.
- **Admin mutations are idempotent.** Adding an already-present entry, or
  removing an absent one, returns `Ok(())` without a storage write. A
  resubmitted admin transaction (e.g. after an unclear submission result)
  is always safe to retry.
- **Bounded growth.** Each dimension is capped at `MAX_ALLOWLIST_ENTRIES`
  (64) entries; `add_allowed_*` returns `AllowlistError::BoundExceeded`
  rather than growing storage unboundedly.

## Rollback

`restore_policy(env, caller, policy)` atomically replaces the entire
`AllowlistPolicy` (all three lists and all three flags) with a caller-
supplied value, after an authorization and bound check. The intended use is:

1. Before a risky change (e.g. removing a host others may still depend on),
   capture the current policy with `get_policy`.
2. Make the change.
3. If it needs to be undone, call `restore_policy` with the captured
   snapshot to return to the exact prior state in one call, rather than
   manually re-adding every removed entry (which would also flip
   `*_enforced` back on if it had been off).

`restore_policy` is also the only way to turn an enforced dimension back
into an unconfigured, pass-through one — pass a policy with that dimension's
flag `false` and its list empty (e.g. `default_policy`).

## Authorization

All mutating functions (`add_allowed_host`, `remove_allowed_host`,
`add_allowed_extension`, `remove_allowed_extension`,
`add_allowed_destination`, `remove_allowed_destination`, `restore_policy`)
require `Permission::ManageConfiguration`. An unauthorized call returns
`AllowlistError::Unauthorized` and leaves the stored policy byte-for-byte
unchanged. Read paths (`get_policy`, `validate_url`, `validate_destination`)
are unauthenticated, matching how `is_currency_whitelisted` is readable by
anyone in `nft-marketplace` today.

## Integration note

A caller that already performs its own admin check before delegating to this
module (e.g. a thin contract wrapper) should **not** also call
`caller.require_auth()` itself first: `shared::allowlist`'s mutators already
call it internally, and Soroban's host rejects authorizing the same
invocation twice within one still-open frame. Let the shared module's own
authorization check be the only one, and map its `AllowlistError::Unauthorized`
onto the caller's local error type instead of pre-checking. See
`nft-marketplace`'s `add_allowed_metadata_host` and friends for the pattern.

## Migration and compatibility

Additive only: no existing contract behavior, storage layout, or entrypoint
changes. `nft-marketplace::register_collection` now also calls
`shared::allowlist::validate_url` on `ipfs_uri`, but with every dimension
unenforced by default this is a no-op until an admin calls
`add_allowed_metadata_host` / `add_allowed_metadata_ext`.
