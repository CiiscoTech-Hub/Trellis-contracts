# Deterministic conflict resolution

`shared::resolve_conflict_pair` resolves two concurrent client edits using a
stable ordering: the greatest revision wins, and equal revisions are ordered
by the SHA-256 digest of the payload. The result includes the chosen revision
and digest so clients can persist an audit decision and repeat retries without
depending on request arrival order. The resolver does not overwrite storage;
callers remain responsible for authorization and applying the selected edit.

## Concurrent registry metadata edits (Issue #478)

`RegistryContract::set_metadata` is last-writer-wins: when two writers (for
example two release pipelines holding the admin key) read an entry and both
write, the later write silently replaces the earlier one.
`RegistryContract::set_metadata_if_match` adds a precondition so the slower
writer is told instead of overwriting.

```text
set_metadata_if_match(caller, name, expected_hash, uri, hash, immutable, schema_version)
```

`expected_hash` is the `hash` the writer last read (`get_metadata_hash`), or
`None` when it expects `name` to have no entry yet.

| Situation | Result |
|---|---|
| `caller` is not the admin | `Unauthorized`, checked before the stored entry is compared |
| Stored entry already equals the requested one | `Ok(())`, nothing is written (safe retry) |
| Stored hash equals `expected_hash`, or no entry and `None` | The edit goes through the same validation as `set_metadata` and is written |
| Anything else (someone else wrote first, entry created meanwhile, expected entry missing) | `StaleData` (error 28), nothing is written |
| Entry is immutable and the hash matches | `ImmutableEntry`, as with `set_metadata` |

### Normal, failure, retry, and authorization paths

- **Normal.** Read `get_metadata_hash`, then call `set_metadata_if_match` with
  that hash. To create an entry, pass `None`.
- **Failure.** Of two writers that read the same hash, the first one wins and
  the second gets `StaleData`. The stored entry is the winner's, unchanged.
- **Retry.** If a response is lost, resend the same call. When the edit already
  landed, the stored entry equals the request and the call returns `Ok(())`
  without rewriting it (`updated_at` keeps the first write's time).
- **Authorization.** A non-admin gets `Unauthorized` whether its expected hash
  is right or wrong, so the error does not reveal anything about the entry.

### Recovery

On `StaleData`, call `get_metadata` again, merge your change into the entry
that is now stored, and call `set_metadata_if_match` with the new hash. A
rejected call writes nothing, so there is nothing to roll back.

### Edge cases

- Two writers sending the identical entry both succeed: the second one is
  treated as a retry.
- The precondition compares the stored `hash` field only. Two edits that keep
  the same `hash` but change `uri` cannot be told apart by `expected_hash`;
  give every content change a new hash.

### Compatibility

The entry point is additive. `set_metadata` keeps its signature and
last-writer-wins behaviour, and the stored `MetadataEntry` layout is
unchanged, so existing callers and entries need no migration. Writers that
need conflict detection switch to `set_metadata_if_match`.
