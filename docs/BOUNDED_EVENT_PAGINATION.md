# Bounded Event Pagination for High-Volume Histories (Issue #323)

Module: `shared/src/event_pagination.rs`

## Bounds

| Bound | Constant | Effect |
|-------|----------|--------|
| Events kept per stream | `retention` (1..=`MAX_RETENTION` = 5 000) | An append past the limit prunes exactly one oldest entry, so each append costs O(1). |
| Page size | `MAX_PAGE_SIZE` = 50 (default 20) | Each page reads at most 50 storage entries. |
| Compaction per call | `MAX_COMPACT_PER_CALL` = 100 | Physical cleanup after a reset is spread over several calls. |

## Cursor model

`EventCursor { stream, epoch, next_seq }`. Sequence numbers increase forever and
are never reused, including across resets. A cursor either points at the same
event every time or fails with an explicit error:

| Situation | Error | Recovery |
|-----------|-------|----------|
| Events behind the cursor were pruned | `CursorExpired` | `recover_cursor`, then resync |
| Stream was reset after the cursor was issued | `CursorEpochMismatch` | `recover_cursor`, then resync |
| Cursor is past the head (forged or corrupt) | `CursorAhead` | restart from `first_cursor` |
| Cursor belongs to another stream | `CursorStreamMismatch` | use the correct stream |

`recover_cursor` returns a cursor at the oldest retained event of the current
epoch. Events between the stale cursor and the recovered one are gone, so
indexers must rebuild derived state from an authoritative snapshot (see
`docs/STATE_SNAPSHOT_EXPORT.md`). They must not assume the history is
continuous.

## Normal, retry and authorization paths

- **Normal**: start with `fetch_page(stream, None, limit)` and pass back
  `next_cursor` until `has_more == false`.
- **Retry**: `fetch_page` is read-only. Fetching the same cursor again returns
  the same page. When `has_more == false`, `next_cursor` points at the head, so
  clients can keep polling with it to pick up new events.
  An identical `init_stream` retry is also a no-op.
- **Authorization**: `init_stream`, `set_writer`, `reset_stream` and `compact`
  are admin-only. `append_event` requires the writer to be registered with
  `set_writer` and to pass `require_auth`. Revoking a writer takes effect on the
  next append. Reads are public.

## Operational edge cases

- **Reset** bumps the epoch and moves `oldest` to `head` in O(1). Physical
  entries stay in storage until `compact` runs. Repeat `compact` until it
  returns `0`. Running it again after that is safe.
- **Lowering retention** is not supported in place. Create a new stream with
  the smaller retention, point writers at it, and let the old stream drain.
- **Archived entries**: if a persistent entry is archived by TTL before it is
  pruned, `fetch_page` skips it. The page then has fewer events than
  `next_seq` advanced by. Clients can spot this as a gap in `seq`.
- **Pruning emits** an `evp_prn` event and **reset emits** an `evp_rst` event,
  so off-chain indexers can see when their cursors are about to expire.

## Migration plan

This change only adds a new module and touches no existing storage.
`shared::pagination` (keyset pagination over records) stays as it is.
Contracts that want a bounded audit history create one stream per history type
and register their own address as the writer. No data needs to be backfilled.
