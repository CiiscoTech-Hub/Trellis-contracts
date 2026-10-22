# Batch Partial-Failure Reporting and Retry

`shared::batch_retry` (Issue #339) closes the one piece `shared::batch`
doesn't cover: once a non-atomic batch finishes with some failures, nothing
gives an addressable record of which transfers failed and why, and there is
no way to retry just the failed subset.

## The gap this closes

`shared::batch::execute_multi_transfer` already gives atomic/non-atomic
semantics, per-operation `OperationResult`s, and aggregate succeeded/failed
counts via `BatchResult`. What it does not give is: a persisted, addressable
list of *which* transfers failed (by recipient, amount, and error code), a
retryable/non-retryable classification, or a way to resubmit just the
retryable ones without the caller manually zipping the original transfer
list against `BatchResult.results` by index.

## Design in one paragraph

`record_batch_failures` zips a `BatchResult` back against the
`BatchTransfer`s that produced it and persists an addressable
`BatchFailureReport` — one `BatchFailureDetail` per failed transfer, with
its original index, recipient, amount, and a retryable classification
(reusing `shared::jobs::is_retryable_error`, corrected so a
`shared::batch::BatchError` code, 800-899, is always treated as permanent
rather than defaulting to retryable). `retry_batch_failures` re-submits only
the `retryable` entries — **always as a forced non-atomic batch**,
regardless of what mode the original run used, because an atomic
`execute_multi_transfer` stops at the first failure and can return fewer
results than inputs, which would otherwise make this module lose track of
untried entries. Only the report's original caller or an admin may trigger
a retry, and it authenticates before anything runs. Non-retryable entries
are never silently dropped — they stay in the report until a maintainer
calls `discard_batch_failure_report`.

## Public surface

| Item | Purpose |
|---|---|
| `record_batch_failures` | Build and persist an addressable failure report from a `BatchResult`. Returns `None` if there's nothing to record. |
| `retry_batch_failures` | Resubmit the retryable subset as a forced non-atomic batch; updates the report in place. |
| `discard_batch_failure_report` | Admin-gated cleanup for a report that is no longer actionable. |
| `get_batch_failure_report` | Inspection. |

## Who can do what

| Action | Required condition |
|---|---|
| Record a failure report | Anyone — bookkeeping after an already-authorized batch execution |
| Retry a batch's failures | The report's original `caller`, or `Role::Admin`; authenticated |
| Discard a report | `Role::Admin`, authenticated |
| Read a report | Anyone (read-only) |

## Operational edge cases

| Situation | Behavior |
|---|---|
| `record_batch_failures` on a result with `failed == 0` | Returns `None`; nothing is stored. |
| `record_batch_failures` after an `Atomic` result | Only validation-stage failures are ever present to record — an execution-stage failure in `Atomic` mode panics and aborts the transaction before `execute_multi_transfer` can return at all. |
| `retry_batch_failures` on an unknown `batch_id` | `Error::NotFound`. |
| `retry_batch_failures` on an already-`resolved` report | `Error::InvalidTransition`. |
| Caller is neither the report's original caller nor an admin | `Error::Unauthorized`, before anything is read further. |
| Every remaining failure is non-retryable | `Error::InvalidTransition` — nothing to retry; use `discard_batch_failure_report`. |
| A retried transfer fails again | Kept in the report with its new `error_code` and re-classified `retryable`; `resolved` stays `false`. |
| A retried transfer succeeds | Removed from the report; `succeeded` on the report increases. |
| `max_operations` too small for the retryable subset | `Error::InvalidArgument` (from `BatchError::BatchTooLarge`), report left untouched. |
| Non-admin calls `discard_batch_failure_report` | `Error::Unauthorized`. |

## Rollback and recovery

1. **Some failures are permanent** (non-retryable, e.g. a validation error
   that needs a corrected amount): `retry_batch_failures` will never
   resubmit them. Either fix the input and submit a fresh, unrelated batch,
   or call `discard_batch_failure_report` once the report is no longer
   actionable.
2. **A retry itself needs to be retried**: `retry_batch_failures` is safe to
   call again on the same `batch_id` — each call only acts on whatever is
   still outstanding in the report.
3. **A report was recorded against the wrong caller** (should not happen if
   `record_batch_failures` is always called with the same `caller` that
   authorized the original batch): an admin can still retry it, since admin
   access is always accepted alongside the original caller.

## Compatibility

Purely additive: new storage keys, no changes to `shared::batch` or
`shared::jobs`. A contract adopts this by calling `record_batch_failures`
after its own `execute_multi_transfer` call whenever `result.failed > 0`.
