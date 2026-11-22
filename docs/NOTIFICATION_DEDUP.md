# Notification Deduplication and Delivery Receipts (Issue #447)

Module: `shared/src/notification_dedup.rs`

Notifications are keyed by `(recipient, notification_id, channel)`. Each one has a `DeliveryReceipt` with a status, the attempt count, the dispatcher, and the dispatch and delivery ledgers.

## States

```
(none) --record_dispatch--> Dispatched --confirm_delivery--> Delivered
                               |
                          mark_failed
                               v
                             Failed --record_dispatch (attempts < 3)--> Dispatched
```

## Paths

| Path | Behaviour |
|---|---|
| Normal | the first `record_dispatch` returns `duplicate = false`; the recipient signs `confirm_delivery` |
| Dedup | `record_dispatch` while `Dispatched` or `Delivered` returns the stored receipt with `duplicate = true`; callers must not resend |
| Failure | `mark_failed` moves a `Dispatched` receipt to `Failed`; confirming a failed receipt is `InvalidTransition` |
| Retry | a `Failed` receipt can be dispatched again until `MAX_DELIVERY_ATTEMPTS` (3); after that the result is `RetryLimitExceeded` |
| Authorization | the dispatcher signs dispatch and failure, and only the dispatcher that made the attempt can fail it (`DispatcherMismatch`); only the recipient can confirm delivery |

## Edge cases

- Confirming delivery twice returns the same receipt and is not an error.
- The same `notification_id` on a different channel is a separate notification.
- Receipts live for `RECEIPT_TTL_LEDGERS` (about 7 days). After expiry, the same key is treated as a new notification. Use fresh ids for anything that must never repeat.

## Recovery

A notification stuck in `Dispatched` (dispatcher crashed) can be failed by its dispatcher and then retried. Once the retry limit is hit, issue a new `notification_id`.

## Compatibility

This is a new module with new storage keys. No existing contract changes.
