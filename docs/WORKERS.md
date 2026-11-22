# Background workers

`shared::jobs` is Trellis' background worker framework for **delayed and
retryable** work. Soroban contracts cannot spawn threads, so "background" here
means *ledger-driven*: work is stored on-chain as a job and advanced one job per
invocation by anyone willing to pay the fee.

- Framework: `shared/src/jobs.rs`
- Tests: `shared/src/test_jobs.rs` (`cargo test -p shared test_jobs`)
- Local runner: `scripts/run-worker.sh`

## Why a job queue inside the contract

A caller who needs something to happen *later* (refund an escrow after its
expiry, retry a settlement, run periodic maintenance) otherwise has two bad
options: poll the contract and pay for failed attempts, or keep the schedule
off-chain and hope the operator's database is the source of truth. Both put the
retry budget and the failure history somewhere the contract cannot see.

A job record moves that state on-chain:

| Concern | Without the framework | With the framework |
| --- | --- | --- |
| When to attempt | Caller decides, every time | `due_ledger` + `next_attempt_ledger` |
| Retry budget | Caller's `while` loop | `RetryPolicy` stored in the job |
| Backoff | Caller's `sleep` | `base * 2^(attempt-1)`, capped |
| Give-up | Silent | `DeadLettered` + error code + ledger |
| Duplicate work | Caller's discipline | `dedupe_key` → job id → `JobReceipt` |
| Audit trail | Operator logs | Contract events + job record |

## Lifecycle

```
                   enqueue_job                 run_due_job (handler Ok)
  (caller)  ───────────────────▶  Pending  ─────────────────────────▶  Succeeded
                                     │                                     │
                                     │ handler Err, attempts < max         │ JobReceipt written
                                     ▼                                     ▼
                                  Pending                            re-enqueue / reprocess
                                  (next_attempt_ledger =             → AlreadyCompleted
                                     now + backoff)
                                     │
                                     │ handler Err, attempts == max
                                     ▼
                               DeadLettered ──▶ requeue_dead_letter / discard_dead_letter
```

Job statuses are `Pending`, `DeadLettered` and `Succeeded`. There is no
`Failed` status: a failure either reschedules the job (`Pending`, with
`next_attempt_ledger` in the future) or, once the attempt budget is spent,
dead-letters it.

## Retry policy

`RetryPolicy` is captured **at enqueue time** and stored in the job, so changing
the contract's configuration never changes the retry behaviour of work that is
already queued.

```rust
RetryPolicy {
    max_attempts: 5,             // total attempts, first one included
    base_backoff_ledgers: 60,    // 5 minutes at 5 s/ledger
    max_backoff_ledgers: 17_280, // ~1 day
}
```

Backoff after attempt `n` is `base * 2^(n-1)`, saturating and capped at
`max_backoff_ledgers`: 60, 120, 240, 480, … Use `RetryPolicy::maintenance()` for
the default above or `RetryPolicy::no_retry()` for work that must not be
repeated (a single attempt, immediately dead-lettered on failure).

## Idempotency

Every job carries a 32-byte `dedupe_key`. Derive it deterministically from the
identity of the work, never from a counter or a timestamp:

```rust
use shared::jobs::{dedupe_key_pair, dedupe_key_u64};

// "this escrow" — one refund job per escrow, forever
let key = dedupe_key_u64(&env, shared::jobs::ESCROW_REFUND_TAG, escrow_id);

// "this (epoch, recipient) settlement"
let key = dedupe_key_pair(&env, SETTLEMENT_TAG, epoch, recipient_index);
```

The key is what makes replays safe:

1. While the job is queued, `WorkerKey::Dedupe(key)` maps to its id, so a second
   `enqueue_job` returns `AlreadyPending(id)` and no duplicate is created.
2. Once the job succeeds, `WorkerKey::Receipt(key)` holds a `JobReceipt`, so
   `enqueue_job` returns `AlreadyCompleted(id)` and `reprocess_job` returns the
   receipt **without invoking the handler again**.

Handlers must still be *effectively* idempotent — the framework suppresses
replays it can see, but a handler that half-applies its work before returning
`Err` will be called again on the next attempt. Prefer
"read → check state → write" over blind mutation.

## Exposing the worker from a contract

The framework is library code; a contract opts in by forwarding a few entry
points. Keep `run_due_job` permissionless (the calling address is recorded on
the job) and the management functions admin-only.

```rust
use shared::jobs::{self, JobHandler, JobError, JobStats, Job, RunOutcome};
use shared::payments::EscrowRefundHandler;

#[contractimpl]
impl MyContract {
    /// Crank: attempts the earliest due job. Safe for anyone to call.
    pub fn run_due_job(env: Env, worker: Address) -> Result<RunOutcome, JobError> {
        let now = env.ledger().sequence();
        jobs::run_due_job(&env, &worker, now, &EscrowRefundHandler)
    }

    /// Run one specific job (dead-letter replay, or an on-demand job).
    pub fn run_job(env: Env, worker: Address, job_id: u64) -> Result<RunOutcome, JobError> {
        let now = env.ledger().sequence();
        jobs::reprocess_job(&env, &worker, job_id, now, &EscrowRefundHandler)
    }

    /// Inspect one job.
    pub fn job(env: Env, job_id: u64) -> Option<Job> {
        jobs::get_job(&env, job_id)
    }

    /// Inspect the queue.
    pub fn worker_stats(env: Env) -> JobStats {
        jobs::job_stats(&env)
    }
}
```

Dispatch to different handlers by matching on `job.payload` before delegating,
or implement one `JobHandler` that matches all variants you enqueue.

### Scheduling an escrow refund

`shared::payments` ships the handler for the escrow lifecycle, where the refund
is only legal after `expiry_ledger`:

```rust
use shared::payments::{create_escrow_with_refund_job, EscrowRefundHandler};

// Deposit and schedule the delayed refund in one call.
let (escrow_id, outcome) =
    create_escrow_with_refund_job(&env, &token, &depositor, &beneficiary, amount, expiry)?;

// Or schedule a refund for an escrow that already exists.
schedule_escrow_refund(&env, &token, escrow_id, expiry)?;
```

The worker then attempts `refund_escrow` at `expiry_ledger`, retries with
backoff while the escrow is still early (`Error::PaymentEscrowNotExpired`), and
dead-letters the job with the error code if a refund is genuinely impossible
(for example because the escrow was already released).

## Operating the queue

| Function | Auth | Purpose |
| --- | --- | --- |
| `enqueue_job` / `enqueue_escrow_refund` | caller | add work (idempotent) |
| `run_due_job` | anyone | attempt the earliest due job |
| `reprocess_job` | anyone | attempt one job by id |
| `get_job`, `get_receipt`, `pending_job_ids`, `dead_letter_job_ids`, `next_due_ledger`, `job_stats` | anyone | inspect |
| `configure_worker`, `pause_worker`, `resume_worker` | admin | enable/disable and set the default policy |
| `requeue_dead_letter` | admin | reset the attempt budget and re-queue |
| `discard_dead_letter` | admin | drop from the dead-letter index (record kept) |

### Events

Every transition publishes `("job", <event>, job_id)` with the full `Job` as
data, so an indexer can reconstruct queue history without reading storage:

| Event symbol | Meaning |
| --- | --- |
| `enqueued` | job created (`JOB_ENQUEUED`) |
| `retried` | attempt failed, job rescheduled (`JOB_RETRIED`) |
| `succeeded` | handler returned `Ok` (`JOB_SUCCEEDED`) |
| `deadltr` | attempt budget exhausted (`JOB_DEAD_LETTERED`) |
| `requeued` | admin reset a dead letter (`JOB_REQUEUED`) |

The `Job` payload in a dead-letter event is the debugging context: `attempts`,
`last_error` (contract error code), `last_attempt_ledger`, `worker`,
`dedupe_key` and `enqueued_ledger` (the correlation id back to the request that
created the job).

### Cost and scaling notes

- `run_due_job` attempts **one** job per invocation, so fees stay predictable
  and a single unbounded loop can never abort the transaction.
- Finding the earliest due job scans the pending index, so each crank call costs
  `O(pending)` reads. Pending is bounded by the work actually queued; an ordered
  index is the obvious next optimisation if a deployment sustains thousands of
  queued jobs.
- `run_due_job` is permissionless by design: run several keepers for liveness,
  and rely on the dedupe keys and receipts for safety rather than on a single
  operator.

## Cancelling a job

`cancel_job(env, admin, job_id, reason)` stops a `Pending` or `DeadLettered`
job for good (Issue #444). It is admin-only and does all of its cleanup in one
call:

- the job leaves the pending and dead-letter indexes, so it stops counting
  against queue capacity and `run_due_job` never picks it again;
- the dedupe key is released, so the same logical work can be enqueued again
  later as a new job;
- the job record is kept with status `Cancelled`, and a `CancellationRecord`
  (previous status, attempts so far, reason code, admin, ledger) is written
  beside it. Read it with `get_cancellation(env, job_id)`;
- a `("job", "cancelled", job_id)` event is published.

Edge cases:

| Situation | Result |
|---|---|
| Job is in backoff between attempts | Cancelled; the next attempt never happens |
| Job already succeeded | `JobError::AlreadyCompleted`, nothing changes |
| Job already cancelled | `Ok(job)`; the first `CancellationRecord` is kept, so a retried cancel is safe |
| Unknown id | `JobError::NotFound` |
| Caller is not the admin | `JobError::Unauthorized`, nothing changes |
| `run_due_job` / `reprocess_job` on a cancelled id | The scheduler skips it; `reprocess_job` returns `JobError::Cancelled` |
| `requeue_dead_letter` on a cancelled id | `JobError::NotRetryable` |

A handler is never interrupted mid-attempt. Soroban executes one invocation at
a time, so a cancellation always lands between attempts. Handlers must still be
idempotent: if an attempt failed after partly changing state, the job is not
retried once it is cancelled, so the domain contract has to compensate if
needed.

**Recovery and rollback.** Cancellation is final for that job id. To undo one,
enqueue the work again with the same dedupe key. The new job gets a fresh id
and a fresh attempt budget, and the cancelled record stays for audit.

**Compatibility.** `JobStatus::Cancelled`, `JobError::Cancelled` and
`WorkerKey::Cancellation` are appended variants, and the cancellation data
lives under its own key instead of on `Job`. Jobs stored before this change
decode unchanged, so no migration is needed.

## Local development

### 1. Build and test the framework

```bash
cargo test -p shared test_jobs
```

### 2. Run a local network

```bash
stellar network container start local
stellar keys generate --network local worker
```

### 3. Deploy a contract that forwards to the worker

Build and deploy any contract exposing `run_due_job` / `job` as shown above,
then export its id:

```bash
export WORKER_CONTRACT_ID=<contract-id>
```

### 4. Crank the queue

```bash
# One job
stellar contract invoke --id "$WORKER_CONTRACT_ID" --source worker --network local \
  -- run_due_job --worker "$(stellar keys address worker)"

# Or leave the runner script looping
WORKER_CONTRACT_ID="$WORKER_CONTRACT_ID" WORKER_SOURCE=worker \
  STELLAR_NETWORK=local ./scripts/run-worker.sh
```

`scripts/run-worker.sh` invokes `run_due_job` on an interval, logs each
outcome, and stops on `Ctrl-C`. It is a convenience wrapper around the same
permissionless entry point any keeper would call — it holds no privileged key.

### 5. Inspect

```bash
stellar contract invoke --id "$WORKER_CONTRACT_ID" --source worker --network local \
  -- job --job_id 1
stellar contract invoke --id "$WORKER_CONTRACT_ID" --source worker --network local \
  -- worker_stats
```

To watch a retry sequence, enqueue a job whose handler will fail (for example a
refund for an escrow that is not yet expired), then run the crank once per
ledger and read `attempts`, `next_attempt_ledger` and `last_error` from `job`
between attempts.

## Deployment notes

- **No migration required.** The framework is additive: new contract entry
  points plus new `WorkerKey::*` storage entries. Existing contracts that do not
  call it are unaffected.
- **Configuration.** The worker defaults to enabled with
  `RetryPolicy::maintenance()`. Call `configure_worker` from the admin account
  to change the policy, and `pause_worker` before an upgrade or maintenance
  window — a paused worker rejects both new work and cranks, while already
  queued jobs stay intact.
- **Storage TTL.** Jobs, receipts and index entries live in persistent storage
  and are bumped on every read/write, so a job that waits weeks for its due
  ledger keeps itself alive. Dead-lettered jobs remain inspectable until an
  admin discards them.
- **Who pays.** The crank pays for the execution; the retry budget belongs to
  the job, so a failed attempt never silently becomes someone else's infinite
  loop.
