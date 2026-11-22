# Workflow Correlation IDs (Issue #330)

A workflow such as "fund aid, claim, then settle" spans several contracts, and
each contract emits its own events. A **workflow correlation ID** is a shared
identifier that every step of the workflow carries, so an indexer can join those
events back into one workflow.

The policy lives in [`shared::workflow_correlation`](../shared/src/workflow_correlation.rs).
It is pure: it reads no storage and checks no caller.

## Policy

| Rule | Value |
|---|---|
| Non-empty | required |
| Maximum length | `MAX_WORKFLOW_ID_LEN` = 64 bytes |
| Allowed bytes | ASCII letters, digits, `-`, `_` |
| Error on violation | `shared::Error::InvalidArgument` |

Two functions enforce it:

- `validate_workflow_id(&Bytes)` checks one ID.
- `check_workflow_chain(&Vec<Bytes>)` checks that every step carries the same
  valid ID and returns it. An empty chain fails.

## Normal, retry, and failure paths

| Scenario | Result |
|---|---|
| Every step of a workflow uses one ID | Accepted; the ID is returned |
| A step is retried and reuses the ID | Accepted (retries are idempotent for correlation) |
| Two different IDs appear in one chain | Rejected with `InvalidArgument` |
| One step's ID is malformed, even if the others match | Rejected |
| Empty chain | Rejected |

## Operational edge cases

- **Mixed IDs across a retry.** A client that generates a fresh ID on retry
  splits one workflow into two. The chain check then rejects it. Generate the ID
  once when the workflow starts and reuse it for every retry.
- **Length boundary.** A 64-byte ID is accepted; a 65-byte ID is rejected. Keep
  IDs short, for example a UUID without dashes (32 hex characters) plus a
  prefix.
- **Spaces and separators.** `.`, `:`, `/`, and spaces are rejected. Use `-` or
  `_` as separators.

## Authorization

The policy does not authorize callers. A contract that accepts a correlation ID
must still check the caller before it emits events under that ID. Correlation
IDs are labels, not credentials: anyone who knows an ID can reuse it, so never
treat one as proof that a workflow was authorized.

## Recovery

A rejected chain changes no state, because the check runs before any write. To
recover, find the step whose ID differs from the rest of the chain, correct it
to the workflow's original ID, and retry that step. No rollback is required.

## Compatibility

This is an additive shared helper. The aid contract's per-record correlation
ID follows its own, looser rule, described below.

## Aid contract request correlation (Issue #476)

`create_aid` accepts an optional `correlation_id: Option<Bytes>`. The contract
stores it with the aid and re-emits it on every later event for that aid, so
one ID joins the whole request from creation to settlement or refund.

| Step | Event (legacy topic) | Correlation ID in the data |
|---|---|---|
| `create_aid` | `aid_crt` | as supplied |
| `claim_aid` | `aid_clm`, `aid_stl` | loaded from storage |
| `refund_aid` | `aid_ref` | loaded from storage |

Claim and refund take no correlation argument, so a later caller cannot
relabel an aid's events.

### Policy

| Input | Result |
|---|---|
| `None` or empty bytes | Accepted; the aid has no correlation ID and events carry `None` |
| 1 to 64 bytes (`CORRELATION_ID_MAX_LEN`) | Accepted as-is; any byte values, so a UUID or a raw 32-byte request hash both fit |
| More than 64 bytes | Rejected with `AidError::InvalidCorrelationId` (code 108) |

### Normal, failure, retry, and authorization paths

- **Normal.** The ID given to `create_aid` appears on `aid_crt`, then on
  `aid_clm` and `aid_stl` when the recipient claims, or on `aid_ref` when the
  donor or admin refunds.
- **Failure.** An oversized ID fails the whole `create_aid` call before any
  write: no aid is stored, the aid counter does not move, and no funds leave
  the donor.
- **Retry.** A claim or refund that fails (paused contract, wrong caller, not
  yet expired) changes nothing, so the stored ID is still there and the retry
  emits it unchanged. Retrying `create_aid` itself is different: each call
  creates a new aid, and both carry the same ID. Before retrying a create
  whose outcome is unknown, look for an `aid_crt` event with that ID.
- **Authorization.** The ID is a label, not a credential. A stranger's claim
  or refund fails with `Unauthorized` and leaves the stored ID untouched.

### Edge cases

- `batch_create_aid` and `create_milestone_aid` take no correlation ID; their
  aids emit `None`.
- The structured `("aid", "created")` and `("logging", "action")` events
  still carry the all-zero 32-byte ID; use the legacy topics above to join a
  request.

### Recovery and rollback

A rejected `create_aid` leaves no state, so the client shortens the ID (a
UUID is 36 bytes, a hex SHA-256 is 64) and calls again. Nothing needs to be
rolled back.

### Migration

Callers that send IDs of 64 bytes or less see no change. Callers that sent
longer IDs now get error 108 and must shorten them. IDs already stored are
never re-checked, so existing aids keep emitting their original ID on claim
or refund.
