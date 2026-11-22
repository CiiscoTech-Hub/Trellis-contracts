# Incident runbook: executable recovery checks

This runbook covers incidents that put **donor funds held in aid escrow** at
risk. Every step below has an executable check in
[`ops-checks/src/incident_runbook.rs`](../ops-checks/src/incident_runbook.rs). The
checks run against a local, in-process deployment of the real `aid-contract`
and a real Stellar Asset Contract token, so the documented procedure is tested
on every `cargo test` (Issue #452).

For general triage (first five minutes, communication, deployment smoke test)
see [`RUNBOOK.md`](RUNBOOK.md). For the monitor that usually detects these
incidents see [`SYNTHETIC_JOURNEY_MONITOR.md`](SYNTHETIC_JOURNEY_MONITOR.md).

## Run the checks

```sh
cargo run -p ops-checks --bin incident-runbook-checks                 # every incident
INCIDENT_RUNBOOK_SCENARIO=emergency_pause cargo run -p ops-checks --bin incident-runbook-checks
INCIDENT_RUNBOOK_FAULT=skip_recovery cargo run -p ops-checks --bin incident-runbook-checks   # rehearse a failed recovery; exits 1
cargo test -p ops-checks incident_runbook                             # unit tests
./scripts/incident-drill.sh                                        # full local drill
```

The binary prints one JSON object:

```json
{"status":"fail","incidents":[{"incident":"emergency_pause","recovered":false,"checks":[
  {"id":"resumed_by_pauser","phase":"recover","status":"skipped","mandatory":true,"attempts":1,
   "detail":"recovery step not performed","remediation":"Call set_paused(pauser, false) once the root cause is fixed, then rerun verify."}, ...]}]}
```

Exit codes: `0` every incident recovered, `1` a mandatory check did not pass,
`2` invalid `INCIDENT_RUNBOOK_*` value. Checks that did not pass include
`detail` and `remediation`.

## How a run is judged

Each incident runs three phases: **contain** (confirm the blast radius is
bounded), **recover** (perform the recovery action) and **verify** (prove
the deployment is healthy again). Every check becomes a
`shared::operator_runbook::RunbookCheck`, and the incident counts as recovered
only when `evaluate_runbook` reports `all_passed`.

`evaluate_runbook` **fails closed**. A mandatory check that is `Skipped` or
still `InProgress` fails the runbook just like a `Failed` one. A recovery step
that nobody performed has verified nothing.

## Incident 1: `emergency_pause`

**Trigger.** Something is wrong with claims (suspected exploit, bad release,
accounting alert from the journey monitor) and the aid contract is paused.

| Phase | Check | Proves |
|---|---|---|
| contain | `pause_applied` | The pauser key holds `Role::Pauser` and can pause. |
| contain | `claims_blocked_while_paused` | `claim_aid` returns `Paused` and escrow does not move. |
| contain | `unauthorized_resume_refused` | A non-pauser's `set_paused(false)` is refused, and the contract stays paused. |
| recover | `resumed_by_pauser` | The pauser resumes after the root cause is fixed. |
| verify | `storage_schema_valid` | `validate_storage_schema` accepts the stored version. |
| verify | `escrow_conserved` | Contract token balance equals the sum of every `Pending` aid. |
| verify | `blocked_claim_completes` | The claim blocked by the pause now pays the recipient exactly once. |
| verify | `post_recovery_journey` | The `donate_claim` journey monitor passes on the recovered deployment. |

**Recovery.** Fix the root cause, then `set_paused(pauser, false)`, then
rerun verify.

**Rollback.** If any verify check fails after resuming, pause again
(`set_paused(pauser, true)`). Funds stay in escrow while paused (the
`escrow_conserved` check passes in that state), so pausing is always the safe
fallback. If the pause itself is not effective (`claims_blocked_while_paused`
fails), stop and escalate. Emergency upgrade follows
[`RUNBOOK.md` §5](RUNBOOK.md#5-emergency-rollback).

## Incident 2: `expired_escrow`

**Trigger.** An aid passed `expiry_ledger` without being claimed. The
recipient can no longer claim, and the funds sit in the contract until
someone refunds them. The journey monitor reports this as `dependency:
"contract"`, `error: Expired`, `funds_escrowed: true`, `severity: "page"`.

| Phase | Check | Proves |
|---|---|---|
| contain | `claim_refused_after_expiry` | The recipient's claim returns `Expired`. |
| contain | `stranger_refund_refused` | Only the donor or admin can refund (`Unauthorized` otherwise). |
| recover | `refund_to_donor` | `refund_aid(aid_id, donor)` (or `admin`) succeeds. |
| verify | `storage_schema_valid` | As above. |
| verify | `escrow_conserved` | As above. |
| verify | `refund_retry_idempotent` | A second refund returns `AlreadyRefunded` and pays nothing. |
| verify | `donor_made_whole` | The donor's balance is back to its pre-donation value. |
| verify | `post_recovery_journey` | The `donate_refund` journey monitor passes. |

**Recovery.** Refund as the donor. If the donor is unreachable, the admin
may call `refund_aid(aid_id, admin)`, and the funds still go to the donor.
The recover step treats an already-landed refund as success, so it is safe
to run after the admin acted.

**Rollback.** None needed: a refund only moves funds back to their original
owner, and a repeated refund is refused.

## Retry behaviour

Every phase can be run again (`IncidentDrill::recover`, `IncidentDrill::verify`).
A rerun replaces that phase's outcomes and increments `attempts`, so the
report shows that a check needed a retry. The retry path for a failed
recovery is:

1. read `detail` and `remediation` for each check that did not pass;
2. fix the cause (e.g. actually resume the contract);
3. rerun `recover`, then `verify`.

Reruns are idempotent. Rerunning a completed recovery never pays the
incident's aid twice: `claim_aid` returns `AlreadyClaimed` and `refund_aid`
returns `AlreadyRefunded`, and the checks confirm the final state from
`get_aid` instead of resubmitting.

## Edge cases

- **Failed post-recovery journey leaves an aid pending.** If verify runs while
  still paused, the journey escrows a new aid that cannot be claimed.
  `escrow_conserved` sums every pending aid, so it still passes, and that aid
  stays claimable after the real resume.
- **Admin refunded before the runbook ran.** `refund_to_donor` accepts
  `AlreadyRefunded` when `get_aid` shows `Refunded`.
- **Pauser role revoked during the incident.** `pause_applied` fails with
  remediation "pause with the admin". Grant the role again via `set_pauser`.
- **Fixture cannot escrow.** The binary reports `recovered:false` with an
  error for that incident instead of skipping it.

## Scope and safety

These checks are **local and read-only with respect to any network**. They
prove that the documented procedure works against the current contract code;
they do not inspect a live deployment. During a live incident, run the same
steps with the Soroban CLI (see [`RUNBOOK.md` §3.1 and §3.6](RUNBOOK.md)),
using this runbook's check list as the verification checklist, then run
`./scripts/verify-deployment.sh <network>` for read-only deployment checks.

## Compatibility

No contract interface, storage layout or event changed. The only behaviour
change is in `shared::operator_runbook::evaluate_runbook`, which no contract
calls. It used to report `all_passed` when a mandatory check was `Skipped` or
`InProgress`, and it now fails closed. Off-chain callers that relied on the
old fail-open result must mark mandatory checks `Passed` explicitly.
