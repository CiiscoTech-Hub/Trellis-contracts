# Synthetic journey monitor

The monitor runs the critical `fund -> oracle quote -> settle` path through the
deterministic sandbox adapters. It checks the expected fee and resulting payer
and payee balances, reports elapsed wall-clock latency, and identifies the
adapter that refused a call when the journey fails.

## Run it

From the repository root:

```sh
cargo run -p testing --bin synthetic-journey-monitor
```

The command prints one JSON object to stdout. Success includes `status`,
`journey`, `latency_ms`, `steps`, `settled_ledger` and `settlement_attempts`.
Failure includes `failed_step`, `dependency`, `detail`, `retryable`,
`settlement_pending` and `settlement_attempts`; it exits with status 1. The
monitor uses a fixed seed and synthetic asset, so the path and settlement values
are reproducible. Wall-clock latency naturally varies between runs.

The journey logic lives in `testing::synthetic_monitor` (Issue #291) and is unit
tested for the normal, failure, retry and authorization paths:

```sh
cargo test -p testing synthetic_monitor
```

### Retry behaviour

A settlement timeout is retried up to `SYNTHETIC_MONITOR_MAX_SETTLEMENT_ATTEMPTS`
times in total (default 3, clamped to 1–10). Retries go through
`Sandbox::retry_pending_settlement`, which resubmits only the settlement leg.
The monitor also asserts that exactly one token transfer happened, so a retry
that paid the recipient twice is reported as a `workflow_assertion` failure.
When the budget is exhausted, the result has `dependency: "rpc"`,
`settlement_pending: true`, `retryable: true`.

### Authorization

The monitor refuses to run (`dependency: "credentials"`) before touching any
adapter when:

- `SYNTHETIC_MONITOR_SECRET` holds any key material (`UnsafeSecret`), or
- `SYNTHETIC_MONITOR_RPC_URL` is not a loopback URL for the local sandbox (`ConfigInvalid`).

A mainnet sandbox configuration is rejected at initialisation (`dependency: "sandbox"`).

### Failure drills

Set `SYNTHETIC_MONITOR_FAULT` to rehearse alerting without editing code:
`oracle_unavailable`, `oracle_stale`, `underfunded_payer`, or `rpc_timeouts:<n>`
(the first `n` settlement submissions time out).

```sh
SYNTHETIC_MONITOR_FAULT=rpc_timeouts:2 cargo run -p testing --bin synthetic-journey-monitor   # recovers, settlement_attempts=3
SYNTHETIC_MONITOR_FAULT=rpc_timeouts:9 cargo run -p testing --bin synthetic-journey-monitor   # fails, retryable
```

`retryable` is `true` only for `oracle` and `rpc` failures. Token, credential,
sandbox and assertion failures need a fix, not a rerun. The output keeps every
field it had before and only adds new ones, so existing parsers keep working.

## High-value journeys against the real aid contract

`fund_quote_settle` checks the harness accounting through fakes. The journeys
that move donor funds are checked separately, against the **real
`aid-contract` code** and a real Stellar Asset Contract token, deployed
in-process (Issue #451):

| Journey | Steps checked |
| --- | --- |
| `donate_claim` | donor escrows aid; stranger's claim refused; recipient claims; recipient paid exactly once; escrow back to its starting balance |
| `donate_refund` | donor escrows aid; early refund refused (`NotExpiredYet`); aid expires; stranger's refund refused; recipient's claim refused (`Expired`); donor refunded; repeated refund refused (`AlreadyRefunded`); donor made whole |

```sh
cargo run -p ops-checks --bin high-value-journey-monitor
cargo test -p ops-checks high_value_journeys
```

Output is one JSON object, `{"status":"pass"|"fail","journeys":[...]}`, and
the command exits 1 if any journey fails. A failed journey reports
`failed_step`, `dependency`, `detail`, `severity`, `retryable`,
`funds_escrowed` and `attempts`.

**Severity.** `page` means funds are at risk or a security control failed:
an `authorization` probe was accepted, `accounting` balances drifted, or
funds are stuck in escrow and a rerun cannot help. `ticket` covers the rest
(underfunded synthetic donor, contract paused, refused configuration).

**Retry.** A claim refused with `Paused` is retried up to
`HV_MONITOR_MAX_CLAIM_ATTEMPTS` times (default 3, clamped to 1–10). If the
budget runs out the result is `retryable: true` with funds still escrowed.
A claim whose response was lost is retried, and an `AlreadyClaimed` reply is
reconciled from contract state (`reconciled: true`), never paid again.

**Authorization.** Each journey sends one probe as a stranger, which must be
refused with `Unauthorized`. The monitor also refuses to start when
`HV_MONITOR_SECRET` holds key material or `HV_MONITOR_RPC_URL` is not a
loopback URL. The host must end right after the loopback prefix, so
`http://localhost.evil.example` is refused.

**Drills.** `HV_MONITOR_FAULT` = `underfunded_donor`, `claim_paused:<n>`
(an operator resumes after `n` refused claims), `lost_claim_ack`,
`claim_after_expiry`, `auth_probe_bypass` (the probe is sent as the real
owner; the monitor must page with `dependency: "authorization"`).

| Dependency | Meaning | Recovery |
| --- | --- | --- |
| `credentials` | Monitor configuration refused | Remove key material; point at loopback only. |
| `token` | Donor escrow transfer failed | Fix fixture funding; no funds moved. |
| `contract` + `Paused` | Contract paused | Follow `emergency_pause` in [`INCIDENT_RUNBOOK.md`](INCIDENT_RUNBOOK.md). |
| `contract` + `Expired` | Funds stuck in escrow | Follow `expired_escrow` in [`INCIDENT_RUNBOOK.md`](INCIDENT_RUNBOOK.md). |
| `authorization` | A stranger was allowed to claim/refund | Pause the contract immediately; treat as a security incident. |
| `accounting` | Balances or status drifted | Pause; reconcile with [`RECONCILIATION_JOB.md`](RECONCILIATION_JOB.md). |

The `synthetic-journey-monitor` binary and its JSON fields are unchanged.

## Safety and scope

This is a local synthetic check, not a live testnet probe. It uses the existing
`testing::sandbox` implementation: token balances, oracle quotes, and RPC
submissions are all in-process fakes. No network endpoint, wallet secret, or
real funds are used. A passing result verifies the workflow harness and its
expected accounting, but does not prove that deployed contracts are reachable
or correctly wired. Use `scripts/verify-deployment.sh testnet` separately for
read-only checks against a deployment.

## Failures and recovery

| Reported dependency | Example failure | Recovery |
| --- | --- | --- |
| `token` | Payer funding or transfer failed | Check the amount and payer balance in the fixture; restore the expected sandbox funding before retrying. |
| `oracle` | Quote is missing, invalid, or stale | Restore a positive, fresh fixture quote, then rerun the monitor. |
| `rpc` | Synthetic settlement submission failed | Retry the pending settlement path; do not repeat the token transfer, which has already succeeded. |
| `workflow_assertion` | Fee, balances, quote, or credential-free expectation differs | Treat as a behavior regression. Inspect the workflow and fee calculation before changing the expected values. |
| `sandbox` / `workflow` | Setup or an unclassified step failed | Inspect `detail`, correct the harness/configuration issue, and rerun. |

The monitor is read-only with respect to deployed networks. Recovery means
repairing the local fixture or code and rerunning it; it does not attempt to
mutate or roll back an on-chain deployment. For a deployed incident, follow
[`RUNBOOK.md`](RUNBOOK.md), preserve transaction and ledger evidence, and use
the established pause/rollback procedures for the affected contract.
