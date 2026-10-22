# Hardening tests: canonical payloads, redaction, invariants, load

This note covers the behaviour, edge cases, and recovery paths for the tests
added for issues #350, #351, #352, and #353.

## Strict canonical payloads (#351)

Module: `shared/src/canonical.rs`. Tests: `shared/src/test_canonical.rs`.

- `normalize_text` stays lenient for producers: it trims, lower-cases, and
  collapses whitespace.
- `normalize_text_strict`, `canonical_bytes_strict`, and
  `verify_canonical_fingerprint` are for verifiers. They reject any text that
  would need rewriting, so one signed payload has exactly one accepted byte form.
- Edge cases rejected with `InvalidArgument`: empty text, upper-case letters,
  leading, trailing, or doubled spaces, tabs or newlines, control or non-ASCII
  bytes, text longer than `MAX_FIELD_LEN`, and more than
  `MAX_CANONICAL_PARTS` (32) parts.
- A fingerprint mismatch on canonical input returns `Unauthorized`.
- Recovery: a rejected attempt keeps no state. The producer re-sends the
  canonical form and verification succeeds.

## Redaction for wallet, secret, and transaction data (#352)

Module: `shared/src/sanitize.rs`. Tests: `shared/src/test_redaction.rs`.

- Label keys are matched as case-insensitive substrings. This catches compound
  names such as `wallet_address`, `tx_signature`, or `wallet_secret`. Before this
  change only exact names matched, so those keys leaked.
- `auth` is exact-match only, so `author` is not over-redacted.
- `wallet`, `transaction`, and transaction-hash keys count as high-cardinality
  (dropped by `sanitize_telemetry_label`) and as sensitive (their value becomes
  `[REDACTED]` when passed to `redact_telemetry_value`).
- `ip` is matched exactly, so unrelated words such as `ship` are not dropped.
- Values that contain control characters, or exceed `MAX_TELEMETRY_LABEL_LEN`,
  are rejected.
- Export: only allow-listed fields survive `redact_fields`. Forbidden fields are
  purged on every pass, whichever caller asks.
- `RedactedSecret` prints only the first four and last two characters. Anything
  of eight characters or fewer prints as `***`.

## Property tests for financial and ownership invariants (#350)

Module under test: `shared/src/payments.rs` (fee split) and `shared/src/auth.rs`
(ownership transfer). Tests: `shared/src/test_invariant_properties.rs`.

- Randomised inputs come from a fixed-seed xorshift generator, so any failure
  reproduces from the seed in the assertion message. No new dependency is added.
- Fee split: `fee + net == amount` for every sampled input, with `0 <= fee <=
  amount`, monotonic in the rate, and pure on retry.
- Validation order: amount is checked before rate, and rate before overflow.
  Overflow is reported as `PaymentFeeOverflow`, never wrapped.
- Ownership: a random walk of propose, accept, cancel, and time advances. After
  every step the admin is a known actor, holds the `Admin` role, and is the only
  holder. A pending transfer always changes the owner.
- Operational edge cases: a second proposal is blocked until the first expires;
  acceptance at the exact expiry timestamp succeeds; an expired transfer is
  refused and cleared; a retried accept after success fails with
  `NoPendingTransfer` and does not re-apply.

## Load tests for high-cardinality workflows (#353)

Module under test: `shared/src/sanitize.rs`, `shared/src/telemetry.rs`, and
`shared/src/pagination.rs`. Tests: `shared/src/test_load_high_cardinality.rs`.

- Volumes are fixed: 1,000 keys, 1,000 values, 4,096 telemetry events, and 10,000
  paginated ids. The test budget is lifted so the logic is exercised, not the
  default instruction limit. Raise the constants locally for soak runs.
- Telemetry sampling: exactly one event survives per `SAMPLE_DENOMINATOR`
  correlation ids.
- Pagination: every id is visited once, in ascending order, and the page count
  matches `ceil(total / MAX_PAGE_LIMIT)`. A cursor past the last id returns an
  empty page with no cursor.

### Known gaps

- `MAX_LABEL_CARDINALITY` in `telemetry.rs` is defined but not enforced. Only
  key classification bounds cardinality today. A bounded key with many distinct
  values is admitted. Enforcing a per-operation distinct-value budget needs
  storage and is not part of these tests.
- The telemetry and sanitize helpers use different `should_sample` functions:
  `sanitize::should_sample(entropy, rate)` and `telemetry::should_sample(id)`
  with a fixed denominator. Callers must not mix them up.
