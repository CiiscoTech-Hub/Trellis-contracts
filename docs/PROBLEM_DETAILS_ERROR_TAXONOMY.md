# Stable API Problem-Details Error Taxonomy

## Executive Summary
This document defines the RFC 7807 and RFC 9457 compliant error presentation taxonomy for Trellis Soroban contracts (`shared::problem_details_taxonomy`, Issue #497).

Contracts return stable numeric error codes across execution entry points. Off-chain API gateways, indexers, client SDKs, and operator dashboards require human- and machine-readable error details that are consistent, safe from information leakage, and actionable.

---

## Architectural Principles

1. **Stable Machine Codes**:
   - Every known contract error discriminant maps to a fixed, permanent machine symbol (e.g., `AUTH_UNAU`, `VAL_AMT`, `STATE_EXPRD`, `SYS_ERR`).
   - Codes are never renumbered or repurposed across releases.
2. **HTTP Transport Harmonization**:
   - Each error category aligns with standard HTTP status semantics:
     - `401 / 403`: Authorization & permission escalation failures.
     - `400 / 422`: Structural validation and arithmetic overflow failures.
     - `404`: Missing resources or state records.
     - `409`: State conflicts, expirations, and claim collisions.
     - `503`: Transient backpressure, contract pause, and dependency degradation.
     - `500`: Unmapped or unexpected internal invariant failures.
3. **Information Leakage Defense**:
   - All client-facing summaries (`title`) and remediation hints (`remediation`) are generic, static descriptors.
   - Internal stack traces, raw memory addresses, cryptographic secrets, and host panic strings are strictly prevented from reaching users.
4. **Retryability Semantics**:
   - Errors are categorized as either permanent (`is_retryable: false`) or transient (`is_retryable: true`).
   - Transient errors include explicit `retry_after_ms` backoff hints (e.g. 5,000ms for paused contracts, 3,000ms for degraded dependencies).

---

## Operational Execution Paths

### Normal Path
- Standard contract errors (e.g., `Unauthorized`, `InvalidAmount`, `NotFound`) map to distinct, structured `ProblemDetailsRecord` structs containing stable machine codes, appropriate HTTP status codes, and user-safe remediation guidance.

### Failure Path
- Unknown, out-of-range, or unanticipated error codes safely resolve to the fallback record:
  - Code: `SYS_ERR`
  - Category: `internal`
  - HTTP Status: `500`
  - Remediation: `ContactOp`
- Fails closed without panicking or triggering host traps.

### Retry Path
- Callers receiving transient errors (`is_retryable == true`) execute backoff and retry.
- Permanent errors (`is_retryable == false`) require payload correction or credential renewal before retrying.

### Authorization Path
- Administrative inspection (`inspect_problem_details`) allows maintainers and telemetry collectors to introspect error metadata.
- Unauthorized callers attempting administrative inspection are rejected with `Error::Unauthorized`.

---

## Migration & Compatibility
- Purely additive: existing contract error enums and Soroban event layouts are unchanged.
- Backward-compatible with all existing frontend clients and indexing pipelines.

---

## Automated Test Coverage (Issue #576)

A dedicated test module `shared/src/test_problem_details_taxonomy.rs` provides
comprehensive path coverage across all four required dimensions.

### Normal path
- Every primary error code (authorization, validation, not-found, conflict, settlement,
  configuration, internal) in every contract domain maps to its correct stable machine
  code, HTTP status class, category, and retryability flag.
- `problem_details_from_error` agrees with `resolve_problem_details` for all core
  `Error` variants.
- `stable_code` agrees with `describe_error` for all documented domain/code pairs.
- `problem_details_for_error` and `problem_details_for_diagnostic_error` produce
  non-empty, non-leaking `code`, `kind`, `message`, `remediation`, and `docs_url` fields.
- `PROBLEM_TYPE_BASE_URI` is pinned as `urn:trellis:error:` and must not drift.

### Failure path
- Unknown codes (0, `u32::MAX`, 999 999) return a safe `SYS_ERR` / `UNEXPECTED_ERROR`
  record with HTTP 500 and `is_retryable = false`.
- `is_documented` returns `false` for unregistered codes.
- No user-facing message contains internal Rust keywords (`panic`, `unwrap`, etc.).
- Every documented code in every domain has a non-empty message and a recovery hint.

### Retry path
- `ContractPaused` (503) and `DependencyDegraded` (503) have `is_retryable = true`
  and a positive `retry_after_ms`.
- Permanent codes (authorization, conflict, validation, internal) have
  `is_retryable = false` and `retry_after_ms = 0`.
- Domain-specific transient errors (rate-limiting, timelock, milestone-not-verified,
  queue-full, treasury-insufficient-funds, governance-below-threshold) are all
  retryable.
- Upgrade rollback and feature-rollback codes are non-retryable.
- `ContractPaused` backoff is ≥ `DependencyDegraded` backoff.

### Authorization path
- `inspect_problem_details` returns the full `ProblemDetailsRecord` for admin callers,
  for both known and unknown codes.
- Non-admin callers receive `Error::Unauthorized` for every code, including
  publicly-known transient codes.

### Edge cases
- Code `960` has different stable meanings in `SupportAccess` and `FeatureFlags`
  domains — the domain is the disambiguating axis.
- Code `961` likewise differs by domain.
- Upgrade rollback (913) is always permanent.
- Aid milestone boundary codes (114–117) are verified individually.
- Marketplace boundary codes (2000, 2023, out-of-range 2024) are verified.
- AccessControl ownership-transfer codes (218–221) are individually verified.
- `describe_error` does not panic for any `u32` input in any domain.

---

## Recovery and Rollback Behavior

### Error taxonomy additions (additive only)
New error codes are always additive: existing codes never change their numeric
discriminant, machine code, HTTP status, or retryability. When a new variant is
added to `errors.rs`:

1. Add a new branch in `error_taxonomy.rs` under the appropriate domain.
2. Add the corresponding `problem_code`, `user_message`, and `remediation_hint`
   branches in `errors.rs`.
3. Extend the coverage tables in `test_problem_details_taxonomy.rs`.
4. Update this document's edge-case section.

### Rollback
Because the taxonomy is a pure mapping layer with no on-chain storage and no
contract events, rolling back a taxonomy change requires only a code revert — no
migration, no ledger entry cleanup, and no on-chain side-effects.

### Information-leakage audit
Run `cargo test` after every taxonomy change. The `failure_path_message_never_contains_internal_identifiers`
test will catch any user-facing field that leaks an internal Rust identifier.
