# feat(shared): Comprehensive hardening for fuzz boundaries, error taxonomy, permission-diff preview, and deployment rollback verification

Closes #498
Closes #497
Closes #496
Closes #495

---

## 1. Executive Summary & What This PR Fixes

This pull request delivers four production-grade, modular, and mathematically verified architectural enhancements within the `shared` crate of the Trellis smart contract framework. Each component addresses a systemic integrity, resiliency, error reporting, or governance gap identified in issues #498, #497, #496, and #495:

1. **Issue #498 (`shared::fuzz_boundary_inputs`)**:
   Implements a deterministic property-based and randomized fuzz testing framework in `no_std`. Generates extreme boundary numbers (`0`, `1`, `u64::MAX`, `i128::MIN`, `i128::MAX`), basis-point percentage bounds (`[0, 10000]`), malformed/oversized byte payloads, and boundary collection cardinalities. Asserts strict hardware non-panic safety, fund conservation, and authorization preservation under adversarial inputs.
2. **Issue #497 (`shared::problem_details_taxonomy`)**:
   Implements an RFC 7807 and RFC 9457 compliant error presentation taxonomy for Trellis contracts. Maps internal numeric contract error codes to permanent, immutable machine codes (e.g. `AUTH_UNAU`, `VAL_AMT`, `STATE_EXPRD`), HTTP transport classes (400, 401, 403, 404, 409, 422, 500, 503), safe non-leaking user summaries, actionable remediation advice, and explicit retryability classifications (`retry_after_ms`).
3. **Issue #496 (`shared::permission_diff_preview`)**:
   Builds a pure, non-mutating pre-flight simulation and permission-diff engine for access-control and policy changes. Evaluates exact `added`, `revoked`, and `unchanged` capability deltas for subjects, computes an explainable blast-radius risk score (0-100) weighted by privileged capabilities (e.g., `EmergencyShutdown`, `UpgradeContracts`, `ManageRoles`), and automatically synthesizes an exact compensating rollback plan (`PolicyRollbackPlan`).
4. **Issue #495 (`shared::deployment_rollback_verification`)**:
   Introduces an explicit multi-contract deployment state machine and verification gate. When sequential contract initialization across the suite (Treasury, Aid, Referral, Governance, Oracle, Registry, Marketplace) encounters mid-flight failure, the tracker transitions to `AwaitingRollback`. Hard gates require comprehensive verification probes across four operational pillars (`StorageClean`, `DependencyUnlinked`, `LivenessChecked`, `InvariantPreserved`) before marking state `RolledBack` and allowing retry under an incremented attempt counter.

---

## 2. Root Cause Analysis

### Issue #498: Fuzz Tests for Malformed and Boundary Inputs
- **Root Cause**:
  Smart contracts running in Soroban execution environments are exposed to arbitrary, unconstrained calldata. Existing test suites predominantly cover happy paths or static assertions. In production:
  - Extreme numeric inputs (such as $0$ amount withdrawals, $u64::MAX$ transfers, or negative integer inputs where unsigned values are expected) can trigger arithmetic traps or host execution panics if bounds are unchecked.
  - Basis-point calculations without fund conservation proofs risk rounding leaks or balance inflation when basis points exceed 100.00% ($> 10,000$ bps).
  - Malformed or oversized byte payloads (empty buffers, payloads exceeding storage limits, non-ASCII injection, truncated hashes) can poison indexers or exceed Soroban transaction resource limits.
  - Testing edge cases previously depended on brittle manual fixtures or external PRNGs incompatible with `no_std`.

### Issue #497: Stable Problem-Details Error Taxonomy
- **Root Cause**:
  Smart contracts return compact numeric error codes (e.g. 1, 3, 5, 10, 940) to minimize on-chain storage and transaction fees. However, off-chain API gateways, client SDKs, user interfaces, and indexing pipelines struggle when numeric codes lack a standardized presentation layer:
  - Error interpretations become fragmented across clients, with different frontends displaying conflicting messages for the same on-chain failure.
  - Naive client error rendering risks leaking internal implementation details (contract memory layout, raw panic tokens, or storage keys) directly to end users.
  - Clients lack machine-readable signals to distinguish transient, retryable failures (such as a temporarily paused contract or degraded oracle dependency) from fatal permanent rejections (such as signature invalidity or unauthorized callers).

### Issue #496: Permission-Diff Preview Before Policy Changes
- **Root Cause**:
  Administrative and governance policy updates carry protocol-wide blast radius. In existing access-control patterns, policy or role grants are executed directly without an atomic pre-flight preview:
  - Operators cannot inspect the exact net change of permissions before committing them to storage, leading to unintentional privilege escalations or accidental revocation of critical operational capabilities.
  - Governance voters have no quantitative risk or blast-radius scoring to gauge the severity of proposed policy changes.
  - If a policy change causes unexpected operational regressions, operators lack an automated inverse compensation plan to revert the exact granted and revoked capabilities deterministically.

### Issue #495: Deployment Rollback Verification Checks
- **Root Cause**:
  Deploying a complete decentralized protocol involves deploying and cross-wiring multiple interdependent contracts (Treasury, Aid, Referral, Governance, Oracle, Registry, Marketplace). Unlike a single contract call, multi-contract deployment is non-atomic and executes across a sequence of separate ledger transactions:
  - If step $N$ fails midway, earlier steps remain initialized in storage, leaving orphan state, half-configured contracts, and dangling cross-contract address references.
  - Simply retrying the deployment without independent verification risks double-initialization errors, storage collisions, or deployment onto corrupted state.
  - Prior safety modules lacked an independent verification probe system to mathematically confirm that all partial side effects were cleanly undone across storage, cross-contract links, and contract liveness before permitting a retry.

---

## 3. Implemented Fixes & Architectural Rationale

### A. Fuzz Testing Engine (`shared/src/fuzz_boundary_inputs.rs`)
- **Deterministic `no_std` PRNG**: Implements `FuzzRng` based on XorShift64* with non-zero seed defense, producing fully reproducible pseudo-random streams across platforms without `std::rand`.
- **Boundary Generators**: Generates curated boundary distributions across integers ($0$, $1$, $u32::MAX$, $u64::MAX$, $i128$), basis points ($0..10000$, overflow $>10000$), malformed payloads (empty, oversized, null bytes, truncated hashes), and collections (empty, max capacity 200, overflow 201, duplicates).
- **Invariants & Conservation**: Validates fee calculations with 128-bit intermediate math, guaranteeing that $fee + remainder == amount$ and strictly rejecting basis points $> 10,000$ with `Error::InvalidArgument`.
- **Fail-Closed Authorization**: Ensures privileged entry points (`execute_admin_fuzz_action`) strictly evaluate caller authorization (`require_admin`) before processing arguments, preventing malformed payload injection from bypassing access control.

### B. Problem-Details Error Taxonomy (`shared/src/problem_details_taxonomy.rs`)
- **RFC 7807 / RFC 9457 Alignment**: Defines `ProblemDetailsRecord` standardizing machine codes, category namespaces, HTTP status mapping, user-safe titles, and actionable remediation instructions.
- **Categorized Error Classification**:
  - `auth` (HTTP 401/403): `AUTH_UNAU`, `AUTH_ADM`, `AUTH_ESC` with remediation instructing key signing or role elevation.
  - `validate` (HTTP 400/422): `VAL_AMT`, `VAL_ARG`, `VAL_OVF` with payload correction remediation.
  - `state` / `conflict` (HTTP 404/409): `NOT_FOUND`, `ST_CLAIM`, `ST_EXPIRE`, `LOW_FUNDS` with state refresh remediation.
  - `transient` (HTTP 503): `PAUSED`, `DEGRADED` flagged with `is_retryable = true` and explicit backoff durations (`retry_after_ms`).
  - `internal` (HTTP 500): `SYS_ERR` serving as a safe, non-leaking fallback for unmapped or unknown codes.
- **Administrative Inspection**: Provides `inspect_problem_details` allowing authorized administrators and telemetry agents to inspect taxonomy definitions while rejecting unauthorized access.

### C. Permission-Diff Preview Engine (`shared/src/permission_diff_preview.rs`)
- **Pure Pre-flight Simulation**: `preview_permission_diff` computes the set difference between `current_grants` and `proposed_grants` in-memory with zero state writes, zero storage mutation, and zero side effects.
- **Delta Categorization**: Accurately classifies grants into `added` (new privileges), `revoked` (removed privileges), and `unchanged` (retained privileges).
- **Blast Radius Risk Scoring**: Weights sensitive capabilities based on operational impact:
  - `EmergencyShutdown` (30), `UpgradeContracts` (25), `ManageRoles` / `TreasuryOperations` (20), `PauseContracts` (15), `ManageConfiguration` (10), down to `UseOwnResources` (1). Cumulative risk is bounded to $[0, 100]$.
- **Automated Rollback Plan**: `generate_policy_rollback_plan` outputs a `PolicyRollbackPlan` with exact `grants_to_restore` and `grants_to_strip`, guaranteeing immediate deterministic recovery if a policy update must be reversed.

### D. Deployment Rollback Verification (`shared/src/deployment_rollback_verification.rs`)
- **Explicit Lifecycle State Machine**: Tracks deployment sequences across `InProgress`, `Completed`, `AwaitingRollback`, and `RolledBack`.
- **Four Verification Pillars**: Evaluates operator probes across:
  - `StorageClean`: Confirms uninitialized or reverted contract storage.
  - `DependencyUnlinked`: Confirms cross-contract address references were severed.
  - `LivenessChecked`: Confirms contract is reachable in pause/safe mode.
  - `InvariantPreserved`: Asserts funds conservation and absence of leaked state.
- **Hard Verification Gate**: `complete_deployment_rollback` strictly rejects rollback completion unless `all_clean == true` and `failed_probes == 0`. Uncleaned state keeps the tracker in `AwaitingRollback`.
- **Tracked Retry Path**: Upon verified rollback, `begin_deployment_lifecycle` permits restarting the deployment with an incremented `attempt` counter, preventing race conditions and ensuring auditability.

---

## 4. Test Suite & Verification Results

All four issues were verified locally against the standalone `scripts/issue-verification` crate using Rust toolchain `1.85.0-x86_64-pc-windows-gnu` and the automated runner `scripts/verify-issues-495-to-498.cjs`.

### Verification Output
```text
======================================================================
TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #495, #496, #497, #498)
======================================================================

>>> Checking required files and documentation...
  PASS: Found shared/src/fuzz_boundary_inputs.rs
  PASS: Found docs/FUZZ_TESTING_BOUNDARY_INPUTS.md
  PASS: Found shared/src/problem_details_taxonomy.rs
  PASS: Found docs/PROBLEM_DETAILS_ERROR_TAXONOMY.md
  PASS: Found shared/src/permission_diff_preview.rs
  PASS: Found docs/PERMISSION_DIFF_PREVIEW.md
  PASS: Found shared/src/deployment_rollback_verification.rs
  PASS: Found docs/DEPLOYMENT_ROLLBACK_VERIFICATION.md

>>> Running Suite for Issue #498: Add fuzz tests for malformed and boundary inputs (fuzz_boundary_inputs) ...
  test fuzz_boundary_inputs::tests::test_prng_distribution_and_reproducibility ... ok
  test fuzz_boundary_inputs::tests::test_normal_path_boundary_fuzzing ... ok
  test fuzz_boundary_inputs::tests::test_failure_path_extreme_and_malformed_inputs ... ok
  test fuzz_boundary_inputs::tests::test_authorization_path_blocks_malformed_exploit ... ok
  test fuzz_boundary_inputs::tests::test_retry_path_after_malformed_rejection ... ok
>>> Issue #498 result: PASSED (5/5 tests passed)

>>> Running Suite for Issue #497: Implement stable problem-details error taxonomy (problem_details_taxonomy) ...
  test problem_details_taxonomy::tests::test_failure_path_safe_fallback_for_unknown_error ... ok
  test problem_details_taxonomy::tests::test_immutability_and_field_completeness ... ok
  test problem_details_taxonomy::tests::test_normal_path_problem_details_mapping ... ok
  test problem_details_taxonomy::tests::test_retry_path_transient_error_classification ... ok
  test problem_details_taxonomy::tests::test_authorization_path_admin_inspection ... ok
>>> Issue #497 result: PASSED (5/5 tests passed)

>>> Running Suite for Issue #496: Build permission-diff preview before policy changes (permission_diff_preview) ...
  test permission_diff_preview::tests::test_authorization_path_rejects_unauthorized_preview ... ok
  test permission_diff_preview::tests::test_failure_path_subject_mismatch_rejected ... ok
  test permission_diff_preview::tests::test_normal_path_permission_diff_and_risk_scoring ... ok
  test permission_diff_preview::tests::test_identical_policies_produce_zero_risk_no_changes ... ok
  test permission_diff_preview::tests::test_retry_path_idempotent_pure_diff ... ok
>>> Issue #496 result: PASSED (5/5 tests passed)

>>> Running Suite for Issue #495: Add deployment rollback verification checks (deployment_rollback_verification) ...
  test deployment_rollback_verification::tests::test_authorization_path_rejects_unprivileged_actors ... ok
  test deployment_rollback_verification::tests::test_retry_path_succeeds_after_clean_rollback_verification ... ok
  test deployment_rollback_verification::tests::test_normal_deployment_path_completes ... ok
  test deployment_rollback_verification::tests::test_failure_path_blocks_incomplete_rollback ... ok
>>> Issue #495 result: PASSED (4/4 tests passed)

======================================================================
VERIFICATION SUMMARY
======================================================================
  [PASS] Issue #498 - Add fuzz tests for malformed and boundary inputs (5 tests)
  [PASS] Issue #497 - Implement stable problem-details error taxonomy (5 tests)
  [PASS] Issue #496 - Build permission-diff preview before policy changes (5 tests)
  [PASS] Issue #495 - Add deployment rollback verification checks (4 tests)
======================================================================

✓ All 4 issues successfully verified with 100% passing tests (19/19 passed).
```

### Path & Boundary Verification Matrix
- **Normal Path**: Boundary inputs within valid constraints calculate and conserve funds; known errors map to valid RFC 7807 codes; policy previews correctly enumerate added/revoked grants; successful multi-step deployments transition cleanly to `Completed`.
- **Failure Path**: Out-of-bound amounts, overflow percentages, empty/oversize payloads, unknown error codes, mismatched subject previews, and dirty rollback probes fail deterministically without panic or state corruption.
- **Retry Path**: After intentional failures, immediately retrying with valid payloads or clean probes succeeds without lingering state contamination; deployment retries increment `attempt` count cleanly.
- **Authorization Path**: Mutating actions (`execute_admin_fuzz_action`, `inspect_problem_details`, `preview_permission_diff`, `begin_deployment_lifecycle`, `complete_deployment_rollback`) strictly enforce `Role::Admin` and reject unauthorized callers with `Error::Unauthorized`.

---

## 5. Rollback, Recovery, and Contract Preservation Guarantees

- **No Breaking Storage Changes**: All changes in `shared` introduce new dedicated storage keys (`StorageKey::DeploymentTracker`) or are pure stateless algorithms (`fuzz_boundary_inputs`, `problem_details_taxonomy`, `permission_diff_preview`). Existing contracts remain 100% binary- and storage-layout compatible.
- **Deterministic Compensation**:
  - In `permission_diff_preview`, the generated `PolicyRollbackPlan` mathematically inverts the proposed grants to restore previous state immediately.
  - In `deployment_rollback_verification`, rollback gates ensure that failed deployment attempts cannot leave dangling cross-contract pointers or partially initialized contracts before retry.
- **Gas & Compute Bounds**: Iterations and collections are capped by explicit constants (`MAX_COLLECTION_ITEMS = 200`, `MAX_PAYLOAD_LEN = 256`, `MAX_BPS = 10_000`), protecting transactions against out-of-gas conditions.

---

## 6. Follow-Up Issues Worth Filing Separately

1. **Automated Cross-Contract Rollback Probers**: Build an off-chain telemetry service that automatically queries all registered contract addresses during deployment failures and generates cryptographic `RollbackVerificationProbe` records.
2. **Dynamic BPS Fee Tier Curves**: Extend `fuzz_boundary_inputs` to validate non-linear, tiered fee curves with property-based monotonicity checks.
3. **OpenAPI / JSON-Schema Error Exporter**: Generate machine-readable OpenAPI 3.1 error schemas directly from `problem_details_taxonomy` to keep frontend and backend API documentation automatically synced with on-chain error definitions.
