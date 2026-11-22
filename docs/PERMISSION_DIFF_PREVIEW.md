# Permission-Diff Preview and Policy Simulation

## Executive Summary
This document specifies the design, risk model, and operational execution of pre-flight permission-diff previews and rollback plan generation (`shared::permission_diff_preview`, Issue #496).

Administrative access control changes carry protocol-level blast radius. Modifying roles, grant sets, or capability policies without a clear before-and-after preview risks accidental privilege escalation, unintended administrative lockout, or broken operational workflows.

---

## Architectural Principles

1. **Pure Pre-flight Simulation**:
   - `preview_permission_diff` executes completely in-memory without writing to instance storage or emitting state-altering events.
   - Idempotent and safe to invoke multiple times across preview and review stages.
2. **Granular Delta Classification**:
   - Compares active `current_grants` against `proposed_grants` for a given subject.
   - Categorizes grants into:
     - `added`: Grants newly assigned by the proposal.
     - `revoked`: Grants removed by the proposal.
     - `unchanged`: Grants retained across both sets.
3. **Blast Radius & Risk Weighting**:
   - Each capability carries an intrinsic risk weight reflecting its potential impact:
     - `EmergencyShutdown`: Weight 30
     - `UpgradeContracts`: Weight 25
     - `ManageRoles` / `TreasuryOperations`: Weight 20
     - `PauseContracts`: Weight 15
     - `ManageConfiguration`: Weight 10
     - `SubmitOracle`: Weight 8
     - `ReferralConfiguration`: Weight 5
     - `ReadAuditTrail`: Weight 3
     - `ServiceOperation`: Weight 2
     - `UseOwnResources`: Weight 1
   - The cumulative score (capped at 100) provides an explainable risk indicator for governance review.
4. **Deterministic Rollback Plan**:
   - Generates a `PolicyRollbackPlan`:
     - `grants_to_restore`: Inverts all revoked grants.
     - `grants_to_strip`: Inverts all added grants.
   - Ensures an immediate, mathematically guaranteed reversal path is available before changes take effect.

---

## Operational Execution Paths

### Normal Path
- Maintainer submits current grant list and proposed grant list for a principal.
- Function outputs `PermissionDiffReport` showing exact added/revoked/unchanged grants and calculated risk score.
- Rollback plan generator synthesizes corresponding compensation operations.

### Failure Path
- Submitting grants referencing an address that does not match `subject` is rejected with `Error::InvalidArgument`.
- Execution halts immediately with zero side effects.

### Retry Path
- Preview calls are pure and side-effect free.
- Retrying previews yields identical reports with zero residual caching or state divergence.

### Authorization Path
- Pre-flight preview is restricted to authorized maintainers and administrators (`require_admin`).
- Outsiders or unauthorized callers are rejected with `Error::Unauthorized`.

---

## Migration & Compatibility
- Purely additive: does not alter existing contract functions or storage keys.
- Integrates seamlessly with access-control contracts and governance voting workflows.
