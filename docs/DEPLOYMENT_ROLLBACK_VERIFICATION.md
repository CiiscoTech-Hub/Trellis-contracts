# Deployment Rollback Verification Checks

## Executive Summary
This document specifies the architecture, verification procedures, and operational state machine for multi-contract deployment rollback verification (`shared::deployment_rollback_verification`, Issue #495).

Deploying the Trellis smart contract suite (Treasury, Aid, Referral, Governance, Oracle, Registry, and Marketplace) is a non-atomic multi-step process across distinct on-chain transactions. When a step fails mid-deployment, simple retries without systematic rollback verification can leave orphaned storage entries, corrupted cross-contract address links, and incomplete configuration state.

---

## Architectural Principles

1. **Explicit State Machine**:
   - `InProgress`: Deployment is actively executing sequential steps.
   - `Completed`: All initialization steps completed successfully.
   - `AwaitingRollback`: A step failed; compensation and rollback verification required.
   - `RolledBack`: Rollback verified clean across all checked components; retry permitted.
2. **Four Operational Verification Pillars**:
   Rollback verification probes (`RollbackVerificationProbe`) systematically evaluate:
   - `StorageClean`: Asserts that contract instance/persistent storage has been uninitialized or restored to baseline.
   - `DependencyUnlinked`: Confirms cross-contract address bindings (e.g. Treasury address in Aid contract) were cleanly unset or reverted.
   - `LivenessChecked`: Verifies the contract is reachable and properly set to paused or maintenance status.
   - `InvariantPreserved`: Asserts balance conservation and confirms no token or state leakage occurred during the aborted attempt.
3. **Hard Verification Gate**:
   - `complete_deployment_rollback` enforces that:
     - `report.deployment_id == tracker.deployment_id`
     - `report.all_clean == true`
     - `report.failed_probes == 0`
   - If any probe reports an unclean state (`is_clean == false`), rollback completion is rejected with `Error::InvalidTransition` and the tracker remains in `AwaitingRollback`.
4. **Distinguishable Deployment Retries**:
   - Once transitioning to `RolledBack`, `begin_deployment_lifecycle` allows restarting with `attempt` incremented.
   - Prevents race conditions and maintains an unambiguous audit log across consecutive attempts.

---

## Operational Execution Paths

### Normal Path
- Administrator initiates deployment (`begin_deployment_lifecycle`).
- Steps are completed sequentially (`record_deployment_step_success`).
- Upon reaching the final step, the tracker marks `Completed` with zero rollback needed.

### Failure Path
- Downstream contract initialization fails (e.g., cross-contract error).
- Step failure is recorded via `record_deployment_step_failure`, transitioning tracker to `AwaitingRollback`.
- Probes reporting dirty state (`is_clean: false`) cause `verify_deployment_rollback_checks` to report `all_clean: false`.
- Calling `complete_deployment_rollback` with unclean reports is strictly rejected (`Error::InvalidTransition`).

### Retry Path
- Operator executes manual/automated compensation across affected contracts.
- Fresh probes confirm clean state (`all_clean: true`).
- `complete_deployment_rollback` transitions tracker to `RolledBack`.
- Administrator initiates retry (`attempt` = 2), proceeding from a provably clean state.

### Authorization Path
- All mutating lifecycle entrypoints (`begin_deployment_lifecycle`, `record_deployment_step_success`, `record_deployment_step_failure`, `complete_deployment_rollback`) enforce `require_admin`.
- Unauthorized callers are rejected with `Error::Unauthorized`.

---

## Migration & Compatibility
- Purely additive: uses dedicated storage keys (`StorageKey::DeploymentTracker`).
- Fully backward-compatible with existing contract deployments and automation scripts.
