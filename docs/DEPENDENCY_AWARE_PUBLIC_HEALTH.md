# Dependency-Aware Public Health Status (Issue #487)

Module: `shared/src/dependency_aware_health.rs`

## What it does

Computes composite, contract-level public availability by continuously aggregating health metrics across all critical dependencies:
- **OraclePriceFeed**: Price quotes for disbursements and rebalancing.
- **AssetContract**: Underlying Stellar Asset Contracts (SACs) for funds transfers.
- **OffchainIndexer**: Event processing and transaction discovery services.
- **PaymentBridge**: External fiat and cross-border on/off ramps.
- **GovernanceTimelock**: Multi-sig proposal delays and upgrade gates.

Provides an authoritative, contract-visible verdict on which user actions are safe to execute, without exposing internal infrastructure secrets or stack traces.

## System Health States

| Composite Status | Conditions | Allowed User Actions |
|------------------|------------|----------------------|
| `Operational` | All critical and high dependencies healthy | All operations permitted (Deposits, Aid, Gov, Exits) |
| `Degraded` | Medium/Low dependency degraded or delayed | Normal operations with public warning notices |
| `SeverelyDegraded` | High dependency down or critical dependency degraded | New commitments throttled; claims permitted |
| `EmergencyHalted` | Any `Critical` dependency down (Oracle, SAC) | New deposits and aid halted; **Exits remain permitted!** |

## Core Invariant: User Fund Exit Guarantee

> **CRITICAL INVARIANT**: User fund exits (`exit`, `refund`, `withdraw`, emergency payouts) are **NEVER BLOCKED**, regardless of dependency failures or emergency halt states. Even if oracle feeds and token bridges are completely down, `can_exit_funds` evaluates to `true`.

## Lifecycle & Operations

| Operation | Entrypoint | Authorization | Effect |
|-----------|------------|---------------|--------|
| Dependency Registration | `register_dependency` | Admin | Registers component with criticality weighting |
| Heartbeat Ingestion | `report_dependency_heartbeat` | Reporter / Admin | Updates dependency health status and latency |
| Health Query | `get_composite_health` | Public | Returns overall status, counts, and action flags |
| Pre-flight Action Check | `is_action_permitted` | Public | Checks whether a specific action is safe to execute |
| Reporter Onboarding | `register_health_reporter` | Admin | Adds authorized health reporting address |

## Failure, Retry, and Authorization Paths

- **Critical Dependency Outage**: When a critical dependency reports `ComponentHealth::Down`, system health transitions immediately to `CompositeSystemStatus::EmergencyHalted`. Aid disbursement and deposits are disallowed, but exits remain permitted.
- **Non-Critical Outage**: If an indexer or low-priority bridge goes down, status moves to `Degraded`, allowing core financial operations to continue.
- **Recovery & Retry**: Consecutive heartbeats reporting `Healthy` instantly restore the system to `Operational` without manual contract unpausing or state migrations.
- **Authorization**: Only registered health reporters or admins can report heartbeats or register dependencies. Unregistered callers fail with `DependencyHealthError::Unauthorized`.

## Operational Edge Cases

- **Latency-Based Degradation**: Reporters report latency in milliseconds. High latency (e.g., > 1000ms) can be flagged as `Degraded` before a hard timeout occurs.
- **Unknown Status**: Unreported or initialized dependencies default to `Unknown` and are treated as degraded until an initial heartbeat is received.

## Recovery and Rollback Behavior

- Health states are purely operational telemetry stored in instance storage.
- A false alarm or stale report can be instantly corrected by issuing an updated heartbeat report from any authorized reporter. No state rollback or contract redeployment is necessary.

## Migration Plan

1. Deploy updated `shared` module.
2. Initialize core dependencies (Oracle feeds, SAC token contracts) with their respective criticality levels.
3. Authorize monitoring daemons as reporters via `register_health_reporter`.
4. Frontends and SDKs query `get_composite_health` before initiating transactions to render helpful user warnings.
