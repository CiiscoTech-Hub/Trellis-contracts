#!/usr/bin/env bash
# Run the local, non-destructive checks used by the incident runbook.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Incident drill: import validation and rollback =="
node scripts/verify-import-pipeline.cjs

echo "== Incident drill: deterministic recovery =="
cargo test -p shared recovery -- --test-threads=1

echo "== Incident drill: release and rollback readiness =="
cargo test -p shared test_release_readiness -- --test-threads=1
node scripts/verify-release-readiness.cjs

echo "== Incident drill: user-impact reporting =="
cargo test -p shared test_dashboard -- --test-threads=1

echo "== Incident drill: high-value journey monitor =="
cargo run --quiet -p ops-checks --bin high-value-journey-monitor

echo "== Incident drill: executable recovery checks =="
cargo run --quiet -p ops-checks --bin incident-runbook-checks
# A skipped recovery step must fail the runbook, never pass it.
if INCIDENT_RUNBOOK_FAULT=skip_recovery cargo run --quiet -p ops-checks --bin incident-runbook-checks >/dev/null; then
  echo "incident-runbook-checks passed with a skipped recovery step" >&2
  exit 1
fi

echo "Incident drill checks passed. No network or deployment actions were run."
