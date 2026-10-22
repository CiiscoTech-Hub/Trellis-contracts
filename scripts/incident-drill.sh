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

echo "Incident drill checks passed. No network or deployment actions were run."
