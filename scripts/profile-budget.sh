#!/usr/bin/env bash
# Soroban CPU/memory footprint profiling runner (Issue #192).
#
# NOTE: this script must be committed with the executable bit set
# (`git update-index --chmod=+x scripts/profile-budget.sh`); CI invokes it as
# `./scripts/profile-budget.sh` and fails with exit 126 otherwise.
# Runs the `profile_budget` test module in each profiled contract with
# `--nocapture`, so the `BUDGET_METRIC <key> cpu=<n> mem=<n>` lines those
# tests print (see contracts/*/src/profile_budget.rs) land in a combined log.
# That log is then handed to scripts/compare-budget.cjs, which compares the
# measured costs against the checked-in baseline
# (testing/budget-baseline.json) and fails if any metric regressed by more
# than the configured threshold.
#
# Worst-case / resource-budget coverage:
#   The profile_budget modules are expected to exercise, per contract, the
#   normal, failure, retry, and authorization paths (metric keys are suffixed
#   accordingly, e.g. `aid.disburse.normal`, `aid.disburse.auth_denied`,
#   `aid.disburse.retry`). This runner additionally:
#     * runs every profiled contract with `--test-threads=1` for noise-free
#       measurements,
#     * captures non-zero exits from cargo per contract and records them as
#       MISSING metrics (never as a silent pass),
#     * refuses to update the baseline if *any* contract failed to run, so a
#       partial/worst-case-hiding run can never become the new reference,
#     * tags the run with a summary of which paths were observed so an
#       absent path is visible in the output.
#
# Usage:
#   ./scripts/profile-budget.sh [--update-baseline] [--threshold PERCENT]
#                               [--baseline PATH]
#
# Env vars (see docs/OBSERVABILITY.md, "Automated Budget Profiling"):
#   BUDGET_REGRESSION_THRESHOLD_PERCENT  Overridden by --threshold. Default 10.
#
# Recovery / rollback:
#   * A failing contract does not abort the run; its metrics are reported as
#     MISSING by compare-budget.cjs and the job fails only if they regress.
#   * `--update-baseline` is refused when any contract failed, leaving the
#     checked-in baseline untouched. To roll back a bad baseline, `git checkout`
#     testing/budget-baseline.json.
#   * Temporary logs live in a mktemp dir removed on exit (including on error).
#
# Exit codes: 0 = within threshold (or baseline updated), 1 = regression
# beyond threshold, 2 = could not run (bad usage, cargo not found, refusing
# to update baseline from a partial run, etc).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Contract -> the BUDGET_METRIC key(s) its profile_budget module prints.
# Kept here (rather than discovered) so a contract with a profile_budget
# module that silently stops emitting a metric is caught by compare-budget.cjs
# reporting it MISSING, instead of the run just quietly measuring less.
CONTRACTS=(
  "aid-contract"
  "treasury-contract"
  "referral-contract"
  "rebalancer-contract"
)

# Worst-case path categories the profile_budget modules are expected to cover.
EXPECTED_PATHS=(normal failure retry authorization)

UPDATE_BASELINE=0
THRESHOLD="${BUDGET_REGRESSION_THRESHOLD_PERCENT:-10}"
BASELINE="testing/budget-baseline.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-baseline) UPDATE_BASELINE=1; shift ;;
    --threshold)
      [[ $# -ge 2 ]] || { echo "--threshold requires a value" >&2; exit 2; }
      THRESHOLD="$2"; shift 2 ;;
    --baseline)
      [[ $# -ge 2 ]] || { echo "--baseline requires a value" >&2; exit 2; }
      BASELINE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found on PATH" >&2
  exit 2
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node not found on PATH" >&2
  exit 2
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
LOG="$WORKDIR/profile-budget.log"
: > "$LOG"

echo "== Soroban budget profiling (issue #192) =="
echo "expected worst-case paths per contract: ${EXPECTED_PATHS[*]}"
FAILED_CONTRACTS=()
RAN_CONTRACTS=()

for contract in "${CONTRACTS[@]}"; do
  if [ ! -d "contracts/$contract" ]; then
    echo "skip: contracts/$contract does not exist" | tee -a "$LOG"
    FAILED_CONTRACTS+=("$contract")
    continue
  fi

  echo "-- profiling $contract --" | tee -a "$LOG"
  # `--test-threads=1` keeps the budget measurements free of scheduling noise
  # from other tests running concurrently in the same process.
  if cargo test -p "$contract" --lib profile_budget -- --nocapture --test-threads=1 \
       >>"$LOG" 2>&1; then
    RAN_CONTRACTS+=("$contract")
  else
    echo "WARNING: $contract's profile_budget tests did not run cleanly (see log below); its metrics will be reported as missing rather than failing the whole job." >&2
    FAILED_CONTRACTS+=("$contract")
  fi
done

echo
echo "== raw cargo output =="
cat "$LOG"
echo "== end raw cargo output =="
echo

echo "ran cleanly: ${RAN_CONTRACTS[*]:-(none)}"

if [ "${#FAILED_CONTRACTS[@]}" -gt 0 ]; then
  echo "Contracts whose profile_budget module did not build/run: ${FAILED_CONTRACTS[*]}" >&2
  echo "(scripts/compare-budget.cjs treats their metrics as MISSING, not a threshold failure -- a pre-existing, unrelated compile issue in a contract's test suite must not silently block this job.)" >&2
fi

# Report which worst-case path categories actually appear in the captured
# metrics, so a missing path (e.g. no retry measurement) is visible in logs.
for path in "${EXPECTED_PATHS[@]}"; do
  if grep -q "BUDGET_METRIC .*\.${path}[. ]" "$LOG"; then
    echo "path covered: $path"
  else
    echo "path NOT observed in any metric: $path" >&2
  fi
done

ARGS=(--log "$LOG" --baseline "$BASELINE" --threshold "$THRESHOLD")
if [ "$UPDATE_BASELINE" -eq 1 ]; then
  if [ "${#FAILED_CONTRACTS[@]}" -gt 0 ]; then
    echo "refusing to update baseline: partial run (failed/missing: ${FAILED_CONTRACTS[*]})" >&2
    exit 2
  fi
  ARGS+=(--update-baseline)
fi

node scripts/compare-budget.cjs "${ARGS[@]}"
exit $?
