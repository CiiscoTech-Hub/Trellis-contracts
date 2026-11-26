#!/usr/bin/env node
/**
 * Verification runner for Trellis-contracts issues:
 * - Issue #322: Add deterministic contract upgrade compatibility snapshots
 * - Issue #323: Implement bounded event pagination for high-volume histories
 * - Issue #324: Create invariant tests for treasury balance conservation
 * - Issue #325: Add replay-safe authorization payload fingerprints
 *
 * Runs the module test suites through the standalone issue-verification crate
 * (see scripts/issue-verification/README.md). Set CARGO_TOOLCHAIN=stable to
 * run with `cargo +stable`.
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const MANIFEST = path.join(ROOT, "scripts", "issue-verification", "Cargo.toml");
const TOOLCHAIN = process.env.CARGO_TOOLCHAIN ? [`+${process.env.CARGO_TOOLCHAIN}`] : [];

const suites = [
  {
    issue: "#322",
    title: "Add deterministic contract upgrade compatibility snapshots",
    filter: "upgrade_compat_snapshot::",
    files: ["shared/src/upgrade_compat_snapshot.rs", "docs/UPGRADE_COMPAT_SNAPSHOTS.md"],
    expectedTests: 7,
  },
  {
    issue: "#323",
    title: "Implement bounded event pagination for high-volume histories",
    filter: "event_pagination::",
    files: ["shared/src/event_pagination.rs", "docs/BOUNDED_EVENT_PAGINATION.md"],
    expectedTests: 6,
  },
  {
    issue: "#324",
    title: "Create invariant tests for treasury balance conservation",
    filter: "treasury_conservation::",
    files: ["shared/src/treasury_conservation.rs", "docs/TREASURY_BALANCE_CONSERVATION.md"],
    expectedTests: 7,
  },
  {
    issue: "#325",
    title: "Add replay-safe authorization payload fingerprints",
    filter: "auth_fingerprint::",
    files: ["shared/src/auth_fingerprint.rs", "docs/AUTH_PAYLOAD_FINGERPRINTS.md"],
    expectedTests: 7,
  },
];

console.log("TRELLIS-CONTRACTS: VERIFICATION RUNNER (Issues #322, #323, #324, #325)\n");

let allPassed = true;
const results = [];

for (const suite of suites) {
  console.log(`>>> Issue ${suite.issue}: ${suite.title}`);
  let passed = true;

  for (const file of suite.files) {
    if (!fs.existsSync(path.join(ROOT, file))) {
      console.error(`  FAIL: missing ${file}`);
      passed = false;
    }
  }

  const result = spawnSync(
    "cargo",
    [...TOOLCHAIN, "test", "--manifest-path", MANIFEST, suite.filter],
    { encoding: "utf8", env: process.env }
  );
  const output = `${result.stdout}\n${result.stderr}`;
  const match = output.match(/test result: (\w+)\. (\d+) passed; (\d+) failed/);
  const ran = match ? Number(match[2]) : 0;

  if (result.status !== 0 || !match) {
    process.stdout.write(output);
    passed = false;
  } else if (ran < suite.expectedTests) {
    console.error(`  FAIL: expected >= ${suite.expectedTests} tests, ran ${ran}`);
    passed = false;
  } else {
    console.log(`  PASS: ${ran} tests`);
  }

  allPassed = allPassed && passed;
  results.push({ ...suite, passed });
}

console.log("\nSUMMARY");
for (const r of results) {
  console.log(`  [${r.passed ? "PASS" : "FAIL"}] Issue ${r.issue}: ${r.title}`);
}

if (!allPassed) {
  console.error("\nVerification failed.");
  process.exit(1);
}
console.log("\nAll 4 issues verified.");
