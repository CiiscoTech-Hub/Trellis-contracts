#!/usr/bin/env node
/**
 * Compares freshly measured Soroban budget metrics against a checked-in
 * baseline and reports the result (Issue #192).
 *
 * Deliberately dependency-free (no external JSON/table library) so it runs
 * on a bare `node` with nothing installed -- matching this repo's other
 * one-off Node scripts (validate-changelog.cjs, verify-deployment.cjs,
 * push-issues.js).
 *
 * Input: a cargo-test log (see scripts/profile-budget.sh) containing lines
 * of the form:
 *
 *   BUDGET_METRIC <key> cpu=<cpu_instructions> mem=<memory_bytes>
 *
 * printed by each contract's `profile_budget` test module (e.g.
 * contracts/aid-contract/src/profile_budget.rs). Those are compared against
 * testing/budget-baseline.json, which has the shape:
 *
 *   {
 *     "metrics": {
 *       "aid.create_aid": { "cpu_instructions": N, "memory_bytes": M },
 *       ...
 *     }
 *   }
 *
 * Usage:
 *   node scripts/compare-budget.cjs --log <path> [--baseline <path>]
 *     [--threshold <percent>] [--update-baseline] [--output <path>]
 *     [--worst-case-budget <path>]
 *
 * Resource budgets (worst-case load tests):
 *   --worst-case-budget <path> reads a JSON file of absolute ceilings,
 *   shaped as { "budgets": { "<key>": { "cpu_instructions": N, "memory_bytes": M } } }.
 *   Every measured metric that exceeds its absolute ceiling is a FAIL,
 *   independent of the relative regression threshold. Metrics without a
 *   budget entry are not checked against an absolute ceiling. Missing or
 *   malformed budget files cause exit code 2 (could not run), never a silent pass.
 *
 * Exit codes: 0 = every metric within threshold and budget (or baseline updated),
 * 1 = at least one metric regressed beyond threshold or exceeded its budget,
 * 2 = could not run.
 */
"use strict";

const fs = require("fs");
const path = require("path");

function parseArgs(argv) {
  const out = {
    log: null,
    baseline: "testing/budget-baseline.json",
    threshold: 10,
    updateBaseline: false,
    output: null,
    worstCaseBudget: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--log") out.log = argv[++i];
    else if (a === "--baseline") out.baseline = argv[++i];
    else if (a === "--threshold") out.threshold = Number(argv[++i]);
    else if (a === "--update-baseline") out.updateBaseline = true;
    else if (a === "--output") out.output = argv[++i];
    else if (a === "--worst-case-budget") out.worstCaseBudget = argv[++i];
    else {
      console.error(`unknown option: ${a}`);
      process.exit(2);
    }
  }
  return out;
}

/** Scrapes `BUDGET_METRIC <key> cpu=<n> mem=<n>` lines out of raw text. */
function parseMetrics(text) {
  const metrics = {};
  const re = /^BUDGET_METRIC\s+(\S+)\s+cpu=(\d+)\s+mem=(\d+)\s*$/;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const m = re.exec(line);
    if (!m) continue;
    const [, key, cpu, mem] = m;
    metrics[key] = {
      cpu_instructions: Number(cpu),
      memory_bytes: Number(mem),
    };
  }
  return metrics;
}

function readJson(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return null;
  return JSON.parse(fs.readFileSync(abs, "utf8"));
}

/**
 * Loads and validates the absolute resource-budget file. Returns a map of
 * key -> { cpu_instructions, memory_bytes } where each field is a finite,
 * non-negative number. Throws on any structural problem so the caller can
 * exit 2 rather than silently skipping enforcement.
 */
function loadWorstCaseBudgets(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    throw new Error(`worst-case budget file not found: ${filePath}`);
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(abs, "utf8"));
  } catch (e) {
    throw new Error(`worst-case budget file is not valid JSON: ${e.message}`);
  }
  if (!doc || typeof doc !== "object" || typeof doc.budgets !== "object" || doc.budgets === null) {
    throw new Error(`worst-case budget file must contain a { "budgets": {...} } object`);
  }
  const budgets = {};
  for (const [key, b] of Object.entries(doc.budgets)) {
    if (!b || typeof b !== "object") {
      throw new Error(`budget entry "${key}" must be an object`);
    }
    for (const field of ["cpu_instructions", "memory_bytes"]) {
      const v = b[field];
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
        throw new Error(`budget entry "${key}".${field} must be a non-negative finite number`);
      }
    }
    budgets[key] = { cpu_instructions: b.cpu_instructions, memory_bytes: b.memory_bytes };
  }
  if (Object.keys(budgets).length === 0) {
    throw new Error("worst-case budget file defines no budget entries (refusing to pass silently)");
  }
  return budgets;
}

/** Percent change of `current` relative to `base`, or null if base is 0. */
function pctChange(base, current) {
  if (base === 0) return null;
  return ((current - base) / base) * 100;
}

function fmtPct(p) {
  if (p === null) return "n/a";
  const sign = p > 0 ? "+" : "";
  return `${sign}${p.toFixed(2)}%`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.log) {
    console.error("usage: compare-budget.cjs --log <path> [--baseline <path>] [--threshold <percent>] [--update-baseline] [--worst-case-budget <path>]");
    process.exit(2);
  }
  if (!fs.existsSync(args.log)) {
    console.error(`✗ log file not found: ${args.log}`);
    process.exit(2);
  }
  if (!Number.isFinite(args.threshold) || args.threshold < 0) {
    console.error(`✗ invalid --threshold: must be a non-negative number`);
    process.exit(2);
  }

  let budgets = null;
  if (args.worstCaseBudget) {
    try {
      budgets = loadWorstCaseBudgets(args.worstCaseBudget);
    } catch (e) {
      console.error(`✗ ${e.message}`);
      process.exit(2);
    }
  }

  const current = parseMetrics(fs.readFileSync(args.log, "utf8"));

  if (args.output) {
    fs.writeFileSync(args.output, JSON.stringify({ metrics: current }, null, 2) + "\n");
  }

  if (args.updateBaseline) {
    const baselinePayload = {
      description:
        "Baseline Soroban CPU-instruction / memory-byte costs for the contract calls profiled by scripts/profile-budget.sh (Issue #192). Regenerate with `./scripts/profile-budget.sh --update-baseline` and record why in the PR.",
      generated_at: new Date().toISOString().slice(0, 10),
      threshold_percent_default: 10,
      metrics: current,
    };
    fs.mkdirSync(path.dirname(path.resolve(args.baseline)), { recursive: true });
    fs.writeFileSync(path.resolve(args.baseline), JSON.stringify(baselinePayload, null, 2) + "\n");
    console.log(`✓ wrote ${Object.keys(current).length} metric(s) to ${args.baseline}`);
    process.exit(0);
  }

  const baselineDoc = readJson(args.baseline);
  if (!baselineDoc || typeof baselineDoc.metrics !== "object") {
    console.error(
      `✗ could not read a { "metrics": {...} } baseline from ${args.baseline}. ` +
        `Run "./scripts/profile-budget.sh --update-baseline" once to create it.`
    );
    process.exit(2);
  }
  const baseline = baselineDoc.metrics;

  const keys = Array.from(new Set([...Object.keys(baseline), ...Object.keys(current)])).sort();

  const rows = [];
  let anyRegression = false;
  let anyMissing = false;
  let anyBudgetBreach = false;
  const breaches = [];

  for (const key of keys) {
    const base = baseline[key];
    const now = current[key];

    if (!now) {
      rows.push({ key, status: "MISSING", detail: "not measured this run" });
      anyMissing = true;
      continue;
    }

    // Absolute worst-case budget check (independent of the relative baseline).
    let overBudget = false;
    let budgetDetail = null;
    if (budgets && budgets[key]) {
      const b = budgets[key];
      const cpuOver = now.cpu_instructions > b.cpu_instructions;
      const memOver = now.memory_bytes > b.memory_bytes;
      if (cpuOver || memOver) {
        overBudget = true;
        const parts = [];
        if (cpuOver) parts.push(`cpu ${now.cpu_instructions} > budget ${b.cpu_instructions}`);
        if (memOver) parts.push(`mem ${now.memory_bytes} > budget ${b.memory_bytes}`);
        budgetDetail = parts.join("; ");
        breaches.push({ key, detail: budgetDetail });
        anyBudgetBreach = true;
      }
    }

    if (!base) {
      rows.push({
        key,
        status: overBudget ? "FAIL" : "NEW",
        detail: `cpu=${now.cpu_instructions} mem=${now.memory_bytes} (no baseline yet)` +
          (budgetDetail ? ` — OVER BUDGET: ${budgetDetail}` : ""),
      });
      continue;
    }

    const cpuPct = pctChange(base.cpu_instructions, now.cpu_instructions);
    const memPct = pctChange(base.memory_bytes, now.memory_bytes);
    const regressed =
      (cpuPct !== null && cpuPct > args.threshold) || (memPct !== null && memPct > args.threshold);
    if (regressed) anyRegression = true;

    rows.push({
      key,
      status: regressed || overBudget ? "FAIL" : "PASS",
      baseCpu: base.cpu_instructions,
      nowCpu: now.cpu_instructions,
      cpuPct,
      baseMem: base.memory_bytes,
      nowMem: now.memory_bytes,
      memPct,
      budgetDetail,
    });
  }

  const lines = [];
  lines.push(`## Soroban Budget Profile (threshold: ${args.threshold}%)`);
  lines.push("");
  lines.push("| Call | CPU (baseline → now, Δ) | Memory (baseline → now, Δ) | Status |");
  lines.push("| --- | --- | --- | --- |");
  for (const r of rows) {
    if (r.status === "MISSING") {
      lines.push(`| \`${r.key}\` | - | - | ⚠️ MISSING (${r.detail}) |`);
    } else if (r.status === "NEW") {
      lines.push(`| \`${r.key}\` | - | - | 🆕 NEW (${r.detail}) |`);
    } else if (r.status === "FAIL" && r.baseCpu === undefined) {
      lines.push(`| \`${r.key}\` | - | - | ❌ FAIL (${r.detail}) |`);
    } else {
      const icon = r.status === "FAIL" ? "❌ FAIL" : "✓ PASS";
      const budgetNote = r.budgetDetail ? ` — OVER BUDGET: ${r.budgetDetail}` : "";
      lines.push(
        `| \`${r.key}\` | ${r.baseCpu} → ${r.nowCpu} (${fmtPct(r.cpuPct)}) | ${r.baseMem} → ${r.nowMem} (${fmtPct(r.memPct)}) | ${icon}${budgetNote} |`
      );
    }
  }
  lines.push("");
  if (anyRegression) {
    lines.push(
      `❌ One or more calls exceeded the ${args.threshold}% regression threshold. If the increase is intended, ` +
        `regenerate the baseline with \`./scripts/profile-budget.sh --update-baseline\`, commit ` +
        `\`${args.baseline}\`, and explain why in the PR description.`
    );
  } else {
    lines.push(`✓ No call exceeded the ${args.threshold}% regression threshold.`);
  }
  if (budgets) {
    if (anyBudgetBreach) {
      lines.push("", "❌ Absolute worst-case resource budget exceeded:");
      for (const b of breaches) lines.push(`- \`${b.key}\`: ${b.detail}`);
    } else {
      lines.push("", "✓ All measured calls are within their absolute worst-case resource budgets.");
    }
  }
  if (anyMissing) {
    lines.push(
      "",
      "⚠️ Metrics marked MISSING were not measured this run (their contract's `profile_budget` " +
        "tests did not build/run -- see the job log). This does not fail the check; it means that " +
        "call's footprint was not verified this run."
    );
  }
  const report = lines.join("\n");

  console.log(report);

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, report + "\n");
  }

  process.exit(anyRegression || anyBudgetBreach ? 1 : 0);
}

main();
