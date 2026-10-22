#!/usr/bin/env node
/**
 * Operator tooling to inspect and retry event dead letters (Issue #267).
 *
 * Drives, through the Stellar CLI, a contract that forwards these entry points
 * to `shared::event_dead_letter` (see docs/EVENT_DEAD_LETTER.md):
 *
 *   dlq_summary()                              -> EventDeadLetterSummary
 *   dlq_list(status, due_by, offset, limit)    -> EventDeadLetterPage
 *   dlq_get(id)                                -> Option<EventDeadLetter>
 *   dlq_retry(id)                              -> DispatchOutcome   (anyone)
 *   dlq_requeue(admin, ids)                    -> BatchResult       (admin)
 *   dlq_discard(admin, id)                     -> EventDeadLetter   (admin)
 *
 * Usage:
 *   node scripts/dead-letter-ops.cjs <command> [args] [options]
 *
 * Commands:
 *   summary                                Queue depth
 *   list [--status S] [--due]              One page of letters; S = Pending | DeadLettered
 *        [--offset N] [--limit N]          (default DeadLettered); --due keeps letters
 *                                          due at the latest ledger
 *   show <id>                              One letter
 *   retry <id>                             Retry one due Pending letter
 *   retry-due [--max N]                    Retry every Pending letter due now (default max 25)
 *   requeue <id>... --admin <address>      Requeue DeadLettered letters, 25 ids per transaction
 *   discard <id> --admin <address>         Drop a DeadLettered letter (record kept for audit)
 *
 * Options:
 *   --contract <id>    Contract forwarding the dlq_* entry points (env DLQ_CONTRACT_ID)
 *   --source <key>     Stellar CLI identity that signs (env DLQ_SOURCE, default: operator)
 *   --network <name>   Stellar CLI network (env STELLAR_NETWORK, default: testnet)
 *   --dry-run          Print the CLI invocations instead of running them
 *   --help             Show this help
 *
 * Reads (summary, list, show, and the scan inside retry-due) are simulated with
 * `--send no` and never submit a transaction.
 *
 * Exit codes: 0 = ok, 1 = an operation failed, 2 = usage error.
 * Env: STELLAR_BIN overrides the stellar executable name/path.
 */
"use strict";

const { spawnSync } = require("child_process");

const STELLAR = process.env.STELLAR_BIN || "stellar";
// Mirrors shared::event_dead_letter::MAX_REQUEUE_BATCH.
const MAX_REQUEUE_BATCH = 25;
const PAGE_LIMIT = 50;
const STATUSES = ["Pending", "DeadLettered"];

class UsageError extends Error {}

function usage() {
  const header = require("fs").readFileSync(__filename, "utf8").split("*/")[0];
  console.log(header.replace(/^#!.*\n\/\*\*\n/, "").replace(/^ \* ?/gm, ""));
}

function parseArgs(argv) {
  const flags = new Set(["dry-run", "due", "help"]);
  const opts = { positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      opts.positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (flags.has(name)) {
      opts[name] = true;
    } else if (i + 1 < argv.length) {
      opts[name] = argv[++i];
    } else {
      throw new UsageError(`missing value for ${arg}`);
    }
  }
  return opts;
}

function count(value, name) {
  if (!/^\d+$/.test(String(value))) throw new UsageError(`${name} must be a non-negative integer`);
  return Number(value);
}

function run(args, opts) {
  if (opts["dry-run"]) {
    console.log([STELLAR, ...args].map((a) => (/[\s"'[\]<>]/.test(a) ? `'${a}'` : a)).join(" "));
    return undefined;
  }
  const result = spawnSync(STELLAR, args, { encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || `exit ${result.status}`).trim());
  }
  const out = result.stdout.trim();
  try {
    return out ? JSON.parse(out) : null;
  } catch {
    return out;
  }
}

function invoke(opts, fn, fnArgs, { read = false } = {}) {
  const contract = opts.contract || process.env.DLQ_CONTRACT_ID;
  if (!contract) throw new UsageError("set --contract or DLQ_CONTRACT_ID");
  const args = [
    "contract", "invoke",
    "--id", contract,
    "--source-account", opts.source || process.env.DLQ_SOURCE || "operator",
    "--network", network(opts),
  ];
  if (read) args.push("--send", "no");
  return run([...args, "--", fn, ...fnArgs], opts);
}

function network(opts) {
  return opts.network || process.env.STELLAR_NETWORK || "testnet";
}

function latestLedger(opts) {
  const info = run(["ledger", "latest", "--network", network(opts), "--output", "json"], opts);
  return info === undefined ? "<latest-ledger>" : String(info.sequence);
}

function listPage(opts, status, dueBy, offset, limit) {
  const args = ["--status", status, "--offset", String(offset), "--limit", String(limit)];
  if (dueBy !== undefined) args.push("--due_by", dueBy);
  return invoke(opts, "dlq_list", args, { read: true });
}

function printLetters(page) {
  for (const r of page.records) {
    console.log(
      `#${r.id}  ${r.status}  event=${r.event.name}  attempts=${r.attempts}  ` +
        `last_error=${r.last_error}  next_attempt_ledger=${r.next_attempt_ledger}`
    );
  }
  console.log(`(${page.records.length} shown, next_offset=${page.next_offset}, has_more=${page.has_more})`);
}

function ids(opts, min) {
  if (opts.positional.length < min) throw new UsageError("missing <id>");
  return opts.positional.map((id) => count(id, "id"));
}

const COMMANDS = {
  summary(opts) {
    const summary = invoke(opts, "dlq_summary", [], { read: true });
    if (summary) console.log(JSON.stringify(summary, null, 2));
  },

  list(opts) {
    const status = opts.status || "DeadLettered";
    if (!STATUSES.includes(status)) throw new UsageError(`--status must be one of ${STATUSES.join(", ")}`);
    const dueBy = opts.due ? latestLedger(opts) : undefined;
    const page = listPage(opts, status, dueBy, count(opts.offset || 0, "--offset"), count(opts.limit || 20, "--limit"));
    if (page) printLetters(page);
  },

  show(opts) {
    const [id] = ids(opts, 1);
    const letter = invoke(opts, "dlq_get", ["--id", String(id)], { read: true });
    if (letter !== undefined) console.log(letter ? JSON.stringify(letter, null, 2) : `#${id} not found`);
  },

  retry(opts) {
    const [id] = ids(opts, 1);
    const outcome = invoke(opts, "dlq_retry", ["--id", String(id)]);
    if (outcome !== undefined) console.log(`#${id} -> ${JSON.stringify(outcome)}`);
  },

  "retry-due"(opts) {
    const max = count(opts.max || MAX_REQUEUE_BATCH, "--max");
    const dueBy = latestLedger(opts);
    // Collect first: each successful retry removes its id from the Pending index.
    const due = [];
    for (let offset = 0; due.length < max; ) {
      const page = listPage(opts, "Pending", dueBy, offset, PAGE_LIMIT);
      if (!page) return; // dry run
      due.push(...page.records.slice(0, max - due.length).map((r) => r.id));
      if (!page.has_more) break;
      offset = page.next_offset;
    }
    let failed = 0;
    for (const id of due) {
      try {
        console.log(`#${id} -> ${JSON.stringify(invoke(opts, "dlq_retry", ["--id", String(id)]))}`);
      } catch (err) {
        failed++;
        console.error(`#${id} failed: ${err.message}`);
      }
    }
    console.log(`retried ${due.length - failed}/${due.length} due letters`);
    if (failed) process.exitCode = 1;
  },

  requeue(opts) {
    if (!opts.admin) throw new UsageError("--admin <address> is required");
    const all = ids(opts, 1);
    for (let i = 0; i < all.length; i += MAX_REQUEUE_BATCH) {
      const chunk = all.slice(i, i + MAX_REQUEUE_BATCH);
      const report = invoke(opts, "dlq_requeue", ["--admin", opts.admin, "--ids", JSON.stringify(chunk)]);
      if (!report) continue;
      chunk.forEach((id, n) => console.log(`#${id} -> ${JSON.stringify(report.results[n])}`));
      if (report.failed > 0) process.exitCode = 1;
    }
  },

  discard(opts) {
    if (!opts.admin) throw new UsageError("--admin <address> is required");
    const [id] = ids(opts, 1);
    const letter = invoke(opts, "dlq_discard", ["--admin", opts.admin, "--id", String(id)]);
    if (letter !== undefined) console.log(`#${id} discarded`);
  },
};

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
    const command = opts.positional.shift();
    if (opts.help || !command) return usage();
    if (!COMMANDS[command]) throw new UsageError(`unknown command: ${command}`);
    COMMANDS[command](opts);
  } catch (err) {
    console.error(`dead-letter-ops: ${err.message}`);
    process.exitCode = err instanceof UsageError ? 2 : 1;
  }
}

main();
