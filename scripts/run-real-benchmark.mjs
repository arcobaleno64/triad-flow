#!/usr/bin/env node
/**
 * Triad-Flow Real Benchmark Runner CLI Script (TF-RBC-v0)
 *
 * Usage:
 *   node scripts/run-real-benchmark.mjs [options]
 *
 * Options:
 *   --mode=<single|dual|risk-routed|all>  Evaluation configuration mode (default: single)
 *   --macro-cmd=<cmd>                     Command for macro sentry (default: agy)
 *   --micro-cmd=<cmd>                     Command for micro sentry (default: claude)
 *   --live                                Use real CLI child processes instead of fast offline mocks
 *   --case=<id>                           Evaluate specific corpus case (e.g. BENCH-REAL-001)
 *   --limit=<n>                           Limit number of cases evaluated
 *   --report=<path>                       Path to write JSON benchmark report (default: benchmark-results.json)
 *   --strict                              Enable strict gate mode
 *   -h, --help                            Show help and usage information
 */

import { parseArgs } from "node:util";
import fs from "node:fs";
import path from "node:path";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import {
  evaluateCorpusSuite,
  formatBenchmarkSummary
} from "../src/core/real-benchmark-runner.mjs";
import { createMockCorpusAdapters } from "../tests/fixtures/real-corpus-fixtures.mjs";

const optionsConfig = {
  mode: { type: "string", default: "single" },
  "macro-cmd": { type: "string", default: "agy" },
  "micro-cmd": { type: "string", default: "claude" },
  live: { type: "boolean", default: false },
  virtual: { type: "boolean" },
  timeout: { type: "string" },
  case: { type: "string" },
  limit: { type: "string" },
  report: { type: "string", default: "benchmark-results.json" },
  strict: { type: "boolean", default: false },
  help: { type: "boolean", short: "h", default: false }
};

let values;
try {
  const parsed = parseArgs({ options: optionsConfig, allowPositionals: true });
  values = parsed.values;
} catch (err) {
  console.error(`Argument error: ${err.message}`);
  process.exit(1);
}

if (values.help) {
  console.log(`
Triad-Flow Real Benchmark Runner (TF-RBC-v0)

Options:
  --mode=<single|dual|risk-routed|all>  Evaluation configuration mode (default: single)
  --macro-cmd=<cmd>                     Command for macro sentry (default: agy)
  --micro-cmd=<cmd>                     Command for micro sentry (default: claude)
  --live                                Use real CLI child processes instead of fast offline mocks
  --virtual                             Force fast in-memory synthetic workspaces (default: true for mock, false for live)
  --timeout=<ms>                        Subprocess execution timeout in ms (default: 90000 for live, 30000 for mock)
  --case=<id>                           Evaluate specific corpus case (e.g. BENCH-REAL-001)
  --limit=<n>                           Limit number of cases evaluated
  --report=<path>                       Path to write JSON benchmark report (default: benchmark-results.json)
  --strict                              Enable strict gate mode (exits non-zero on case failure)
  -h, --help                            Show help and usage information
  `);
  process.exit(0);
}

const VALID_MODES = new Set(["single", "dual", "risk-routed", "all"]);
if (values.mode && !VALID_MODES.has(values.mode)) {
  console.error(`Error: Invalid --mode='${values.mode}'. Must be one of: ${Array.from(VALID_MODES).join(", ")}`);
  process.exit(1);
}

let parsedLimit = undefined;
if (values.limit !== undefined) {
  parsedLimit = parseInt(values.limit, 10);
  if (!Number.isFinite(parsedLimit) || parsedLimit <= 0) {
    console.error(`Error: Invalid --limit='${values.limit}'. Must be a positive integer.`);
    process.exit(1);
  }
}

let parsedTimeout = undefined;
if (values.timeout !== undefined) {
  parsedTimeout = parseInt(values.timeout, 10);
  if (!Number.isFinite(parsedTimeout) || parsedTimeout <= 0) {
    console.error(`Error: Invalid --timeout='${values.timeout}'. Must be a positive integer in milliseconds.`);
    process.exit(1);
  }
}

async function main() {
  const isLive = Boolean(values.live);
  if (isLive && values.virtual) {
    console.error("Error: Live evaluation requires physical repository workspace (--live and --virtual cannot be combined).");
    process.exit(1);
  }
  const mode = values.mode || "single";
  const macroCmd = values["macro-cmd"] || "agy";
  const microCmd = values["micro-cmd"] || "claude";
  const isVirtual = values.virtual !== undefined ? Boolean(values.virtual) : !isLive;
  const timeoutMs = parsedTimeout || (isLive ? 90000 : 30000);
  const reportPath = values.report ? path.resolve(values.report) : null;

  console.log(`[TF-RBC-v0] Starting benchmark run... (mode: ${mode}, live: ${isLive}, virtual: ${isVirtual})`);

  let adapters;
  if (isLive) {
    console.log(`[TF-RBC-v0] Initializing live provider adapters: macro='${macroCmd}', micro='${microCmd}'`);
    adapters = {
      macro: new CliReviewAdapter({ command: macroCmd }),
      micro: new CliReviewAdapter({ command: microCmd })
    };
  } else {
    console.log("[TF-RBC-v0] Using high-fidelity offline mock adapters (< 2s execution).");
    adapters = createMockCorpusAdapters();
  }

  const suiteOptions = {
    mode,
    live: isLive,
    executionMode: isLive ? "live" : "mock",
    virtual: isVirtual,
    workspaceMode: isVirtual ? "virtual" : "physical",
    timeoutMs,
    strict: values.strict,
    ...(values.case ? { case: values.case } : {}),
    ...(parsedLimit ? { limit: parsedLimit } : {})
  };

  const startTime = Date.now();
  const runResult = await evaluateCorpusSuite(undefined, adapters, suiteOptions);
  const totalElapsed = Date.now() - startTime;

  console.log("\n" + formatBenchmarkSummary(runResult));
  console.log(`\nExecution completed in ${(totalElapsed / 1000).toFixed(2)}s.`);

  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(runResult, null, 2) + "\n", "utf8");
    console.log(`Benchmark audit report saved to: ${reportPath}`);
  }

  // If strict mode is requested, enforce non-zero exit on failures
  if (values.strict) {
    let hasFailures = false;
    if (runResult.mode === "all" && runResult.configurations) {
      hasFailures = Object.values(runResult.configurations).some(cfg =>
        (cfg.caseResults || []).some(c => !c.passed)
      );
    } else if (runResult.caseResults) {
      hasFailures = runResult.caseResults.some(c => !c.passed);
    }

    if (hasFailures) {
      console.error("\n[TF-RBC-v0] Strict Mode Failure: Benchmark run contains failed cases or false blocks.");
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error(`\n[TF-RBC-v0] Fatal error during benchmark execution:\n${err.stack || err.message}`);
  process.exit(1);
});
