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
 *   --receipt[=<path>]                    Path to write JSON audit receipt (default: audit-receipt.json)
 *   --manifest[=<path>]                   Generate baseline artifact manifest bundle (default: artifact-manifest.json)
 *   --verify-with=<cmd>                   Independent verifier command (e.g. claude or agy)
 *   --verification-report=<path>          Path to write verification record JSON (default: verification-record.json)
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
import { generateManifestBundle } from "../src/core/manifest-bundle.mjs";
import { createMockCorpusAdapters, getCorpusCaseById, buildSynthesizedChangeSet } from "../tests/fixtures/real-corpus-fixtures.mjs";
import {
  conductIndependentVerification,
  validateVerifierCommand,
  createMockVerifierAdapter,
  buildDisagreementLedgerDocument,
  CliVerifierAdapter,
  VERIFICATION_SCHEMA_VERSION
} from "../src/core/independent-verifier.mjs";

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
  receipt: { type: "string" },
  manifest: { type: "string" },
  "verify-with": { type: "string" },
  "verification-report": { type: "string" },
  strict: { type: "boolean", default: false },
  help: { type: "boolean", short: "h", default: false }
};

const rawArgs = process.argv.slice(2);
const normalizedArgs = [];
for (let i = 0; i < rawArgs.length; i++) {
  const arg = rawArgs[i];
  if (arg === "--receipt") {
    const next = rawArgs[i + 1];
    if (next && !next.startsWith("-")) {
      normalizedArgs.push(`--receipt=${next}`);
      i++;
    } else {
      normalizedArgs.push("--receipt=audit-receipt.json");
    }
  } else if (arg === "--manifest") {
    const next = rawArgs[i + 1];
    if (next && !next.startsWith("-")) {
      normalizedArgs.push(`--manifest=${next}`);
      i++;
    } else {
      normalizedArgs.push("--manifest=artifact-manifest.json");
    }
  } else if (arg === "--verify-with") {
    const next = rawArgs[i + 1];
    if (next && !next.startsWith("-")) {
      normalizedArgs.push(`--verify-with=${next}`);
      i++;
    }
  } else if (arg === "--verification-report") {
    const next = rawArgs[i + 1];
    if (next && !next.startsWith("-")) {
      normalizedArgs.push(`--verification-report=${next}`);
      i++;
    } else {
      normalizedArgs.push("--verification-report=verification-record.json");
    }
  } else {
    normalizedArgs.push(arg);
  }
}

let values;
try {
  const parsed = parseArgs({ args: normalizedArgs, options: optionsConfig, allowPositionals: true });
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
  --receipt[=<path>]                    Path to write JSON audit receipt (default: audit-receipt.json)
  --manifest[=<path>]                   Generate baseline artifact manifest bundle (default: artifact-manifest.json)
  --verify-with=<cmd>                   Independent verifier command (e.g. claude or agy)
  --verification-report=<path>          Path to write verification record JSON (default: verification-record.json)
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
  let verifierProfile = null;
  if (values["verify-with"]) {
    try {
      verifierProfile = validateVerifierCommand(values["verify-with"]);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  }

  const isLive = Boolean(values.live) || process.env.TRIAD_LIVE_BENCHMARK === "1";
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
  const additionalArtifacts = {};

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

  // Save audit-receipt.json alongside benchmark-results.json when --receipt or --report is given
  const receiptTarget = values.receipt
    ? (typeof values.receipt === "string" && values.receipt.trim().length > 0
        ? path.resolve(values.receipt.trim())
        : (reportPath ? path.join(path.dirname(reportPath), "audit-receipt.json") : path.resolve("audit-receipt.json")))
  : (reportPath ? path.join(path.dirname(reportPath), "audit-receipt.json") : null);

  if (receiptTarget && runResult.receipt) {
    fs.mkdirSync(path.dirname(receiptTarget), { recursive: true });
    fs.writeFileSync(receiptTarget, JSON.stringify(runResult.receipt, null, 2) + "\n", "utf8");
    console.log(`Benchmark audit receipt saved to: ${receiptTarget}`);
  }

  // Independent verification when --verify-with is specified
  if (verifierProfile) {
    console.log(`\n[TF-RBC-v0] Initiating Independent Verification with '${verifierProfile.id}'...`);
    let verifierAdapter;
    if (isLive) {
      console.log(`[TF-RBC-v0] Initializing live independent verifier: '${verifierProfile.id}'`);
      verifierAdapter = new CliVerifierAdapter({
        command: verifierProfile.command,
        providerName: verifierProfile.id,
        modelName: "cli-default"
      });
    } else {
      console.log(`[TF-RBC-v0] Using high-fidelity offline mock verifier for '${verifierProfile.id}'.`);
      verifierAdapter = createMockVerifierAdapter(verifierProfile.id);
    }

    const verificationTarget = values["verification-report"]
      ? path.resolve(values["verification-report"].trim())
      : (reportPath ? path.join(path.dirname(reportPath), "verification-record.json") : path.resolve("verification-record.json"));
    const disagreementLedgerTarget = path.join(path.dirname(verificationTarget), "disagreement-ledger.json");

    let verificationRecord = null;
    const caseResults = runResult.caseResults || [];

    if (caseResults.length === 1) {
      const c = caseResults[0];
      const cs = c.changeSet || buildSynthesizedChangeSet(getCorpusCaseById(c.caseId));
      verificationRecord = await conductIndependentVerification(
        cs,
        c.actualFindings || [],
        verifierAdapter,
        {
          producerName: macroCmd,
          verifierName: verifierProfile.id,
          changeSetDigest: cs?.contentDigest
        }
      );
    } else if (caseResults.length > 1) {
      const caseRecords = {};
      for (const c of caseResults) {
        const cs = c.changeSet || buildSynthesizedChangeSet(getCorpusCaseById(c.caseId));
        const rec = await conductIndependentVerification(
          cs,
          c.actualFindings || [],
          verifierAdapter,
          {
            producerName: macroCmd,
            verifierName: verifierProfile.id,
            changeSetDigest: cs?.contentDigest
          }
        );
        caseRecords[c.caseId] = rec;
      }
      verificationRecord = {
        schemaVersion: VERIFICATION_SCHEMA_VERSION,
        verifiedAt: new Date().toISOString(),
        verifier: {
          providerName: verifierProfile.id,
          modelName: "cli-default"
        },
        cases: caseRecords,
        summary: {
          totalCases: caseResults.length,
          totalEvaluated: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.totalEvaluated || 0), 0),
          supportedCount: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.supportedCount || 0), 0),
          partiallySupportedCount: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.partiallySupportedCount || 0), 0),
          contestedCount: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.contestedCount || 0), 0),
          insufficientEvidenceCount: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.insufficientEvidenceCount || 0), 0),
          omissionsCount: Object.values(caseRecords).reduce((s, r) => s + (r.summary?.omissionsCount || 0), 0)
        }
      };
    }

    if (verificationRecord) {
      fs.mkdirSync(path.dirname(verificationTarget), { recursive: true });
      fs.writeFileSync(verificationTarget, JSON.stringify(verificationRecord, null, 2) + "\n", "utf8");
      console.log(`Independent verification record saved to: ${verificationTarget}`);
      additionalArtifacts[path.basename(verificationTarget)] = verificationTarget;

      if (verificationRecord.disagreementLedger) {
        const ledgerDoc = buildDisagreementLedgerDocument({
          verificationRecord,
          producerRunId: runResult.runId || runResult.receipt?.run?.runId || "unknown",
          commitSha: runResult.receipt?.systemProvenance?.commitSha || "unknown"
        });
        fs.writeFileSync(disagreementLedgerTarget, JSON.stringify(ledgerDoc, null, 2) + "\n", "utf8");
        console.log(`Disagreement ledger saved to: ${disagreementLedgerTarget}`);
        additionalArtifacts[path.basename(disagreementLedgerTarget)] = disagreementLedgerTarget;
      }
    }
  }

  // Generate baseline artifact manifest bundle when --manifest is specified
  if (values.manifest) {
    const isManifestDefault = !values.manifest || values.manifest === "true" || values.manifest === "artifact-manifest.json";
    const manifestTarget = isManifestDefault
      ? (reportPath ? path.join(path.dirname(reportPath), "artifact-manifest.json") : path.resolve("artifact-manifest.json"))
      : path.resolve(values.manifest.trim());

    const bundle = generateManifestBundle({
      targetDir: path.dirname(manifestTarget),
      resultsPath: reportPath || path.join(path.dirname(manifestTarget), "benchmark-results.json"),
      receiptPath: receiptTarget || path.join(path.dirname(manifestTarget), "audit-receipt.json"),
      manifestPath: manifestTarget,
      resultsData: runResult,
      receiptData: runResult.receipt,
      additionalArtifacts: Object.keys(additionalArtifacts).length > 0 ? additionalArtifacts : null
    });
    console.log(`Baseline artifact manifest bundle generated: ${bundle.manifestPath}`);
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
