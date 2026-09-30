/**
 * Triad-Flow CLI: Command Routing, Capability Doctor, Simulation Demo & Real Review
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { SpanTracer } from "./core/telemetry.mjs";
import { evaluateDiffScale } from "./core/graph-router.mjs";
import { aggregateConsensus } from "./core/loop.mjs";
import { evaluateGateDecision, formatSarifReport } from "./core/harness.mjs";
import { collectGitWorkingState, buildChangeSet } from "./core/git-collector.mjs";
import { runFactoryPipeline } from "./core/factory.mjs";
import { orchestrateReview } from "./adapters/review-orchestrator.mjs";
import { CliReviewAdapter } from "./adapters/cli-transport.mjs";
import { buildReviewRunReport, REVIEW_RUN_STATUS } from "./core/review-run-report.mjs";
import { collectDoctorReport, formatDoctorReport } from "./core/doctor.mjs";
import { evaluateCorpusSuite, formatBenchmarkSummary } from "./core/real-benchmark-runner.mjs";
import { generateManifestBundle } from "./core/manifest-bundle.mjs";
import { createMockCorpusAdapters, getCorpusCaseById, buildSynthesizedChangeSet, createCorpusCaseWorkspace, createCorpusMultiCaseWorkspace } from "../tests/fixtures/real-corpus-fixtures.mjs";
import {
  ControlledRemediationSession,
  REMEDIATION_STATES,
  computeRemediationReceiptDigest
} from "./core/controlled-remediation.mjs";
import {
  BatchRemediationSession,
  BATCH_REMEDIATION_STATES,
  BATCH_VERDICTS,
  validateBatchReceipt
} from "./core/batch-remediation.mjs";
import {
  resolveSandboxDriver,
  SandboxUnavailableError,
  SANDBOX_DRIVERS
} from "./core/sandbox-driver.mjs";
import {
  conductIndependentVerification,
  validateVerifierCommand,
  createMockVerifierAdapter,
  buildDisagreementLedgerDocument,
  CliVerifierAdapter,
  VERIFICATION_SCHEMA_VERSION
} from "./core/independent-verifier.mjs";

export const EXIT_CODES = {
  SUCCESS: 0,
  GATE_BLOCKED: 1,
  USAGE_ERROR: 2,
  SYSTEM_FAILURE: 3
};

function printBanner(io, title) {
  io.stderr.write("\n=======================================================\n");
  io.stderr.write(`  ${title}\n`);
  io.stderr.write("=======================================================\n\n");
}

export function normalizeCommandName(cmd) {
  if (!cmd || typeof cmd !== "string") return "";
  const base = path.basename(cmd.trim()).toLowerCase();
  return base.replace(/\.(exe|cmd|bat|ps1|js|mjs)$/i, "");
}

export function extractFindingsFromReport(reportData) {
  if (!reportData || typeof reportData !== "object") return [];

  // 1. Check for consensus findings (Triad-Flow review report / audit report)
  if (Array.isArray(reportData.consensus?.findings)) {
    return reportData.consensus.findings.map((f, idx) => ({
      id: f.id || f.findingId || `FINDING-${idx + 1}`,
      targetFiles: f.file ? [f.file] : (Array.isArray(f.targetFiles) ? f.targetFiles : []),
      severity: f.severity || "medium",
      title: f.title || f.ruleId || "Security Finding",
      rationale: f.rationale || f.body || f.description || "",
      patch: f.patch || null
    }));
  }

  // 2. Direct findings array
  if (Array.isArray(reportData.findings)) {
    return reportData.findings.map((f, idx) => ({
      id: f.id || f.findingId || `FINDING-${idx + 1}`,
      targetFiles: f.file ? [f.file] : (Array.isArray(f.targetFiles) ? f.targetFiles : []),
      severity: f.severity || "medium",
      title: f.title || f.ruleId || "Security Finding",
      rationale: f.rationale || f.body || f.description || "",
      patch: f.patch || null
    }));
  }

  // 3. Review run report format (review-run-report.mjs)
  if (reportData.reviewRun && Array.isArray(reportData.reviewRun.findings)) {
    return reportData.reviewRun.findings.map((f, idx) => ({
      id: f.id || `FINDING-${idx + 1}`,
      targetFiles: f.file ? [f.file] : [],
      severity: f.severity || "medium",
      title: f.title || "Security Finding",
      patch: null
    }));
  }

  // 4. SARIF format (runs[0].results)
  if (Array.isArray(reportData.runs) && reportData.runs[0] && Array.isArray(reportData.runs[0].results)) {
    return reportData.runs[0].results.map((r, idx) => {
      const file = r.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
      const targetFiles = file ? [file] : [];
      const sevMap = { error: "critical", warning: "high", note: "medium" };
      return {
        id: r.ruleId || `SARIF-${idx + 1}`,
        targetFiles,
        severity: sevMap[r.level] || "medium",
        title: r.message?.text || r.ruleId || "SARIF Result",
        rationale: r.message?.text || "",
        patch: null
      };
    });
  }

  // 5. Benchmark report (caseResults)
  if (Array.isArray(reportData.caseResults)) {
    const list = [];
    for (const c of reportData.caseResults) {
      if (Array.isArray(c.findings)) {
        list.push(...c.findings.map((f, idx) => ({
          id: f.id || `${c.caseId || "CASE"}-F${idx + 1}`,
          targetFiles: f.file ? [f.file] : [],
          severity: f.severity || "medium",
          title: f.title || "Benchmark Finding",
          patch: null
        })));
      }
    }
    return list;
  }

  return [];
}

export async function runCli(argv = process.argv.slice(2), io = { stdout: process.stdout, stderr: process.stderr }, options = {}) {
  const strictArg = argv.includes("--strict") || Boolean(options.strict);
  const stagedArg = argv.includes("--staged") || Boolean(options.staged);

  const consumedArgsIndices = new Set();
  const isTriadFlag = (arg) => {
    if (!arg || typeof arg !== "string" || !arg.startsWith("--")) return false;
    const name = arg.split("=")[0];
    return [
      "--format",
      "--strict",
      "--staged",
      "--base",
      "--head",
      "--report",
      "--output-run",
      "--receipt",
      "--manifest",
      "--verify-with",
      "--verification-report",
      "--macro-cmd",
      "--micro-cmd",
      "--macro-args",
      "--micro-args",
      "--mode",
      "--case",
      "--cases",
      "--limit",
      "--timeout",
      "--live",
      "--virtual",
      "--diff",
      "--authorizer",
      "--synthesizer",
      "--plan-only",
      "--batch",
      "--sandbox"
    ].includes(name);
  };

  const VALUE_FLAGS = new Set([
    "--format",
    "--base",
    "--head",
    "--report",
    "--output-run",
    "--receipt",
    "--manifest",
    "--verify-with",
    "--verification-report",
    "--macro-cmd",
    "--micro-cmd",
    "--macro-args",
    "--micro-args",
    "--mode",
    "--case",
    "--cases",
    "--limit",
    "--timeout",
    "--diff",
    "--authorizer",
    "--synthesizer",
    "--sandbox"
  ]);

  for (let i = 0; i < argv.length; i++) {
    if (VALUE_FLAGS.has(argv[i]) && argv[i + 1] && !argv[i + 1].startsWith("--")) {
      consumedArgsIndices.add(i + 1);
    }
  }

  const positionalArgs = argv.filter((a, idx) => !a.startsWith("--") && !consumedArgsIndices.has(idx));
  const command = positionalArgs[0] || "doctor";

  let formatArg = "text";
  const formatExplicit = argv.find(a => a.startsWith("--format="));
  if (formatExplicit) {
    formatArg = formatExplicit.slice("--format=".length);
  } else {
    const formatIdx = argv.indexOf("--format");
    if (formatIdx !== -1 && argv[formatIdx + 1] && !argv[formatIdx + 1].startsWith("--")) {
      formatArg = argv[formatIdx + 1];
    }
  }
  if (options.format) {
    formatArg = options.format;
  }

  let baseArg = null;
  const baseExplicit = argv.find(a => a.startsWith("--base="));
  if (baseExplicit) {
    baseArg = baseExplicit.slice("--base=".length);
  } else {
    const baseIdx = argv.indexOf("--base");
    if (baseIdx !== -1 && argv[baseIdx + 1] && !argv[baseIdx + 1].startsWith("--")) {
      baseArg = argv[baseIdx + 1];
    }
  }

  let headArg = null;
  const headExplicit = argv.find(a => a.startsWith("--head="));
  if (headExplicit) {
    headArg = headExplicit.slice("--head=".length);
  } else {
    const headIdx = argv.indexOf("--head");
    if (headIdx !== -1 && argv[headIdx + 1] && !argv[headIdx + 1].startsWith("--")) {
      headArg = argv[headIdx + 1];
    }
  }

  let reportArg = null;
  const reportExplicit = argv.find(a => a.startsWith("--report=") || a.startsWith("--output-run="));
  if (reportExplicit) {
    reportArg = reportExplicit.slice(reportExplicit.indexOf("=") + 1);
  } else {
    const reportIdx = argv.findIndex(a => a === "--report" || a === "--output-run");
    if (reportIdx !== -1 && argv[reportIdx + 1] && !argv[reportIdx + 1].startsWith("--")) {
      reportArg = argv[reportIdx + 1];
    }
  }

  let receiptArg = null;
  const receiptExplicit = argv.find(a => a.startsWith("--receipt="));
  if (receiptExplicit) {
    receiptArg = receiptExplicit.slice("--receipt=".length);
  } else {
    const receiptIdx = argv.indexOf("--receipt");
    if (receiptIdx !== -1) {
      if (argv[receiptIdx + 1] && !argv[receiptIdx + 1].startsWith("--")) {
        receiptArg = argv[receiptIdx + 1];
        consumedArgsIndices.add(receiptIdx + 1);
      } else {
        receiptArg = "audit-receipt.json";
      }
    }
  }

  let manifestArg = null;
  const manifestExplicit = argv.find(a => a.startsWith("--manifest="));
  if (manifestExplicit) {
    manifestArg = manifestExplicit.slice("--manifest=".length);
  } else {
    const manifestIdx = argv.indexOf("--manifest");
    if (manifestIdx !== -1) {
      if (argv[manifestIdx + 1] && !argv[manifestIdx + 1].startsWith("--")) {
        manifestArg = argv[manifestIdx + 1];
        consumedArgsIndices.add(manifestIdx + 1);
      } else {
        manifestArg = "artifact-manifest.json";
      }
    }
  }

  let verifyWithArg = null;
  const verifyWithExplicit = argv.find(a => a.startsWith("--verify-with="));
  if (verifyWithExplicit) {
    verifyWithArg = verifyWithExplicit.slice("--verify-with=".length);
  } else {
    const verifyWithIdx = argv.indexOf("--verify-with");
    if (verifyWithIdx !== -1 && argv[verifyWithIdx + 1] && !argv[verifyWithIdx + 1].startsWith("--")) {
      verifyWithArg = argv[verifyWithIdx + 1];
    }
  }
  verifyWithArg = verifyWithArg || options.verifyWith || null;
  if (typeof verifyWithArg === "string") {
    verifyWithArg = verifyWithArg.trim() || null;
  }

  let verificationReportArg = null;
  const verificationReportExplicit = argv.find(a => a.startsWith("--verification-report="));
  if (verificationReportExplicit) {
    verificationReportArg = verificationReportExplicit.slice("--verification-report=".length);
  } else {
    const verificationReportIdx = argv.indexOf("--verification-report");
    if (verificationReportIdx !== -1) {
      if (argv[verificationReportIdx + 1] && !argv[verificationReportIdx + 1].startsWith("--")) {
        verificationReportArg = argv[verificationReportIdx + 1];
        consumedArgsIndices.add(verificationReportIdx + 1);
      } else {
        verificationReportArg = "verification-record.json";
      }
    }
  }
  verificationReportArg = verificationReportArg || options.verificationReport || null;

  let macroCmd = null;
  const macroCmdExplicit = argv.find(a => a.startsWith("--macro-cmd="));
  if (macroCmdExplicit) {
    macroCmd = macroCmdExplicit.slice("--macro-cmd=".length);
  } else {
    const macroCmdIdx = argv.indexOf("--macro-cmd");
    if (macroCmdIdx !== -1 && argv[macroCmdIdx + 1] && !argv[macroCmdIdx + 1].startsWith("--")) {
      macroCmd = argv[macroCmdIdx + 1];
    }
  }
  macroCmd = macroCmd || options.macroCmd || null;
  if (typeof macroCmd === "string") {
    macroCmd = macroCmd.trim() || null;
  }

  let microCmd = null;
  const microCmdExplicit = argv.find(a => a.startsWith("--micro-cmd="));
  if (microCmdExplicit) {
    microCmd = microCmdExplicit.slice("--micro-cmd=".length);
  } else {
    const microCmdIdx = argv.indexOf("--micro-cmd");
    if (microCmdIdx !== -1 && argv[microCmdIdx + 1] && !argv[microCmdIdx + 1].startsWith("--")) {
      microCmd = argv[microCmdIdx + 1];
    }
  }
  microCmd = microCmd || options.microCmd || null;
  if (typeof microCmd === "string") {
    microCmd = microCmd.trim() || null;
  }

  let macroArgs = null;
  const macroArgsExplicit = argv.find(a => a.startsWith("--macro-args="));
  if (macroArgsExplicit) {
    macroArgs = macroArgsExplicit.slice("--macro-args=".length).split(",").map(s => s.trim()).filter(Boolean);
  } else {
    const macroArgsIdx = argv.indexOf("--macro-args");
    if (macroArgsIdx !== -1 && argv[macroArgsIdx + 1] && !isTriadFlag(argv[macroArgsIdx + 1])) {
      consumedArgsIndices.add(macroArgsIdx + 1);
      macroArgs = argv[macroArgsIdx + 1].split(",").map(s => s.trim()).filter(Boolean);
    }
  }
  if (!macroArgs && options.macroArgs) {
    macroArgs = Array.isArray(options.macroArgs) ? options.macroArgs : String(options.macroArgs).split(",").map(s => s.trim()).filter(Boolean);
  }

  let microArgs = null;
  const microArgsExplicit = argv.find(a => a.startsWith("--micro-args="));
  if (microArgsExplicit) {
    microArgs = microArgsExplicit.slice("--micro-args=".length).split(",").map(s => s.trim()).filter(Boolean);
  } else {
    const microArgsIdx = argv.indexOf("--micro-args");
    if (microArgsIdx !== -1 && argv[microArgsIdx + 1] && !isTriadFlag(argv[microArgsIdx + 1])) {
      consumedArgsIndices.add(microArgsIdx + 1);
      microArgs = argv[microArgsIdx + 1].split(",").map(s => s.trim()).filter(Boolean);
    }
  }
  if (!microArgs && options.microArgs) {
    microArgs = Array.isArray(options.microArgs) ? options.microArgs : String(options.microArgs).split(",").map(s => s.trim()).filter(Boolean);
  }

  let modeArg = null;
  const modeExplicit = argv.find(a => a.startsWith("--mode="));
  if (modeExplicit) {
    modeArg = modeExplicit.slice("--mode=".length);
  } else {
    const modeIdx = argv.indexOf("--mode");
    if (modeIdx !== -1 && argv[modeIdx + 1] && !argv[modeIdx + 1].startsWith("--")) {
      modeArg = argv[modeIdx + 1];
    }
  }
  modeArg = modeArg || options.mode || "single";

  let caseArg = null;
  const caseExplicit = argv.find(a => a.startsWith("--case="));
  if (caseExplicit) {
    caseArg = caseExplicit.slice("--case=".length);
  } else {
    const caseIdx = argv.indexOf("--case");
    if (caseIdx !== -1 && argv[caseIdx + 1] && !argv[caseIdx + 1].startsWith("--")) {
      caseArg = argv[caseIdx + 1];
    }
  }
  caseArg = caseArg || options.case || null;

  let casesArg = null;
  const casesExplicit = argv.find(a => a.startsWith("--cases="));
  if (casesExplicit) {
    casesArg = casesExplicit.slice("--cases=".length);
  } else {
    const casesIdx = argv.indexOf("--cases");
    if (casesIdx !== -1 && argv[casesIdx + 1] && !argv[casesIdx + 1].startsWith("--")) {
      casesArg = argv[casesIdx + 1];
    }
  }
  casesArg = casesArg || options.cases || null;
  if (!casesArg && caseArg && caseArg.includes(",")) {
    casesArg = caseArg;
  }

  const batchArg = argv.includes("--batch") || Boolean(options.batch);

  let limitArg = null;
  const limitExplicit = argv.find(a => a.startsWith("--limit="));
  if (limitExplicit) {
    limitArg = limitExplicit.slice("--limit=".length);
  } else {
    const limitIdx = argv.indexOf("--limit");
    if (limitIdx !== -1 && argv[limitIdx + 1] && !argv[limitIdx + 1].startsWith("--")) {
      limitArg = argv[limitIdx + 1];
    }
  }
  if (limitArg === null && options.limit !== undefined) {
    limitArg = String(options.limit);
  }

  let timeoutArg = null;
  const timeoutExplicit = argv.find(a => a.startsWith("--timeout="));
  if (timeoutExplicit) {
    timeoutArg = timeoutExplicit.slice("--timeout=".length);
  } else {
    const timeoutIdx = argv.indexOf("--timeout");
    if (timeoutIdx !== -1 && argv[timeoutIdx + 1] && !argv[timeoutIdx + 1].startsWith("--")) {
      timeoutArg = argv[timeoutIdx + 1];
    }
  }
  if (timeoutArg === null && options.timeout !== undefined) {
    timeoutArg = String(options.timeout);
  }

  const liveArg = argv.includes("--live") || Boolean(options.live);
  const virtualArg = argv.includes("--virtual") ? true : (options.virtual !== undefined ? Boolean(options.virtual) : undefined);

  let diffArg = null;
  const diffExplicit = argv.find(a => a.startsWith("--diff="));
  if (diffExplicit) {
    diffArg = diffExplicit.slice("--diff=".length);
  } else {
    const diffIdx = argv.indexOf("--diff");
    if (diffIdx !== -1 && argv[diffIdx + 1] && !argv[diffIdx + 1].startsWith("--")) {
      diffArg = argv[diffIdx + 1];
    }
  }
  diffArg = diffArg || options.diff || null;

  let authorizerArg = null;
  const authExplicit = argv.find(a => a.startsWith("--authorizer="));
  if (authExplicit) {
    authorizerArg = authExplicit.slice("--authorizer=".length);
  } else {
    const authIdx = argv.indexOf("--authorizer");
    if (authIdx !== -1 && argv[authIdx + 1] && !argv[authIdx + 1].startsWith("--")) {
      authorizerArg = argv[authIdx + 1];
    }
  }
  authorizerArg = authorizerArg || options.authorizer || null;

  let synthesizerArg = null;
  const synthExplicit = argv.find(a => a.startsWith("--synthesizer="));
  if (synthExplicit) {
    synthesizerArg = synthExplicit.slice("--synthesizer=".length);
  } else {
    const synthIdx = argv.indexOf("--synthesizer");
    if (synthIdx !== -1 && argv[synthIdx + 1] && !argv[synthIdx + 1].startsWith("--")) {
      synthesizerArg = argv[synthIdx + 1];
    }
  }
  synthesizerArg = synthesizerArg || options.synthesizer || null;

  let sandboxArg = null;
  const hasSandboxExplicit = argv.some(a => a.startsWith("--sandbox="));
  const sandboxExplicit = argv.find(a => a.startsWith("--sandbox="));
  if (hasSandboxExplicit) {
    sandboxArg = sandboxExplicit.slice("--sandbox=".length);
  } else {
    const sandboxIdx = argv.indexOf("--sandbox");
    if (sandboxIdx !== -1) {
      if (argv[sandboxIdx + 1] && !argv[sandboxIdx + 1].startsWith("--")) {
        sandboxArg = argv[sandboxIdx + 1];
      } else {
        sandboxArg = "";
      }
    }
  }

  const hasSandboxFlag = hasSandboxExplicit || argv.includes("--sandbox");
  if (!hasSandboxFlag) {
    sandboxArg = options.sandbox || "worktree";
  }

  const planOnlyArg = argv.includes("--plan-only") || Boolean(options.planOnly);

  const isRecognizedArg = (arg) => {
    if (arg.startsWith("--format=") || arg === "--format") return true;
    if (arg === "--strict" || arg === "--staged" || arg === "--plan-only" || arg === "--batch") return true;
    if (arg.startsWith("--base=") || arg === "--base") return true;
    if (arg.startsWith("--head=") || arg === "--head") return true;
    if (arg.startsWith("--report=") || arg === "--report") return true;
    if (arg.startsWith("--receipt=") || arg === "--receipt") return true;
    if (arg.startsWith("--manifest=") || arg === "--manifest") return true;
    if (arg.startsWith("--verify-with=") || arg === "--verify-with") return true;
    if (arg.startsWith("--verification-report=") || arg === "--verification-report") return true;
    if (arg.startsWith("--output-run=") || arg === "--output-run") return true;
    if (arg.startsWith("--macro-cmd=") || arg === "--macro-cmd") return true;
    if (arg.startsWith("--micro-cmd=") || arg === "--micro-cmd") return true;
    if (arg.startsWith("--macro-args=") || arg === "--macro-args") return true;
    if (arg.startsWith("--micro-args=") || arg === "--micro-args") return true;
    if (arg.startsWith("--mode=") || arg === "--mode") return true;
    if (arg.startsWith("--case=") || arg === "--case") return true;
    if (arg.startsWith("--cases=") || arg === "--cases") return true;
    if (arg.startsWith("--limit=") || arg === "--limit") return true;
    if (arg.startsWith("--timeout=") || arg === "--timeout") return true;
    if (arg.startsWith("--diff=") || arg === "--diff") return true;
    if (arg.startsWith("--authorizer=") || arg === "--authorizer") return true;
    if (arg.startsWith("--synthesizer=") || arg === "--synthesizer") return true;
    if (arg.startsWith("--sandbox=") || arg === "--sandbox") return true;
    if (arg === "--live" || arg === "--virtual") return true;
    return false;
  };

  const unknownFlags = argv.filter((a, idx) => a.startsWith("--") && !consumedArgsIndices.has(idx) && !isRecognizedArg(a));
  if (unknownFlags.length > 0) {
    io.stderr.write(`✖ [USAGE ERROR] Unsupported option(s): ${unknownFlags.join(", ")}\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--format" || a === "--format=") && (!formatArg || (argv.includes("--format") && (!argv[argv.indexOf("--format") + 1] || argv[argv.indexOf("--format") + 1].startsWith("--"))))) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--format' requires a <format> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--base" || a === "--base=") && !baseArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--base' requires a <ref> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--head" || a === "--head=") && !headArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--head' requires a <ref> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--report" || a === "--report=" || a === "--output-run" || a === "--output-run=") && !reportArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--report' requires a <file> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--macro-cmd" || a === "--macro-cmd=") && !macroCmd) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--macro-cmd' requires a <cmd> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--micro-cmd" || a === "--micro-cmd=") && !microCmd) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--micro-cmd' requires a <cmd> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--mode" || a === "--mode=") && (!modeArg || (argv.includes("--mode") && (!argv[argv.indexOf("--mode") + 1] || argv[argv.indexOf("--mode") + 1].startsWith("--"))))) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--mode' requires a <mode> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--case" || a === "--case=") && (!caseArg || (argv.includes("--case") && (!argv[argv.indexOf("--case") + 1] || argv[argv.indexOf("--case") + 1].startsWith("--"))))) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--case' requires a <case-id> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--limit" || a === "--limit=") && (!limitArg || (argv.includes("--limit") && (!argv[argv.indexOf("--limit") + 1] || argv[argv.indexOf("--limit") + 1].startsWith("--"))))) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--limit' requires a <number> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--timeout" || a === "--timeout=") && (!timeoutArg || (argv.includes("--timeout") && (!argv[argv.indexOf("--timeout") + 1] || argv[argv.indexOf("--timeout") + 1].startsWith("--"))))) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--timeout' requires a <ms> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--verify-with" || a === "--verify-with=") && !verifyWithArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--verify-with' requires a <cmd> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (argv.some(a => a === "--diff" || a === "--diff=") && !diffArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--diff' requires a <file> argument.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (hasSandboxFlag && (!sandboxArg || !sandboxArg.trim())) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--sandbox' requires a <driver> argument (e.g. --sandbox=worktree or --sandbox=container).\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (headArg && !baseArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--head' requires '--base <ref>' to be specified.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (macroCmd && microCmd) {
    const normMacro = normalizeCommandName(macroCmd);
    const normMicro = normalizeCommandName(microCmd);
    if (normMacro && normMicro && normMacro === normMicro) {
      io.stderr.write(`✖ [USAGE ERROR] Heterogeneity violation: '--macro-cmd' and '--micro-cmd' cannot be identical ('${macroCmd}' vs '${microCmd}').\n`);
      return EXIT_CODES.USAGE_ERROR;
    }
  }

  switch (command) {
    case "doctor": {
      const report = collectDoctorReport({
        cwd: options.cwd || process.cwd(),
        getGitState: options.getGitState,
        execFn: options.execFn,
        timeoutMs: timeoutArg ? parseInt(timeoutArg, 10) : (liveArg ? 60000 : options.timeoutMs),
        env: options.env || process.env,
        reviewers: options.reviewers,
        live: liveArg
      });

      const formatted = formatDoctorReport(report, formatArg);
      if (formatArg === "json") {
        io.stdout.write(formatted);
      } else {
        io.stderr.write(formatted);
      }

      return EXIT_CODES.SUCCESS;
    }

    case "demo": {
      printBanner(io, "Triad-Flow • Deterministic Simulation [DEMO / SIMULATION MODE]");
      const tracer = new SpanTracer("triad-flow-demo");
      const rootSpan = tracer.startSpan("simulation-run");

      io.stderr.write("1️⃣  [Simulation] Evaluating sample Diff topology...\n");
      const sampleFiles = [
        { path: "src/auth/jwt.ts", additions: 45, deletions: 12 },
        { path: "src/utils/calc.ts", additions: 10, deletions: 2 }
      ];
      const plan = evaluateDiffScale(sampleFiles);
      io.stderr.write(`  ▶ Simulated Mode: ${plan.mode.toUpperCase()} (${plan.reason})\n`);
      io.stderr.write(`  ⚡ Simulated Swarm: ${plan.subagents.join(", ")}\n\n`);

      io.stderr.write("2️⃣  [Simulation] Synthesizing mock multi-sentry findings...\n");
      const mockMacro = {
        name: "macro-sentry",
        findings: [
          { severity: "critical", title: "Unvalidated Token Signature", file: "src/auth/jwt.ts", line_start: 34, body: "Token decoded without signature verification." }
        ]
      };
      const mockMicro = {
        name: "micro-arbiter",
        findings: [
          { severity: "critical", title: "Unvalidated Token Signature", file: "src/auth/jwt.ts", line_start: 34, recommendation: "Use jwt.verify(token, secret)" }
        ]
      };

      const consensus = aggregateConsensus(mockMacro, mockMicro);
      io.stderr.write(`  ★ Simulated Consensus: ${consensus.verdict.toUpperCase()}\n`);

      const gate = evaluateGateDecision(consensus);
      io.stderr.write(`  🛡️ Simulated Gate: ${gate.decision.toUpperCase()} - ${gate.reason}\n\n`);

      const sarif = formatSarifReport(consensus.findings);
      if (formatArg === "sarif") {
        io.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
      }

      rootSpan.end("ok");
      io.stderr.write("ℹ [Simulation Complete] Demo run finished successfully.\n\n");
      return EXIT_CODES.SUCCESS;
    }

    case "review": {
      printBanner(io, "Triad-Flow • Real Scale-Adaptive Review");
      const gitOptions = {
        base: baseArg,
        head: headArg,
        stagedOnly: stagedArg
      };

      const opts = { ...io, ...options };
      let changeSet;

      if (typeof opts.getChangeSet === "function") {
        changeSet = opts.getChangeSet(gitOptions);
      } else if (typeof opts.getGitState === "function") {
        const state = opts.getGitState(gitOptions);
        if (!state || !state.ok) {
          changeSet = state;
        } else {
          changeSet = {
            ok: true,
            schemaVersion: "1.0.0",
            scopeMode: state.scopeMode || "working-tree",
            repository: state.repository,
            contentDigest: crypto.createHash("sha256").update(JSON.stringify(state.files || []), "utf8").digest("hex"),
            totalFiles: (state.files || []).length,
            totalAdditions: (state.files || []).reduce((sum, f) => sum + (f.additions || 0), 0),
            totalDeletions: (state.files || []).reduce((sum, f) => sum + (f.deletions || 0), 0),
            files: state.files || [],
            diffHunks: ""
          };
        }
      } else {
        changeSet = buildChangeSet(opts.cwd || process.cwd(), gitOptions);
      }

      // Invariant (INV-01): Git inspection failure MUST fail closed as SYSTEM_FAILURE (3) or USAGE_ERROR (2) on invalid ref
      if (!changeSet || !changeSet.ok) {
        const errorMsg = changeSet?.error?.message || "Failed to inspect Git repository state.";
        if (changeSet?.error?.code === "INVALID_BASE_REF" || changeSet?.error?.code === "INVALID_HEAD_REF") {
          io.stderr.write(`✖ [USAGE ERROR] ${errorMsg}\n\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
        io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Git inspection error: ${errorMsg}\n\n`);
        return EXIT_CODES.SYSTEM_FAILURE;
      }

      const files = changeSet.files || [];
      const scopeLabel = changeSet.scopeMode || "working-tree";

      if (files.length === 0) {
        io.stderr.write(`✔ [No Changes] Scope '${scopeLabel}' has no files to review (No-op).\n\n`);
        const runReport = buildReviewRunReport({
          runId: crypto.randomUUID(),
          status: REVIEW_RUN_STATUS.NO_CHANGES,
          exitCode: EXIT_CODES.SUCCESS,
          changeSet,
          policy: { id: "SINGLE_SENTRY", strict: strictArg },
          gate: { decision: "approve", reason: "No files changed to review." }
        });

        if (reportArg) {
          try {
            fs.writeFileSync(reportArg, JSON.stringify(runReport, null, 2) + "\n", "utf8");
            io.stderr.write(`📝 Saved review audit run: ${reportArg}\n`);
          } catch (err) {
            io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write audit run report: ${err.message}\n`);
            return EXIT_CODES.SYSTEM_FAILURE;
          }
        }

        if (formatArg === "json") {
          io.stdout.write(JSON.stringify(runReport, null, 2) + "\n");
        } else if (formatArg === "sarif") {
          io.stdout.write(JSON.stringify(formatSarifReport([], { executionSuccessful: true }), null, 2) + "\n");
        }
        return EXIT_CODES.SUCCESS;
      }

      io.stderr.write(`✔ Captured Git Scope '${scopeLabel}': ${files.length} active file(s)\n`);
      const plan = evaluateDiffScale(files);
      io.stderr.write(`▶ Scale Routing: Mode = ${plan.mode.toUpperCase()} (${plan.reason})\n`);

      let cliAdapters = null;
      if (macroCmd || microCmd) {
        cliAdapters = {};
        if (macroCmd) {
          cliAdapters.macro = new CliReviewAdapter({
            command: macroCmd,
            ...(macroArgs ? { args: macroArgs } : {}),
            providerName: macroCmd,
            modelName: "cli-default",
            execFn: options.macroExecFn || options.execFn || null
          });
        }
        if (microCmd) {
          cliAdapters.micro = new CliReviewAdapter({
            command: microCmd,
            ...(microArgs ? { args: microArgs } : {}),
            providerName: microCmd,
            modelName: "cli-default",
            execFn: options.microExecFn || options.execFn || null
          });
        }
      }

      const reviewAdapters = opts.reviewAdapters || opts.adapters || cliAdapters || null;
      let consensus;
      let gate;
      let orchResult = null;
      let runStatus;

      if (reviewAdapters) {
        orchResult = await orchestrateReview(changeSet, reviewAdapters, {
          strict: strictArg,
          timeoutMs: options.timeoutMs,
          signal: options.signal,
          limits: options.limits
        });
        consensus = orchResult.consensus;
        gate = orchResult.gate;
        if (orchResult.status === "error") {
          runStatus = REVIEW_RUN_STATUS.EXECUTION_ERROR;
        } else if (orchResult.status === "incomplete") {
          runStatus = REVIEW_RUN_STATUS.INCOMPLETE;
        } else if (gate.decision === "approve") {
          runStatus = (consensus?.findings && consensus.findings.length > 0)
            ? REVIEW_RUN_STATUS.REVIEWED_WITH_FINDINGS
            : REVIEW_RUN_STATUS.REVIEWED_CLEAN;
        } else if (consensus?.findings && consensus.findings.length > 0) {
          runStatus = REVIEW_RUN_STATUS.REVIEWED_WITH_FINDINGS;
        } else {
          runStatus = REVIEW_RUN_STATUS.INCOMPLETE;
        }
      } else {
        // In standalone CLI without live provider adapters, fail closed on unconfigured sentries
        consensus = aggregateConsensus(
          { error: "No configured macro sentry provider" },
          { error: "No configured micro sentry provider" }
        );
        gate = evaluateGateDecision(consensus, { strict: strictArg });
        runStatus = REVIEW_RUN_STATUS.INCOMPLETE;
      }

      let exitCode;
      if (runStatus === REVIEW_RUN_STATUS.EXECUTION_ERROR) {
        exitCode = EXIT_CODES.EXECUTION_ERROR;
      } else if (runStatus === REVIEW_RUN_STATUS.CONFIGURATION_ERROR) {
        exitCode = EXIT_CODES.CONFIGURATION_ERROR;
      } else {
        exitCode = gate.decision === "approve" ? EXIT_CODES.SUCCESS : EXIT_CODES.GATE_BLOCKED;
      }

      const runReport = buildReviewRunReport({
        runId: orchResult?.runId || crypto.randomUUID(),
        status: runStatus,
        exitCode,
        changeSet,
        policy: { id: plan.mode === "hierarchical" ? "STRICT_HETEROGENEOUS" : "SINGLE_SENTRY", strict: strictArg },
        routing: plan,
        providers: orchResult?.results
          ? Object.entries(orchResult.results).map(([role, res]) => ({ role, ...res }))
          : (orchResult?.result
            ? [{ role: (reviewAdapters?.macro ? "macro" : "micro"), ...orchResult.result }]
            : (orchResult?.activeResult
              ? [{ role: (reviewAdapters?.macro ? "macro" : "micro"), ...orchResult.activeResult }]
              : [])),
        consensus,
        gate
      });

      if (reportArg) {
        try {
          fs.writeFileSync(reportArg, JSON.stringify(runReport, null, 2) + "\n", "utf8");
          io.stderr.write(`📝 Saved review audit run: ${reportArg}\n`);
        } catch (err) {
          io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write audit run report: ${err.message}\n`);
          return EXIT_CODES.SYSTEM_FAILURE;
        }
      }

      io.stderr.write(`\n★ Consensus Verdict: ${consensus.verdict.toUpperCase()} (${consensus.consensusProof})\n`);
      io.stderr.write(`🛡️ Gate Decision: ${gate.decision.toUpperCase()} - ${gate.reason}\n\n`);

      if (formatArg === "json") {
        io.stdout.write(JSON.stringify(runReport, null, 2) + "\n");
      } else if (formatArg === "sarif") {
        const executionSuccessful = runStatus !== REVIEW_RUN_STATUS.INCOMPLETE && runStatus !== REVIEW_RUN_STATUS.EXECUTION_ERROR;
        const sarif = formatSarifReport(consensus.findings, {
          executionSuccessful,
          failureReason: executionSuccessful ? undefined : (consensus.consensusProof || gate.reason || "Review unconfigured or quorum failed")
        });
        io.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
      }

      return exitCode;
    }

    case "factory": {
      printBanner(io, "Triad-Flow • Autonomous Factory Pipeline");
      const factoryResult = runFactoryPipeline(options.factoryAdapters || {});
      for (const line of factoryResult.lines) io.stderr.write(line);
      return factoryResult.halted ? EXIT_CODES.GATE_BLOCKED : EXIT_CODES.SUCCESS;
    }

    case "bench":
    case "benchmark": {
      if (liveArg && virtualArg === true) {
        io.stderr.write("✖ [USAGE ERROR] Live evaluation requires physical repository workspace (--live and --virtual cannot be combined).\n");
        return EXIT_CODES.USAGE_ERROR;
      }

      if (formatArg && formatArg !== "text" && formatArg !== "json") {
        io.stderr.write(`✖ [USAGE ERROR] Invalid format '${formatArg}' for benchmark. Supported formats: text, json\n`);
        return EXIT_CODES.USAGE_ERROR;
      }

      const VALID_MODES = new Set(["single", "dual", "risk-routed", "all"]);
      if (modeArg && !VALID_MODES.has(modeArg)) {
        io.stderr.write(`✖ [USAGE ERROR] Invalid --mode='${modeArg}'. Must be one of: ${Array.from(VALID_MODES).join(", ")}\n`);
        return EXIT_CODES.USAGE_ERROR;
      }

      let verifierProfile = null;
      if (verifyWithArg) {
        try {
          verifierProfile = validateVerifierCommand(verifyWithArg);
        } catch (err) {
          io.stderr.write(`✖ [USAGE ERROR] ${err.message}\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
      }

      let parsedLimit;
      if (limitArg !== null && limitArg !== undefined) {
        parsedLimit = parseInt(limitArg, 10);
        if (!Number.isFinite(parsedLimit) || parsedLimit <= 0) {
          io.stderr.write(`✖ [USAGE ERROR] Invalid --limit='${limitArg}'. Must be a positive integer.\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
      }

      let parsedTimeout;
      if (timeoutArg !== null && timeoutArg !== undefined) {
        parsedTimeout = parseInt(timeoutArg, 10);
        if (!Number.isFinite(parsedTimeout) || parsedTimeout <= 0) {
          io.stderr.write(`✖ [USAGE ERROR] Invalid --timeout='${timeoutArg}'. Must be a positive integer in milliseconds.\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
      }

      const isLive = liveArg;
      const isVirtual = virtualArg !== undefined ? virtualArg : !isLive;
      const timeoutMs = parsedTimeout || (isLive ? 90000 : 30000);

      let adapters = options.adapters || options.reviewAdapters || null;
      if (!adapters) {
        if (isLive) {
          adapters = {
            macro: new CliReviewAdapter({
              command: macroCmd || "agy",
              ...(macroArgs ? { args: macroArgs } : {}),
              providerName: macroCmd || "agy",
              modelName: "cli-default",
              execFn: options.macroExecFn || options.execFn || null
            }),
            micro: new CliReviewAdapter({
              command: microCmd || "claude",
              ...(microArgs ? { args: microArgs } : {}),
              providerName: microCmd || "claude",
              modelName: "cli-default",
              execFn: options.microExecFn || options.execFn || null
            })
          };
        } else {
          adapters = createMockCorpusAdapters();
        }
      }

      const suiteOptions = {
        mode: modeArg,
        live: isLive,
        executionMode: isLive ? "live" : "mock",
        virtual: isVirtual,
        workspaceMode: isVirtual ? "virtual" : "physical",
        timeoutMs,
        strict: strictArg,
        ...(caseArg ? { case: caseArg } : {}),
        ...(parsedLimit ? { limit: parsedLimit } : {})
      };

      let runResult;
      try {
        runResult = await evaluateCorpusSuite(undefined, adapters, suiteOptions);
      } catch (err) {
        if (/Corpus case .* not found/i.test(err.message)) {
          io.stderr.write(`✖ [USAGE ERROR] ${err.message}\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
        io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Benchmark evaluation failed: ${err.message}\n`);
        return EXIT_CODES.SYSTEM_FAILURE;
      }

      if (reportArg) {
        try {
          const reportFullPath = path.resolve(reportArg);
          fs.mkdirSync(path.dirname(reportFullPath), { recursive: true });
          fs.writeFileSync(reportFullPath, JSON.stringify(runResult, null, 2) + "\n", "utf8");
          io.stderr.write(`📝 Benchmark audit report saved to: ${reportFullPath}\n`);

          const defaultReceiptPath = path.join(path.dirname(reportFullPath), "audit-receipt.json");
          const receiptFullPath = receiptArg ? path.resolve(receiptArg) : defaultReceiptPath;
          if (runResult.receipt) {
            fs.mkdirSync(path.dirname(receiptFullPath), { recursive: true });
            fs.writeFileSync(receiptFullPath, JSON.stringify(runResult.receipt, null, 2) + "\n", "utf8");
            io.stderr.write(`📝 Benchmark audit receipt saved to: ${receiptFullPath}\n`);
          }
        } catch (err) {
          io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write report to '${reportArg}': ${err.message}\n`);
          return EXIT_CODES.SYSTEM_FAILURE;
        }
      } else if (receiptArg && runResult.receipt) {
        try {
          const receiptFullPath = path.resolve(receiptArg);
          fs.mkdirSync(path.dirname(receiptFullPath), { recursive: true });
          fs.writeFileSync(receiptFullPath, JSON.stringify(runResult.receipt, null, 2) + "\n", "utf8");
          io.stderr.write(`📝 Benchmark audit receipt saved to: ${receiptFullPath}\n`);
        } catch (err) {
          io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write receipt to '${receiptArg}': ${err.message}\n`);
          return EXIT_CODES.SYSTEM_FAILURE;
        }
      }

      const additionalArtifacts = {};

      if (verifierProfile) {
        io.stderr.write(`\n[TF-RBC-v0] Initiating Independent Verification with '${verifierProfile.id}'...\n`);
        let verifierAdapter = options.verifierAdapter || null;
        if (!verifierAdapter) {
          if (isLive) {
            verifierAdapter = new CliVerifierAdapter({
              command: verifierProfile.command,
              providerName: verifierProfile.id,
              modelName: "cli-default"
            });
          } else {
            verifierAdapter = createMockVerifierAdapter(verifierProfile.id);
          }
        }

        const reportDir = reportArg ? path.dirname(path.resolve(reportArg)) : process.cwd();
        const verificationTarget = verificationReportArg
          ? path.resolve(verificationReportArg)
          : path.join(reportDir, "verification-record.json");
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
              producerName: macroCmd || "agy",
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
                producerName: macroCmd || "agy",
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
          try {
            fs.mkdirSync(path.dirname(verificationTarget), { recursive: true });
            fs.writeFileSync(verificationTarget, JSON.stringify(verificationRecord, null, 2) + "\n", "utf8");
            io.stderr.write(`📝 Independent verification record saved to: ${verificationTarget}\n`);
            additionalArtifacts[path.basename(verificationTarget)] = verificationTarget;

            if (verificationRecord.disagreementLedger) {
              const ledgerDoc = buildDisagreementLedgerDocument({
                verificationRecord,
                producerRunId: runResult.runId || runResult.receipt?.run?.runId || "unknown",
                commitSha: runResult.receipt?.systemProvenance?.commitSha || "unknown"
              });
              fs.writeFileSync(disagreementLedgerTarget, JSON.stringify(ledgerDoc, null, 2) + "\n", "utf8");
              io.stderr.write(`📝 Disagreement ledger saved to: ${disagreementLedgerTarget}\n`);
              additionalArtifacts[path.basename(disagreementLedgerTarget)] = disagreementLedgerTarget;
            }
          } catch (err) {
            io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write verification report to '${verificationTarget}': ${err.message}\n`);
            return EXIT_CODES.SYSTEM_FAILURE;
          }
        }
      }

      if (manifestArg) {
        try {
          const reportFullPath = reportArg ? path.resolve(reportArg) : path.resolve("benchmark-results.json");
          const receiptFullPath = receiptArg ? path.resolve(receiptArg) : path.join(path.dirname(reportFullPath), "audit-receipt.json");
          const isManifestDefault = !manifestArg || manifestArg === "true" || manifestArg === "artifact-manifest.json";
          const manifestFullPath = isManifestDefault
            ? path.join(path.dirname(reportFullPath), "artifact-manifest.json")
            : path.resolve(manifestArg);
          const bundle = generateManifestBundle({
            additionalArtifacts: Object.keys(additionalArtifacts).length > 0 ? additionalArtifacts : null,
            manifestPath: manifestFullPath,
            receiptData: runResult.receipt,
            receiptPath: receiptFullPath,
            resultsData: runResult,
            resultsPath: reportFullPath,
            targetDir: path.dirname(manifestFullPath)
          });
          io.stderr.write(`📝 Benchmark artifact manifest saved to: ${bundle.manifestPath}\n`);
        } catch (err) {
          io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to generate artifact manifest bundle: ${err.message}\n`);
          return EXIT_CODES.SYSTEM_FAILURE;
        }
      }

      if (formatArg === "json") {
        io.stdout.write(JSON.stringify(runResult, null, 2) + "\n");
      } else {
        io.stdout.write("\n" + formatBenchmarkSummary(runResult) + "\n");
      }

      if (strictArg) {
        let hasFailures = false;
        if (runResult.mode === "all" && runResult.configurations) {
          hasFailures = Object.values(runResult.configurations).some(cfg =>
            (cfg.caseResults || []).some(c => !c.passed)
          );
        } else if (runResult.caseResults) {
          hasFailures = runResult.caseResults.some(c => !c.passed);
        }

        if (hasFailures) {
          io.stderr.write("\n[TF-RBC-v0] Strict Mode Failure: Benchmark run contains failed cases or false blocks.\n");
          return EXIT_CODES.GATE_BLOCKED;
        }
      }

      return EXIT_CODES.SUCCESS;
    }

    case "remediate": {
      const opts = { ...io, ...options };
      const isBatch = batchArg || Boolean(casesArg && casesArg.includes(","));

      let sandboxDriverInstance;
      try {
        sandboxDriverInstance = resolveSandboxDriver(sandboxArg, {
          execFn: options.sandboxExecFn || options.execFn || null
        });
      } catch (err) {
        io.stderr.write(`✖ [USAGE ERROR] ${err.message}\n`);
        return EXIT_CODES.USAGE_ERROR;
      }

      if (isBatch) {
        printBanner(io, "Triad-Flow • Multi-Finding Remediation Orchestrator [BATCH PLAN-ONLY]");

        let caseDefs = null;
        let workspace = null;
        let findings = [];

        // 1. Resolve candidate cases or report
        if (casesArg) {
          const caseIds = casesArg.split(",").map(s => s.trim()).filter(Boolean);
          caseDefs = [];
          for (const cId of caseIds) {
            const def = getCorpusCaseById(cId);
            if (!def) {
              io.stderr.write(`✖ [USAGE ERROR] Unknown corpus case: '${cId}'.\n`);
              return EXIT_CODES.USAGE_ERROR;
            }
            caseDefs.push(def);
          }
          workspace = createCorpusMultiCaseWorkspace(caseDefs);
          for (const cDef of caseDefs) {
            let candidateDiff = "";
            try {
              candidateDiff = execFileSync("git", ["diff", workspace.headSha, workspace.baseSha, "--", cDef.targetFile], {
                cwd: workspace.dir,
                encoding: "utf8",
                stdio: ["ignore", "pipe", "pipe"],
                windowsHide: true
              });
            } catch (err) {
              io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to extract reference patch diff for '${cDef.id}': ${err.message}\n`);
              workspace.cleanup();
              return EXIT_CODES.SYSTEM_FAILURE;
            }

            findings.push({
              id: `${cDef.id}-FINDING-001`,
              targetFiles: [cDef.targetFile],
              severity: cDef.goldenFindings?.[0]?.severity || "high",
              title: cDef.title,
              rationale: `Remediation for ${cDef.goldenFindings?.[0]?.cwe || "Defect"} in ${cDef.targetFile}`,
              patch: candidateDiff
            });
          }
        } else if (reportArg) {
          const reportFullPath = path.resolve(opts.cwd || process.cwd(), reportArg);
          if (!fs.existsSync(reportFullPath)) {
            io.stderr.write(`✖ [USAGE ERROR] Report file does not exist: "${reportFullPath}"\n`);
            return EXIT_CODES.USAGE_ERROR;
          }
          let reportData;
          try {
            reportData = JSON.parse(fs.readFileSync(reportFullPath, "utf8"));
          } catch (err) {
            io.stderr.write(`✖ [USAGE ERROR] Failed to parse JSON report '${reportFullPath}': ${err.message}\n`);
            return EXIT_CODES.USAGE_ERROR;
          }
          findings = extractFindingsFromReport(reportData);
          if (findings.length === 0) {
            io.stderr.write(`✖ [USAGE ERROR] No candidate findings found in report '${reportArg}'.\n`);
            return EXIT_CODES.USAGE_ERROR;
          }

          if (diffArg) {
            const diffFullPath = path.resolve(opts.cwd || process.cwd(), diffArg);
            if (!fs.existsSync(diffFullPath)) {
              io.stderr.write(`✖ [USAGE ERROR] Patch diff file does not exist: "${diffFullPath}"\n`);
              return EXIT_CODES.USAGE_ERROR;
            }
            const explicitDiff = fs.readFileSync(diffFullPath, "utf8");
            for (const f of findings) {
              if (!f.patch) f.patch = explicitDiff;
            }
          }
        } else if (caseArg) {
          const def = getCorpusCaseById(caseArg);
          if (!def) {
            io.stderr.write(`✖ [USAGE ERROR] Unknown corpus case: '${caseArg}'.\n`);
            return EXIT_CODES.USAGE_ERROR;
          }
          workspace = createCorpusMultiCaseWorkspace([def]);
          let candidateDiff = "";
          try {
            candidateDiff = execFileSync("git", ["diff", workspace.headSha, workspace.baseSha, "--", def.targetFile], {
              cwd: workspace.dir,
              encoding: "utf8",
              stdio: ["ignore", "pipe", "pipe"],
              windowsHide: true
            });
          } catch (err) {
            io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to extract reference patch diff for '${def.id}': ${err.message}\n`);
            workspace.cleanup();
            return EXIT_CODES.SYSTEM_FAILURE;
          }
          findings.push({
            id: `${def.id}-FINDING-001`,
            targetFiles: [def.targetFile],
            severity: def.goldenFindings?.[0]?.severity || "high",
            title: def.title,
            rationale: `Remediation for ${def.goldenFindings?.[0]?.cwe || "Defect"} in ${def.targetFile}`,
            patch: candidateDiff
          });
        } else {
          io.stderr.write(`✖ [USAGE ERROR] Command 'remediate --batch' requires '--report <file>' or '--cases <case-ids>' (e.g. --cases=BENCH-REAL-001,BENCH-REAL-002).\n`);
          return EXIT_CODES.USAGE_ERROR;
        }

        try {
          const batchId = `BATCH-${Date.now().toString(36).toUpperCase()}`;
          const batch = new BatchRemediationSession(batchId, findings);
          const synthProvider = synthesizerArg || options.synthesizer || "codex";

          io.stderr.write(`[1/4] Proposing patch plans for ${batch.sessionsCount} finding(s) in batch ${batchId}...\n`);
          for (const f of findings) {
            const session = batch.getSession(f.id);
            session.proposeFix({
              diff: f.patch || "",
              rationale: f.rationale || `Remediation for ${f.id}`,
              synthesizer: { providerName: synthProvider, modelName: "cli-remediate" }
            });
          }

          const explicitAuthorizer = authorizerArg || options.authorizer || null;
          if (explicitAuthorizer) {
            const authorizerObj = typeof explicitAuthorizer === "object"
              ? explicitAuthorizer
              : { identity: String(explicitAuthorizer), type: "human" };
            io.stderr.write(`[2/4] Authorizing patch evaluation under human/policy gate (${authorizerObj.identity})...\n`);
            for (const f of findings) {
              const session = batch.getSession(f.id);
              session.authorizePatch({ authorizer: authorizerObj });
            }
          } else {
            io.stderr.write(`[2/4] No human authorizer specified (missing '--authorizer <id>'). Patches cannot be authorized; remaining in FIX_PROPOSED.\n`);
          }

          const anyAuthorized = Array.from(batch.sessions.values()).some(s => s.status === REMEDIATION_STATES.PATCH_AUTHORIZED);
          if (anyAuthorized) {
            const batchRunner = opts.testRunner || opts.testRunnerFn;
            const validRunner = typeof batchRunner === "function" || (batchRunner && typeof batchRunner === "object" && batchRunner.command);
            if (validRunner) {
              io.stderr.write(`[3/4] Executing batch sequential trials in ephemeral Patch Jail worktree...\n`);
              batch.executeBatchInJailWorktree(workspace ? workspace.dir : (opts.cwd || process.cwd()), {
                baseSha: workspace ? workspace.headSha : (headArg || "HEAD"),
                testRunnerFn: batchRunner,
                sandboxDriver: sandboxDriverInstance
              });
            } else {
              io.stderr.write(`[3/4] No deterministic test runner provided. Cannot execute verification in Patch Jail; remaining in PATCH_AUTHORIZED.\n`);
            }
          } else {
            io.stderr.write(`[3/4] Skipping ephemeral Patch Jail execution because sessions are not authorized.\n`);
          }

          const verifierProvider = verifyWithArg || (synthProvider === "claude" ? "agy" : "claude");
          const anyPendingVerify = Array.from(batch.sessions.values()).some(s => s.status === REMEDIATION_STATES.FIXED_PENDING_VERIFY);
          if (anyPendingVerify) {
            if (typeof opts.closureVerifierFn === "function") {
              io.stderr.write(`[4/4] Conducting independent heterogeneous verification (${verifierProvider} verifying ${synthProvider})...\n`);
              for (const session of batch.sessions.values()) {
                if (session.status === REMEDIATION_STATES.FIXED_PENDING_VERIFY) {
                  const verificationRecord = opts.closureVerifierFn(session);
                  session.recordClosureVerification({
                    verifier: { providerName: verifierProvider, modelName: "cli-default" },
                    verificationRecord
                  });
                }
              }
            } else {
              io.stderr.write(`[4/4] No independent closure verifier provided. Remediation cannot be closed; remaining in FIXED_PENDING_VERIFY.\n`);
            }
          } else {
            io.stderr.write(`[4/4] Skipping closure verification because no sessions reached FIXED_PENDING_VERIFY.\n`);
          }

          batch.finalize();
          const batchReceipt = batch.toBatchReceipt();
          const receiptOutPath = path.resolve(opts.cwd || process.cwd(), receiptArg || "batch-remediation-receipt.json");
          fs.writeFileSync(receiptOutPath, JSON.stringify(batchReceipt, null, 2) + "\n", "utf8");
          io.stderr.write(`📄 Batch remediation receipt saved to: ${receiptOutPath}\n\n`);

          if (formatArg === "json") {
            io.stdout.write(JSON.stringify(batchReceipt, null, 2) + "\n");
          } else {
            const lines = [
              "=======================================================",
              `  Triad-Flow Batch Remediation Summary: ${batchReceipt.verdict}`,
              "=======================================================",
              `Batch ID:           ${batchReceipt.batchId}`,
              `Batch Verdict:      ${batchReceipt.verdict}`,
              `Sandbox Driver:     ${batchReceipt.sandbox?.driver || "worktree"} (fs: ${batchReceipt.sandbox?.capabilities?.filesystemIsolation || "git-worktree"}, egress: ${batchReceipt.sandbox?.capabilities?.networkEgressDenial || "unavailable"})`,
              `Total Findings:     ${batchReceipt.summary.totalFindings}`,
              `Closed:             ${batchReceipt.summary.closedCount}`,
              `Rejected:           ${batchReceipt.summary.rejectedCount}`,
              `Waived:             ${batchReceipt.summary.waivedCount}`,
              `Pending/Open:       ${batchReceipt.summary.openCount}`,
              `Receipt Path:       ${receiptOutPath}`,
              "-------------------------------------------------------",
              "Finding Details:"
            ];
            for (const r of batchReceipt.receipts) {
              const files = (r.patch?.targetFiles || []).join(", ") || "no target files";
              lines.push(`  - [${r.status}] ${r.findingId} (${files})`);
            }
            lines.push("-------------------------------------------------------");
            lines.push("Plan-Only Boundary: Ephemeral jail destroyed. Authoritative branch untouched.");
            lines.push("=======================================================\n");
            io.stdout.write(lines.join("\n"));
          }

          if (workspace) {
            workspace.assertImmutability();
          }

          if (strictArg && batchReceipt.verdict !== BATCH_VERDICTS.ALL_CLOSED) {
            io.stderr.write(`\n[Strict Mode] Batch remediation did not reach ALL_CLOSED verdict (verdict: ${batchReceipt.verdict}).\n`);
            return EXIT_CODES.GATE_BLOCKED;
          }

          return batchReceipt.verdict === BATCH_VERDICTS.ALL_CLOSED ? EXIT_CODES.SUCCESS : EXIT_CODES.GATE_BLOCKED;
        } finally {
          if (workspace) {
            workspace.cleanup();
          }
        }
      }

      printBanner(io, "Triad-Flow • Controlled Remediation & Patch Jail Sandbox [PLAN-ONLY]");

      const targetCaseId = caseArg || options.case || null;
      if (!targetCaseId) {
        io.stderr.write(`✖ [USAGE ERROR] Command 'remediate' requires '--case <case-id>' (e.g. --case=BENCH-REAL-001).\n`);
        return EXIT_CODES.USAGE_ERROR;
      }

      const caseDef = getCorpusCaseById(targetCaseId);
      if (!caseDef) {
        io.stderr.write(`✖ [USAGE ERROR] Unknown corpus case: '${targetCaseId}'.\n`);
        return EXIT_CODES.USAGE_ERROR;
      }

      // 1. Resolve candidate patch diff
      let candidateDiff = "";
      if (diffArg) {
        const diffFullPath = path.resolve(opts.cwd || process.cwd(), diffArg);
        if (!fs.existsSync(diffFullPath)) {
          io.stderr.write(`✖ [USAGE ERROR] Patch diff file does not exist: "${diffFullPath}"\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
        candidateDiff = fs.readFileSync(diffFullPath, "utf8");
      }

      // Create isolated disposable workspace from corpus case
      const workspace = createCorpusCaseWorkspace(caseDef, { virtual: false });
      try {
        // If candidateDiff not explicitly supplied, extract canonical reference diff
        if (!candidateDiff) {
          try {
            candidateDiff = execFileSync("git", ["diff", workspace.headSha, workspace.baseSha], {
              cwd: workspace.dir,
              encoding: "utf8",
              stdio: ["ignore", "pipe", "pipe"],
              windowsHide: true
            });
          } catch (err) {
            io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to extract reference patch diff: ${err.message}\n`);
            return EXIT_CODES.SYSTEM_FAILURE;
          }
        }

        if (!candidateDiff || !candidateDiff.trim()) {
          io.stderr.write(`✖ [USAGE ERROR] No candidate patch diff available for case '${caseDef.id}'.\n`);
          return EXIT_CODES.USAGE_ERROR;
        }

        const findingId = `${caseDef.id}-FINDING-001`;
        const session = new ControlledRemediationSession(findingId, [caseDef.targetFile]);
        const synthProvider = synthesizerArg || options.synthesizer || "codex";

        io.stderr.write(`[1/4] Proposing patch plan for ${caseDef.id} (${caseDef.title})...\n`);
        session.proposeFix({
          diff: candidateDiff,
          rationale: `Remediation for ${caseDef.goldenFindings?.[0]?.cwe || "Defect"} in ${caseDef.targetFile}`,
          synthesizer: { providerName: synthProvider, modelName: "cli-remediate" }
        });

        const explicitAuthorizer = authorizerArg || options.authorizer || null;
        if (explicitAuthorizer) {
          const authorizerObj = typeof explicitAuthorizer === "object"
            ? explicitAuthorizer
            : { identity: String(explicitAuthorizer), type: "human" };
          io.stderr.write(`[2/4] Authorizing patch evaluation under human/policy gate (${authorizerObj.identity})...\n`);
          session.authorizePatch({
            authorizer: authorizerObj
          });
        } else {
          io.stderr.write(`[2/4] No human authorizer specified (missing '--authorizer <id>'). Patch cannot be authorized; remaining in FIX_PROPOSED.\n`);
        }

        if (session.status === REMEDIATION_STATES.PATCH_AUTHORIZED) {
          const singleRunner = opts.testRunner || opts.testRunnerFn;
          const validRunner = typeof singleRunner === "function" || (singleRunner && typeof singleRunner === "object" && singleRunner.command);
          if (validRunner) {
            io.stderr.write(`[3/4] Executing trial inside ephemeral Patch Jail worktree...\n`);
            session.executeInJailWorktree(workspace.dir, {
              baseSha: workspace.headSha,
              testRunnerFn: singleRunner,
              sandboxDriver: sandboxDriverInstance
            });
          } else {
            io.stderr.write(`[3/4] No deterministic test runner provided. Cannot execute verification in Patch Jail; remaining in PATCH_AUTHORIZED.\n`);
          }
        } else {
          io.stderr.write(`[3/4] Skipping ephemeral Patch Jail execution because session status is: ${session.status}\n`);
        }

        const verifierProvider = verifyWithArg || (synthProvider === "claude" ? "agy" : "claude");

        if (session.status === REMEDIATION_STATES.FIXED_PENDING_VERIFY) {
          if (typeof opts.closureVerifierFn === "function") {
            io.stderr.write(`[4/4] Conducting independent heterogeneous verification (${verifierProvider} verifying ${synthProvider})...\n`);
            const verificationRecord = opts.closureVerifierFn(session);
            session.recordClosureVerification({
              verifier: { providerName: verifierProvider, modelName: "cli-default" },
              verificationRecord
            });
          } else {
            io.stderr.write(`[4/4] No independent closure verifier provided. Remediation cannot be closed; remaining in FIXED_PENDING_VERIFY.\n`);
          }
        } else {
          io.stderr.write(`[4/4] Skipping closure verification because session status is: ${session.status}\n`);
        }

        const receipt = session.toReceipt();
        const receiptOutPath = path.resolve(opts.cwd || process.cwd(), receiptArg || "remediation-receipt.json");
        fs.writeFileSync(receiptOutPath, JSON.stringify(receipt, null, 2) + "\n", "utf8");
        io.stderr.write(`📄 Remediation receipt saved to: ${receiptOutPath}\n\n`);

        if (formatArg === "json") {
          io.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
        } else {
          io.stdout.write(
            [
              "=======================================================",
              `  Triad-Flow Remediation Summary: ${receipt.status}`,
              "=======================================================",
              `Case ID:            ${caseDef.id} (${caseDef.title})`,
              `Target File:        ${caseDef.targetFile}`,
              `Lifecycle Status:   ${receipt.status}`,
              `Sandbox Driver:     ${receipt.jail?.driver || "worktree"} (fs: ${receipt.jail?.capabilities?.filesystemIsolation || "git-worktree"}, egress: ${receipt.jail?.capabilities?.networkEgressDenial || "unavailable"})`,
              `Synthesizer:        ${receipt.actors.synthesizer?.providerName || "none"}`,
              `Verifier:           ${receipt.actors.verifier?.providerName || "none"}`,
              `Worktree SHA:       ${receipt.jail?.worktreeSha || "none"}`,
              `Pre-Patch Digest:   ${(receipt.jail?.prePatchTreeDigest || "").slice(0, 19) || "none"}...`,
              `Post-Patch Digest:  ${(receipt.jail?.postPatchTreeDigest || "").slice(0, 19) || "none"}...`,
              `Deterministic Pass: ${receipt.deterministicChecks?.executed ? (receipt.deterministicChecks.exitCode === 0 ? "YES (exit 0)" : "NO (exit " + receipt.deterministicChecks.exitCode + ")") : "SKIPPED (not executed)"}`,
              `Closure Verified:   ${receipt.closureVerification?.verified ? "YES (SUPPORTED)" : "NO (" + (receipt.closureVerification?.verdict || "NOT_RUN") + ")"}`,
              `Receipt Path:       ${receiptOutPath}`,
              "-------------------------------------------------------",
              "Plan-Only Boundary: Ephemeral jail destroyed. Authoritative branch untouched.",
              "=======================================================",
              ""
            ].join("\n") + "\n"
          );
        }

        workspace.assertImmutability();

        if (strictArg && receipt.status !== REMEDIATION_STATES.CLOSED) {
          io.stderr.write(`\n[Strict Mode] Remediation did not reach CLOSED state (status: ${receipt.status}).\n`);
          return EXIT_CODES.GATE_BLOCKED;
        }

        return receipt.status === REMEDIATION_STATES.CLOSED ? EXIT_CODES.SUCCESS : EXIT_CODES.GATE_BLOCKED;
      } finally {
        workspace.cleanup();
      }
    }

    default: {
      io.stderr.write(`Usage: triad-flow [doctor | demo | review | factory | benchmark | remediate] [--format=sarif|json] [--strict] [--staged] [--base=<ref>] [--head=<ref>] [--report=<file>] [--receipt=<file>] [--manifest[=<file>]] [--verify-with=<cmd>] [--verification-report=<file>] [--macro-cmd=<cmd>] [--micro-cmd=<cmd>] [--macro-args=<csv>] [--micro-args=<csv>] [--mode=<mode>] [--case=<id>] [--cases=<ids>] [--limit=<n>] [--live] [--virtual] [--diff=<file>] [--authorizer=<id>] [--synthesizer=<provider>] [--sandbox=worktree|container] [--plan-only] [--batch]\n`);
      return EXIT_CODES.USAGE_ERROR;
    }
  }
}
