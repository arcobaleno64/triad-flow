/**
 * Triad-Flow CLI: Command Routing, Capability Doctor, Simulation Demo & Real Review
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
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
import { createMockCorpusAdapters } from "../tests/fixtures/real-corpus-fixtures.mjs";

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
      "--macro-cmd",
      "--micro-cmd",
      "--macro-args",
      "--micro-args",
      "--mode",
      "--case",
      "--limit",
      "--timeout",
      "--live",
      "--virtual"
    ].includes(name);
  };

  const VALUE_FLAGS = new Set([
    "--format",
    "--base",
    "--head",
    "--report",
    "--output-run",
    "--macro-cmd",
    "--micro-cmd",
    "--macro-args",
    "--micro-args",
    "--mode",
    "--case",
    "--limit",
    "--timeout"
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

  const isRecognizedArg = (arg) => {
    if (arg.startsWith("--format=") || arg === "--format") return true;
    if (arg === "--strict" || arg === "--staged") return true;
    if (arg.startsWith("--base=") || arg === "--base") return true;
    if (arg.startsWith("--head=") || arg === "--head") return true;
    if (arg.startsWith("--report=") || arg === "--report") return true;
    if (arg.startsWith("--output-run=") || arg === "--output-run") return true;
    if (arg.startsWith("--macro-cmd=") || arg === "--macro-cmd") return true;
    if (arg.startsWith("--micro-cmd=") || arg === "--micro-cmd") return true;
    if (arg.startsWith("--macro-args=") || arg === "--macro-args") return true;
    if (arg.startsWith("--micro-args=") || arg === "--micro-args") return true;
    if (arg.startsWith("--mode=") || arg === "--mode") return true;
    if (arg.startsWith("--case=") || arg === "--case") return true;
    if (arg.startsWith("--limit=") || arg === "--limit") return true;
    if (arg.startsWith("--timeout=") || arg === "--timeout") return true;
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
        timeoutMs: options.timeoutMs,
        env: options.env || process.env,
        reviewers: options.reviewers
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
        } catch (err) {
          io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Failed to write report to '${reportArg}': ${err.message}\n`);
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

    default: {
      io.stderr.write(`Usage: triad-flow [doctor | demo | review | factory | benchmark] [--format=sarif|json] [--strict] [--staged] [--base=<ref>] [--head=<ref>] [--report=<file>] [--macro-cmd=<cmd>] [--micro-cmd=<cmd>] [--macro-args=<csv>] [--micro-args=<csv>] [--mode=<mode>] [--case=<id>] [--limit=<n>] [--live] [--virtual]\n`);
      return EXIT_CODES.USAGE_ERROR;
    }
  }
}
