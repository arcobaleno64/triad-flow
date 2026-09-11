/**
 * Triad-Flow CLI: Command Routing, Capability Doctor, Simulation Demo & Real Review
 */

import { SpanTracer } from "./core/telemetry.mjs";
import { evaluateDiffScale } from "./core/graph-router.mjs";
import { aggregateConsensus } from "./core/loop.mjs";
import { evaluateGateDecision, formatSarifReport } from "./core/harness.mjs";
import { collectGitWorkingState } from "./core/git-collector.mjs";
import { runFactoryPipeline } from "./core/factory.mjs";

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

export async function runCli(argv = process.argv.slice(2), io = { stdout: process.stdout, stderr: process.stderr }, options = {}) {
  const command = argv[0] || "doctor";
  const formatArg = argv.find(a => a.startsWith("--format="))?.split("=")[1] || "text";
  const strictArg = argv.includes("--strict") || Boolean(options.strict);
  const stagedArg = argv.includes("--staged") || Boolean(options.staged);

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

  const isRecognizedArg = (arg) => {
    if (arg.startsWith("--format=")) return true;
    if (arg === "--strict" || arg === "--staged") return true;
    if (arg.startsWith("--base=") || arg === "--base") return true;
    if (arg.startsWith("--head=") || arg === "--head") return true;
    return false;
  };

  const unknownFlags = argv.filter(a => a.startsWith("--") && !isRecognizedArg(a));
  if (unknownFlags.length > 0) {
    io.stderr.write(`✖ [USAGE ERROR] Unsupported option(s): ${unknownFlags.join(", ")}\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (headArg && !baseArg) {
    io.stderr.write(`✖ [USAGE ERROR] Option '--head' requires '--base <ref>' to be specified.\n`);
    return EXIT_CODES.USAGE_ERROR;
  }

  switch (command) {
    case "doctor": {
      printBanner(io, "Triad-Flow • Environment & Capability Doctor");
      io.stderr.write("🩺 Probing Environment Capabilities:\n");
      io.stderr.write(`  ✔ Node.js Runtime: ${process.version}\n`);

      const gitState = typeof options.getGitState === "function" ? options.getGitState() : collectGitWorkingState(options.cwd || process.cwd());
      if (gitState.ok) {
        io.stderr.write("  ✔ Git Repository: Detected and active\n");
      } else {
        io.stderr.write(`  ⚠️ Git Repository: Not detected or unreadable (${gitState.error?.message || "none"})\n`);
      }

      io.stderr.write("  ✔ Deterministic Safety Core: Loaded (Harness + Loop + Graph)\n");

      const hasAnthropic = Boolean(process.env.ANTHROPIC_API_KEY);
      const hasGemini = Boolean(process.env.GEMINI_API_KEY);
      const hasOpenAI = Boolean(process.env.OPENAI_API_KEY);

      io.stderr.write(`  ℹ Anthropic Key: ${hasAnthropic ? "Configured" : "Unset (Real provider execution requires adapter)"}\n`);
      io.stderr.write(`  ℹ Google Gemini Key: ${hasGemini ? "Configured" : "Unset (Real provider execution requires adapter)"}\n`);
      io.stderr.write(`  ℹ OpenAI Codex Key: ${hasOpenAI ? "Configured" : "Unset (Real provider execution requires adapter)"}\n`);
      io.stderr.write(`  ℹ Provider Integration Status: Standalone Core Ready (External adapters require explicit configuration)\n\n`);

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
      const gitState = typeof options.getGitState === "function"
        ? options.getGitState(gitOptions)
        : collectGitWorkingState(options.cwd || process.cwd(), gitOptions);

      // Invariant (INV-01): Git inspection failure MUST fail closed as SYSTEM_FAILURE (3) or USAGE_ERROR (2) on invalid ref
      if (!gitState || !gitState.ok) {
        const errorMsg = gitState?.error?.message || "Failed to inspect Git repository state.";
        if (gitState?.error?.code === "INVALID_BASE_REF" || gitState?.error?.code === "INVALID_HEAD_REF") {
          io.stderr.write(`✖ [USAGE ERROR] ${errorMsg}\n\n`);
          return EXIT_CODES.USAGE_ERROR;
        }
        io.stderr.write(`✖ [FATAL SYSTEM FAILURE] Git inspection error: ${errorMsg}\n\n`);
        return EXIT_CODES.SYSTEM_FAILURE;
      }

      const files = gitState.files || [];
      const scopeLabel = gitState.scopeMode || "working-tree";

      if (files.length === 0) {
        io.stderr.write(`✔ [No Changes] Scope '${scopeLabel}' has no files to review (No-op).\n\n`);
        if (formatArg === "sarif") {
          io.stdout.write(JSON.stringify(formatSarifReport([], { executionSuccessful: true }), null, 2) + "\n");
        }
        return EXIT_CODES.SUCCESS;
      }

      io.stderr.write(`✔ Captured Git Scope '${scopeLabel}': ${files.length} active file(s)\n`);
      const plan = evaluateDiffScale(files);
      io.stderr.write(`▶ Scale Routing: Mode = ${plan.mode.toUpperCase()} (${plan.reason})\n`);

      // In standalone CLI without live provider adapters, fail closed on unconfigured sentries
      const consensus = aggregateConsensus(
        { error: "No configured macro sentry provider" },
        { error: "No configured micro sentry provider" }
      );
      const gate = evaluateGateDecision(consensus, { strict: strictArg });

      io.stderr.write(`\n★ Consensus Verdict: ${consensus.verdict.toUpperCase()} (${consensus.consensusProof})\n`);
      io.stderr.write(`🛡️ Gate Decision: ${gate.decision.toUpperCase()} - ${gate.reason}\n\n`);

      if (formatArg === "sarif") {
        const isApprove = gate.decision === "approve";
        const sarif = formatSarifReport(consensus.findings, {
          executionSuccessful: isApprove,
          failureReason: isApprove ? undefined : (consensus.consensusProof || gate.reason || "Review unconfigured or quorum failed")
        });
        io.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
      }

      return gate.decision === "approve" ? EXIT_CODES.SUCCESS : EXIT_CODES.GATE_BLOCKED;
    }

    case "factory": {
      printBanner(io, "Triad-Flow • Autonomous Factory Pipeline");
      const factoryResult = runFactoryPipeline(options.factoryAdapters || {});
      for (const line of factoryResult.lines) io.stderr.write(line);
      return factoryResult.halted ? EXIT_CODES.GATE_BLOCKED : EXIT_CODES.SUCCESS;
    }

    default: {
      io.stderr.write(`Usage: triad-flow [doctor | demo | review | factory] [--format=sarif] [--strict] [--staged] [--base=<ref>] [--head=<ref>]\n`);
      return EXIT_CODES.USAGE_ERROR;
    }
  }
}
