/**
 * Triad-Flow Dogfooding Review (Track D1: Shadow Dogfooding)
 *
 * Implements Phase 4.3 Dogfood Track D1:
 * - Runs Triad-Flow tri-party review on its own repository pull request diff
 * - Mode: SHADOW_DOGFOOD (Advisory / Observation Only, Zero Merge Authority)
 * - Collects operational telemetry:
 *   • Provider completion / malformed-output rate
 *   • Review latency per provider and overall wall-clock latency
 *   • Inter-provider disagreement frequency and solitary blocker vetoes
 *   • Finding provenance and architecture invariant compliance
 * - Emits `dogfood-run.json`
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { buildChangeSet } from "../src/core/git-collector.mjs";
import {
  CliReviewAdapter,
  resolveProviderProfile
} from "../src/adapters/cli-transport.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { evaluateGateDecision } from "../src/core/harness.mjs";
import { convertProviderResultToSentryReport } from "../src/adapters/provider-contract.mjs";
import {
  conductIndependentVerification,
  buildDisagreementLedgerDocument,
  CliVerifierAdapter,
  createMockVerifierAdapter,
  VERIFICATION_SCHEMA_VERSION
} from "../src/core/independent-verifier.mjs";
import { TOOL_VERSION } from "../src/core/review-run-report.mjs";

export function getCurrentCommitSha() {
  try {
    const out = execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
    if (/^[0-9a-f]{40,64}$/i.test(out)) return out;
  } catch {}
  return "0000000000000000000000000000000000000000";
}

export function getCurrentBranch() {
  try {
    const out = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
    if (out && !out.includes("\n") && out !== "HEAD") return out;
  } catch {}
  return "main";
}

export function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    help: false,
    live: false,
    mock: false,
    base: "main",
    head: "HEAD",
    out: "dogfood-run.json",
    timeoutMs: null
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--live") {
      options.live = true;
    } else if (arg === "--mock") {
      options.mock = true;
    } else if (arg === "--base") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --base");
      }
      options.base = argv[++i];
    } else if (arg.startsWith("--base=")) {
      options.base = arg.slice("--base=".length);
    } else if (arg === "--head") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --head");
      }
      options.head = argv[++i];
    } else if (arg.startsWith("--head=")) {
      options.head = arg.slice("--head=".length);
    } else if (arg === "--out") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --out");
      }
      options.out = argv[++i];
    } else if (arg.startsWith("--out=")) {
      options.out = arg.slice("--out=".length);
    } else if (arg === "--timeout") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --timeout");
      }
      const val = argv[++i];
      const parsed = parseInt(val, 10);
      if (isNaN(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout value: '${val}'. Must be a positive integer.`);
      }
      options.timeoutMs = parsed;
    } else if (arg.startsWith("--timeout=")) {
      const val = arg.slice("--timeout=".length);
      const parsed = parseInt(val, 10);
      if (isNaN(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout value: '${val}'. Must be a positive integer.`);
      }
      options.timeoutMs = parsed;
    } else {
      throw new Error(`Unknown argument: '${arg}'`);
    }
  }

  if (!options.live) {
    options.mock = true;
  }

  return options;
}

export function printHelp() {
  console.log(`
Triad-Flow Track D1: Shadow Dogfood Review

Usage:
  node scripts/dogfood-review.mjs [options]

Options:
  --live              Execute review using installed local provider CLIs (agy, claude, codex)
  --mock              Execute review using deterministic simulation (default)
  --base <ref>        Git base reference to diff against (default: main)
  --head <ref>        Git head reference (default: HEAD)
  --out <file>        Output report path (default: dogfood-run.json)
  --timeout <ms>      Per-provider timeout in milliseconds (default: 120000 live / 30000 mock)
  --help, -h          Show this help message
`);
}

/**
 * Creates mock adapters for dogfood review simulation.
 */
function createMockDogfoodAdapters(changeSet) {
  const coveredFiles = (changeSet.files || []).map(f => f.path);

  const agy = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    modelName: "gemini-3.8-flash",
    actualModel: { value: "gemini-3.8-flash", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 600, completionTokens: 50, totalTokens: 650 }
      })
    })
  });

  const claude = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    actualModel: { value: "claude-5.5-sonnet", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 620, completionTokens: 40, totalTokens: 660 }
      })
    })
  });

  const codex = new CliReviewAdapter({
    command: "codex",
    providerName: "codex",
    modelName: "gpt-6.1-sol",
    actualModel: { value: "gpt-6.1-sol", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 580, completionTokens: 45, totalTokens: 625 }
      })
    })
  });

  return { agy, claude, codex };
}

/**
 * Classifies file risk tier based on sensitivity and architectural boundaries.
 */
export function classifyDogfoodFileRisk(filePath) {
  if (!filePath) return 2;
  const normalized = String(filePath).replace(/\\/g, "/").toLowerCase();
  const tier1Patterns = [
    /^\.github\/workflows\//,
    /^src\/core\//,
    /^src\/adapters\//,
    /^src\/auth\//,
    /^src\/crypto\//,
    /^src\/security\//,
    /^scripts\/bump-version\.mjs/,
    /^scripts\/release-verify\.mjs/,
    /auth|crypto|secret|token|credential|permission/i
  ];
  if (tier1Patterns.some(p => p.test(normalized))) {
    return 1;
  }
  return 2;
}

/**
 * Executes Track D1 Shadow Dogfood Review.
 */
export async function runDogfoodReview(userOptions = {}) {
  const isLive = Boolean(userOptions.live);
  const isMock = !isLive;
  const base = userOptions.base || "main";
  const head = userOptions.head || "HEAD";
  const timeoutMs = userOptions.timeoutMs || (isLive ? 180000 : 30000);
  const log = userOptions.log !== false;
  const outPath = path.resolve(userOptions.out || "dogfood-run.json");

  const commitSha = getCurrentCommitSha();
  const branch = getCurrentBranch();

  if (log) {
    console.log("==================================================================================");
    console.log("  Triad-Flow Track D1: Shadow Dogfood Review");
    console.log(`  Authority Mode: SHADOW_DOGFOOD (Advisory / Observation Only, Zero Merge Authority)`);
    console.log(`  Execution Mode: ${isLive ? "LIVE (Real Provider CLIs)" : "MOCK (Deterministic Simulation)"}`);
    console.log(`  Git Scope: ${base}...${head} (Branch: ${branch}, HEAD: ${commitSha.slice(0, 10)})`);
    console.log("==================================================================================\n");
  }

  // 1. Capture Git ChangeSet
  let changeSet = userOptions.changeSet || null;
  if (!changeSet) {
    if (log) console.log(`[1/5] Inspecting Git changes between '${base}' and '${head}'...`);
    let resolvedBase = base;
    try {
      execFileSync("git", ["rev-parse", "--verify", base], { stdio: "ignore" });
    } catch {
      try {
        execFileSync("git", ["rev-parse", "--verify", `origin/${base}`], { stdio: "ignore" });
        resolvedBase = `origin/${base}`;
      } catch {
        resolvedBase = "HEAD";
      }
    }
    changeSet = buildChangeSet(process.cwd(), { base: resolvedBase, head });
  }

  if (!changeSet || !changeSet.ok) {
    throw new Error(`Failed to capture ChangeSet: ${changeSet?.error?.message || "Unknown Git inspection failure"}`);
  }

  const rawFiles = (changeSet.files || []).filter(f => {
    const norm = (f.path || "").replace(/\\/g, "/");
    return !norm.endsWith("dogfood-run.json");
  });
  const files = rawFiles.map(f => ({
    ...f,
    riskTier: f.riskTier || classifyDogfoodFileRisk(f.path)
  }));
  const totalAdditions = files.reduce((acc, f) => acc + (f.additions || 0), 0);
  const totalDeletions = files.reduce((acc, f) => acc + (f.deletions || 0), 0);
  changeSet = {
    ...changeSet,
    files,
    totalAdditions,
    totalDeletions
  };
  if (log) {
    console.log(`  ✔ Changed files (excluding telemetry output): ${files.length}`);
    console.log(`  ✔ Total additions: +${totalAdditions} / deletions: -${totalDeletions}`);
    for (const f of files.slice(0, 10)) {
      console.log(`    • ${f.path} (+${f.additions || 0}/-${f.deletions || 0}, Tier ${f.riskTier})`);
    }
    if (files.length > 10) console.log(`    ... and ${files.length - 10} more files`);
  }

  const totalChangedLines = totalAdditions + totalDeletions;
  const hasTier1 = files.some(f => f.riskTier === 1) || totalChangedLines >= 50;
  const diffTier = hasTier1 ? 1 : 2;

  // 2. Configure Tri-Party Reviewers
  if (log) console.log("\n[2/5] Configuring tri-party heterogeneous review sentries...");
  let reviewAdapters;
  let verifierAdapter;

  if (isLive) {
    const codexProfile = resolveProviderProfile("codex");
    let codexCommand = "codex";
    let codexArgs;

    if (codexProfile?.nativeResolution?.resolvedType === "NATIVE_EXE") {
      codexCommand = codexProfile.nativeResolution.command;
    } else if (codexProfile?.nativeResolution?.resolvedType === "NODE_SCRIPT") {
      codexCommand = codexProfile.nativeResolution.command;
      codexArgs = [
        ...(codexProfile.nativeResolution.prefixArgs || []),
        ...(codexProfile.args || [])
      ];
    }

    const codexAdapter = new CliReviewAdapter({
      command: codexCommand,
      args: codexArgs,
      providerName: "codex",
      modelName: "gpt-6.1-sol",
      actualModel: { value: "gpt-6.1-sol", source: "reported" },
      inputChannel: "stdin",
      supportsStdin: true,
      useStdin: true
    });
    codexAdapter.profile = codexProfile;

    reviewAdapters = {
      agy: new CliReviewAdapter({
        command: "agy",
        providerName: "agy",
        modelName: "gemini-3.8-flash",
        actualModel: { value: "gemini-3.8-flash", source: "reported" }
      }),
      claude: new CliReviewAdapter({
        command: "claude",
        providerName: "claude",
        modelName: "claude-5.5-sonnet",
        actualModel: { value: "claude-5.5-sonnet", source: "reported" }
      }),
      codex: codexAdapter
    };
    verifierAdapter = new CliVerifierAdapter({
      command: "claude",
      providerName: "claude",
      modelName: "claude-5.5-sonnet",
      actualModel: { value: "claude-5.5-sonnet", source: "reported" }
    });
  } else {
    reviewAdapters = createMockDogfoodAdapters(changeSet);
    verifierAdapter = createMockVerifierAdapter("claude");
  }

  // 3. Execute Tri-Party Review
  if (log) console.log("\n[3/5] Executing tri-party review on PR changeset...");
  const t0 = Date.now();

  const tAgy0 = Date.now();
  const pAgy = reviewAdapters.agy.executeReview({
    runId: `dogfood-${Date.now()}-agy`,
    role: "agy",
    changeSet,
    policyId: "TRI_PARTY_HETEROGENEOUS",
    timeoutMs,
    signal: userOptions.signal || null
  }).then(res => ({ res, latencyMs: Date.now() - tAgy0 }));

  const tClaude0 = Date.now();
  const pClaude = reviewAdapters.claude.executeReview({
    runId: `dogfood-${Date.now()}-claude`,
    role: "claude",
    changeSet,
    policyId: "TRI_PARTY_HETEROGENEOUS",
    timeoutMs,
    signal: userOptions.signal || null
  }).then(res => ({ res, latencyMs: Date.now() - tClaude0 }));

  const tCodex0 = Date.now();
  const pCodex = reviewAdapters.codex.executeReview({
    runId: `dogfood-${Date.now()}-codex`,
    role: "codex",
    changeSet,
    policyId: "TRI_PARTY_HETEROGENEOUS",
    timeoutMs,
    signal: userOptions.signal || null
  }).then(res => ({ res, latencyMs: Date.now() - tCodex0 }));

  const [agyOut, claudeOut, codexOut] = await Promise.all([pAgy, pClaude, pCodex]);
  const reviewerPhaseDurationMs = Date.now() - t0;

  const rawReports = {
    agy: {
      ...convertProviderResultToSentryReport(agyOut.res, "agy"),
      latencyMs: agyOut.latencyMs,
      executionStatus: agyOut.res?.executionStatus || "unknown"
    },
    claude: {
      ...convertProviderResultToSentryReport(claudeOut.res, "claude"),
      latencyMs: claudeOut.latencyMs,
      executionStatus: claudeOut.res?.executionStatus || "unknown"
    },
    codex: {
      ...convertProviderResultToSentryReport(codexOut.res, "codex"),
      latencyMs: codexOut.latencyMs,
      executionStatus: codexOut.res?.executionStatus || "unknown"
    }
  };

  if (log) {
    console.log(`  ✔ Google agy:   status=${rawReports.agy.executionStatus} (${rawReports.agy.findings?.length || 0} findings, ${agyOut.latencyMs}ms)`);
    console.log(`  ✔ Anthropic claude: status=${rawReports.claude.executionStatus} (${rawReports.claude.findings?.length || 0} findings, ${claudeOut.latencyMs}ms)`);
    console.log(`  ✔ OpenAI codex: status=${rawReports.codex.executionStatus} (${rawReports.codex.findings?.length || 0} findings, ${codexOut.latencyMs}ms)`);
  }

  // 4. Consensus & Policy Evaluation
  if (log) console.log("\n[4/5] Evaluating consensus & disagreement ledger...");
  const consensus = aggregateConsensus(rawReports, {
    policy: "TRI_PARTY_HETEROGENEOUS",
    tier: diffTier
  });

  const gate = evaluateGateDecision(consensus, {
    tier: diffTier,
    strict: true
  });

  const findings = consensus.findings || [];
  if (log) {
    console.log(`  ★ Consensus Verdict: ${consensus.verdict} (Quorum reached: ${consensus.quorumReached})`);
    console.log(`  🛡️ Policy Gate: ${gate.decision.toUpperCase()} (${gate.reason})`);
    console.log(`  📋 Consensus Findings: ${findings.length}`);
    for (const f of findings) {
      console.log(`    • [${f.severity?.toUpperCase() || "MEDIUM"}] ${f.title} (${f.file}:${f.line_start || 1})`);
    }
  }

  // 5. Verification & Telemetry Compilation
  if (log) console.log("\n[5/5] Compiling operational telemetry into dogfood-run.json...");
  let verificationRecord = null;
  if (findings.length > 0) {
    verificationRecord = await conductIndependentVerification(
      changeSet,
      findings,
      verifierAdapter,
      {
        producerName: "tri-party-quorum",
        producerModel: "agy+claude+codex",
        verifierName: "claude",
        verifierModel: "claude-5.5-sonnet",
        changeSetDigest: changeSet.contentDigest,
        timeoutMs,
        signal: userOptions.signal || null
      }
    );
  }

  const totalDurationMs = Date.now() - t0;

  const providerOutputs = [rawReports.agy, rawReports.claude, rawReports.codex];
  const malformedCount = providerOutputs.filter(r => r.executionStatus === "malformed_output").length;
  const timeoutCount = providerOutputs.filter(r => r.executionStatus === "timeout").length;
  const authFailureCount = providerOutputs.filter(r => r.executionStatus === "auth_failure").length;
  const otherFailureCount = providerOutputs.filter(r => !["success", "empty"].includes(r.executionStatus)).length;
  const allProvidersSucceeded = providerOutputs.every(r => ["success", "empty"].includes(r.executionStatus));
  const isExecutionComplete = consensus.quorumReached && allProvidersSucceeded;

  const dogfoodDoc = {
    schemaVersion: "1.0.0",
    runId: `dogfood-${Date.now()}`,
    timestamp: new Date().toISOString(),
    track: "Track D1: SHADOW_DOGFOOD",
    authority: "NONE (ADVISORY_ONLY)",
    triadFlowVersion: TOOL_VERSION,
    repository: {
      commitSha,
      branch,
      base,
      head
    },
    changeSetSummary: {
      totalFiles: files.length,
      totalAdditions: changeSet.totalAdditions,
      totalDeletions: changeSet.totalDeletions,
      riskTier: diffTier,
      files: files.map(f => ({ path: f.path, additions: f.additions, deletions: f.deletions, riskTier: f.riskTier }))
    },
    providerTelemetry: {
      agy: {
        family: "google",
        model: "gemini-3.8-flash",
        executionStatus: rawReports.agy.executionStatus,
        findingsCount: rawReports.agy.findings?.length || 0,
        latencyMs: agyOut.latencyMs
      },
      claude: {
        family: "anthropic",
        model: "claude-5.5-sonnet",
        executionStatus: rawReports.claude.executionStatus,
        findingsCount: rawReports.claude.findings?.length || 0,
        latencyMs: claudeOut.latencyMs
      },
      codex: {
        family: "openai",
        model: "gpt-6.1-sol",
        executionStatus: rawReports.codex.executionStatus,
        findingsCount: rawReports.codex.findings?.length || 0,
        latencyMs: codexOut.latencyMs
      }
    },
    consensus: {
      verdict: consensus.verdict,
      quorumReached: consensus.quorumReached,
      totalFindings: findings.length,
      findings: findings.map(f => ({
        title: f.title,
        severity: f.severity,
        file: f.file,
        line: f.line_start || f.line,
        corroborations: f.corroborations || 1,
        sources: f.sources || []
      }))
    },
    advisoryGate: {
      decision: gate.decision,
      reason: gate.reason,
      effectiveMergeAuthority: "NONE",
      simulatedGateBlock: gate.decision === "block",
      mergeBlockedInProduction: false
    },
    telemetryMetrics: {
      totalDurationMs,
      reviewerPhaseDurationMs,
      avgProviderLatencyMs: Math.round((agyOut.latencyMs + claudeOut.latencyMs + codexOut.latencyMs) / 3),
      executionComplete: isExecutionComplete,
      malformedOutputCount: malformedCount,
      timeoutCount,
      authFailureCount,
      otherFailureCount
    },
    verificationRecord
  };

  fs.writeFileSync(outPath, JSON.stringify(dogfoodDoc, null, 2) + "\n", "utf8");
  if (log) {
    console.log(`  ✔ Saved dogfood telemetry to ${path.relative(process.cwd(), outPath)}`);
    console.log("\n🎉 Shadow Dogfood Review successfully recorded!");
  }

  return dogfoodDoc;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printHelp();
    process.exit(0);
  }

  try {
    await runDogfoodReview(options);
  } catch (err) {
    console.error("Fatal:", err);
    process.exit(1);
  }
}

const isMainModule = process.argv[1] && (
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
);

if (isMainModule) {
  main();
}
