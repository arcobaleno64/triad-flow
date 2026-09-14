/**
 * Triad-Flow Real Benchmark Evaluation Engine & Metric Aggregator (TF-RBC-v0)
 *
 * Implements the empirical evaluation engine for the 20 frozen real corpus cases:
 * - Executes controlled reviews across Single, Dual (Heterogeneous), and Risk-Adaptive modes.
 * - Asserts repository immutability before and after every execution.
 * - Measures Recall (R), Precision (P), False Block Rate (FBR), Token Cost Ratio (CR),
 *   and P50/P95 wall-clock latency profiles.
 * - Generates formatted ASCII summaries and structured JSON audit reports.
 */

import {
  TF_RBC_V0_CASES,
  createCorpusCaseWorkspace,
  createMockCorpusAdapters,
  getCorpusCaseById,
  listCorpusCases
} from "../../tests/fixtures/real-corpus-fixtures.mjs";
import { orchestrateReview } from "../adapters/review-orchestrator.mjs";
import { verifyHeldOutBaseline } from "./scoring.mjs";
import { deduplicateBenchmarkFindings } from "./benchmark-pilot.mjs";
import { evaluateDiffScale } from "./graph-router.mjs";

export const BENCHMARK_FRAMEWORK_NAME = "Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)";

/**
 * Evaluates a single corpus case in an isolated, disposable Git workspace.
 *
 * @param {object} caseDef - Corpus case definition from TF_RBC_V0_CASES.
 * @param {object} adapters - Review adapters { macro, micro }.
 * @param {object} [options]
 * @param {"single"|"dual"|"risk-routed"} [options.mode="single"]
 * @param {boolean} [options.strict=false]
 * @param {number} [options.timeoutMs=30000]
 * @returns {Promise<object>} Case evaluation record.
 */
export async function evaluateCorpusCase(caseDef, adapters = {}, options = {}) {
  if (!caseDef || !caseDef.id) {
    throw new Error("Invalid caseDef: must be a valid corpus case definition with an 'id'.");
  }

  const mode = options.mode || "single";
  const strict = Boolean(options.strict);
  const timeoutMs = options.timeoutMs || 30000;

  // 1. Create isolated disposable workspace (or zero-spawn virtual workspace)
  const workspace = createCorpusCaseWorkspace(caseDef, { virtual: Boolean(options.virtual) });
  try {
    // 2. Pre-execution immutability check
    workspace.assertImmutability();

    // 3. Determine plan based on mode and risk tier
    let plan;
    if (mode === "single") {
      plan = { mode: "single", reason: "benchmark-single-reviewer" };
    } else if (mode === "dual") {
      plan = { mode: "hierarchical", reason: "benchmark-dual-heterogeneous" };
    } else if (mode === "risk-routed") {
      const scale = evaluateDiffScale(workspace.changeSet?.files || []);
      plan = {
        mode: scale.mode,
        reason: `benchmark-risk-routed:${scale.reason}`
      };
    } else {
      plan = { mode: "single", reason: "benchmark-default-plan" };
    }

    // 4. Time the execution
    const startTime = Date.now();
    const orchResult = await orchestrateReview(workspace.changeSet, adapters, {
      plan,
      strict,
      timeoutMs
    });
    const latencyMs = Date.now() - startTime;

    // 5. Post-execution immutability check (guarantee zero file mutations or leaks)
    workspace.assertImmutability();

    // 6. Aggregate token usage (preserving null/unavailable without fake zero sum)
    let hasUsage = false;
    let promptTokens = null;
    let completionTokens = null;
    let totalTokens = null;

    const collectUsage = (u) => {
      if (!u) return;
      if (typeof u.promptTokens === "number") {
        promptTokens = (promptTokens ?? 0) + u.promptTokens;
        hasUsage = true;
      }
      if (typeof u.completionTokens === "number") {
        completionTokens = (completionTokens ?? 0) + u.completionTokens;
        hasUsage = true;
      }
      if (typeof u.totalTokens === "number") {
        totalTokens = (totalTokens ?? 0) + u.totalTokens;
        hasUsage = true;
      }
    };

    if (orchResult.results) {
      for (const res of Object.values(orchResult.results)) {
        collectUsage(res?.usage);
      }
    } else if (orchResult.result?.usage) {
      collectUsage(orchResult.result.usage);
    }

    if (totalTokens === null && promptTokens !== null && completionTokens !== null) {
      totalTokens = promptTokens + completionTokens;
    }

    const usage = {
      available: hasUsage,
      promptTokens,
      completionTokens,
      totalTokens
    };

    // 7. Extract combined findings
    let actualFindings = [];
    if (orchResult.consensus?.findings) {
      actualFindings = [...orchResult.consensus.findings];
    } else if (orchResult.result?.findings) {
      actualFindings = [...orchResult.result.findings];
    } else if (orchResult.results) {
      const all = [];
      if (orchResult.results.macro?.findings) all.push(...orchResult.results.macro.findings);
      if (orchResult.results.micro?.findings) all.push(...orchResult.results.micro.findings);
      actualFindings = deduplicateBenchmarkFindings(all);
    }

    // 8. Ground-truth CWE & line-tolerance scoring
    const goldenFindings = caseDef.goldenFindings || [];
    const evalResult = verifyHeldOutBaseline(actualFindings, goldenFindings, workspace.dir);

    // 9. 3-Point Passed Check & Negative Controls
    // Point 1 (detectionPass): Golden CWEs caught (or Clean case has no blocking findings)
    const isClean = caseDef.category === "clean";
    const detectionPass = isClean
      ? !actualFindings.some(f => /critical|high/i.test(f.severity || ""))
      : (goldenFindings.length > 0 && evalResult.caughtGoldens === goldenFindings.length);

    // Point 2 (gatePolicyPass): Actual gate decision strictly matches expected gate decision
    const actualGateDecision = orchResult.gate?.decision || "block";
    const gatePolicyPass = actualGateDecision === caseDef.expectedGateDecision;

    // Point 3 (executionComplete): Reviewer completed execution without incomplete coverage or runtime error
    const executionComplete = orchResult.status !== "incomplete" && orchResult.status !== "error";

    const isFalseBlock = isClean && actualGateDecision === "block";
    const isRecallCaught = !isClean && evalResult.caughtGoldens === goldenFindings.length;

    // Passed requires all 3 points to hold simultaneously
    const passed = Boolean(detectionPass && gatePolicyPass && executionComplete);

    return {
      caseId: caseDef.id,
      title: caseDef.title,
      category: caseDef.category,
      riskTier: caseDef.riskTier,
      expectedGateDecision: caseDef.expectedGateDecision,
      actualGateDecision,
      gateReason: orchResult.gate?.reason || "",
      status: orchResult.status,
      latencyMs,
      usage,
      actualFindings,
      goldenFindings,
      evalResult,
      isFalseBlock,
      isRecallCaught,
      detectionPass,
      gatePolicyPass,
      executionComplete,
      passed
    };
  } finally {
    workspace.cleanup();
  }
}

/**
 * Evaluates an entire suite of corpus cases across a given configuration.
 *
 * @param {object[]} [corpus=TF_RBC_V0_CASES]
 * @param {object|null} [adapters=null] - Review adapters { macro, micro }. If null, uses mock adapters.
 * @param {object} [options]
 * @param {"single"|"dual"|"risk-routed"|"all"} [options.mode="single"]
 * @param {string} [options.case] - Case ID filter.
 * @param {number} [options.limit] - Max cases.
 * @param {boolean} [options.strict=false]
 * @param {number} [options.timeoutMs=30000]
 * @returns {Promise<object>} Benchmark execution report.
 */
export async function evaluateCorpusSuite(corpus = TF_RBC_V0_CASES, adapters = null, options = {}) {
  const mode = options.mode || "single";

  // Delegate 3-way comparison if mode is "all"
  if (mode === "all") {
    return runThreeWayRealComparison(corpus, adapters, options);
  }

  // Use high-fidelity mock adapters if adapters are not explicitly provided and not in live mode
  const activeAdapters = adapters || createMockCorpusAdapters(options.mockOptions || {});

  // Case filtering
  let cases = Array.isArray(corpus) ? [...corpus] : [...TF_RBC_V0_CASES];
  if (options.case) {
    const single = getCorpusCaseById(options.case);
    if (!single) {
      throw new Error(`Corpus case '${options.case}' not found.`);
    }
    cases = [single];
  } else if (options.filter) {
    cases = listCorpusCases(options.filter);
  }

  if (options.limit && Number.isFinite(options.limit) && options.limit > 0) {
    cases = cases.slice(0, options.limit);
  }

  const caseResults = [];
  for (const c of cases) {
    const res = await evaluateCorpusCase(c, activeAdapters, {
      ...options,
      mode
    });
    caseResults.push(res);
  }

  // Aggregate metrics
  let vulnerableCasesCount = 0;
  let cleanCasesCount = 0;
  let totalGoldens = 0;
  let caughtGoldens = 0;
  let totalReportedFindings = 0;
  let truePositives = 0;
  let falseBlocks = 0;
  let totalPromptTokens = 0;
  let totalCompletionTokens = 0;
  let totalTokens = 0;
  let hasValidTokens = false;

  for (const r of caseResults) {
    if (r.usage?.available && typeof r.usage.totalTokens === "number") {
      hasValidTokens = true;
      totalPromptTokens += r.usage.promptTokens ?? 0;
      totalCompletionTokens += r.usage.completionTokens ?? 0;
      totalTokens += r.usage.totalTokens;
    }
    totalReportedFindings += r.actualFindings.length;

    if (r.category === "clean") {
      cleanCasesCount++;
      if (r.isFalseBlock) {
        falseBlocks++;
      }
    } else {
      vulnerableCasesCount++;
      totalGoldens += r.goldenFindings.length;
      caughtGoldens += r.evalResult.caughtGoldens;
      truePositives += r.evalResult.claimedFindingsCount;
    }
  }

  const falsePositives = Math.max(0, totalReportedFindings - truePositives);
  const recall = totalGoldens > 0
    ? parseFloat((caughtGoldens / totalGoldens).toFixed(3))
    : (cases.length > 0 && cleanCasesCount === cases.length ? 1.0 : 0.0);
  const precisionDenominator = truePositives + falsePositives;
  const precision = precisionDenominator > 0
    ? parseFloat((truePositives / precisionDenominator).toFixed(3))
    : (vulnerableCasesCount > 0 ? 0.0 : 1.0);
  const falseBlockRate = cleanCasesCount > 0 ? parseFloat((falseBlocks / cleanCasesCount).toFixed(3)) : null;

  const latencies = caseResults.map(r => r.latencyMs).sort((a, b) => a - b);
  const p50Ms = latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.5)] : 0;
  const p95Index = latencies.length > 0 ? Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95)) : 0;
  const p95Ms = latencies.length > 0 ? latencies[p95Index] : 0;
  const avgMs = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;
  const minMs = latencies.length > 0 ? latencies[0] : 0;
  const maxMs = latencies.length > 0 ? latencies[latencies.length - 1] : 0;

  const avgTokensPerCase = (cases.length > 0 && hasValidTokens) ? Math.round(totalTokens / cases.length) : null;

  const executionMode = options.executionMode || (options.live ? "live" : "mock");
  const workspaceMode = Boolean(options.virtual) ? "virtual" : "physical";

  return {
    framework: BENCHMARK_FRAMEWORK_NAME,
    mode,
    executionMode,
    workspaceMode,
    timestamp: new Date().toISOString(),
    totalCases: cases.length,
    caseResults,
    metrics: {
      totalCases: cases.length,
      vulnerableCasesCount,
      cleanCasesCount,
      totalGoldens,
      caughtGoldens,
      totalReportedFindings,
      truePositives,
      falsePositives,
      falseBlocks,
      recall,
      precision,
      falseBlockRate,
      latency: {
        p50Ms,
        p95Ms,
        avgMs,
        minMs,
        maxMs
      },
      tokens: hasValidTokens ? {
        available: true,
        totalPromptTokens,
        totalCompletionTokens,
        totalTokens,
        avgTokensPerCase
      } : {
        available: false,
        totalPromptTokens: null,
        totalCompletionTokens: null,
        totalTokens: null,
        avgTokensPerCase: null
      },
      costRatio: hasValidTokens ? (options.costRatio ?? 1.0) : null
    }
  };
}

/**
 * Runs 3-way empirical comparison across Single, Fixed Dual, and Risk-Routed configurations.
 *
 * @param {object[]} [corpus=TF_RBC_V0_CASES]
 * @param {object|null} [adapters=null]
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function runThreeWayRealComparison(corpus = TF_RBC_V0_CASES, adapters = null, options = {}) {
  const single = await evaluateCorpusSuite(corpus, adapters, { ...options, mode: "single" });
  const dual = await evaluateCorpusSuite(corpus, adapters, { ...options, mode: "dual" });
  const riskRouted = await evaluateCorpusSuite(corpus, adapters, { ...options, mode: "risk-routed" });

  const tokensAvailable = Boolean(
    single.metrics.tokens?.available &&
    dual.metrics.tokens?.available &&
    riskRouted.metrics.tokens?.available &&
    single.metrics.tokens?.totalTokens > 0
  );

  let dualTokenMultiplier = null;
  let routedTokenMultiplier = null;

  if (tokensAvailable) {
    const baselineTokens = single.metrics.tokens.totalTokens;
    dualTokenMultiplier = parseFloat((dual.metrics.tokens.totalTokens / baselineTokens).toFixed(2));
    routedTokenMultiplier = parseFloat((riskRouted.metrics.tokens.totalTokens / baselineTokens).toFixed(2));
    single.metrics.costRatio = 1.0;
    dual.metrics.costRatio = dualTokenMultiplier;
    riskRouted.metrics.costRatio = routedTokenMultiplier;
  } else {
    single.metrics.costRatio = null;
    dual.metrics.costRatio = null;
    riskRouted.metrics.costRatio = null;
  }

  const marginalRecallGain = parseFloat((dual.metrics.recall - single.metrics.recall).toFixed(3));

  let recommendation = "";
  if (!tokensAvailable) {
    recommendation = "Token usage data unavailable; insufficient data to support configuration cost-efficiency conclusion.";
  } else if (marginalRecallGain > 0 && riskRouted.metrics.recall >= dual.metrics.recall * 0.95 && routedTokenMultiplier < dualTokenMultiplier) {
    const savingsPct = dualTokenMultiplier > 0 ? Math.round((1 - routedTokenMultiplier / dualTokenMultiplier) * 100) : 0;
    recommendation = `Risk-Adaptive Routing is empirically justified: captures ${(riskRouted.metrics.recall * 100).toFixed(1)}% recall while saving ${savingsPct}% of multi-agent token overhead.`;
  } else if (dual.metrics.recall > single.metrics.recall) {
    recommendation = `Dual Heterogeneous sentries provide highest safety with +${(marginalRecallGain * 100).toFixed(1)}% marginal recall gain.`;
  } else {
    recommendation = "Single Sentry baseline showed no observed recall gap in current workload; no marginal gain observed for dual reviewers.";
  }

  const executionMode = options.executionMode || (options.live ? "live" : "mock");
  const workspaceMode = Boolean(options.virtual) ? "virtual" : "physical";

  return {
    framework: BENCHMARK_FRAMEWORK_NAME,
    mode: "all",
    executionMode,
    workspaceMode,
    timestamp: new Date().toISOString(),
    configurations: {
      single,
      dual,
      riskRouted
    },
    metrics: {
      marginalRecallGain,
      dualTokenMultiplier,
      routedTokenMultiplier
    },
    recommendation
  };
}

/**
 * Formats benchmark execution report into a clean, human-readable ASCII summary table.
 *
 * @param {object} runResult - Report from evaluateCorpusSuite or runThreeWayRealComparison.
 * @returns {string} Formatted ASCII text.
 */
export function formatBenchmarkSummary(runResult) {
  if (!runResult) return "No benchmark results available.";

  const lines = [];

  if (runResult.mode === "all" && runResult.configurations) {
    const { single, dual, riskRouted } = runResult.configurations;
    const { marginalRecallGain, dualTokenMultiplier, routedTokenMultiplier } = runResult.metrics || {};

    const formatTokenCol = (m) => m.tokens?.available ? String(m.tokens.totalTokens).padStart(6) : "  null";
    const formatRatioCol = (m) => m.costRatio !== null && m.costRatio !== undefined ? m.costRatio.toFixed(2).padStart(10) : "       N/A";
    const formatFbrCol = (m) => (m.cleanCasesCount > 0 && m.falseBlockRate !== null && m.falseBlockRate !== undefined)
      ? `${(m.falseBlockRate * 100).toFixed(1)}%`.padStart(16)
      : "             N/A";

    lines.push("==================================================================================");
    lines.push(` ${BENCHMARK_FRAMEWORK_NAME} Three-Way Comparison Matrix`);
    lines.push("==================================================================================");
    lines.push(" Configuration    | Recall  | Precision | False Block Rate | P50 (ms) | Tokens | Cost Ratio");
    lines.push("------------------+---------+-----------+------------------+----------+--------+-----------");
    lines.push(` 1. Single        | ${(single.metrics.recall * 100).toFixed(1).padStart(6)}% | ${(single.metrics.precision * 100).toFixed(1).padStart(8)}% | ${formatFbrCol(single.metrics)} | ${String(single.metrics.latency.p50Ms).padStart(7)}ms | ${formatTokenCol(single.metrics)} | ${formatRatioCol(single.metrics)}`);
    lines.push(` 2. Dual (Hetero) | ${(dual.metrics.recall * 100).toFixed(1).padStart(6)}% | ${(dual.metrics.precision * 100).toFixed(1).padStart(8)}% | ${formatFbrCol(dual.metrics)} | ${String(dual.metrics.latency.p50Ms).padStart(7)}ms | ${formatTokenCol(dual.metrics)} | ${formatRatioCol(dual.metrics)}`);
    lines.push(` 3. Risk-Adaptive | ${(riskRouted.metrics.recall * 100).toFixed(1).padStart(6)}% | ${(riskRouted.metrics.precision * 100).toFixed(1).padStart(8)}% | ${formatFbrCol(riskRouted.metrics)} | ${String(riskRouted.metrics.latency.p50Ms).padStart(7)}ms | ${formatTokenCol(riskRouted.metrics)} | ${formatRatioCol(riskRouted.metrics)}`);
    lines.push("------------------+---------+-----------+------------------+----------+--------+-----------");
    lines.push(` Marginal Recall Gain (Dual - Single):   +${(marginalRecallGain * 100).toFixed(1)}%`);
    const tokenMultText = (dualTokenMultiplier !== null && routedTokenMultiplier !== null)
      ? `Dual: ${dualTokenMultiplier}x | Risk-Adaptive: ${routedTokenMultiplier}x`
      : "unavailable (insufficient token metadata)";
    lines.push(` Multi-Agent Token Multipliers:          ${tokenMultText}`);
    lines.push(` Recommendation: ${runResult.recommendation}`);
    lines.push("==================================================================================");
    return lines.join("\n");
  }

  const { mode, totalCases, metrics, caseResults } = runResult;
  lines.push("==================================================================================");
  lines.push(` ${BENCHMARK_FRAMEWORK_NAME}`);
  lines.push(` Mode: ${mode.toUpperCase()} | Execution: ${runResult.executionMode || "mock"} | Workspace: ${runResult.workspaceMode || "virtual"} | Total Cases: ${totalCases}`);
  lines.push("==================================================================================");
  lines.push(" Case ID        | Risk   | Expected | Actual   | Status                 | Latency | Result");
  lines.push("----------------+--------+----------+----------+------------------------+---------+-------");

  for (const c of caseResults || []) {
    const id = c.caseId.padEnd(14);
    const risk = `Tier ${c.riskTier}`.padEnd(6);
    const exp = c.expectedGateDecision.toUpperCase().padEnd(8);
    const act = c.actualGateDecision.toUpperCase().padEnd(8);
    const status = c.status.padEnd(22);
    const latency = `${c.latencyMs}ms`.padStart(7);
    const pass = c.passed ? " PASS " : "!FAIL!";
    lines.push(` ${id} | ${risk} | ${exp} | ${act} | ${status} | ${latency} | ${pass}`);
  }

  lines.push("----------------+--------+----------+----------+------------------------+---------+-------");
  lines.push(" METRICS SUMMARY:");
  const recallText = metrics.totalGoldens > 0
    ? `${(metrics.recall * 100).toFixed(1)}% (${metrics.caughtGoldens}/${metrics.totalGoldens} Golden CWEs caught)`
    : "N/A (0 Golden CWEs in evaluation set)";
  const precTotal = metrics.truePositives + metrics.falsePositives;
  const precText = precTotal > 0
    ? `${(metrics.precision * 100).toFixed(1)}% (${metrics.truePositives}/${precTotal} Findings verified)`
    : (metrics.vulnerableCasesCount > 0 ? "0.0% (0/0 Findings reported)" : "100.0% (0 False Alarms on Clean Cases)");
  lines.push(`  • Recall Rate (R):         ${recallText}`);
  lines.push(`  • Precision (P):           ${precText}`);
  const fbrText = (metrics.cleanCasesCount > 0 && metrics.falseBlockRate !== null && metrics.falseBlockRate !== undefined)
    ? `${(metrics.falseBlockRate * 100).toFixed(1)}% (${metrics.falseBlocks}/${metrics.cleanCasesCount} Clean cases blocked)`
    : "not-applicable (0/0 Clean cases in evaluation set)";
  lines.push(`  • False Block Rate (FBR):  ${fbrText}`);
  lines.push(`  • Latency Profile:         P50: ${metrics.latency.p50Ms}ms | P95: ${metrics.latency.p95Ms}ms | Avg: ${metrics.latency.avgMs}ms`);
  const tokenText = metrics.tokens?.available
    ? `${metrics.tokens.totalTokens.toLocaleString()} tokens total (Avg: ${metrics.tokens.avgTokensPerCase} tokens/case)`
    : "unavailable (provider did not report usage metadata)";
  lines.push(`  • Token Expenditure:       ${tokenText}`);
  lines.push("==================================================================================");

  return lines.join("\n");
}
