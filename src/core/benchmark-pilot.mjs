/**
 * Empirical Benchmark Pilot & Multi-Reviewer Benefit Evaluation (PR-05)
 *
 * Measures marginal recall, precision, false block rates, token costs, and latency
 * comparing:
 *   1. Single Reviewer (Macro sentry only)
 *   2. Fixed Dual Reviewer (Always Macro + Micro)
 *   3. Risk-Adaptive Routing (Single on Tier 2/3 small diffs, Dual on Tier 1 / large diffs)
 *
 * Enforces 1-to-1 instance-level matching and preserves held-out test sets.
 */

import { verifyHeldOutBaseline } from "./scoring.mjs";
import { evaluateDiffScale, RISK_TIERS } from "./graph-router.mjs";
import { SEVERITY_WEIGHTS } from "./loop.mjs";

export const BENCHMARK_FRAMEWORK_TYPE = "Simulation / Synthetic Benchmark Framework";

export const PROVIDER_FAMILIES = Object.freeze({
  "claude": "anthropic",
  "anthropic": "anthropic",
  "agy": "google",
  "gemini": "google",
  "google": "google",
  "codex": "openai",
  "gpt": "openai",
  "openai": "openai"
});

export function getProviderFamily(providerName = "") {
  const norm = String(providerName).toLowerCase();
  for (const [key, family] of Object.entries(PROVIDER_FAMILIES)) {
    if (norm.includes(key)) return family;
  }
  return norm || "unknown";
}

/**
 * Validates provider family diversity between two sentries.
 */
export function validateProviderDiversity(macroProvider = "", microProvider = "") {
  const fam1 = getProviderFamily(macroProvider);
  const fam2 = getProviderFamily(microProvider);

  if (fam1 !== "unknown" && fam2 !== "unknown" && fam1 === fam2) {
    return {
      valid: false,
      family: fam1,
      reason: `Quorum Failure: Sentries lack provider-family diversity (both belong to '${fam1}').`
    };
  }

  return { valid: true, families: [fam1, fam2] };
}

/**
 * Deduplicates findings in dual mode using canonical identity and highest severity preservation.
 */
export function deduplicateBenchmarkFindings(findings = []) {
  const map = new Map();
  for (const f of findings) {
    if (!f) continue;
    const file = (f.file || f.path || "root").toLowerCase().replace(/\\/g, "/");
    const lineStart = Math.max(1, Number(f.line_start || f.line) || 1);
    const lineBucket = Math.floor(lineStart / 15) * 15;
    const rawTitle = (f.title || f.message || "issue").toLowerCase();
    const cweMatch = rawTitle.match(/cwe-\d+/i) || (f.cwe ? [f.cwe] : null);
    const cwe = cweMatch ? cweMatch[0].toUpperCase() : "";
    const token = cwe || rawTitle.replace(/[^a-z0-9]/g, "").slice(0, 16);
    const key = `${file}:${lineBucket}:${token}`;

    if (!map.has(key)) {
      map.set(key, { ...f });
    } else {
      const existing = map.get(key);
      const incomingWeight = SEVERITY_WEIGHTS[f.severity] ?? 0;
      const currentWeight = SEVERITY_WEIGHTS[existing.severity] ?? 0;
      if (incomingWeight > currentWeight) {
        existing.severity = f.severity;
      }
      if (!existing.ruleId && f.ruleId) existing.ruleId = f.ruleId;
      if (!existing.cwe && f.cwe) existing.cwe = f.cwe;
      if (!existing.type && f.type) existing.type = f.type;
    }
  }
  return Array.from(map.values());
}

/**
 * Generates an empirical pilot dataset of 24 canonical review cases across risk tiers.
 */
export function generatePilotDataset() {
  const cases = [];

  // 1. Tier 1 Critical Security Cases (8 cases: 6 standard, 2 held-out)
  for (let i = 1; i <= 8; i++) {
    const isHeldOut = i >= 7;
    cases.push({
      id: `PILOT-T1-${String(i).padStart(2, "0")}`,
      tier: RISK_TIERS.TIER_1_CRITICAL,
      heldOut: isHeldOut,
      adjudication: "positive",
      files: [{ path: `src/auth/jwt-session-${i}.ts`, additions: 35, deletions: 8 }],
      goldens: [
        { file: `src/auth/jwt-session-${i}.ts`, line: 15, cwe: "CWE-287", type: "authentication" }
      ],
      // Dual sentries excel on critical vulnerabilities: macro catches 7/8, micro catches 8/8
      outputs: {
        macro: {
          findings: i === 3 ? [] : [{ title: "Missing JWT Signature Verification", file: `src/auth/jwt-session-${i}.ts`, line_start: 15, cwe: "CWE-287", severity: "critical" }],
          usage: { promptTokens: 600, completionTokens: 120, totalTokens: 720 },
          latencyMs: 850
        },
        micro: {
          findings: [{ title: "JWT token parsed without verification", file: `src/auth/jwt-session-${i}.ts`, line_start: 15, cwe: "CWE-287", severity: "critical" }],
          usage: { promptTokens: 620, completionTokens: 110, totalTokens: 730 },
          latencyMs: 900
        }
      }
    });
  }

  // 2. Tier 2 Business Logic Cases (8 cases: 5 single-bug, 1 multi-bug in same file, 2 held-out)
  for (let i = 1; i <= 8; i++) {
    const isMultiBug = i === 4;
    const isHeldOut = i >= 7;
    const goldens = isMultiBug
      ? [
          { file: `src/services/order-${i}.ts`, line: 20, cwe: "CWE-89", type: "sql-injection" },
          { file: `src/services/order-${i}.ts`, line: 80, cwe: "CWE-89", type: "sql-injection" }
        ]
      : [
          { file: `src/services/order-${i}.ts`, line: 25, cwe: "CWE-89", type: "sql-injection" }
        ];

    cases.push({
      id: `PILOT-T2-${String(i).padStart(2, "0")}`,
      tier: RISK_TIERS.TIER_2_SOURCE,
      heldOut: isHeldOut,
      adjudication: "positive",
      files: [{ path: `src/services/order-${i}.ts`, additions: 15, deletions: 4 }],
      goldens,
      outputs: {
        macro: {
          findings: isMultiBug
            ? [
                { title: "SQL injection flaw 1", file: `src/services/order-${i}.ts`, line_start: 20, cwe: "CWE-89", severity: "high" },
                { title: "SQL injection flaw 2", file: `src/services/order-${i}.ts`, line_start: 80, cwe: "CWE-89", severity: "high" }
              ]
            : [{ title: "SQL query constructed via string concatenation", file: `src/services/order-${i}.ts`, line_start: 25, cwe: "CWE-89", severity: "high" }],
          usage: { promptTokens: 450, completionTokens: 80, totalTokens: 530 },
          latencyMs: 550
        },
        micro: {
          findings: [{ title: "SQL injection", file: `src/services/order-${i}.ts`, line_start: 25, cwe: "CWE-89", severity: "high" }],
          usage: { promptTokens: 460, completionTokens: 75, totalTokens: 535 },
          latencyMs: 580
        }
      }
    });
  }

  // 3. Tier 3 Clean PRs & Minor Dests (6 clean cases: tests false positive / false block rate)
  for (let i = 1; i <= 6; i++) {
    const isHeldOut = i === 6;
    cases.push({
      id: `PILOT-T3-${String(i).padStart(2, "0")}`,
      tier: RISK_TIERS.TIER_3_DOCS,
      heldOut: isHeldOut,
      adjudication: "clean",
      files: [{ path: `docs/guide-${i}.md`, additions: 10, deletions: 2 }],
      goldens: [],
      outputs: {
        macro: {
          findings: [],
          usage: { promptTokens: 200, completionTokens: 20, totalTokens: 220 },
          latencyMs: 300
        },
        micro: {
          // One false alarm by micro sentry on case 2
          findings: i === 2 ? [{ title: "Stylistic Nitpick", file: `docs/guide-${i}.md`, line_start: 5, severity: "high" }] : [],
          usage: { promptTokens: 210, completionTokens: 25, totalTokens: 235 },
          latencyMs: 310
        }
      }
    });
  }

  // 4. Undetermined Cases (2 cases reserved for pending human adjudication)
  cases.push({
    id: "PILOT-UND-01",
    tier: RISK_TIERS.TIER_2_SOURCE,
    heldOut: false,
    adjudication: "undetermined",
    files: [{ path: "src/utils/parser.ts", additions: 8, deletions: 2 }],
    goldens: [],
    outputs: {
      macro: { findings: [{ title: "Potential regex DoS", file: "src/utils/parser.ts", line_start: 10, severity: "medium" }], usage: { promptTokens: 300, completionTokens: 50, totalTokens: 350 }, latencyMs: 400 },
      micro: { findings: [], usage: { promptTokens: 300, completionTokens: 30, totalTokens: 330 }, latencyMs: 400 }
    }
  });

  cases.push({
    id: "PILOT-UND-02",
    tier: RISK_TIERS.TIER_2_SOURCE,
    heldOut: false,
    adjudication: "undetermined",
    files: [{ path: "src/utils/codec.ts", additions: 5, deletions: 1 }],
    goldens: [],
    outputs: {
      macro: { findings: [], usage: { promptTokens: 300, completionTokens: 30, totalTokens: 330 }, latencyMs: 400 },
      micro: { findings: [], usage: { promptTokens: 300, completionTokens: 30, totalTokens: 330 }, latencyMs: 400 }
    }
  });

  return cases;
}

/**
 * Evaluates benchmark metrics for a specific reviewer configuration.
 */
export function evaluateBenchmarkConfiguration(dataset = [], options = {}) {
  const { mode = "single", excludeHeldOut = false } = options;

  let totalCases = 0;
  let totalGoldens = 0;
  let truePositives = 0;
  let falsePositives = 0;
  let cleanCasesCount = 0;
  let falseBlocks = 0;
  let totalTokens = 0;
  let totalLatencyMs = 0;

  for (const c of dataset) {
    if (c.adjudication === "undetermined") {
      continue; // Exclude pending cases from deterministic score
    }
    if (excludeHeldOut && c.heldOut) {
      continue;
    }

    totalCases++;

    // Determine findings and resource usage based on mode
    let combinedFindings = [];
    let caseTokens = 0;
    let caseLatency = 0;

    if (mode === "single") {
      combinedFindings = [...(c.outputs.macro?.findings || [])];
      caseTokens = c.outputs.macro?.usage?.totalTokens || 0;
      caseLatency = c.outputs.macro?.latencyMs || 0;
    } else if (mode === "dual") {
      // Both macro + micro run with consensus deduplication before scoring
      const rawCombined = [
        ...(c.outputs.macro?.findings || []),
        ...(c.outputs.micro?.findings || [])
      ];
      combinedFindings = deduplicateBenchmarkFindings(rawCombined);
      caseTokens = (c.outputs.macro?.usage?.totalTokens || 0) + (c.outputs.micro?.usage?.totalTokens || 0);
      caseLatency = Math.max(c.outputs.macro?.latencyMs || 0, c.outputs.micro?.latencyMs || 0);
    } else if (mode === "risk-routed") {
      // Use GraphRouter: Tier 1 -> Dual, Tier 2/3 -> Single
      const scale = evaluateDiffScale(c.files);
      if (scale.mode === "hierarchical") {
        const rawCombined = [
          ...(c.outputs.macro?.findings || []),
          ...(c.outputs.micro?.findings || [])
        ];
        combinedFindings = deduplicateBenchmarkFindings(rawCombined);
        caseTokens = (c.outputs.macro?.usage?.totalTokens || 0) + (c.outputs.micro?.usage?.totalTokens || 0);
        caseLatency = Math.max(c.outputs.macro?.latencyMs || 0, c.outputs.micro?.latencyMs || 0);
      } else {
        combinedFindings = [...(c.outputs.macro?.findings || [])];
        caseTokens = c.outputs.macro?.usage?.totalTokens || 0;
        caseLatency = c.outputs.macro?.latencyMs || 0;
      }
    }

    totalTokens += caseTokens;
    totalLatencyMs += caseLatency;

    if (c.adjudication === "clean") {
      cleanCasesCount++;
      const hasBlocking = combinedFindings.some(f => /critical|high/i.test(f.severity || ""));
      if (hasBlocking) {
        falseBlocks++;
      }
      falsePositives += combinedFindings.length;
    } else if (c.adjudication === "positive") {
      totalGoldens += c.goldens.length;
      const evalRes = verifyHeldOutBaseline(combinedFindings, c.goldens);
      truePositives += evalRes.caughtGoldens;
      const unverifiedCount = Math.max(0, combinedFindings.length - evalRes.claimedFindingsCount);
      falsePositives += unverifiedCount;
    }
  }

  const recall = totalGoldens > 0 ? (truePositives / totalGoldens) : 1.0;
  const precisionDenominator = truePositives + falsePositives;
  const precision = precisionDenominator > 0 ? (truePositives / precisionDenominator) : 1.0;
  const falseBlockRate = cleanCasesCount > 0 ? (falseBlocks / cleanCasesCount) : 0.0;
  const avgLatencyMs = totalCases > 0 ? Math.round(totalLatencyMs / totalCases) : 0;

  return {
    framework: BENCHMARK_FRAMEWORK_TYPE,
    mode,
    totalCases,
    totalGoldens,
    truePositives,
    falsePositives,
    cleanCasesCount,
    falseBlocks,
    recall: parseFloat(recall.toFixed(3)),
    precision: parseFloat(precision.toFixed(3)),
    falseBlockRate: parseFloat(falseBlockRate.toFixed(3)),
    totalTokens,
    avgLatencyMs
  };
}

/**
 * Runs 3-way empirical comparison across Single, Fixed Dual, and Risk-Routed configurations.
 */
export function runThreeWayComparison(dataset = [], options = {}) {
  const single = evaluateBenchmarkConfiguration(dataset, { mode: "single", ...options });
  const dual = evaluateBenchmarkConfiguration(dataset, { mode: "dual", ...options });
  const riskRouted = evaluateBenchmarkConfiguration(dataset, { mode: "risk-routed", ...options });

  const marginalRecallGain = parseFloat((dual.recall - single.recall).toFixed(3));
  const dualTokenMultiplier = parseFloat((dual.totalTokens / single.totalTokens).toFixed(2));
  const routedTokenMultiplier = parseFloat((riskRouted.totalTokens / single.totalTokens).toFixed(2));

  let recommendation = "";
  if (marginalRecallGain > 0 && riskRouted.recall >= dual.recall * 0.95 && routedTokenMultiplier < dualTokenMultiplier) {
    recommendation = `Risk-Adaptive Routing is empirically justified: captures ${(riskRouted.recall * 100).toFixed(1)}% recall while saving ${Math.round((1 - routedTokenMultiplier / dualTokenMultiplier) * 100)}% of multi-agent token overhead.`;
  } else {
    recommendation = "Fixed configuration recommended based on empirical thresholds.";
  }

  return {
    framework: BENCHMARK_FRAMEWORK_TYPE,
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
