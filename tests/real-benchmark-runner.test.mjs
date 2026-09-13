/**
 * Comprehensive Offline Test Suite for Real Benchmark Runner (TF-RBC-v0)
 *
 * Enforces:
 * - Test 1: 15-case corpus schema and ground-truth label completeness.
 * - Test 2: Disposable workspace lifecycle and strict repository immutability assertion.
 * - Test 3: Metric aggregation mathematics (Recall, Precision, FBR, Latency, Tokens).
 * - Test 4: Case filtering (--case=<id>) and evaluation limits (--limit=<n>).
 * - Test 5: Three-Way Comparison (Single vs Dual vs Risk-Adaptive) Pareto calculations.
 * - Test 6: Simulation of misses and false blocks to verify fail-closed and FBR calculations.
 * - Test 7: Formatter produces structured ASCII tables for both single and 3-way matrix runs.
 *
 * Invariant: 100% offline, zero network, fast execution (< 3s total).
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import {
  TF_RBC_V0_CASES,
  createCorpusCaseWorkspace,
  createMockCorpusAdapters,
  getCorpusCaseById,
  listCorpusCases,
  assertRepoImmutability
} from "./fixtures/real-corpus-fixtures.mjs";
import {
  evaluateCorpusCase,
  evaluateCorpusSuite,
  runThreeWayRealComparison,
  formatBenchmarkSummary,
  BENCHMARK_FRAMEWORK_NAME
} from "../src/core/real-benchmark-runner.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";

test("Test 1 (Corpus Schema & Ground-Truth Completeness): 15 cases adhere strictly to TF-RBC-v0 specification", () => {
  assert.equal(TF_RBC_V0_CASES.length, 15, "Corpus must contain exactly 15 frozen cases");

  const vulnerableCases = TF_RBC_V0_CASES.filter(c => c.category === "vulnerable");
  const cleanCases = TF_RBC_V0_CASES.filter(c => c.category === "clean");

  assert.equal(vulnerableCases.length, 12, "Must contain exactly 12 vulnerable cases");
  assert.equal(cleanCases.length, 3, "Must contain exactly 3 clean negative controls");

  const idSet = new Set();
  const validTiers = new Set([1, 2, 3]);

  for (const c of TF_RBC_V0_CASES) {
    assert.ok(c.id, "Case ID must be defined");
    assert.match(c.id, /^BENCH-REAL-\d{3}$/, `Case ID format invalid: ${c.id}`);
    assert.ok(!idSet.has(c.id), `Duplicate case ID detected: ${c.id}`);
    idSet.add(c.id);

    assert.ok(typeof c.title === "string" && c.title.trim().length > 0, `Missing title for ${c.id}`);
    assert.ok(validTiers.has(c.riskTier), `Invalid riskTier for ${c.id}: ${c.riskTier}`);
    assert.ok(["vulnerable", "clean"].includes(c.category), `Invalid category for ${c.id}: ${c.category}`);
    assert.ok(typeof c.targetFile === "string" && c.targetFile.includes("/"), `Invalid targetFile for ${c.id}`);
    assert.ok(typeof c.description === "string" && c.description.length > 0, `Missing description for ${c.id}`);
    assert.ok(["block", "approve"].includes(c.expectedGateDecision), `Invalid expectedGateDecision for ${c.id}`);
    assert.equal(c.lineTolerance, 50, `Line tolerance must be 50 lines for ${c.id}`);
    assert.ok(c.baseFiles && typeof c.baseFiles === "object", `Missing baseFiles for ${c.id}`);
    assert.ok(c.headFiles && typeof c.headFiles === "object", `Missing headFiles for ${c.id}`);

    if (c.category === "vulnerable") {
      assert.equal(c.expectedGateDecision, "block", `Vulnerable case ${c.id} must expect BLOCK decision`);
      assert.ok(Array.isArray(c.goldenFindings) && c.goldenFindings.length > 0, `Vulnerable case ${c.id} must have golden findings`);
      const headText = c.headFiles[c.targetFile] || "";
      const headLineCount = headText.split("\n").length;

      for (const g of c.goldenFindings) {
        assert.match(g.cwe, /^CWE-\d+$/, `Golden CWE invalid in ${c.id}: ${g.cwe}`);
        assert.ok(g.type, `Missing golden finding type in ${c.id}`);
        assert.equal(g.file, c.targetFile, `Golden finding file must match targetFile in ${c.id}`);
        assert.ok(Number.isFinite(g.line) && g.line > 0, `Golden line must be a positive number in ${c.id}`);
        assert.ok(g.line <= headLineCount, `Golden line ${g.line} exceeds head file length (${headLineCount}) in ${c.id}`);
        assert.ok(["critical", "high"].includes(g.severity), `Golden severity must be critical or high in ${c.id}`);
        assert.ok(g.rationale, `Missing rationale in ${c.id}`);
      }
    } else {
      assert.equal(c.expectedGateDecision, "approve", `Clean case ${c.id} must expect APPROVE decision`);
      assert.equal(c.goldenFindings.length, 0, `Clean case ${c.id} must have 0 golden findings`);
    }
  }
});

test("Test 2 (Workspace Lifecycle & Read-Only Immutability): Repositories remain strictly untouched", () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(caseDef, "Must find BENCH-REAL-001");

  const workspace = createCorpusCaseWorkspace(caseDef);
  try {
    assert.ok(fs.existsSync(workspace.dir), "Workspace directory must exist");
    assert.ok(workspace.baseSha, "baseSha must be generated");
    assert.ok(workspace.headSha, "headSha must be generated");
    assert.ok(workspace.changeSet.ok, "changeSet must be valid");
    assert.equal(workspace.changeSet.scopeMode, "revision-range");

    // 1. Initial state is 100% clean
    assert.equal(workspace.assertImmutability(), true);

    // 2. Unauthorized mutation triggers immutability failure
    const roguePath = path.join(workspace.dir, "rogue-agent-leak.tmp");
    fs.writeFileSync(roguePath, "unauthorized\n", "utf8");
    assert.throws(() => workspace.assertImmutability(), /Repo immutability violated/);

    // 3. Clean rogue mutation restores immutability
    fs.unlinkSync(roguePath);
    assert.equal(workspace.assertImmutability(), true);
  } finally {
    workspace.cleanup();
  }

  // Directory cleaned up
  assert.ok(!fs.existsSync(workspace.dir), "Workspace directory must be removed after cleanup");
});

test("Test 3 (Metric Aggregation Mathematics): Evaluates 15 cases and verifies Recall, Precision, and FBR", async () => {
  // Use mock adapters that catch all 12 vulnerabilities and approve all 3 clean cases
  const mockAdapters = createMockCorpusAdapters();

  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, { mode: "single", virtual: true });

  assert.equal(report.framework, BENCHMARK_FRAMEWORK_NAME);
  assert.equal(report.mode, "single");
  assert.equal(report.totalCases, 15);
  assert.equal(report.caseResults.length, 15);

  const m = report.metrics;
  assert.equal(m.totalCases, 15);
  assert.equal(m.vulnerableCasesCount, 12);
  assert.equal(m.cleanCasesCount, 3);
  assert.equal(m.totalGoldens, 12);
  assert.equal(m.caughtGoldens, 12);
  assert.equal(m.falseBlocks, 0);

  // Math assertions
  assert.equal(m.recall, 1.0, "Recall must be 100% when all 12 goldens caught");
  assert.equal(m.precision, 1.0, "Precision must be 100% when zero false alarms");
  assert.equal(m.falseBlockRate, 0.0, "FBR must be 0% when zero clean cases blocked");
  assert.ok(m.tokens.totalTokens > 0, "Total tokens must be > 0");
  assert.ok(m.tokens.avgTokensPerCase > 0, "Average tokens must be > 0");
  assert.ok(m.latency.p50Ms >= 0, "P50 latency must be non-negative");
  assert.ok(m.latency.p95Ms >= m.latency.p50Ms, "P95 latency must be >= P50");
});

test("Test 4 (Case Filtering & Limits): --case and --limit selectively execute target cases", async () => {
  const mockAdapters = createMockCorpusAdapters();

  // 1. Filter by single case ID
  const singleReport = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, {
    case: "BENCH-REAL-003",
    mode: "single",
    virtual: true
  });
  assert.equal(singleReport.totalCases, 1);
  assert.equal(singleReport.caseResults[0].caseId, "BENCH-REAL-003");
  assert.equal(singleReport.caseResults[0].passed, true);

  // 2. Limit execution to 2 cases
  const limitReport = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, {
    limit: 2,
    mode: "single",
    virtual: true
  });
  assert.equal(limitReport.totalCases, 2);
  assert.equal(limitReport.caseResults.length, 2);

  // 3. Unknown case throws clear error
  await assert.rejects(
    () => evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, { case: "UNKNOWN-999", virtual: true }),
    /Corpus case 'UNKNOWN-999' not found/
  );
});

test("Test 5 (Three-Way Comparison): Single vs Dual vs Risk-Adaptive Pareto calculations", async () => {
  // Simulate macro sentry missing 1 vulnerability on Tier 1 critical file (BENCH-REAL-012: crypto)
  // Dual sentry catches all 12 vulnerabilities
  const mockAdapters = createMockCorpusAdapters({
    macroMisses: ["BENCH-REAL-012"]
  });

  const threeWayReport = await runThreeWayRealComparison(TF_RBC_V0_CASES, mockAdapters, { virtual: true });

  assert.equal(threeWayReport.framework, BENCHMARK_FRAMEWORK_NAME);
  assert.equal(threeWayReport.mode, "all");
  assert.ok(threeWayReport.configurations.single);
  assert.ok(threeWayReport.configurations.dual);
  assert.ok(threeWayReport.configurations.riskRouted);

  const { single, dual, riskRouted } = threeWayReport.configurations;

  // Single missed 1 golden -> 11/12 = 0.917 recall
  assert.equal(single.metrics.caughtGoldens, 11);
  assert.equal(single.metrics.recall, 0.917);

  // Dual caught all 12 goldens -> 12/12 = 1.0 recall
  assert.equal(dual.metrics.caughtGoldens, 12);
  assert.equal(dual.metrics.recall, 1.0);

  // Risk-Adaptive routes Tier 1 (BENCH-REAL-012) to Dual via production evaluateDiffScale -> 12/12 = 1.0 recall
  assert.equal(riskRouted.metrics.caughtGoldens, 12);
  assert.equal(riskRouted.metrics.recall, 1.0);

  // Metrics comparison
  const metrics = threeWayReport.metrics;
  assert.equal(metrics.marginalRecallGain, 0.083); // +8.3% gain
  assert.ok(metrics.dualTokenMultiplier > 1.5, "Dual mode consumes approximately 2x tokens");
  assert.ok(metrics.routedTokenMultiplier < metrics.dualTokenMultiplier, "Risk-adaptive saves tokens compared to dual");
  assert.match(threeWayReport.recommendation, /Risk-Adaptive Routing is empirically justified/);
});

test("Test 6 (False Block & Miss Simulation): Accurately records FBR when clean cases are blocked", async () => {
  // Simulate false alarm on clean case BENCH-REAL-014
  const mockAdapters = createMockCorpusAdapters({
    macroFalseBlocks: ["BENCH-REAL-014"]
  });

  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, { mode: "single", virtual: true });
  const m = report.metrics;

  assert.equal(m.cleanCasesCount, 3);
  assert.equal(m.falseBlocks, 1);
  assert.equal(m.falseBlockRate, 0.333); // 1/3 = 33.3%

  const blockedCase = report.caseResults.find(r => r.caseId === "BENCH-REAL-014");
  assert.equal(blockedCase.isFalseBlock, true);
  assert.equal(blockedCase.passed, false);
});

test("Test 7 (Summary Formatter): Generates clean human-readable ASCII output", async () => {
  const mockAdapters = createMockCorpusAdapters();

  // 1. Single run formatting
  const singleReport = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, { limit: 3, mode: "single", virtual: true });
  const singleOutput = formatBenchmarkSummary(singleReport);
  assert.ok(singleOutput.includes("TF-RBC-v0"), "Must include framework title");
  assert.ok(singleOutput.includes("BENCH-REAL-001"), "Must include case rows");
  assert.ok(singleOutput.includes("METRICS SUMMARY"), "Must include summary");

  // 2. Three-way comparison formatting
  const threeWayReport = await runThreeWayRealComparison(TF_RBC_V0_CASES.slice(0, 3), mockAdapters, { virtual: true });
  const threeWayOutput = formatBenchmarkSummary(threeWayReport);
  assert.ok(threeWayOutput.includes("Three-Way Comparison Matrix"), "Must include comparison title");
  assert.ok(threeWayOutput.includes("Marginal Recall Gain"), "Must include marginal gain");
  assert.ok(threeWayOutput.includes("Recommendation:"), "Must include recommendation");
});

test("Test 8 (Physical Workspace Lifecycle): evaluateCorpusCase completes on real disposable Git repository", async () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(caseDef);

  const mockAdapters = createMockCorpusAdapters();
  const res = await evaluateCorpusCase(caseDef, mockAdapters, { mode: "single", virtual: false });

  assert.equal(res.caseId, "BENCH-REAL-001");
  assert.equal(res.actualGateDecision, "block");
  assert.equal(res.passed, true);
  assert.equal(res.evalResult.caughtGoldens, 1);
});

test("Test 9 (Precision Edge Case): Zero findings verified on vulnerable code results in 0.0% precision (not fake 100%)", async () => {
  // Simulate macro sentry reporting 0 findings on vulnerable case
  const zeroAdapters = createMockCorpusAdapters({ macroMisses: ["BENCH-REAL-001"] });
  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, zeroAdapters, {
    case: "BENCH-REAL-001",
    mode: "single",
    virtual: true
  });

  assert.equal(report.metrics.vulnerableCasesCount, 1);
  assert.equal(report.metrics.cleanCasesCount, 0);
  assert.equal(report.metrics.caughtGoldens, 0);
  assert.equal(report.metrics.totalReportedFindings, 0);
  assert.equal(report.metrics.recall, 0.0, "Recall must be 0% when defect missed");
  assert.equal(report.metrics.precision, 0.0, "Precision must be 0.0% when 0 findings verified on vulnerable code");
  assert.equal(report.metrics.falseBlockRate, null, "FBR must be null when cleanCasesCount is 0");
  assert.equal(report.executionMode, "mock");
  assert.equal(report.workspaceMode, "virtual");

  const formatted = formatBenchmarkSummary(report);
  assert.ok(formatted.includes("not-applicable (0/0 Clean cases in evaluation set)"));
  assert.ok(formatted.includes("Execution: mock | Workspace: virtual"));
});

test("Test 10 (Clean-Only Cases Metric Format): Formatter displays N/A recall without fake 100%", async () => {
  const mockAdapters = createMockCorpusAdapters();
  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, {
    case: "BENCH-REAL-013",
    mode: "single",
    virtual: true
  });

  assert.equal(report.metrics.totalGoldens, 0);
  assert.equal(report.metrics.cleanCasesCount, 1);
  assert.equal(report.metrics.precision, 1.0);

  const output = formatBenchmarkSummary(report);
  assert.ok(output.includes("N/A (0 Golden CWEs in evaluation set)"));
  assert.ok(output.includes("100.0% (0 False Alarms on Clean Cases)"));
});

test("Test 11 (CLI Execution Integration): scripts/run-real-benchmark.mjs supports CLI arguments, reports, and strict validation", () => {
  const tmpReport = path.join(os.tmpdir(), `tf-bench-cli-test-${Date.now()}.json`);
  try {
    const cliRes = spawnSync(process.execPath, ["scripts/run-real-benchmark.mjs", "--limit=1", `--report=${tmpReport}`], {
      cwd: process.cwd(),
      encoding: "utf8"
    });
    assert.equal(cliRes.status, 0, `CLI script failed: ${cliRes.stderr}`);
    assert.ok(fs.existsSync(tmpReport), "Report JSON must be written to disk");
    const json = JSON.parse(fs.readFileSync(tmpReport, "utf8"));
    assert.equal(json.totalCases, 1);

    // Verify invalid limit argument is rejected
    const invalidLimit = spawnSync(process.execPath, ["scripts/run-real-benchmark.mjs", "--limit=abc"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });
    assert.equal(invalidLimit.status, 1, "CLI must exit with code 1 on invalid --limit");
    assert.ok(invalidLimit.stderr.includes("Invalid --limit"));

    // Verify invalid mode is rejected
    const invalidMode = spawnSync(process.execPath, ["scripts/run-real-benchmark.mjs", "--mode=invalid"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });
    assert.equal(invalidMode.status, 1, "CLI must exit with code 1 on invalid --mode");
    assert.ok(invalidMode.stderr.includes("Invalid --mode"));
  } finally {
    try {
      if (fs.existsSync(tmpReport)) fs.unlinkSync(tmpReport);
    } catch {}
  }
});

test("Test 12 (3-Point Passed Check): Requires detectionPass, gatePolicyPass, and executionComplete", async () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(caseDef);

  // Scenario A: Reviewer catches golden defect but tags it as 'info' severity -> Gate approves -> gatePolicyPass is false -> passed is false
  const infoAdapter = new CliReviewAdapter({
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [
          {
            title: "Detected SQL injection (CWE-89)",
            severity: "info",
            file: caseDef.targetFile,
            line_start: 3,
            line_end: 3,
            cwe: "CWE-89",
            type: "sql-injection"
          }
        ],
        coverage: { coveredFiles: [caseDef.targetFile], omittedFiles: [] },
        usage: { promptTokens: 100, completionTokens: 20, totalTokens: 120 }
      })
    })
  });

  const resInfo = await evaluateCorpusCase(caseDef, { macro: infoAdapter }, { mode: "single", virtual: true });
  assert.equal(resInfo.detectionPass, true, "Golden CWE was detected");
  assert.equal(resInfo.actualGateDecision, "approve", "Info severity findings do not block default gate");
  assert.equal(resInfo.gatePolicyPass, false, "Actual gate decision 'approve' differs from expected 'block'");
  assert.equal(resInfo.passed, false, "Case must NOT pass when gate policy failed to block defect");

  // Scenario B: Incomplete review status fails executionComplete
  const incompleteAdapter = new CliReviewAdapter({
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [
          {
            title: "Detected SQL injection (CWE-89)",
            severity: "critical",
            file: caseDef.targetFile,
            line_start: 3,
            line_end: 3,
            cwe: "CWE-89",
            type: "sql-injection"
          }
        ],
        coverage: { coveredFiles: [], omittedFiles: [{ path: caseDef.targetFile, reason: "omitted" }] }
      })
    })
  });

  const resIncomplete = await evaluateCorpusCase(caseDef, { macro: incompleteAdapter }, { mode: "single", virtual: true });
  assert.equal(resIncomplete.status, "incomplete");
  assert.equal(resIncomplete.executionComplete, false);
  assert.equal(resIncomplete.passed, false);
});

test("Test 13 (Token Metadata Preservation): Preserves null/unavailable without fake zero-sum", async () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");

  // Adapter that returns null usage
  const nullUsageAdapter = new CliReviewAdapter({
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [
          {
            title: "Detected SQL injection (CWE-89)",
            severity: "high",
            file: caseDef.targetFile,
            line_start: 3,
            line_end: 3,
            cwe: "CWE-89"
          }
        ],
        coverage: { coveredFiles: [caseDef.targetFile], omittedFiles: [] },
        usage: { promptTokens: null, completionTokens: null, totalTokens: null }
      })
    })
  });

  const singleRes = await evaluateCorpusCase(caseDef, { macro: nullUsageAdapter }, { mode: "single", virtual: true });
  assert.equal(singleRes.usage.available, false);
  assert.equal(singleRes.usage.promptTokens, null);
  assert.equal(singleRes.usage.totalTokens, null);

  const suiteRes = await evaluateCorpusSuite([caseDef], { macro: nullUsageAdapter }, { mode: "single", virtual: true });
  assert.equal(suiteRes.metrics.tokens.available, false);
  assert.equal(suiteRes.metrics.tokens.totalTokens, null);
  assert.equal(suiteRes.metrics.costRatio, null);

  const summary = formatBenchmarkSummary(suiteRes);
  assert.match(summary, /unavailable \(provider did not report usage metadata\)/);

  // In 3-way comparison with missing usage, recommendation must downgrade to insufficient data
  const threeWay = await runThreeWayRealComparison([caseDef], { macro: nullUsageAdapter, micro: nullUsageAdapter }, { virtual: true });
  assert.equal(threeWay.metrics.dualTokenMultiplier, null);
  assert.equal(threeWay.metrics.routedTokenMultiplier, null);
  assert.match(threeWay.recommendation, /Token usage data unavailable; insufficient data to support configuration cost-efficiency conclusion/);
});

test("Test 14 (Live & Virtual Rejection): scripts/run-real-benchmark.mjs rejects --live with --virtual", () => {
  const liveVirtual = spawnSync(process.execPath, ["scripts/run-real-benchmark.mjs", "--live", "--virtual"], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
  assert.equal(liveVirtual.status, 1, "Must exit with code 1 when --live and --virtual combined");
  assert.match(liveVirtual.stderr, /Live evaluation requires physical repository workspace/);
});

test("Test 15 (Metadata & Non-Optimal Baseline): Reports expose executionMode and workspaceMode, and recommendation avoids prohibited optimal claim", async () => {
  const mockAdapters = createMockCorpusAdapters();
  // With no misses, single recall equals dual recall (0 observed gap)
  const threeWay = await runThreeWayRealComparison(TF_RBC_V0_CASES, mockAdapters, { virtual: true });
  assert.equal(threeWay.executionMode, "mock");
  assert.equal(threeWay.workspaceMode, "virtual");
  assert.ok(!threeWay.recommendation.includes("optimal"), "Recommendation must not claim baseline is optimal");
  assert.match(threeWay.recommendation, /no observed recall gap/);
});



