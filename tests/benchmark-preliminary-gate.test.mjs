/**
 * Unit & Integration Tests for Benchmark Preliminary Gate Decision Consistency
 * Issue: G5-P2-07 (Threads: ra7k3, rtv6N, slqmG)
 *
 * Verifies:
 * 1. Clean cases in preliminary execution fail closed to "block" at the final gate.
 * 2. Vulnerable cases with detected defects in preliminary mode have finalGatePassed: false (Thread slqmG).
 * 3. Vulnerable cases with missed defects (false negatives) in preliminary mode derive finalGateDecision: "block"
 *    rather than "approve" due to missing Clean Challenge at final gate (Thread rtv6N).
 * 4. Suite evaluation metrics report finalGateScores.passedCasesCount === 0 and passRate === 0.0 in preliminary mode.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  evaluateCorpusCase,
  evaluateCorpusSuite,
  formatBenchmarkSummary
} from "../src/core/real-benchmark-runner.mjs";
import {
  TF_RBC_V0_CASES,
  getCorpusCaseById,
  createMockCorpusAdapters
} from "./fixtures/real-corpus-fixtures.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";

test("G5-P2-07-01: Clean case in preliminary mode fails closed at final gate with finalGatePassed = false", async () => {
  const cleanCaseDef = getCorpusCaseById("BENCH-REAL-013");
  assert.ok(cleanCaseDef, "BENCH-REAL-013 must exist");
  assert.equal(cleanCaseDef.category, "clean");
  assert.equal(cleanCaseDef.expectedGateDecision, "approve");

  const mockAdapters = createMockCorpusAdapters();
  const res = await evaluateCorpusCase(cleanCaseDef, mockAdapters, { mode: "single", virtual: true });

  assert.equal(res.isPreliminary, true, "Case must be preliminary");
  assert.equal(res.actualGateDecision, "approve", "Preliminary gate decision approves clean consensus");
  assert.equal(res.preliminaryPassed, true, "Preliminary passed must be true for clean consensus");
  assert.equal(res.finalGateDecision, "block", "Final gate must fail closed (block) without Clean Challenge");
  assert.equal(res.finalGatePolicyPass, false, "Final gate policy pass must be false for unverified clean case");
  assert.equal(res.finalGatePassed, false, "Final gate passed must be false");
  assert.equal(res.promotionEligible, false, "Preliminary cases must not be promotion eligible");
});

test("G5-P2-07-02: Vulnerable case caught in preliminary mode has finalGatePassed = false (Thread slqmG)", async () => {
  const vulnCaseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(vulnCaseDef, "BENCH-REAL-001 must exist");
  assert.equal(vulnCaseDef.category, "vulnerable");
  assert.equal(vulnCaseDef.expectedGateDecision, "block");

  const mockAdapters = createMockCorpusAdapters();
  const res = await evaluateCorpusCase(vulnCaseDef, mockAdapters, { mode: "single", virtual: true });

  assert.equal(res.isPreliminary, true);
  assert.equal(res.detectionPass, true, "Golden CWE must be detected");
  assert.equal(res.actualGateDecision, "block", "Preliminary gate blocks on detected vulnerability");
  assert.equal(res.preliminaryPassed, true, "Preliminary passed check succeeds under preliminary conditions");
  assert.equal(res.finalGateDecision, "block", "Final gate decision is block");
  assert.equal(res.finalGatePolicyPass, false, "Preliminary run must not pass final gate policy (Thread slqmG)");
  assert.equal(res.finalGatePassed, false, "Preliminary run must have finalGatePassed = false (Thread slqmG)");
});

test("G5-P2-07-03: Vulnerable case missed (false negative) derives finalGateDecision: block from missing Clean Challenge (Thread rtv6N)", async () => {
  const vulnCaseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(vulnCaseDef);

  // Reviewer reports 0 findings on vulnerable code (false negative / miss)
  const missingAdapter = new CliReviewAdapter({
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: [vulnCaseDef.targetFile], omittedFiles: [] },
        usage: { promptTokens: 100, completionTokens: 20, totalTokens: 120 }
      })
    })
  });

  const res = await evaluateCorpusCase(vulnCaseDef, { macro: missingAdapter }, { mode: "single", virtual: true });

  assert.equal(res.isPreliminary, true);
  assert.equal(res.actualFindings.length, 0, "No findings reported by reviewer");
  assert.equal(res.actualGateDecision, "approve", "Preliminary orchestrator approved 0 findings");
  assert.equal(res.detectionPass, false, "Missed defect fails detectionPass");
  assert.equal(res.preliminaryPassed, false, "Missed defect fails preliminaryPassed");
  // Thread rtv6N: At a real final gate, 0 findings without Clean Challenge fails closed to block (NOT approve based on category)
  assert.equal(res.finalGateDecision, "block", "Observed zero findings without verification record must block at final gate");
  assert.equal(res.finalGatePolicyPass, false, "Missed defect must not pass final gate policy");
  assert.equal(res.finalGatePassed, false, "Missed defect must not pass final gate");
});

test("G5-P2-07-04: Corpus suite aggregation reports passedCasesCount = 0 in finalGateScores (Thread slqmG & ra7k3)", async () => {
  const cases = TF_RBC_V0_CASES.slice(0, 5); // contains both clean and vulnerable cases
  const mockAdapters = createMockCorpusAdapters();

  const suiteResult = await evaluateCorpusSuite(cases, mockAdapters, { mode: "single", virtual: true });
  const metrics = suiteResult.metrics;

  assert.ok(metrics.preliminaryScores, "Preliminary scores must be recorded");
  assert.equal(metrics.preliminaryScores.isPreliminary, true);
  assert.ok(metrics.preliminaryScores.passedCasesCount > 0, "Preliminary passes must be recorded");

  assert.ok(metrics.finalGateScores, "Final gate scores must be present");
  assert.equal(metrics.finalGateScores.passedCasesCount, 0, "No preliminary cases can be counted in finalGateScores.passedCasesCount");
  assert.equal(metrics.finalGateScores.passRate, 0.0, "finalGateScores.passRate must be 0.0 in preliminary mode");
  assert.equal(metrics.finalGateScores.promotionEligible, false);

  assert.ok(metrics.promotionEligibility);
  assert.equal(metrics.promotionEligibility.eligible, false);
  assert.equal(metrics.promotionEligibility.finalGatePassCount, 0);

  // Formatter output check
  const summary = formatBenchmarkSummary(suiteResult);
  assert.ok(summary.includes("[PROVISIONAL ONLY]"), "Summary must mark preliminary scores as provisional only");
  assert.ok(summary.includes("DISQUALIFIED"), "Summary must indicate promotion disqualification");
});
