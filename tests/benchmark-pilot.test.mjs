import test from "node:test";
import assert from "node:assert/strict";
import {
  generatePilotDataset,
  evaluateBenchmarkConfiguration,
  runThreeWayComparison,
  validateProviderDiversity,
  getProviderFamily
} from "../src/core/benchmark-pilot.mjs";
import { verifyHeldOutBaseline } from "../src/core/scoring.mjs";

test("PR-05: 1-to-1 Instance Matching prevents 1 finding from claiming multiple golden defects", () => {
  // Scenario: Two distinct SQL injection vulnerabilities in the same file (lines 20 and 80)
  const twoGoldensInSameFile = [
    { file: "src/order.js", line: 20, cwe: "CWE-89", type: "sql-injection" },
    { file: "src/order.js", line: 80, cwe: "CWE-89", type: "sql-injection" }
  ];

  // The reviewer only reported ONE finding (at line 20)
  const singleActualFinding = [
    { file: "src/order.js", line_start: 20, cwe: "CWE-89", type: "sql-injection", title: "SQL Injection at line 20" }
  ];

  const evalRes = verifyHeldOutBaseline(singleActualFinding, twoGoldensInSameFile);

  // Invariant: The single finding must only claim 1 golden. Recall MUST be 50.0%, NOT 100.0%!
  assert.equal(evalRes.totalGoldens, 2);
  assert.equal(evalRes.caughtGoldens, 1);
  assert.equal(evalRes.claimedFindingsCount, 1);
  assert.equal(evalRes.recallRate, "50.0%");
  assert.equal(evalRes.passed, false);

  // When reviewer reports BOTH findings at distinct lines, recall reaches 100.0%
  const bothActualFindings = [
    { file: "src/order.js", line_start: 20, cwe: "CWE-89", type: "sql-injection", title: "SQL Injection 1" },
    { file: "src/order.js", line_start: 80, cwe: "CWE-89", type: "sql-injection", title: "SQL Injection 2" }
  ];
  const evalBothRes = verifyHeldOutBaseline(bothActualFindings, twoGoldensInSameFile);
  assert.equal(evalBothRes.caughtGoldens, 2);
  assert.equal(evalBothRes.claimedFindingsCount, 2);
  assert.equal(evalBothRes.recallRate, "100.0%");
  assert.equal(evalBothRes.passed, true);
});

test("PR-05: Pilot dataset comprises 24 cases spanning Tiers 1-3, clean PRs, held-out set and undetermined cases", () => {
  const dataset = generatePilotDataset();
  assert.equal(dataset.length, 24);

  const t1Cases = dataset.filter(c => c.tier === 1);
  const t2Cases = dataset.filter(c => c.tier === 2 && c.adjudication === "positive");
  const t3Clean = dataset.filter(c => c.tier === 3 && c.adjudication === "clean");
  const heldOutCases = dataset.filter(c => c.heldOut);
  const undeterminedCases = dataset.filter(c => c.adjudication === "undetermined");

  assert.equal(t1Cases.length, 8);
  assert.equal(t2Cases.length, 8);
  assert.equal(t3Clean.length, 6);
  assert.ok(heldOutCases.length >= 5, "Must preserve at least 5 held-out cases");
  assert.equal(undeterminedCases.length, 2, "Must preserve unadjudicated cases");
});

test("PR-05: Provider family diversity validation prevents single-vendor monoculture", () => {
  assert.equal(getProviderFamily("claude-3-5-sonnet"), "anthropic");
  assert.equal(getProviderFamily("claude-opus"), "anthropic");
  assert.equal(getProviderFamily("gemini-1.5-pro"), "google");
  assert.equal(getProviderFamily("agy-cli"), "google");
  assert.equal(getProviderFamily("gpt-4o"), "openai");
  assert.equal(getProviderFamily("codex-transport"), "openai");

  // Same vendor family fails diversity
  const sameFam = validateProviderDiversity("claude-3-5-sonnet", "claude-3-haiku");
  assert.equal(sameFam.valid, false);
  assert.match(sameFam.reason, /lack.*diversity.*anthropic/i);

  // Different vendor families pass diversity
  const diffFam1 = validateProviderDiversity("claude-3-5-sonnet", "gemini-1.5-pro");
  assert.equal(diffFam1.valid, true);

  const diffFam2 = validateProviderDiversity("agy-cli", "codex-transport");
  assert.equal(diffFam2.valid, true);
});

test("PR-05: 3-way empirical comparison demonstrates efficiency of Risk-Adaptive Routing", () => {
  const dataset = generatePilotDataset();
  const comparison = runThreeWayComparison(dataset);

  const { single, dual, riskRouted } = comparison.configurations;

  // Dual reviewer catches the edge case that Macro missed in Tier 1
  assert.ok(dual.recall >= single.recall);
  assert.ok(comparison.metrics.marginalRecallGain >= 0);

  // Fixed Dual costs ~2x tokens compared to single
  assert.ok(comparison.metrics.dualTokenMultiplier >= 1.8);

  // Risk-Adaptive Routing achieves same recall as Dual on critical cases while saving tokens on Tier 2/3
  assert.ok(riskRouted.recall >= single.recall);
  assert.ok(comparison.metrics.routedTokenMultiplier < comparison.metrics.dualTokenMultiplier);

  // Recommendation confirms empirical justification
  assert.match(comparison.recommendation, /Risk-Adaptive Routing is empirically justified/i);
});

test("PR-05: Held-out isolation excludes reserved validation cases when requested", () => {
  const dataset = generatePilotDataset();

  const allEval = evaluateBenchmarkConfiguration(dataset, { mode: "single", excludeHeldOut: false });
  const trainEval = evaluateBenchmarkConfiguration(dataset, { mode: "single", excludeHeldOut: true });

  assert.ok(trainEval.totalCases < allEval.totalCases);
  assert.ok(trainEval.totalGoldens < allEval.totalGoldens);
});
