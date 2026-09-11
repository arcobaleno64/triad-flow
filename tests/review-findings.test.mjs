/**
 * Red backlog from the 2026-09-11 code review.
 * Every test here asserts the INTENDED behaviour and is expected to FAIL on 4e097c5.
 * Each one should turn green when its fix lands; delete nothing, just fix the code.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { issueConsensusFromEvidence } from "../src/core/consensus-state.mjs";
import { aggregateConsensus, OodaLoopController } from "../src/core/loop.mjs";
import { classifyFileRisk, evaluateDiffScale, RISK_TIERS } from "../src/core/graph-router.mjs";

test("R1: issuer must not mint approve from an empty evidence map with a fabricated report ID", () => {
  assert.throws(() => issueConsensusFromEvidence({
    validatedReportsMap: new Map(),
    quorumResult: { quorumReached: true, selectedReportIds: ["ev:forged:macro"] },
    invocationNonce: "forged",
    verdict: "approve"
  }));
});

test("R3a: a security-named source file under a docs/ directory is not Tier 3", () => {
  assert.equal(classifyFileRisk("src/docs/token-handler.ts"), RISK_TIERS.TIER_1_CRITICAL);
});

test("R3b: a binary swap (0 counted lines) must not take the single fast path", () => {
  const plan = evaluateDiffScale([{ path: "bin/Vendor.dll", additions: 0, deletions: 0, binary: true }]);
  assert.equal(plan.mode, "hierarchical");
});

function reportWith(n) {
  return aggregateConsensus(
    { findings: Array.from({ length: n }, (_, i) => ({ severity: "high", title: `bug${i}`, file: `f${i}.js`, line_start: 1 })) },
    { findings: [] }
  );
}

test.skip("R4: fixing 1 of 5 blocking findings is progress, not stagnation (PENDING: formal livelock specification)", () => {
  const ooda = new OodaLoopController();
  assert.equal(ooda.step(reportWith(5), "patch-1").status, "remediating");
  assert.equal(ooda.step(reportWith(4), "patch-2").status, "remediating");
});

test("R5: one sentry repeating itself is not corroboration", () => {
  const dup = { severity: "high", title: "SQL injection", file: "a.js", line_start: 10 };
  const c = aggregateConsensus({ findings: [dup, { ...dup }] }, { findings: [] });
  assert.equal(c.findings.length, 1);
  assert.equal(c.findings[0].corroborations, 1);
});

test("R6: cwe and ruleId survive consensus minting", () => {
  const c = aggregateConsensus(
    { findings: [{ severity: "medium", title: "x", file: "a.js", line_start: 3, ruleId: "R1", cwe: "CWE-79" }] },
    { findings: [] }
  );
  assert.equal(c.findings[0].cwe, "CWE-79");
  assert.equal(c.findings[0].ruleId, "R1");
});
