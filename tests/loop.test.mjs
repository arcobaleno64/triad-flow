import test from "node:test";
import assert from "node:assert/strict";
import { aggregateConsensus, OodaLoopController, synthesizeRemediationVector } from "../src/core/loop.mjs";

test("aggregateConsensus preserves highest severity during deduplication (prevents Downgrade attack)", () => {
  const macroReport = {
    findings: [{ file: "src/auth.js", line_start: 10, title: "Auth bypass", severity: "info" }]
  };
  const microReport = {
    findings: [{ file: "src/auth.js", line_start: 10, title: "Auth bypass", severity: "critical" }]
  };

  const consensus = aggregateConsensus(macroReport, microReport);
  assert.equal(consensus.totalFindings, 1);
  assert.equal(consensus.findings[0].severity, "critical");
  assert.equal(consensus.findings[0].corroborations, 2);
  assert.equal(consensus.verdict, "needs-attention");
});

test("aggregateConsensus detects Quorum failure when both sentries error out", () => {
  const consensus = aggregateConsensus({ error: true }, null);
  assert.equal(consensus.quorumReached, false);
  assert.equal(consensus.verdict, "error");
});

test("OodaLoopController breaks circuit when max iterations exceeded", () => {
  const controller = new OodaLoopController({ maxIterations: 2 });
  const failedReport = {
    verdict: "needs-attention",
    quorumReached: true,
    findings: [{ file: "a.js", line_start: 1, severity: "high", title: "Bug 1" }]
  };

  const step1 = controller.step(failedReport);
  assert.equal(step1.status, "remediating");

  // Repeated state triggers oscillation detection
  const step2 = controller.step(failedReport);
  assert.equal(step2.status, "oscillation_detected");
  assert.equal(step2.action, "escalate_to_human");
});
