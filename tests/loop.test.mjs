import test from "node:test";
import assert from "node:assert/strict";
import {
  aggregateConsensus,
  canonicalFindingKey,
  OodaLoopController,
  QuorumPolicies
} from "../src/core/loop.mjs";
import { isTrustedConsensus } from "../src/core/consensus-state.mjs";

test("aggregateConsensus enforces strict heterogeneous Quorum (Macro + Micro required)", () => {
  const mockMacroOk = {
    name: "macro-sentry",
    provider: "agy",
    findings: [{ severity: "critical", title: "Unvalidated JWT", file: "src/auth.ts", line_start: 12 }]
  };
  const mockMicroOk = {
    name: "micro-arbiter",
    provider: "claude",
    findings: [{ severity: "critical", title: "Unvalidated JWT", file: "src/auth.ts", line_start: 12 }]
  };

  const consensus = aggregateConsensus(mockMacroOk, mockMicroOk);
  assert.equal(isTrustedConsensus(consensus), true);
  assert.equal(consensus.quorumReached, true);
  assert.equal(consensus.verdict, "needs-attention");
  assert.equal(consensus.totalFindings, 1);

  // Single sentry failure triggers Quorum failure & Fail-Closed
  const brokenConsensus = aggregateConsensus(
    { name: "macro-sentry", provider: "agy", error: "Connection timeout to Claude provider" },
    mockMicroOk
  );
  assert.equal(isTrustedConsensus(brokenConsensus), true);
  assert.equal(brokenConsensus.quorumReached, false);
  assert.equal(brokenConsensus.verdict, "error");
});

test("QuorumPolicies.STRICT_HETEROGENEOUS enforces Default-Deny on unknown families and lack of diversity", () => {
  const mk = (macroProv, microProv) => aggregateConsensus(
    { macro: { provider: macroProv, findings: [] }, micro: { provider: microProv, findings: [] } },
    { policy: "STRICT_HETEROGENEOUS" }
  );

  // 1. google + anthropic -> quorumReached: true
  const res1 = mk("agy", "claude");
  assert.equal(res1.quorumReached, true);
  assert.equal(res1.verdict, "approve");

  // 2. google + google -> quorumReached: false (lack diversity)
  const res2 = mk("agy", "gemini");
  assert.equal(res2.quorumReached, false);
  assert.equal(res2.verdict, "error");
  assert.match(res2.consensusProof, /lack provider-family diversity.*google/i);

  // 3. google + unknown -> quorumReached: false (Default-Deny)
  const res3 = mk("agy", "custom-unregistered-tool");
  assert.equal(res3.quorumReached, false);
  assert.equal(res3.verdict, "error");
  assert.match(res3.consensusProof, /cannot be verified under Default-Deny/i);

  // 4. unknown + unknown -> quorumReached: false (Default-Deny)
  const res4 = mk("tool-a", "tool-b");
  assert.equal(res4.quorumReached, false);
  assert.equal(res4.verdict, "error");
  assert.match(res4.consensusProof, /cannot be verified under Default-Deny/i);

  // 5. Explicit family with case difference ('Google' vs 'google') fails closed for lack of diversity
  const resCaseDiff = aggregateConsensus(
    { macro: { family: "Google", findings: [] }, micro: { family: "google", findings: [] } },
    { policy: "STRICT_HETEROGENEOUS" }
  );
  assert.equal(resCaseDiff.quorumReached, false);
  assert.equal(resCaseDiff.verdict, "error");
  assert.match(resCaseDiff.consensusProof, /lack provider-family diversity.*google/i);

  // 6. Explicit family with uppercase 'UNKNOWN' fails closed under Default-Deny
  const resUnknownUpper = aggregateConsensus(
    { macro: { family: "UNKNOWN", findings: [] }, micro: { family: "anthropic", findings: [] } },
    { policy: "STRICT_HETEROGENEOUS" }
  );
  assert.equal(resUnknownUpper.quorumReached, false);
  assert.equal(resUnknownUpper.verdict, "error");
  assert.match(resUnknownUpper.consensusProof, /cannot be verified under Default-Deny/i);

  // 7. Whitespace or unverified fake family string fails closed under Default-Deny
  const resWhitespace = aggregateConsensus(
    { macro: { family: "   ", findings: [] }, micro: { family: "anthropic", findings: [] } },
    { policy: "STRICT_HETEROGENEOUS" }
  );
  assert.equal(resWhitespace.quorumReached, false);
  assert.equal(resWhitespace.verdict, "error");

  const resFakeFamily = aggregateConsensus(
    { macro: { family: "fake_unregistered_vendor", findings: [] }, micro: { family: "anthropic", findings: [] } },
    { policy: "STRICT_HETEROGENEOUS" }
  );
  assert.equal(resFakeFamily.quorumReached, false);
  assert.equal(resFakeFamily.verdict, "error");
  assert.match(resFakeFamily.consensusProof, /cannot be verified under Default-Deny/i);
});

test("aggregateConsensus blocks identical object aliased in both macro and micro roles (PR-05, Probe 1)", () => {
  const singleReport = {
    name: "sentry-1",
    findings: []
  };

  const aliasedConsensus = aggregateConsensus({
    macro: singleReport,
    micro: singleReport
  });

  assert.equal(isTrustedConsensus(aliasedConsensus), true);
  assert.equal(aliasedConsensus.quorumReached, false);
  assert.equal(aliasedConsensus.verdict, "error");
  assert.match(aliasedConsensus.consensusProof, /heterogeneity violation.*identical object/i);
});

test("PR-01 & PR-02: Custom policy cannot fabricate active evidence or select unknown report IDs (P0-01)", () => {
  const downReports = {
    macro: { error: "down", findings: [] },
    micro: { error: "down", findings: [] }
  };

  // PR-01: Custom policy attempting to select forged ID
  const forgedPolicy = () => ({
    quorumReached: true,
    selectedReportIds: ["forged_sentry_id"]
  });

  const res1 = aggregateConsensus(downReports, { policy: forgedPolicy });
  assert.equal(res1.quorumReached, false);
  assert.equal(res1.verdict, "error");
  assert.match(res1.consensusProof, /unknown to current invocation|forged/i);

  // PR-03: Duplicate report IDs rejected (Sybil inflation)
  const okReports = {
    macro: { findings: [] }
  };
  const sybilPolicy = (meta) => {
    const ids = Object.keys(meta);
    return {
      quorumReached: true,
      selectedReportIds: [ids[0], ids[0]]
    };
  };

  const res2 = aggregateConsensus(okReports, { policy: sybilPolicy });
  assert.equal(res2.quorumReached, false);
  assert.equal(res2.verdict, "error");
  assert.match(res2.consensusProof, /duplicate report id/i);
});

test("aggregateConsensus preserves highest severity during deduplication (prevents Downgrade attack)", () => {
  const mockMacro = {
    name: "macro",
    provider: "agy",
    findings: [{ severity: "critical", title: "Auth bypass", file: "src/auth.ts", line_start: 10 }]
  };
  const mockMicro = {
    name: "micro",
    provider: "claude",
    findings: [{ severity: "low", title: "Auth bypass", file: "src/auth.ts", line_start: 10 }]
  };

  const consensus = aggregateConsensus(mockMacro, mockMicro);
  assert.equal(consensus.findings[0].severity, "critical");
});

test("canonicalFindingKey normalizes file, absorbs line drift into buckets, and extracts core tokens", () => {
  const f1 = { file: "src/auth/jwt.ts", line_start: 12, title: "CWE-287: Missing validation" };
  const f2 = { file: "src\\auth\\jwt.ts", line_start: 14, title: "Missing validation (CWE-287)" };
  assert.equal(canonicalFindingKey(f1), canonicalFindingKey(f2));
});

test("OodaLoopController enforces In-Process Capability Boundary and anti-livelock", () => {
  const ooda = new OodaLoopController({ maxIterations: 2 });

  // 1. Untrusted plain forged object MUST escalate to human
  const forgedClean = {
    verdict: "approve",
    quorumReached: true,
    totalFindings: 0,
    findings: []
  };
  const stepUntrusted = ooda.step(forgedClean);
  assert.equal(stepUntrusted.status, "failed");
  assert.equal(stepUntrusted.action, "escalate_to_human");
  assert.match(stepUntrusted.reason, /UNTRUSTED_CONSENSUS/i);

  // 2. Real trusted approve exits green
  const realTrusted = aggregateConsensus({
    macro: { provider: "agy", findings: [] },
    micro: { provider: "claude", findings: [] }
  });
  const stepGreen = ooda.step(realTrusted);
  assert.equal(stepGreen.status, "completed");
  assert.equal(stepGreen.action, "exit_green");

  // 3. Real trusted blocker triggers remediation
  ooda.reset();
  const realBlocker = aggregateConsensus({
    macro: { provider: "agy", findings: [{ title: "RCE", severity: "critical", file: "src/app.js" }] },
    micro: { provider: "claude", findings: [{ title: "RCE", severity: "critical", file: "src/app.js" }] }
  });
  const stepBlocker = ooda.step(realBlocker);
  assert.equal(stepBlocker.status, "remediating");
  assert.equal(stepBlocker.action, "apply_patch");
});

function createMockConsensus(keys) {
  const findings = keys.map((k, i) => ({
    title: `Finding_${k}`,
    severity: "high",
    file: `src/${k}.js`,
    line_start: 10 + i
  }));
  return aggregateConsensus(
    {
      macro: { provider: "agy", findings },
      micro: { provider: "claude", findings }
    },
    { policy: "STRICT_HETEROGENEOUS" }
  );
}

test("OodaLoopController: immediate monotonic reduction permits multi-step progress", () => {
  const ooda = new OodaLoopController({ maxIterations: 5 });

  // Iter 1: {A, B, C, D, E}
  const s1 = ooda.step(createMockConsensus(["A", "B", "C", "D", "E"]), "diff-1");
  assert.equal(s1.status, "remediating");

  // Iter 2: {A, B, C, D} (Strict immediate subset of S1)
  const s2 = ooda.step(createMockConsensus(["A", "B", "C", "D"]), "diff-2");
  assert.equal(s2.status, "remediating");

  // Iter 3: {A, B, C} (Strict immediate subset of S2)
  const s3 = ooda.step(createMockConsensus(["A", "B", "C"]), "diff-3");
  assert.equal(s3.status, "remediating");
});

test("OodaLoopController: cross-iteration alternating subset without immediate progress is blocked by Jaccard", () => {
  const ooda = new OodaLoopController({ maxIterations: 5, similarityThreshold: 0.8 });

  // Iter 1: {A, B, C, D, E}
  const s1 = ooda.step(createMockConsensus(["A", "B", "C", "D", "E"]), "diff-1");
  assert.equal(s1.status, "remediating");

  // Iter 2: {A, B, C, D} (fixes E)
  const s2 = ooda.step(createMockConsensus(["A", "B", "C", "D"]), "diff-2");
  assert.equal(s2.status, "remediating");

  // Iter 3: {A, B, C, E} (fixes D but re-introduces E; NOT a subset of S2, and 80% similar to S1)
  const s3 = ooda.step(createMockConsensus(["A", "B", "C", "E"]), "diff-3");
  assert.equal(s3.status, "oscillation_detected");
  assert.match(s3.reason, /Remediation stagnation\/oscillation detected/i);
});

test("OodaLoopController: exact cycle in history is unconditionally blocked by Layer 1", () => {
  const ooda = new OodaLoopController({ maxIterations: 5 });

  // Iter 1: {A, B}
  const s1 = ooda.step(createMockConsensus(["A", "B"]), "diff-1");
  assert.equal(s1.status, "remediating");

  // Iter 2: {A, B, C}
  const s2 = ooda.step(createMockConsensus(["A", "B", "C"]), "diff-2");
  assert.equal(s2.status, "remediating");

  // Iter 3: {A, B} (Although fewer than S2, it is EXACTLY identical to S1 in history)
  const s3 = ooda.step(createMockConsensus(["A", "B"]), "diff-3");
  assert.equal(s3.status, "oscillation_detected");
  assert.match(s3.reason, /Remediation cycle detected: Exact identical finding set/i);
});

test("OodaLoopController: exceeds maxIterations hard cap even with monotonic progress", () => {
  const ooda = new OodaLoopController({ maxIterations: 2 });

  // Iter 1: {A, B, C}
  assert.equal(ooda.step(createMockConsensus(["A", "B", "C"]), "diff-1").status, "remediating");

  // Iter 2: {A, B}
  assert.equal(ooda.step(createMockConsensus(["A", "B"]), "diff-2").status, "remediating");

  // Iter 3: {A} -> Exceeds maxIterations=2
  const s3 = ooda.step(createMockConsensus(["A"]), "diff-3");
  assert.equal(s3.status, "circuit_broken");
  assert.match(s3.reason, /Exceeded max self-healing iterations/i);
});

