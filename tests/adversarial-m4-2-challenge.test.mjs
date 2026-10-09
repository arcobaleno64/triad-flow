/**
 * Adversarial Stress & Empirical Challenge Harness for Milestone 4
 * Evaluates edge cases, boundary conditions, and invariant stress testing:
 * 1. Complete 13-branch omission matrix exhaustive coverage (§3.1.1)
 * 2. Multi-omission permutation and precedence stress tests
 * 3. Zero-finding fail-closed behavior (missing, present, unregistered, forged)
 * 4. RunContext binding edge cases (casing, prefix, whitespace, tampering)
 * 5. Post-hoc empirical controls: CYCLE-0047 (fail clean/block), CYCLE-0042 & CYCLE-0044 (clean approval)
 * 6. Capability registry security boundary & prototype tampering
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  registerTrustedVerificationRecord,
  isTrustedVerificationRecord,
  RunContext,
  normalizeDigest,
  normalizeObjective,
  normalizeCommitSha
} from "../src/core/harness.mjs";

import { aggregateConsensus } from "../src/core/loop.mjs";

function makeTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
      id: f.id || f.findingId,
      title: f.title,
      severity: f.severity,
      file: f.file,
      line_start: f.line_start || f.line || 1
    };
    const sources = Array.isArray(f.sources) && f.sources.length > 0
      ? f.sources
      : (f.corroborations >= 2 ? ["agy", "claude"] : ["codex"]);

    if (sources.includes("agy")) agyFindings.push(rawF);
    if (sources.includes("claude")) claudeFindings.push(rawF);
    if (sources.includes("codex")) codexFindings.push(rawF);
  }

  const rawReports = {
    agy: {
      provider: "agy",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: agyFindings
    },
    claude: {
      provider: "claude",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: claudeFindings
    },
    codex: {
      provider: "codex",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: codexFindings
    }
  };

  return aggregateConsensus(rawReports, {
    policy: "TRI_PARTY_HETEROGENEOUS",
    tier
  });
}

// ============================================================================
// 1. Exhaustive 13-Branch Decision Truth Table Verification
// ============================================================================

test("Adversarial M4: 13-Branch Matrix - Exhaustive Truth Table Stress", () => {
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const patchObjective = "Preserve default map values";

  // Helper to create registered record
  function makeRec(omissions = [], extra = {}) {
    return registerTrustedVerificationRecord({
      ok: true,
      patchObjective,
      fileCoverageComplete: true,
      evaluations: [],
      verifierOmissions: omissions,
      ...extra
    });
  }

  // Branch 1: Clean confirmation -> APPROVE
  const recB1 = makeRec([]);
  assert.equal(evaluatePostVerificationGate(consensusT1, recB1, { tier: 1 }).decision, "approve");
  assert.equal(evaluatePostVerificationGate(consensusT2, recB1, { tier: 2 }).decision, "approve");

  // Branch 2: Confirmed Objective Violation -> BLOCK (tested across all severities: critical, high, medium, low, info)
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const recB2 = makeRec([{
      findingId: `b2-${sev}`,
      title: `Objective violation ${sev}`,
      severity: sev,
      evidenceSupport: "SUPPORTED",
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "Observable counterexample demonstrating regression"
    }]);
    const resT1 = evaluatePostVerificationGate(consensusT1, recB2, { tier: 1 });
    assert.equal(resT1.decision, "block", `Branch 2 failed to block on ${sev} in Tier 1`);
    assert.match(resT1.reason, /Confirmed Objective Violation/i);

    const resT2 = evaluatePostVerificationGate(consensusT2, recB2, { tier: 2 });
    assert.equal(resT2.decision, "block", `Branch 2 failed to block on ${sev} in Tier 2`);
    assert.match(resT2.reason, /Confirmed Objective Violation/i);
  }

  // Branch 3: Confirmed Critical/High Omission -> BLOCK
  for (const sev of ["critical", "high"]) {
    const recB3 = makeRec([{
      findingId: `b3-${sev}`,
      title: `Confirmed omission ${sev}`,
      severity: sev,
      evidenceSupport: "SUPPORTED",
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Counterexample present"
    }]);
    assert.equal(evaluatePostVerificationGate(consensusT1, recB3, { tier: 1 }).decision, "block");
    assert.equal(evaluatePostVerificationGate(consensusT2, recB3, { tier: 2 }).decision, "block");
  }

  // Branch 4: Supported Medium Omission in Tier 1 -> BLOCK
  const recB4 = makeRec([{
    findingId: "b4-med",
    title: "Supported Medium T1",
    severity: "medium",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    reasoning: "Counterexample present"
  }]);
  const resB4 = evaluatePostVerificationGate(consensusT1, recB4, { tier: 1 });
  assert.equal(resB4.decision, "block");
  assert.match(resB4.reason, /Supported Medium Omission \(Tier 1\)/i);

  // Branch 5: Supported Medium Omission in Tier 2 -> HUMAN_REVIEW_REQUIRED
  const resB5 = evaluatePostVerificationGate(consensusT2, recB4, { tier: 2 });
  assert.equal(resB5.decision, "human_review_required");
  assert.match(resB5.reason, /Supported Medium Omission \(Tier 2\)/i);

  // Branch 6: Supported Low/Info Omission in Tier 1 -> HUMAN_REVIEW_REQUIRED
  for (const sev of ["low", "info"]) {
    const recB6 = makeRec([{
      findingId: `b6-${sev}`,
      title: `Supported ${sev} T1`,
      severity: sev,
      evidenceSupport: "SUPPORTED",
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Counterexample present"
    }]);
    const resB6 = evaluatePostVerificationGate(consensusT1, recB6, { tier: 1 });
    assert.equal(resB6.decision, "human_review_required", `Branch 6 failed for ${sev} in Tier 1`);
  }

  // Branch 7: Supported Low/Info Omission in Tier 2 -> APPROVE (Advisory)
  for (const sev of ["low", "info"]) {
    const recB7 = makeRec([{
      findingId: `b7-${sev}`,
      title: `Supported ${sev} T2`,
      severity: sev,
      evidenceSupport: "SUPPORTED",
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Counterexample present"
    }]);
    const resB7 = evaluatePostVerificationGate(consensusT2, recB7, { tier: 2 });
    assert.equal(resB7.decision, "approve", `Branch 7 failed for ${sev} in Tier 2`);
    assert.equal(resB7.advisoryFindings.length, 1);
  }

  // Branch 8: Contested Omission in Tier 2 -> APPROVE (Advisory) across all severities
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const recB8 = makeRec([{
      findingId: `b8-${sev}`,
      title: `Contested ${sev} T2`,
      severity: sev,
      evidenceSupport: "CONTESTED",
      reasoning: "Guarded by invariant"
    }]);
    const resB8 = evaluatePostVerificationGate(consensusT2, recB8, { tier: 2 });
    assert.equal(resB8.decision, "approve", `Branch 8 failed for ${sev} in Tier 2`);
    assert.equal(resB8.advisoryFindings.length, 1);
  }

  // Branch 9: Contested Omission in Tier 1 with critical or high -> HUMAN_REVIEW_REQUIRED
  for (const sev of ["critical", "high"]) {
    const recB9 = makeRec([{
      findingId: `b9-${sev}`,
      title: `Contested ${sev} T1`,
      severity: sev,
      evidenceSupport: "CONTESTED",
      reasoning: "Guarded by invariant"
    }]);
    const resB9 = evaluatePostVerificationGate(consensusT1, recB9, { tier: 1 });
    assert.equal(resB9.decision, "human_review_required", `Branch 9 failed for ${sev} in Tier 1`);
  }

  // Branch 9b: Contested Omission in Tier 1 with medium/low/info -> Advisory pass (APPROVE)
  for (const sev of ["medium", "low", "info"]) {
    const recB9b = makeRec([{
      findingId: `b9b-${sev}`,
      title: `Contested ${sev} T1`,
      severity: sev,
      evidenceSupport: "CONTESTED",
      reasoning: "Guarded by invariant"
    }]);
    const resB9b = evaluatePostVerificationGate(consensusT1, recB9b, { tier: 1 });
    assert.equal(resB9b.decision, "approve", `Branch 9b failed for ${sev} in Tier 1`);
  }

  // Branch 10: Insufficient Evidence -> HUMAN_REVIEW_REQUIRED across all severities & tiers
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    const recB10 = makeRec([{
      findingId: `b10-${sev}`,
      title: `Insufficient ${sev}`,
      severity: sev,
      evidenceSupport: "INSUFFICIENT_EVIDENCE",
      reasoning: "Theoretical concern without reproducible counterexample"
    }]);
    assert.equal(evaluatePostVerificationGate(consensusT1, recB10, { tier: 1 }).decision, "human_review_required");
    assert.equal(evaluatePostVerificationGate(consensusT2, recB10, { tier: 2 }).decision, "human_review_required");
  }

  // Branch 11a: Context Insufficient / Uncertain (Record-level status: UNCERTAIN)
  const recB11a = makeRec([], { overallStatus: "UNCERTAIN" });
  assert.equal(evaluatePostVerificationGate(consensusT1, recB11a, { tier: 1 }).decision, "human_review_required");
  assert.equal(evaluatePostVerificationGate(consensusT2, recB11a, { tier: 2 }).decision, "human_review_required");

  // Branch 11b: Context Insufficient / Uncertain (Omission-level evidenceSupport: UNCERTAIN)
  const recB11b = makeRec([{
    findingId: "b11b",
    title: "Unresolved context callee boundary",
    severity: "medium",
    evidenceSupport: "UNCERTAIN",
    reasoning: "Callee not in diff and not resolved"
  }]);
  assert.equal(evaluatePostVerificationGate(consensusT1, recB11b, { tier: 1 }).decision, "human_review_required");
  assert.equal(evaluatePostVerificationGate(consensusT2, recB11b, { tier: 2 }).decision, "human_review_required");

  // Branch 12: Clean Challenge Missing / Bypassed -> BLOCK (Fail-Closed)
  const resB12a = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: null });
  assert.equal(resB12a.decision, "block");
  assert.match(resB12a.reason, /Clean Challenge missing/i);

  const resB12b = evaluateGateDecision(consensusT2, { tier: 2, cleanChallenge: true });
  assert.equal(resB12b.decision, "block");
  assert.match(resB12b.reason, /Clean Challenge missing/i);

  // Branch 13: Execution Failure / Timeout / Malformed -> BLOCK (Fail-Closed)
  const recB13a = { ok: false, error: "TIMEOUT: Verification timed out" };
  const resB13a = evaluatePostVerificationGate(consensusT2, recB13a, { tier: 2 });
  assert.equal(resB13a.decision, "block");
  assert.match(resB13a.reason, /TIMEOUT/i);

  const resB13b = evaluatePostVerificationGate(consensusT2, null, { tier: 2 });
  assert.equal(resB13b.decision, "block");
});

// ============================================================================
// 2. Multi-Omission Precedence Stress Tests
// ============================================================================

test("Adversarial M4: Multi-Omission Precedence Hierarchy", () => {
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });

  // Scenario 1: Advisory (Low/Tier2) + Blocker (Critical Supported) -> BLOCK wins
  const rec1 = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Sample obj",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-advisory",
        title: "Minor style",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        reasoning: "Unneeded assignment"
      },
      {
        findingId: "om-blocker",
        title: "Critical memory leak",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        reasoning: "Observable counterexample: malloc without free"
      }
    ]
  });
  const res1 = evaluatePostVerificationGate(consensusT2, rec1, { tier: 2 });
  assert.equal(res1.decision, "block");
  assert.equal(res1.criticals.length, 1);
  assert.equal(res1.advisoryFindings.length, 1);

  // Scenario 2: Advisory (Low/Tier2) + Human Review (Medium/Tier2) -> HUMAN_REVIEW_REQUIRED wins
  const rec2 = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Sample obj",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-advisory",
        title: "Minor style",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        reasoning: "Unneeded assignment"
      },
      {
        findingId: "om-medium",
        title: "Medium unhandled input",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        reasoning: "Observable counterexample: NaN input"
      }
    ]
  });
  const res2 = evaluatePostVerificationGate(consensusT2, rec2, { tier: 2 });
  assert.equal(res2.decision, "human_review_required");
  assert.equal(res2.criticals.length, 0);
  assert.equal(res2.advisoryFindings.length, 1);

  // Scenario 3: Human Review (Medium/Tier2) + Blocker (Objective Falsified Low) -> BLOCK wins
  const rec3 = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Sample obj",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-medium",
        title: "Medium unhandled input",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        reasoning: "Observable counterexample"
      },
      {
        findingId: "om-obj-falsify",
        title: "Objective violated in corner case",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
        reasoning: "Directly falsifies patch objective"
      }
    ]
  });
  const res3 = evaluatePostVerificationGate(consensusT2, rec3, { tier: 2 });
  assert.equal(res3.decision, "block");
});

// ============================================================================
// 3. RunContext Binding Security & Normalization Stress Tests
// ============================================================================

test("Adversarial M4: RunContext Binding Security & Strict Integrity", () => {
  const consensus = makeTrustedConsensus([], { tier: 2 });

  const activeRc = new RunContext({
    runId: "run-adv-m4",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    contentDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    patchObjective: "Strict security patch for input parser"
  });

  // Normalization Stress: uppercase hex + sha256 prefix + multiline whitespace
  const normalizedRec = registerTrustedVerificationRecord({
    ok: true,
    headSha: "93A63E30A039239212D54DB501CE2B0655F3BD49",
    changeSetDigest: "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
    patchObjective: "\t Strict   security \n patch for \r\n input parser   ",
    evaluations: [],
    verifierOmissions: []
  });

  const gatePass = evaluateGateDecision(consensus, {
    tier: 2,
    verificationRecord: normalizedRec,
    runContext: activeRc
  });
  assert.equal(gatePass.decision, "approve");

  // Adversarial Tampering: 1 character difference in contentDigest
  const tamperedDigestRec = registerTrustedVerificationRecord({
    ok: true,
    headSha: activeRc.headSha,
    changeSetDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456788", // ends in 88 instead of 89
    patchObjective: activeRc.patchObjective,
    evaluations: [],
    verifierOmissions: []
  });
  const gateTamperedDigest = evaluateGateDecision(consensus, {
    tier: 2,
    verificationRecord: tamperedDigestRec,
    runContext: activeRc
  });
  assert.equal(gateTamperedDigest.decision, "block");
  assert.match(gateTamperedDigest.reason, /FORGED_OR_STALE_RECORD/i);

  // Adversarial Tampering: subtle prose change in patchObjective
  const tamperedObjectiveRec = registerTrustedVerificationRecord({
    ok: true,
    headSha: activeRc.headSha,
    changeSetDigest: activeRc.contentDigest,
    patchObjective: "Strict security patch for output parser", // input -> output
    evaluations: [],
    verifierOmissions: []
  });
  const gateTamperedObj = evaluateGateDecision(consensus, {
    tier: 2,
    verificationRecord: tamperedObjectiveRec,
    runContext: activeRc
  });
  assert.equal(gateTamperedObj.decision, "block");
  assert.match(gateTamperedObj.reason, /FORGED_OR_STALE_RECORD/i);

  // Adversarial Tampering: 1 character difference in headSha
  const tamperedShaRec = registerTrustedVerificationRecord({
    ok: true,
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd48", // 48 instead of 49
    changeSetDigest: activeRc.contentDigest,
    patchObjective: activeRc.patchObjective,
    evaluations: [],
    verifierOmissions: []
  });
  const gateTamperedSha = evaluateGateDecision(consensus, {
    tier: 2,
    verificationRecord: tamperedShaRec,
    runContext: activeRc
  });
  assert.equal(gateTamperedSha.decision, "block");
  assert.match(gateTamperedSha.reason, /FORGED_OR_STALE_RECORD/i);
});

// ============================================================================
// 4. In-Process Capability Registry & Prototype Tampering Resistance
// ============================================================================

test("Adversarial M4: In-Process Capability Registry Tampering Resistance", () => {
  const consensus = makeTrustedConsensus([], { tier: 2 });

  // Attack 1: Plain mock
  const plainMock = { ok: true, fileCoverageComplete: true, evaluations: [], verifierOmissions: [] };
  assert.equal(isTrustedVerificationRecord(plainMock), false);
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: plainMock }).decision, "block");

  // Attack 2: Object.assign
  const genuine = registerTrustedVerificationRecord({ ok: true, evaluations: [], verifierOmissions: [] });
  assert.equal(isTrustedVerificationRecord(genuine), true);
  const assigned = Object.assign({}, genuine);
  assert.equal(isTrustedVerificationRecord(assigned), false);
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: assigned }).decision, "block");

  // Attack 3: Object.create prototype inheritance
  const inherited = Object.create(genuine);
  assert.equal(isTrustedVerificationRecord(inherited), false);
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: inherited }).decision, "block");

  // Attack 4: Non-object primitives passed as verificationRecord
  assert.equal(isTrustedVerificationRecord("string-token"), false);
  assert.equal(isTrustedVerificationRecord(12345), false);
  assert.equal(isTrustedVerificationRecord(null), false);
  assert.equal(isTrustedVerificationRecord(undefined), false);
});

// ============================================================================
// 5. Post-Hoc Controls Empirical Verification (CYCLE-0047, CYCLE-0042, CYCLE-0044)
// ============================================================================

test("Adversarial M4: Post-Hoc Historical Simulation - CYCLE-0047, CYCLE-0042, CYCLE-0044", () => {
  // --- CYCLE-0047 (Negative Control / Origin Defect) ---
  const patchObjective47 = "Preserve rows whose missing map keys evaluate to default values that match after tokenizer";
  const consensus47 = makeTrustedConsensus([], { tier: 1 });

  // Control A: Missing Clean Challenge -> Fail Closed BLOCK
  const gate47Missing = evaluateGateDecision(consensus47, { tier: 1, cleanChallenge: true });
  assert.equal(gate47Missing.decision, "block");
  assert.match(gate47Missing.reason, /Clean Challenge missing/i);

  // Control B: Unregistered record -> Fail Closed BLOCK
  const gate47Untrusted = evaluateGateDecision(consensus47, {
    tier: 1,
    verificationRecord: { ok: true, patchObjective: patchObjective47, verifierOmissions: [] }
  });
  assert.equal(gate47Untrusted.decision, "block");
  assert.match(gate47Untrusted.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // Control C: Verifier catches objective falsification -> BLOCK
  const rec47Defect = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: patchObjective47,
    evaluations: [],
    verifierOmissions: [{
      findingId: "omission-47",
      title: "FixedString default needle rejected",
      severity: "critical",
      evidenceSupport: "SUPPORTED",
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "Observable counterexample: traverseMapElementValueNode returns false on default needle, dropping absent-key rows."
    }]
  });
  const gate47Defect = evaluateGateDecision(consensus47, { tier: 1, verificationRecord: rec47Defect });
  assert.equal(gate47Defect.decision, "block");
  assert.match(gate47Defect.reason, /Confirmed Objective Violation/i);

  // --- CYCLE-0042 (Positive Control - curl/curl PR #23196, Tier 1) ---
  const consensus42 = makeTrustedConsensus([], { tier: 1 });
  const rec42Clean = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });
  const gate42 = evaluateGateDecision(consensus42, { tier: 1, verificationRecord: rec42Clean });
  assert.equal(gate42.decision, "approve");
  assert.ok(gate42.reason.includes("Clean Challenge passed"));

  // --- CYCLE-0044 (Positive Control - nodejs/node PR #66565, Tier 2) ---
  const consensus44 = makeTrustedConsensus([], { tier: 2 });
  const rec44Clean = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });
  const gate44 = evaluateGateDecision(consensus44, { tier: 2, verificationRecord: rec44Clean });
  assert.equal(gate44.decision, "approve");
  assert.ok(gate44.reason.includes("Clean Challenge passed"));
});
