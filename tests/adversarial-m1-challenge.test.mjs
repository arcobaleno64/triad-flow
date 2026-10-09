/**
 * Adversarial Stress-Test Suite for LOOP2-SYSTEMIC-REMEDIATION-007 Milestone 1
 * Agent: challenger_m1_2
 * Role: EMPIRICAL CHALLENGER
 *
 * Verifies and stress-tests:
 * 1. Counterexample enforcement & downgrades
 * 2. Objective impact bypass attempts
 * 3. Tier 1 vs Tier 2 policy divergences
 * 4. Zero findings without verification record / Clean Challenge enforcement
 * 5. Malformed, timeout, and fail-closed verifier records
 * 6. RunContext integrity and tampering attempts
 * 7. Multi-omission combinations & edge cases
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  registerTrustedVerificationRecord,
  isTrustedVerificationRecord,
  RunContext
} from "../src/core/harness.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import {
  normalizeDigest,
  normalizeObjective,
  normalizeCommitSha,
  hasConcreteCounterexample,
  validateVerificationOutput,
  OBJECTIVE_IMPACTS,
  VERIFICATION_VERDICTS
} from "../src/core/independent-verifier.mjs";

function makeTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
      id: f.id,
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

// ==============================================================================
// 1. Counterexample Enforcement & Downgrade Stress Tests
// ==============================================================================

test("CHALLENGE 1.1: hasConcreteCounterexample rejects bare assertions and hand-waving", () => {
  const bareAssertions = [
    "Missing validation",
    "Potential issue",
    "Needs investigation",
    "Edge case unhandled",
    "Missing check.",
    "potential bug",
    "potential flaw.",
    "short string", // < 25 chars
    "A generic issue where user input might not be checked properly in the codebase." // no call/expression/input/failure path
  ];

  for (const assertion of bareAssertions) {
    assert.equal(
      hasConcreteCounterexample({ reasoning: assertion }),
      false,
      `Expected false for bare assertion: "${assertion}"`
    );
    assert.equal(
      hasConcreteCounterexample(assertion),
      false,
      `Expected false for string input: "${assertion}"`
    );
  }
});

test("CHALLENGE 1.2: hasConcreteCounterexample accepts concrete failure mechanics", () => {
  const validCounterexamples = [
    {
      // Explicit counterexample field >= 10 chars
      counterexample: "call(null) -> throws NullPointerException"
    },
    {
      // Call + Failure Path
      reasoning: "Passing traverseMapElementValueNode(null) causes absent key rows to be dropped."
    },
    {
      // Quoted payload + failure symptom
      reasoning: "Input payload 'SELECT * WHERE id = 0x00' crashes the engine with panic."
    },
    {
      // Expression + failure symptom
      reasoning: "Array lookup `items[idx]` leads to out-of-bounds crash when idx is negative."
    },
    {
      // Repro prefix + failure path
      reasoning: "repro: send packet with length -1 -> bypasses security check and leaks memory."
    }
  ];

  for (const valid of validCounterexamples) {
    assert.equal(
      hasConcreteCounterexample(valid),
      true,
      `Expected true for valid counterexample: ${JSON.stringify(valid)}`
    );
  }
});

test("CHALLENGE 1.3: validateVerificationOutput normalizes bare assertion omission to INSUFFICIENT_EVIDENCE", () => {
  const rawOutput = {
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-bare-1",
        title: "Missing input validation",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/auth.c",
        line_start: 10,
        line_end: 15,
        reasoning: "Missing validation"
      },
      {
        findingId: "om-bare-2",
        title: "Potential flaw in session handling",
        severity: "high",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/session.c",
        line_start: 50,
        line_end: 50,
        reasoning: "Potential issue"
      }
    ]
  };

  const validated = validateVerificationOutput(rawOutput, {}, { patchObjective: "Secure auth" });
  assert.equal(validated.ok, true);
  assert.equal(validated.verifierOmissions.length, 2);

  // Both must be downgraded to INSUFFICIENT_EVIDENCE
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");
  assert.equal(validated.verifierOmissions[1].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  // Confirmation source must be immutably set by pipeline
  assert.equal(validated.verifierOmissions[0].confirmationSource, "independent_validation");
  assert.equal(validated.verifierOmissions[1].confirmationSource, "independent_validation");
});

test("CHALLENGE 1.4: validateVerificationOutput downgrades SUPPORTED omission when locator is inaccurate or invalid", () => {
  const rawOutput = {
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-loc-1",
        title: "Valid counterexample but inaccurate locator",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: false, // Inaccurate locator
        file: "src/calc.js",
        line_start: 20,
        line_end: 25,
        counterexample: "calc(0) -> division by zero crash"
      },
      {
        findingId: "om-loc-2",
        title: "Valid counterexample but invalid line_start 0",
        severity: "high",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/calc.js",
        line_start: 0, // Invalid line_start
        line_end: 25,
        counterexample: "calc(null) -> unhandled TypeError"
      },
      {
        findingId: "om-loc-3",
        title: "Valid counterexample but line_end < line_start",
        severity: "high",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/calc.js",
        line_start: 50,
        line_end: 20, // line_end < line_start
        counterexample: "calc(-1) -> memory leak occurs"
      }
    ]
  };

  const validated = validateVerificationOutput(rawOutput, {}, { patchObjective: "Math fix" });
  assert.equal(validated.ok, true);
  for (const om of validated.verifierOmissions) {
    assert.equal(
      om.evidenceSupport,
      "INSUFFICIENT_EVIDENCE",
      `Expected omission ${om.findingId} with broken locator to be downgraded to INSUFFICIENT_EVIDENCE`
    );
  }
});

test("CHALLENGE 1.5: Bare assertion omission downgraded to INSUFFICIENT_EVIDENCE routes to human_review_required", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rawOutput = {
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-bare",
        title: "Uncorroborated injection vulnerability",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/db.js",
        line_start: 10,
        line_end: 10,
        reasoning: "Missing validation"
      }
    ]
  };

  const validated = validateVerificationOutput(rawOutput, {}, { patchObjective: "DB cleanup" });
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "DB cleanup",
    evaluations: [],
    verifierOmissions: validated.verifierOmissions
  });

  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /Insufficient Evidence/i);
});

// ==============================================================================
// 2. Objective Impact Bypass Stress Tests
// ==============================================================================

test("CHALLENGE 2.1: Low severity omission with FALSIFIES_PATCH_OBJECTIVE strictly blocks in Tier 1 and Tier 2", () => {
  const lowFalsifyingOmission = {
    findingId: "om-low-falsify",
    title: "Low severity bug that directly contradicts patch objective",
    severity: "low",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/parser.c",
    line_start: 42,
    line_end: 42,
    reasoning: "parse_token(empty) -> drops valid tokens violating stated preservation objective."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Preserve all valid tokens during parsing",
    evaluations: [],
    verifierOmissions: [lowFalsifyingOmission]
  });

  // Test Tier 1
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  const gateT1 = evaluateGateDecision(consensusT1, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "block");
  assert.match(gateT1.reason, /falsifies stated patch objective/i);

  // Test Tier 2
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "block");
  assert.match(gateT2.reason, /falsifies stated patch objective/i);
});

test("CHALLENGE 2.2: Info severity omission with FALSIFIES_PATCH_OBJECTIVE strictly blocks in Tier 1 and Tier 2", () => {
  const infoFalsifyingOmission = {
    findingId: "om-info-falsify",
    title: "Info level comment that contradicts contract",
    severity: "info",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/doc.md",
    line_start: 1,
    line_end: 1,
    reasoning: "Calling format() -> emits wrong header violating preservation objective."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Preserve header output",
    evaluations: [],
    verifierOmissions: [infoFalsifyingOmission]
  });

  // Test Tier 1
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  assert.equal(evaluateGateDecision(consensusT1, { tier: 1, verificationRecord: rec }).decision, "block");

  // Test Tier 2
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  assert.equal(evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec }).decision, "block");
});

test("CHALLENGE 2.3: FALSIFIES_PATCH_OBJECTIVE without bound patchObjective cannot block on objective violation", () => {
  const omission = {
    findingId: "om-unbound",
    title: "Unbound objective assertion",
    severity: "low",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/util.c",
    line_start: 10,
    line_end: 10,
    counterexample: "test(0) -> causes memory leak"
  };

  // Record has NO patchObjective bound
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [omission]
  });

  // In Tier 2, low severity supported omission with unbound objective passes as advisory
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "approve");
  assert.equal(gateT2.advisoryFindings.length, 1);
});

test("CHALLENGE 2.4: Omission with bare assertion and FALSIFIES_PATCH_OBJECTIVE cannot bypass counterexample check to block", () => {
  // Verifier tries to claim FALSIFIES_PATCH_OBJECTIVE with a bare assertion (no counterexample)
  const rawOutput = {
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-fake-block",
        title: "Maliciously claimed objective blocker",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/core.c",
        line_start: 15,
        line_end: 15,
        reasoning: "Missing validation" // BARE ASSERTION!
      }
    ]
  };

  const validated = validateVerificationOutput(rawOutput, { patchObjective: "Strict contract" });
  // Must be downgraded to INSUFFICIENT_EVIDENCE
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Strict contract",
    evaluations: [],
    verifierOmissions: validated.verifierOmissions
  });

  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  // Since it was downgraded to INSUFFICIENT_EVIDENCE, it does NOT block as objective violation; routes to human review
  assert.equal(gateT2.decision, "human_review_required");
  assert.match(gateT2.reason, /Insufficient Evidence/i);
});

// ==============================================================================
// 3. Tier 1 vs Tier 2 Policy Divergence Stress Tests
// ==============================================================================

test("CHALLENGE 3.1: Supported Medium omission with DOES_NOT_FALSIFY: Tier 1 BLOCKS vs Tier 2 HUMAN_REVIEW_REQUIRED", () => {
  const medOmission = {
    findingId: "om-med",
    title: "Side-effect bug unrelated to objective",
    severity: "medium",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/worker.js",
    line_start: 88,
    line_end: 88,
    counterexample: "worker.drain() -> unhandled timeout exception"
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Fix worker queue",
    evaluations: [],
    verifierOmissions: [medOmission]
  });

  // Tier 1: MUST BLOCK (Row 4)
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  const gateT1 = evaluateGateDecision(consensusT1, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "block");
  assert.match(gateT1.reason, /Tier 1/i);

  // Tier 2: MUST REQUIRE HUMAN REVIEW (Row 5)
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "human_review_required");
  assert.match(gateT2.reason, /human adjudication/i);
});

test("CHALLENGE 3.2: Supported Low omission with DOES_NOT_FALSIFY: Tier 1 HUMAN_REVIEW_REQUIRED vs Tier 2 APPROVE + Advisory", () => {
  const lowOmission = {
    findingId: "om-low",
    title: "Minor code style or non-critical issue",
    severity: "low",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/fmt.js",
    line_start: 12,
    line_end: 12,
    counterexample: "fmt(' ') -> returns double space"
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Formatting cleanup",
    evaluations: [],
    verifierOmissions: [lowOmission]
  });

  // Tier 1: MUST REQUIRE HUMAN REVIEW (Row 6)
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  const gateT1 = evaluateGateDecision(consensusT1, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "human_review_required");
  assert.match(gateT1.reason, /Tier 1/i);

  // Tier 2: MUST APPROVE as advisory (Row 7)
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "approve");
  assert.equal(gateT2.advisoryFindings.length, 1);
});

test("CHALLENGE 3.3: CONTESTED High omission: Tier 1 HUMAN_REVIEW_REQUIRED vs Tier 2 APPROVE + Advisory", () => {
  const contestedHighOmission = {
    findingId: "om-contested-high",
    title: "Contested race condition claim",
    severity: "high",
    evidenceSupport: "CONTESTED",
    objectiveImpact: "NOT_ASSESSED",
    locatorAccurate: true,
    file: "src/sync.c",
    line_start: 100,
    line_end: 100,
    reasoning: "Mutex lock at line 90 already prevents race condition."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [contestedHighOmission]
  });

  // Tier 1: Critical/High contested requires human review (Row 9)
  const consensusT1 = makeTrustedConsensus([], { tier: 1 });
  const gateT1 = evaluateGateDecision(consensusT1, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "human_review_required");

  // Tier 2: passes as advisory (Row 8)
  const consensusT2 = makeTrustedConsensus([], { tier: 2 });
  const gateT2 = evaluateGateDecision(consensusT2, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "approve");
  assert.equal(gateT2.advisoryFindings.length, 1);
});

// ==============================================================================
// 4. Zero Findings Without Verification Record & Capability Forgery Stress Tests
// ==============================================================================

test("CHALLENGE 4.1: evaluateGateDecision strictly blocks zero-finding consensus when verificationRecord is null", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: null
  });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Clean Challenge missing/i);
});

test("CHALLENGE 4.2: evaluateGateDecision strictly blocks zero-finding consensus when cleanChallenge flag is set without record", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    cleanChallenge: true
  });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Clean Challenge missing/i);
});

test("CHALLENGE 4.3: evaluateGateDecision strictly blocks zero-finding consensus when requireVerification is set without record", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    requireVerification: true
  });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Clean Challenge missing/i);
});

test("CHALLENGE 4.4: evaluateGateDecision strictly blocks zero-finding consensus when verificationMode is set without record", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationMode: "clean_challenge"
  });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Clean Challenge missing/i);
});

test("CHALLENGE 4.5: Pre-gate zero-finding evaluation preserves approve when verification has not yet run", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // No verificationRecord, no cleanChallenge/requireVerification/verificationMode flags
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2 });
  assert.equal(gate.decision, "approve");
});

test("CHALLENGE 4.6: Capability forgery: plain mock object or clone passed as verificationRecord is rejected", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // 1. Plain mock object
  const plainObj = {
    ok: true,
    evaluations: [],
    verifierOmissions: []
  };
  const gate1 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: plainObj });
  assert.equal(gate1.decision, "block");
  assert.match(gate1.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // 2. Structured clone of registered record
  const registered = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: []
  });
  const cloned = structuredClone(registered);
  const gate2 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: cloned });
  assert.equal(gate2.decision, "block");
  assert.match(gate2.reason, /UNTRUSTED_VERIFICATION_RECORD/i);
});

// ==============================================================================
// 5. Malformed, Timeout, and Fail-Closed Verifier Records Stress Tests
// ==============================================================================

test("CHALLENGE 5.1: evaluatePostVerificationGate fails closed on null, undefined, or ok: false record", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // null record
  assert.equal(evaluatePostVerificationGate(cleanConsensus, null).decision, "block");

  // undefined record
  assert.equal(evaluatePostVerificationGate(cleanConsensus, undefined).decision, "block");

  // ok: false with custom error
  const recErr = { ok: false, error: "TIMEOUT: Subprocess timed out after 60000ms" };
  const gateErr = evaluatePostVerificationGate(cleanConsensus, recErr);
  assert.equal(gateErr.decision, "block");
  assert.equal(gateErr.reason, "TIMEOUT: Subprocess timed out after 60000ms");

  // ok: false with empty error
  const recNoErr = { ok: false };
  const gateNoErr = evaluatePostVerificationGate(cleanConsensus, recNoErr);
  assert.equal(gateNoErr.decision, "block");
  assert.match(gateNoErr.reason, /Verifier execution failed/i);
});

test("CHALLENGE 5.2: validateVerificationOutput fails closed on unparseable, malformed, or hostile JSON outputs", () => {
  // Non-JSON string
  const res1 = validateVerificationOutput("Invalid syntax { [", {}, {});
  assert.equal(res1.ok, false);
  assert.equal(res1.valid, false);

  // Missing evaluations array
  const res2 = validateVerificationOutput({ verifierOmissions: [] }, {}, {});
  assert.equal(res2.ok, false);

  // Non-array evaluations
  const res3 = validateVerificationOutput({ evaluations: "not an array" }, {}, {});
  assert.equal(res3.ok, false);

  // Evaluation with invalid verdict
  const res4 = validateVerificationOutput({
    evaluations: [{ findingId: "f1", verdict: "FABRICATED_VERDICT" }]
  }, {}, {});
  assert.equal(res4.ok, false);

  // Non-array verifierOmissions
  const res5 = validateVerificationOutput({
    evaluations: [],
    verifierOmissions: "not an array"
  }, {}, {});
  assert.equal(res5.ok, false);

  // Omission with NUL byte in file path
  const res6 = validateVerificationOutput({
    evaluations: [],
    verifierOmissions: [{
      title: "Exploit",
      severity: "critical",
      file: "src/\0exploit.c"
    }]
  }, {}, {});
  assert.equal(res6.ok, false);

  // Omission with invalid severity
  const res7 = validateVerificationOutput({
    evaluations: [],
    verifierOmissions: [{
      title: "Exploit",
      severity: "super-critical",
      file: "src/exploit.c"
    }]
  }, {}, {});
  assert.equal(res7.ok, false);
});

test("CHALLENGE 5.3: Record with overallStatus: UNCERTAIN triggers human_review_required even with 0 omissions", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    overallStatus: "UNCERTAIN",
    evaluations: [],
    verifierOmissions: []
  });

  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /UNCERTAIN/i);
});

test("CHALLENGE 5.4: Omission with evidenceSupport: UNCERTAIN triggers human_review_required", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-unc",
        title: "Uncertain callee context",
        severity: "medium",
        evidenceSupport: "UNCERTAIN",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: true,
        file: "src/unresolved.cpp",
        line_start: 1,
        line_end: 1,
        reasoning: "Context missing"
      }
    ]
  });

  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /UNCERTAIN/i);
});

// ==============================================================================
// 6. RunContext Binding Tampering & Integrity Stress Tests
// ==============================================================================

test("CHALLENGE 6.1: RunContext and normalizers handle prefixes, whitespace, casing, and reject invalid formats", () => {
  // Digest normalizer: trims, lowercases, strips optional sha256: prefix, requires 64 hex chars
  assert.equal(
    normalizeDigest("sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  );
  assert.equal(
    normalizeDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  );
  assert.equal(normalizeDigest("invalid-short-digest"), "");
  assert.equal(normalizeDigest(""), "");
  assert.equal(normalizeDigest(null), "");

  // Objective normalizer: trims and collapses internal whitespace
  assert.equal(
    normalizeObjective("  Preserve   absent   key\n\trows  "),
    "Preserve absent key rows"
  );
  assert.equal(normalizeObjective(""), "");
  assert.equal(normalizeObjective(null), "");

  // Commit SHA normalizer: handles 40/64 hex, trims, lowercases, rejects all-zeros
  assert.equal(
    normalizeCommitSha("93A63E30A039239212D54DB501CE2B0655F3BD49"),
    "93a63e30a039239212d54db501ce2b0655f3bd49"
  );
  assert.equal(normalizeCommitSha("0000000000000000000000000000000000000000"), ""); // Reject null SHA
  assert.equal(normalizeCommitSha("not-a-sha"), "");
  assert.equal(normalizeCommitSha(null), "");
});

test("CHALLENGE 6.2: evaluateGateDecision rejects forged or stale records when RunContext fields mismatch", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const baseRc = new RunContext({
    runId: "run-test-01",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    contentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    patchObjective: "Preserve absent key rows"
  });

  // Stale Digest
  const recBadDigest = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    evaluations: []
  });
  const gateDigest = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadDigest, runContext: baseRc });
  assert.equal(gateDigest.decision, "block");
  assert.match(gateDigest.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Objective
  const recBadObj = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Completely different patch objective",
    evaluations: []
  });
  const gateObj = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadObj, runContext: baseRc });
  assert.equal(gateObj.decision, "block");
  assert.match(gateObj.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Head SHA
  const recBadSha = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    headSha: "1111111111111111111111111111111111111111",
    patchObjective: "Preserve absent key rows",
    evaluations: []
  });
  const gateSha = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadSha, runContext: baseRc });
  assert.equal(gateSha.decision, "block");
  assert.match(gateSha.reason, /FORGED_OR_STALE_RECORD/i);
});

// ==============================================================================
// 7. Multi-Omission and Fallback States Stress Tests
// ==============================================================================

test("CHALLENGE 7.1: Precedence: Blocker takes precedence over Human Review and Advisory in mixed omissions", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Fix all bugs",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-advisory",
        title: "Low advisory omission",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/a.js",
        line_start: 1,
        line_end: 1,
        counterexample: "a() -> returns null"
      },
      {
        findingId: "om-human-review",
        title: "Medium omission in Tier 2",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/b.js",
        line_start: 10,
        line_end: 10,
        counterexample: "b() -> unhandled timeout"
      },
      {
        findingId: "om-blocker",
        title: "Critical omission missed by sentries",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/c.js",
        line_start: 20,
        line_end: 20,
        counterexample: "c() -> remote code execution exploit"
      }
    ]
  });

  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  // The Critical blocker must win over human review and advisory
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Confirmed Critical \/ High Omission/i);
  assert.equal(gate.criticals.length, 1);
});

test("CHALLENGE 7.2: Unrecognized omission evidence state triggers fail-safe human review", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "om-unknown-state",
        title: "Omission with strange state",
        severity: "low",
        evidenceSupport: "UNKNOWN_STATE_FROM_SYNTHETIC_TEST",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: true,
        file: "src/weird.js",
        line_start: 1,
        line_end: 1,
        reasoning: "Synthetic unusual state"
      }
    ]
  });

  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /Unrecognized omission assessment state/i);
});
