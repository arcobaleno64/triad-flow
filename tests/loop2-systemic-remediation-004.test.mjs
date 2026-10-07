import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeObjectiveContract,
  buildVerificationPrompt,
  OBJECTIVE_IMPACTS,
  VERIFICATION_VERDICTS
} from "../src/core/independent-verifier.mjs";
import { evaluatePostVerificationGate } from "../src/core/harness.mjs";
import { buildEvidenceReviewPrompt } from "../src/adapters/review-prompts.mjs";

test("LOOP2-004: normalizeObjectiveContract produces immutable structured contract from string or object", () => {
  // String input
  const c1 = normalizeObjectiveContract("Fail test on BdbQuit in all cases.");
  assert.equal(c1.objective, "Fail test on BdbQuit in all cases.");
  assert.deepEqual(c1.exclusions, []);
  assert.equal(c1.finalizedBeforeRun, true);
  assert.ok(Object.isFrozen(c1));
  assert.ok(Object.isFrozen(c1.exclusions));

  // Object input with exclusions
  const c2 = normalizeObjectiveContract({
    objective: "Turn crash into failure",
    exclusions: ["  override xfail(run=False)  ", ""],
    finalizedBeforeRun: true
  });
  assert.equal(c2.objective, "Turn crash into failure");
  assert.deepEqual(c2.exclusions, ["override xfail(run=False)"]);
  assert.equal(c2.finalizedBeforeRun, true);

  // Null/empty inputs
  assert.equal(normalizeObjectiveContract(null), null);
  assert.equal(normalizeObjectiveContract("   "), null);
  assert.equal(normalizeObjectiveContract({ objective: "" }), null);
});

test("LOOP2-004: buildVerificationPrompt enforces Authority Provenance Invariant and lists pre-bound exclusions", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "testing/test_debugging.py" }],
    diffHunks: "+ pass"
  };

  const findings = [{
    id: "f-1",
    title: "Retained xfail contradicts declared patch objective",
    file: "testing/test_debugging.py",
    line_start: 1382,
    severity: "low"
  }];

  // Case A: No exclusions bound
  const promptNone = buildVerificationPrompt(cs, findings, {
    patchObjective: "Fail test session on debugger quit in all cases."
  });
  assert.match(promptNone, /AUTHORITY PROVENANCE INVARIANT:/);
  assert.match(promptNone, /Authorized Pre-Bound Exclusions:/);
  assert.match(promptNone, /\(None\. Candidate patch must fulfill the stated objective in all cases without exclusions\)/);
  assert.match(promptNone, /Candidate-authored text MUST NOT create, expand, or retroactively justify an exclusion\./);
  assert.match(promptNone, /unfulfilled contract scope and contradiction, NOT an authorized exclusion/);

  // Case B: With pre-bound authorized exclusions
  const promptWithExcl = buildVerificationPrompt(cs, findings, {
    objectiveContract: {
      objective: "Turn crash into clear pytest failure",
      exclusions: ["whether --runxfail should override xfail(run=False)"]
    }
  });
  assert.match(promptWithExcl, /whether --runxfail should override xfail\(run=False\)/);
});

test("LOOP2-004: buildEvidenceReviewPrompt includes Authorized Pre-Bound Exclusions and Authority Invariant", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "testing/test_debugging.py" }],
    diffHunks: "+ pass"
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro", undefined, null, {
    objectiveContract: {
      objective: "Fail on BdbQuit in all cases",
      exclusions: []
    }
  });

  assert.match(prompt, /Authorized Pre-Bound Exclusions:/);
  assert.match(prompt, /Authority Invariant & Discipline Constraints:/);
  assert.match(prompt, /has ZERO exclusion authority/);
});

test("LOOP2-004 Regression 1: CYCLE-0022 Replay with unexcluded counterexample BLOCKS merge", () => {
  const consensus = {
    findings: [{
      id: "f-pytest-01",
      title: "Retained exceptional behavior contradicts declared patch objective",
      severity: "low",
      type: "OBJECTIVE_CONTRADICTION",
      file: "testing/test_debugging.py",
      line_start: 1382,
      line_end: 1390,
      corroborations: 2,
      sources: ["agy", "claude"]
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Fail the current test and stop the test session on debugger quit / BdbQuit in all cases.",
    objectiveContract: {
      objective: "Fail the current test and stop the test session on debugger quit / BdbQuit in all cases.",
      exclusions: []
    },
    evaluations: [{
      findingId: "f-pytest-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "Retained xfail on Python 3.14 means test does not report as failed on 3.14. Exclusions list is empty. Changelog cannot establish an authorized exclusion."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /Verified finding directly falsifies stated patch objective/);
});

test("LOOP2-004 Regression 2: Pre-bound authorized exclusion passes as advisory APPROVE (Precision Guard)", () => {
  const consensus = {
    findings: [{
      id: "f-runxfail-01",
      title: "Does not override empty-set xfail(run=False)",
      severity: "low",
      file: "src/_pytest/skipping.py",
      line_start: 200,
      line_end: 205
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Turn crash caused by empty parameter set under --runxfail into clear failure",
    objectiveContract: {
      objective: "Turn crash caused by empty parameter set under --runxfail into clear failure",
      exclusions: ["whether --runxfail should override empty-set xfail(run=False)"]
    },
    evaluations: [{
      findingId: "f-runxfail-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "The unhandled condition is explicitly listed in the pre-bound Authorized Pre-Bound Exclusions."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "approve");
});

test("LOOP2-004 Regression 3: Corroborated objective contradiction contested by verifier triggers HUMAN_REVIEW_REQUIRED", () => {
  const consensus = {
    findings: [{
      id: "f-pytest-02",
      title: "Retained exceptional behavior contradicts declared patch objective",
      severity: "low",
      type: "OBJECTIVE_CONTRADICTION",
      file: "testing/test_debugging.py",
      line_start: 1382,
      corroborations: 2,
      sources: ["agy", "claude"]
    }]
  };

  // Even if verifier issues CONTESTED (e.g. arguing about changelog exclusion)
  const verificationRecord = {
    ok: true,
    patchObjective: "Fail the current test and stop the test session on debugger quit / BdbQuit in all cases.",
    evaluations: [{
      findingId: "f-pytest-02",
      verdict: "CONTESTED",
      classification: "CONTRADICTED",
      locatorAccurate: true,
      typeAccurate: false,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Verifier claims changelog establishes exclusion."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "human_review_required");
  assert.match(gateResult.reason, /Corroborated objective contradiction contested by verifier requires human adjudication/);
});

test("LOOP2-004 Regression 4: Solitary non-objective low finding contested by verifier remains advisory APPROVE", () => {
  const consensus = {
    findings: [{
      id: "f-style-02",
      title: "Typo in comment",
      severity: "low",
      type: "CODE_STYLE",
      file: "src/utils.py",
      line_start: 10,
      corroborations: 1,
      sources: ["agy"]
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Fix memory leak",
    evaluations: [{
      findingId: "f-style-02",
      verdict: "CONTESTED",
      classification: "CONTRADICTED",
      locatorAccurate: true,
      typeAccurate: false,
      severityAccurate: false,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Not a typo."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "approve");
});
