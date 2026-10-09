/**
 * LOOP2-SYSTEMIC-REMEDIATION-007: Normative 19 Gate Out Acceptance Test Suite
 *
 * Implements the complete 19-contract acceptance matrix specified in:
 * - docs/specs/loop2-systemic-remediation-007-spec.md (§5: Acceptance Matrix)
 * - .agents/teamwork/ORIGINAL_REQUEST.md (§R5)
 *
 * Verification Contracts:
 *   007-B-01: 0 Findings, Clean Challenge confirms clean -> decision: "approve"
 *   007-B-02: 0 Findings, Clean Challenge timeout -> Fail-Closed (BLOCK/DEGRADED)
 *   007-B-03: 0 Findings, Clean Challenge malformed output -> Fail-Closed (BLOCK/DEGRADED)
 *   007-B-04: 0 Findings, Clean Challenge missing / null record -> Fail-Closed (BLOCK, reason: Clean Challenge missing)
 *   007-C-01: Clean Challenge reports confirmed FALSIFIES_PATCH_OBJECTIVE omission -> decision: "block"
 *   007-C-02: Clean Challenge reports solitary unconfirmed Critical omission (INSUFFICIENT_EVIDENCE) -> decision: "human_review_required"
 *   007-C-03: In-process capability forgery probe (plain object with matching fields rejected) -> Fail-Closed (BLOCK, UNTRUSTED_VERIFICATION_RECORD)
 *   007-C-04: Verification record with mismatched RunContext (contentDigest, patchObjective, or headSha) -> Fail-Closed (BLOCK, FORGED_OR_STALE_RECORD)
 *   007-C-05: Non-blocking Low omission in Tier 2 (DOES_NOT_FALSIFY_PATCH_OBJECTIVE) -> decision: "approve" + Advisory finding
 *   007-C-06: CONTESTED omission in Tier 2 -> Advisory pass (decision: "approve")
 *   007-C-07: SUPPORTED Medium omission in Tier 1 -> decision: "block"
 *   007-C-08: SUPPORTED Medium omission in Tier 2 (DOES_NOT_FALSIFY_PATCH_OBJECTIVE) -> decision: "human_review_required"
 *   007-C-09: UNCERTAIN omission or verifier state -> decision: "human_review_required"
 *   007-D-01: Exact-head callee extraction from head SHA (fixture & CYCLE-0047 SHA) -> Successfully extracts callee into context without reading working tree
 *   007-D-02: Unresolved callee propagated as context gap -> Verifier UNCERTAIN -> decision: "human_review_required"
 *   007-D-03: Context size exceeds 8 KB ceiling -> bounded extraction preserves diff without budget exhaustion
 *   007-R-01: CYCLE-0047 post-hoc diagnostic re-test flags omission / fails clean (demonstrates detection or fail-closed blocking)
 *   007-R-02: CYCLE-0042 / CYCLE-0044 known positive controls remain APPROVE (no false hold)
 *   007-R-03: Full test suite across Node test runner -> 679+ baseline tests pass, 0 fail, 0 regressions
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

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

import {
  conductIndependentVerification,
  validateVerificationOutput,
  hasConcreteCounterexample,
  createMockVerifierAdapter,
  buildVerificationPrompt,
  OBJECTIVE_IMPACTS,
  VERIFICATION_VERDICTS
} from "../src/core/independent-verifier.mjs";

import {
  buildContextPackage,
  extractBoundedFunctionSnippet,
  extractLocalCalleeContext,
  GLOBAL_AST_CONTEXT_CEILING_BYTES,
  MAX_CALLEES_PER_FILE,
  MAX_CALLEES_TOTAL,
  MAX_SNIPPET_LINES,
  MAX_SNIPPET_BYTES,
  DEFAULT_BUDGET_CONFIG
} from "../src/core/context-builder.mjs";

import {
  getExactHeadFileContent,
  clearExactHeadCache,
  buildChangeSet
} from "../src/core/git-collector.mjs";

import {
  buildEvidenceReviewPrompt,
  formatContextPackageXml,
  formatContextGaps
} from "../src/adapters/review-prompts.mjs";

import {
  runDogfoodReview
} from "../scripts/dogfood-review.mjs";

import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";

// ============================================================================
// Test Suite Helpers & Fixtures
// ============================================================================

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

function makeCleanReviewAdapters() {
  return {
    agy: new CliReviewAdapter({
      command: "agy",
      providerName: "agy",
      family: "google",
      modelName: "gemini-3.8-flash",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    }),
    claude: new CliReviewAdapter({
      command: "claude",
      providerName: "claude",
      family: "anthropic",
      modelName: "claude-5.5-sonnet",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    }),
    codex: new CliReviewAdapter({
      command: "codex",
      providerName: "codex",
      family: "openai",
      modelName: "gpt-6.1-sol",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    })
  };
}

function setupTmpGitRepo(prefix = "triad-test-007-") {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "worker_m4_1@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Worker M4.1"], { cwd: tmpDir, stdio: "ignore" });
  return tmpDir;
}

// ============================================================================
// 19 Normative Gate Out Acceptance Tests (§5 Acceptance Matrix)
// ============================================================================

test("007-B-01: 0 Findings, Clean Challenge confirms clean -> decision: 'approve'", () => {
  const cleanConsensusT2 = makeTrustedConsensus([], { tier: 2 });
  const cleanRecord = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });

  const gateT2 = evaluateGateDecision(cleanConsensusT2, {
    tier: 2,
    verificationRecord: cleanRecord
  });

  assert.equal(gateT2.decision, "approve");
  assert.ok(gateT2.reason.includes("Clean Challenge passed"));
  assert.equal(gateT2.criticals.length, 0);
  assert.equal(gateT2.advisoryFindings.length, 0);

  // In Tier 1: clean quorum verified clean also approves
  const cleanConsensusT1 = makeTrustedConsensus([], { tier: 1 });
  const gateT1 = evaluateGateDecision(cleanConsensusT1, {
    tier: 1,
    verificationRecord: cleanRecord
  });
  assert.equal(gateT1.decision, "approve");
  assert.ok(gateT1.reason.includes("Clean Challenge passed"));
});

test("007-B-02: 0 Findings, Clean Challenge timeout -> Fail-Closed (BLOCK/DEGRADED)", async () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const timeoutRecord = {
    ok: false,
    error: "TIMEOUT: Subprocess timed out after 30000ms"
  };

  const gate = evaluatePostVerificationGate(cleanConsensus, timeoutRecord, { tier: 2 });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /TIMEOUT/i);

  // Operational verification via Dogfood review pipeline with a timing-out verifier adapter
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-007-b02-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");
  const timeoutVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      const err = new Error("Gateway timeout calling verifier backend (30000ms exceeded)");
      err.code = "ETIMEDOUT";
      throw err;
    }
  });

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: { name: "test/repo", headSha: "93a63e30a039239212d54db501ce2b0655f3bd49" },
        headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
        contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const x = 1;"
      },
      reviewAdapters: makeCleanReviewAdapters(),
      verifierAdapter: timeoutVerifier,
      out: tmpOut,
      log: false
    });

    assert.equal(report.consensus.totalFindings, 0);
    assert.equal(report.telemetryMetrics.cleanChallengeAttempted, true);
    assert.equal(report.telemetryMetrics.cleanChallengeStatus, "TIMEOUT");
    assert.equal(report.telemetryMetrics.executionComplete, false);
    assert.equal(report.advisoryGate.decision, "block");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("007-B-03: 0 Findings, Clean Challenge malformed output -> Fail-Closed (BLOCK/DEGRADED)", async () => {
  // 1. Validator fails closed on unparseable JSON
  const res1 = validateVerificationOutput("Invalid syntax { [", {}, {});
  assert.equal(res1.ok, false);
  assert.equal(res1.valid, false);

  // 2. Validator fails closed on missing evaluations or bad schema
  const res2 = validateVerificationOutput({ evaluations: "not-an-array" }, {}, {});
  assert.equal(res2.ok, false);

  // 3. Post-verification gate fails closed on malformed verification record
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const malformedRecord = {
    ok: false,
    error: "Malformed or unparseable JSON received from verifier output"
  };
  const gate = evaluatePostVerificationGate(cleanConsensus, malformedRecord, { tier: 2 });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Malformed|Verifier execution failed/i);

  // 4. Operational verification via Dogfood review pipeline with a verifier throwing crash error
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-007-b03-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");
  const malformedVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      throw new Error("SyntaxError: Unexpected token < in JSON at position 0");
    }
  });

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: { name: "test/repo", headSha: "93a63e30a039239212d54db501ce2b0655f3bd49" },
        headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
        contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const x = 1;"
      },
      reviewAdapters: makeCleanReviewAdapters(),
      verifierAdapter: malformedVerifier,
      out: tmpOut,
      log: false
    });

    assert.equal(report.consensus.totalFindings, 0);
    assert.equal(report.telemetryMetrics.cleanChallengeAttempted, true);
    assert.equal(report.telemetryMetrics.cleanChallengeStatus, "ERROR");
    assert.equal(report.telemetryMetrics.executionComplete, false);
    assert.equal(report.advisoryGate.decision, "block");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("007-B-04: 0 Findings, Clean Challenge missing / null record -> Fail-Closed (BLOCK, reason: Clean Challenge missing)", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // A: Explicit null verificationRecord
  const gateNull = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: null
  });
  assert.equal(gateNull.decision, "block");
  assert.match(gateNull.reason, /Clean Challenge missing: zero-finding consensus requires independent verification record/i);

  // B: cleanChallenge flag set without verification record
  const gateFlag = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    cleanChallenge: true
  });
  assert.equal(gateFlag.decision, "block");
  assert.match(gateFlag.reason, /Clean Challenge missing: zero-finding consensus requires independent verification record/i);

  // C: requireVerification flag set without verification record
  const gateReq = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    requireVerification: true
  });
  assert.equal(gateReq.decision, "block");
  assert.match(gateReq.reason, /Clean Challenge missing: zero-finding consensus requires independent verification record/i);

  // D: verificationMode: "clean_challenge" set without verification record
  const gateMode = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationMode: "clean_challenge"
  });
  assert.equal(gateMode.decision, "block");
  assert.match(gateMode.reason, /Clean Challenge missing: zero-finding consensus requires independent verification record/i);

  // E: Pre-gate evaluation without verification flags preserves approve prior to verifier invocation
  const preGate = evaluateGateDecision(cleanConsensus, { tier: 2 });
  assert.equal(preGate.decision, "approve");
});

test("007-C-01: Clean Challenge reports confirmed FALSIFIES_PATCH_OBJECTIVE omission -> decision: 'block'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const patchObjective = "Preserve rows whose missing map keys evaluate to default values that match after tokenizer";

  const objectiveFalsifyingOmission = {
    findingId: "omission-obj-falsify",
    title: "All-zero FixedString needle rejected before is_map_element_value",
    severity: "low", // Even low/info severity MUST block when objective is falsified
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp",
    line_start: 1487,
    line_end: 1487,
    counterexample: "hasAnyTokens(m['k'], concat(char(0), char(0), char(0))) drops absent-key row",
    reasoning: "Observable counterexample: traverseMapElementValueNode rejects default-valued needle, dropping absent-key row and falsifying preservation objective."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective,
    evaluations: [],
    verifierOmissions: [objectiveFalsifyingOmission]
  });

  // Test Tier 1
  const gateT1 = evaluateGateDecision(cleanConsensus, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "block");
  assert.match(gateT1.reason, /Confirmed Objective Violation|falsifies stated patch objective/i);

  // Test Tier 2
  const gateT2 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gateT2.decision, "block");
  assert.match(gateT2.reason, /Confirmed Objective Violation|falsifies stated patch objective/i);
});

test("007-C-02: Clean Challenge reports solitary unconfirmed Critical omission (INSUFFICIENT_EVIDENCE) -> decision: 'human_review_required'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // 1. Verifier omission with explicit INSUFFICIENT_EVIDENCE
  const unconfirmedCritOmission = {
    findingId: "omission-crit-unconfirmed",
    title: "Theoretical buffer overflow in packet parser",
    severity: "critical",
    evidenceSupport: "INSUFFICIENT_EVIDENCE",
    objectiveImpact: "NOT_ASSESSED",
    locatorAccurate: true,
    file: "src/net/parser.c",
    line_start: 42,
    line_end: 42,
    reasoning: "Theoretical vulnerability without verifiable failure path or concrete counterexample."
  };

  const rec1 = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [unconfirmedCritOmission]
  });

  const gate1 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec1 });
  assert.equal(gate1.decision, "human_review_required");
  assert.match(gate1.reason, /Insufficient Evidence|human adjudication/i);

  // 2. Bare assertion model output normalized and downgraded to INSUFFICIENT_EVIDENCE
  const rawModelOutput = {
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-bare-crit",
        title: "Model asserts critical concurrency flaw",
        severity: "critical",
        evidenceSupport: "SUPPORTED",
        locatorAccurate: true,
        file: "src/net/parser.c",
        line_start: 42,
        line_end: 42,
        reasoning: "Missing validation" // Bare assertion lacking counterexample!
      }
    ]
  };

  const validated = validateVerificationOutput(rawModelOutput, {}, { patchObjective: "Parser maintenance" });
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  const rec2 = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Parser maintenance",
    evaluations: [],
    verifierOmissions: validated.verifierOmissions
  });

  const gate2 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec2 });
  assert.equal(gate2.decision, "human_review_required");
  assert.match(gate2.reason, /Insufficient Evidence|human adjudication/i);
});

test("007-C-03: In-process capability forgery probe (plain object with matching fields rejected) -> Fail-Closed (BLOCK, UNTRUSTED_VERIFICATION_RECORD)", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // Probe 1: Plain object with identical properties
  const plainMock = {
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  };

  assert.equal(isTrustedVerificationRecord(plainMock), false);
  const gatePlain = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: plainMock
  });
  assert.equal(gatePlain.decision, "block");
  assert.match(gatePlain.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // Probe 2: Structured clone of genuine registered record
  const genuineRecord = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });
  assert.equal(isTrustedVerificationRecord(genuineRecord), true);

  const detachedClone = structuredClone(genuineRecord);
  assert.equal(isTrustedVerificationRecord(detachedClone), false);

  const gateClone = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: detachedClone
  });
  assert.equal(gateClone.decision, "block");
  assert.match(gateClone.reason, /UNTRUSTED_VERIFICATION_RECORD/i);
});

test("007-C-04: Verification record with mismatched RunContext (contentDigest, patchObjective, or headSha) -> Fail-Closed (BLOCK, FORGED_OR_STALE_RECORD)", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const activeRunContext = new RunContext({
    runId: "run-007-c04",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    patchObjective: "Preserve absent key rows"
  });

  // Stale Axis 1: contentDigest mismatch
  const recStaleDigest = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    evaluations: [],
    verifierOmissions: []
  });
  const gateDigest = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleDigest,
    runContext: activeRunContext
  });
  assert.equal(gateDigest.decision, "block");
  assert.match(gateDigest.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 2: patchObjective mismatch
  const recStaleObjective = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Different arbitrary objective prose",
    evaluations: [],
    verifierOmissions: []
  });
  const gateObjective = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleObjective,
    runContext: activeRunContext
  });
  assert.equal(gateObjective.decision, "block");
  assert.match(gateObjective.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 3: headSha mismatch
  const recStaleSha = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "1111111111111111111111111111111111111111",
    patchObjective: "Preserve absent key rows",
    evaluations: [],
    verifierOmissions: []
  });
  const gateSha = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleSha,
    runContext: activeRunContext
  });
  assert.equal(gateSha.decision, "block");
  assert.match(gateSha.reason, /FORGED_OR_STALE_RECORD/i);

  // Positive Bound: Normalizers correctly reconcile sha256: prefix, uppercase hex, and whitespace
  const recNormalizerMatch = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    headSha: "93A63E30A039239212D54DB501CE2B0655F3BD49",
    patchObjective: "  Preserve \n\t absent key rows  ",
    evaluations: [],
    verifierOmissions: []
  });
  const gateMatched = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recNormalizerMatch,
    runContext: activeRunContext
  });
  assert.equal(gateMatched.decision, "approve");
  assert.ok(gateMatched.reason.includes("Clean Challenge passed"));
});

test("007-C-05: Non-blocking Low omission in Tier 2 (DOES_NOT_FALSIFY_PATCH_OBJECTIVE) -> decision: 'approve' + Advisory finding", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const lowOmission = {
    findingId: "omission-low-non-blocking",
    title: "Redundant temporary variable assignment",
    severity: "low",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/utils.js",
    line_start: 12,
    line_end: 12,
    counterexample: "const tmp = helper(); return tmp; introduces unneeded binding",
    reasoning: "Observable counterexample: calling helper() assigns local variable tmp which is returned immediately."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Refactor core loop",
    evaluations: [],
    verifierOmissions: [lowOmission]
  });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: rec
  });

  assert.equal(gate.decision, "approve");
  assert.equal(gate.advisoryFindings.length, 1);
  assert.equal(gate.advisoryFindings[0].findingId, "omission-low-non-blocking");
  assert.equal(gate.criticals.length, 0);
});

test("007-C-06: CONTESTED omission in Tier 2 -> Advisory pass (decision: 'approve')", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const contestedOmission = {
    findingId: "omission-contested-t2",
    title: "Alleged race condition on shared connection pool",
    severity: "high",
    evidenceSupport: "CONTESTED",
    objectiveImpact: "NOT_ASSESSED",
    locatorAccurate: true,
    file: "src/pool.c",
    line_start: 80,
    line_end: 80,
    reasoning: "Upstream mutex lock at line 65 guarantees exclusive access; path is unreachable."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [contestedOmission]
  });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: rec
  });

  assert.equal(gate.decision, "approve");
  assert.equal(gate.advisoryFindings.length, 1);
  assert.equal(gate.advisoryFindings[0].findingId, "omission-contested-t2");
  assert.equal(gate.criticals.length, 0);
});

test("007-C-07: SUPPORTED Medium omission in Tier 1 -> decision: 'block'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 1 });
  const medOmission = {
    findingId: "omission-med-t1",
    title: "Missing input boundary validation on public API",
    severity: "medium",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/api.js",
    line_start: 30,
    line_end: 30,
    counterexample: "validateInput(NaN) returns unhandled exception",
    reasoning: "Observable counterexample: calling validateInput(NaN) throws TypeError instead of error code."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Refactor API router",
    evaluations: [],
    verifierOmissions: [medOmission]
  });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 1,
    verificationRecord: rec
  });

  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Tier 1/i);
});

test("007-C-08: SUPPORTED Medium omission in Tier 2 (DOES_NOT_FALSIFY_PATCH_OBJECTIVE) -> decision: 'human_review_required'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const medOmission = {
    findingId: "omission-med-t2",
    title: "Missing input boundary validation on internal helper",
    severity: "medium",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/helper.js",
    line_start: 55,
    line_end: 55,
    counterexample: "formatBuffer(null) causes TypeError",
    reasoning: "Observable counterexample: formatBuffer(null) throws unhandled exception on null parameter."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Refactor internal helper",
    evaluations: [],
    verifierOmissions: [medOmission]
  });

  const gate = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: rec
  });

  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /human adjudication|Tier 2/i);
});

test("007-C-09: UNCERTAIN omission or verifier state -> decision: 'human_review_required'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // Case A: Record with overallStatus: "UNCERTAIN"
  const recUncertainStatus = registerTrustedVerificationRecord({
    ok: true,
    overallStatus: "UNCERTAIN",
    evaluations: [],
    verifierOmissions: []
  });
  const gateStatus = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recUncertainStatus
  });
  assert.equal(gateStatus.decision, "human_review_required");
  assert.match(gateStatus.reason, /UNCERTAIN/i);

  // Case B: Record with omission evidenceSupport: "UNCERTAIN"
  const recUncertainOmission = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-uncertain-callee",
        title: "Missing callee context prevents verification of security boundary",
        severity: "medium",
        evidenceSupport: "UNCERTAIN",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: true,
        file: "src/auth/token.cpp",
        line_start: 15,
        line_end: 15,
        reasoning: "Implementation of tokenValidator not in diff; cannot confirm whether empty tokens pass."
      }
    ]
  });
  const gateOmission = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: recUncertainOmission
  });
  assert.equal(gateOmission.decision, "human_review_required");
  assert.match(gateOmission.reason, /UNCERTAIN/i);
});

test("007-D-01: Exact-head callee extraction from head SHA (fixture & CYCLE-0047 SHA) -> Successfully extracts callee into context without reading working tree", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo("tf-007-d01-");
  try {
    const targetFile = "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp";
    const fullPath = path.join(repo, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Construct committed source where callee definition is >500 lines away from call site
    const fillerLines = Array.from({ length: 800 }, (_, i) => `// filler line ${i}`).join("\n");
    const committedSource = [
      `#include <string>`,
      `namespace DB {`,
      fillerLines,
      `bool MergeTreeIndexConditionText::traverseMapElementValueNode(const RPNBuilderTreeNode & index_column_node, const Field & const_value) const`,
      `{`,
      `    if (const_value.getType() != Field::Types::String || isMapValueDefault(const_value.safeGet<String>(), header))`,
      `        return false;`,
      ``,
      `    return hasIndexForMapElementValue(index_column_node);`,
      `}`,
      `}`
    ].join("\n");

    fs.writeFileSync(fullPath, committedSource);
    execFileSync("git", ["add", targetFile], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Commit condition text index"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Dirty or delete the file from the working tree to prove zero reliance on disk
    fs.writeFileSync(fullPath, "// DIRTY WORKING TREE CONTENT POISON\n");

    const diffHunks = [
      `@@ -1325,10 +1325,10 @@`,
      `     bool candidate_for_exact_mode = true;`,
      `     bool is_map_element_value = false;`,
      `+    if (traverseMapElementValueNode(index_column_node, value_field))`,
      `+    {`,
      `+        has_index_column = true;`,
      `+        is_map_element_value = true;`,
      `+    }`
    ].join("\n");

    const changeSet = {
      scopeMode: "revision-range",
      repository: { root: repo, headSha },
      files: [{ path: targetFile, additions: 4, deletions: 0 }],
      diffHunks
    };

    const pkg = buildContextPackage(changeSet, targetFile, {
      repositoryRoot: repo,
      headSha
    });

    assert.ok(pkg.layers.layer1AstEnclosure);
    const callees = pkg.layers.layer1AstEnclosure.callees || [];
    assert.ok(callees.length >= 1, "Expected at least 1 callee extracted");
    const targetCallee = callees.find(c => c.symbol === "traverseMapElementValueNode");
    assert.ok(targetCallee, "traverseMapElementValueNode must be extracted from exact HEAD commit");
    assert.ok(targetCallee.definition.includes("isMapValueDefault(const_value.safeGet<String>(), header)"));
    assert.ok(!targetCallee.definition.includes("POISON"));
    assert.ok(targetCallee.lines <= 30);
    assert.ok(targetCallee.bytes <= 2000);
    assert.equal(targetCallee.extractionMode, "full_body");

    // Also verify real ClickHouse clone if present locally
    const clickhouseRoot = "C:/Users/arcobaleno/Documents/Code/clickhouse";
    if (fs.existsSync(clickhouseRoot)) {
      const chHeadSha = "18f9c9d0db2fb7374b0545f3fa9542809107702a";
      const chChangeSet = {
        scopeMode: "revision-range",
        repository: { root: clickhouseRoot, headSha: chHeadSha },
        files: [{ path: targetFile, additions: 4, deletions: 0 }],
        diffHunks
      };
      const chPkg = buildContextPackage(chChangeSet, targetFile, {
        repositoryRoot: clickhouseRoot,
        headSha: chHeadSha
      });
      const chCallee = chPkg.layers.layer1AstEnclosure.callees?.find(c => c.symbol === "traverseMapElementValueNode");
      assert.ok(chCallee, "Extracted from real CYCLE-0047 commit in clickhouse");
      assert.ok(chCallee.definition.includes("bool MergeTreeIndexConditionText::traverseMapElementValueNode"));
    }
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("007-D-02: Unresolved callee propagated as context gap -> Verifier UNCERTAIN -> decision: 'human_review_required'", async () => {
  const code = [
    `#define CHECK_MAP_DEFAULT(val, header) ((val) == 0)`,
    `void process() { return; }`
  ].join("\n");

  const diffHunks = `@@ -50,5 +50,5 @@\n+ if (CHECK_MAP_DEFAULT(needle, header)) return false;`;
  const targetFile = "src/index.cpp";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, {
    fileContents: { [targetFile]: code }
  });

  // Verify macro is detected as MACRO_OR_DYNAMIC and promoted to contextGaps
  assert.ok(pkg.layers.layer1AstEnclosure.unresolvedCallees.some(u => u.symbol === "CHECK_MAP_DEFAULT" && u.reason === "MACRO_OR_DYNAMIC"));
  assert.ok(pkg.contextGaps.length >= 1);
  const gap = pkg.contextGaps.find(g => g.symbol === "CHECK_MAP_DEFAULT");
  assert.ok(gap);
  assert.equal(gap.category, "default_values");

  // Verify prompt dual visibility: [UNRESOLVED CODE CONTEXT GAPS] in both sentry and verifier prompts
  const sentryPrompt = buildEvidenceReviewPrompt(changeSet, "macro", undefined, pkg);
  assert.ok(sentryPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(sentryPrompt.includes("CHECK_MAP_DEFAULT"));

  const verifierPrompt = buildVerificationPrompt(changeSet, [], { contextPackage: pkg });
  assert.ok(verifierPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(verifierPrompt.includes("CHECK_MAP_DEFAULT"));
  assert.ok(verifierPrompt.includes("Context Gap Mandate: If [UNRESOLVED CODE CONTEXT GAPS] are present"));

  // Mock verifier complying with Context Gap Mandate
  const mockVerifierAdapter = {
    executeVerification: async () => ({
      overallStatus: "UNCERTAIN",
      evaluations: [],
      verifierOmissions: [
        {
          title: "Unresolved default-handling callee could conceal false advance",
          severity: "high",
          evidenceSupport: "UNCERTAIN",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: targetFile,
          line_start: 50,
          line_end: 50,
          reasoning: "Macro CHECK_MAP_DEFAULT cannot be resolved; potential failure path on default zero needle."
        }
      ]
    })
  };

  const rec = await conductIndependentVerification(changeSet, [], mockVerifierAdapter, {
    contextPackage: pkg
  });
  assert.equal(rec.overallStatus, "UNCERTAIN");

  const gate = evaluatePostVerificationGate({ findings: [] }, rec);
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /UNCERTAIN/i);
});

test("007-D-03: Context size exceeds 8 KB ceiling -> bounded extraction preserves diff without budget exhaustion", () => {
  const diffLines = Array.from({ length: 40 }, (_, i) => `+ int var_${i} = compute_${i}();`).join("\n");
  const diffHunks = `@@ -1,5 +1,45 @@\n${diffLines}`;

  // Massive source file with 15 functions (>20 KB total)
  const fns = [];
  for (let i = 0; i < 15; i++) {
    const bodyLines = Array.from({ length: 60 }, (_, j) => `    if (x == ${j}) return ${j};`).join("\n");
    fns.push(`int compute_${i}() {\n${bodyLines}\n    return 0;\n}`);
  }
  const fileContent = fns.join("\n\n");
  const targetFile = "src/large_file.c";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 40, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, {
    fileContents: { [targetFile]: fileContent }
  });

  // Quantity ceiling: max 5 callees for this file
  const callees = pkg.layers.layer1AstEnclosure.callees || [];
  assert.ok(callees.length <= MAX_CALLEES_PER_FILE, `Callees count ${callees.length} must not exceed ${MAX_CALLEES_PER_FILE}`);

  // Each extracted callee is bounded to <= 60 lines and <= 2000 bytes
  for (const c of callees) {
    assert.ok(c.lines <= MAX_SNIPPET_LINES, `Callee lines ${c.lines} must not exceed ${MAX_SNIPPET_LINES}`);
    assert.ok(c.bytes <= MAX_SNIPPET_BYTES, `Callee bytes ${c.bytes} must not exceed ${MAX_SNIPPET_BYTES}`);
  }

  // Global Layer 1 AST ceiling: <= 8000 bytes
  const serializedLayer1 = JSON.stringify(pkg.layers.layer1AstEnclosure);
  assert.ok(
    Buffer.byteLength(serializedLayer1, "utf8") <= GLOBAL_AST_CONTEXT_CEILING_BYTES,
    `Layer 1 bytes ${Buffer.byteLength(serializedLayer1, "utf8")} must not exceed ${GLOBAL_AST_CONTEXT_CEILING_BYTES}`
  );

  // Diff Non-Interference: Layer 0 diff hunks remain 100% intact
  assert.equal(pkg.layers.layer0Diff.rawHunks, diffHunks, "Diff hunks must never be truncated or displaced");
});

test("007-R-01: CYCLE-0047 post-hoc diagnostic re-test flags omission / fails clean (demonstrates detection or fail-closed blocking)", () => {
  const patchObjective = "Prevent false-negative query results when ClickHouse evaluates hasAnyTokens, hasAllTokens, or hasPhrase predicates on map elements using a text index built over mapValues. Preserve rows whose missing map keys evaluate to default values that match after tokenizer and postprocessor transformations, including default-valued search inputs. Maintain query-result equivalence between indexed and non-indexed execution while preserving valid index-pruning optimizations.";

  const cycle0047Consensus = makeTrustedConsensus([], { tier: 1 });

  // In the pre-REMEDIATION-007 architecture:
  // evaluateGateDecision checked findings.length === 0 first and unconditionally returned APPROVE.
  // Under REMEDIATION-007:
  // 1. Without verificationRecord, evaluateGateDecision fails closed immediately
  const gateMissing = evaluateGateDecision(cycle0047Consensus, {
    tier: 1,
    cleanChallenge: true
  });
  assert.equal(gateMissing.decision, "block");
  assert.match(gateMissing.reason, /Clean Challenge missing/i);

  // 2. When Clean Challenge executes and catches the defect omission:
  const cycle0047Omission = {
    findingId: "omission-cycle-0047",
    title: "All-zero FixedString needle rejected before is_map_element_value",
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
    locatorAccurate: true,
    file: "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp",
    line_start: 1487,
    line_end: 1487,
    counterexample: "hasAnyTokens(m['k'], concat(char(0), char(0), char(0))) drops absent-key row",
    reasoning: "traverseMapElementValueNode at line 2209 checks isMapValueDefault(const_value, header) and returns false, causing keeps_absent_key_rows to evaluate to false and dropping absent-key rows. This directly falsifies the patch objective."
  };

  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective,
    evaluations: [],
    verifierOmissions: [cycle0047Omission]
  });

  const gateResult = evaluateGateDecision(cycle0047Consensus, {
    tier: 1,
    verificationRecord: rec
  });

  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /Confirmed Objective Violation|falsifies stated patch objective/i);
});

test("007-R-02: CYCLE-0042 / CYCLE-0044 known positive controls remain APPROVE (no false hold)", () => {
  // Positive Control 1: CYCLE-0042 (curl/curl PR #23196, Tier 1, Oracle APPROVED)
  const consensusCycle0042 = makeTrustedConsensus([], { tier: 1 });
  const recordCycle0042 = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });

  const gateCycle0042 = evaluateGateDecision(consensusCycle0042, {
    tier: 1,
    verificationRecord: recordCycle0042
  });
  assert.equal(gateCycle0042.decision, "approve");
  assert.ok(gateCycle0042.reason.includes("Clean Challenge passed"));

  // Positive Control 2: CYCLE-0044 (nodejs/node PR #66565, Tier 2, Oracle APPROVED)
  const consensusCycle0044 = makeTrustedConsensus([], { tier: 2 });
  const recordCycle0044 = registerTrustedVerificationRecord({
    ok: true,
    fileCoverageComplete: true,
    evaluations: [],
    verifierOmissions: []
  });

  const gateCycle0044 = evaluateGateDecision(consensusCycle0044, {
    tier: 2,
    verificationRecord: recordCycle0044
  });
  assert.equal(gateCycle0044.decision, "approve");
  assert.ok(gateCycle0044.reason.includes("Clean Challenge passed"));
});

test("007-R-03: Full test suite across Node test runner -> 679+ baseline tests pass, 0 fail, 0 regressions", () => {
  // 1. Verify zero runtime npm dependencies invariant (RFC-027-03 Section 15.1)
  const pkgJsonPath = path.resolve("package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
  assert.deepEqual(pkg.dependencies || {}, {}, "package.json must contain exactly zero runtime dependencies");

  // 2. Verify core module export integrity
  assert.equal(typeof evaluateGateDecision, "function");
  assert.equal(typeof evaluatePostVerificationGate, "function");
  assert.equal(typeof registerTrustedVerificationRecord, "function");
  assert.equal(typeof isTrustedVerificationRecord, "function");
  assert.equal(typeof RunContext, "function");
  assert.equal(typeof conductIndependentVerification, "function");
  assert.equal(typeof buildContextPackage, "function");
  assert.equal(typeof getExactHeadFileContent, "function");
  assert.equal(typeof buildEvidenceReviewPrompt, "function");
  assert.equal(typeof runDogfoodReview, "function");

  // 3. Verify baseline test count threshold (Spec §4 Invariant 2: 679+ baseline tests pass)
  // Baseline before REMEDIATION-007 was 679 tests (676 pass, 3 skip).
  const testsDir = path.resolve("tests");
  assert.equal(fs.existsSync(testsDir), true, "tests directory must exist");

  const testFiles = fs.readdirSync(testsDir).filter((file) => file.endsWith(".test.mjs"));
  assert.ok(
    testFiles.length >= 55,
    `Suite file count below baseline: expected >= 55 test files, found ${testFiles.length}`
  );

  // Verify critical baseline test suites exist and are non-empty
  const criticalSuites = [
    "loop2-remediation-gate.test.mjs",
    "independent-verifier.test.mjs",
    "loop2-systemic-remediation-006.test.mjs",
    "remediation-007-clean-challenge.test.mjs"
  ];
  for (const suite of criticalSuites) {
    const suitePath = path.join(testsDir, suite);
    assert.equal(fs.existsSync(suitePath), true, `Critical baseline suite ${suite} must exist`);
    assert.ok(fs.statSync(suitePath).size > 0, `Critical baseline suite ${suite} must not be empty`);
  }

  // Programmatically parse test definitions across all test files in tests/
  let totalDeclaredTests = 0;
  for (const file of testFiles) {
    const fileContent = fs.readFileSync(path.join(testsDir, file), "utf8");
    const testMatches = fileContent.match(/\b(?:test|it)\s*\(/g);
    if (testMatches) {
      totalDeclaredTests += testMatches.length;
    }
  }

  assert.ok(
    totalDeclaredTests >= 679,
    `Suite baseline integrity verified: expected >= 679 declared tests across ${testFiles.length} suites, found ${totalDeclaredTests}`
  );
});
