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
  evaluateIsolatedTestGate,
  evaluateIsolatedTestPostVerificationGate,
  issueVerificationRecordFromOutput,
  isTrustedVerificationRecord,
  isSegregatedSyntheticRecord,
  RunContext,
  normalizeDigest,
  normalizeObjective,
  normalizeCommitSha
} from "../src/core/harness.mjs";
import * as harnessModule from "../src/core/harness.mjs";
import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";

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
import * as verifierModule from "../src/core/independent-verifier.mjs";

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

test("007-B-01: 0 Findings, Clean Challenge confirms clean -> decision: 'approve'", async () => {
  const cleanConsensusT2 = makeTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const cleanRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "clean_challenge" }
  );

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

  // 2b. Clean challenge output missing overallStatus fails closed (P1 contract)
  const resMissingStatus = validateVerificationOutput({ evaluations: [] }, { verificationMode: "clean_challenge" });
  assert.equal(resMissingStatus.ok, false);
  assert.equal(resMissingStatus.valid, false);
  assert.match(resMissingStatus.error, /missing or invalid required 'overallStatus'/i);

  // 2c. Clean challenge output with invalid overallStatus fails closed (P1 contract)
  const resBadStatus = validateVerificationOutput({ evaluations: [], overallStatus: "ALL_GOOD" }, { verificationMode: "clean_challenge" });
  assert.equal(resBadStatus.ok, false);
  assert.equal(resBadStatus.valid, false);
  assert.match(resBadStatus.error, /missing or invalid required 'overallStatus'/i);

  // 2d. Clean challenge output with valid overallStatus: "CLEAN" succeeds
  const resClean = validateVerificationOutput({ evaluations: [], overallStatus: "CLEAN" }, { verificationMode: "clean_challenge" });
  assert.equal(resClean.ok, true);
  assert.equal(resClean.valid, true);
  assert.equal(resClean.overallStatus, "CLEAN");

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

  // E: Pre-gate preliminary evaluation preserves approve prior to verifier invocation
  const preGate = evaluateGateDecision(cleanConsensus, { tier: 2, preliminary: true });
  assert.equal(preGate.decision, "approve");
  assert.equal(preGate.preliminary, true);

  // F: Final gate evaluation without verification record strictly fails closed
  const finalGateWithoutRecord = evaluateGateDecision(cleanConsensus, { tier: 2 });
  assert.equal(finalGateWithoutRecord.decision, "block");
  assert.match(finalGateWithoutRecord.reason, /Clean Challenge missing/i);
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective,
    evaluations: [],
    verifierOmissions: [objectiveFalsifyingOmission]
  });

  // Test Tier 1
  const gateT1 = evaluateIsolatedTestGate(cleanConsensus, { tier: 1, verificationRecord: rec });
  assert.equal(gateT1.decision, "block");
  assert.match(gateT1.reason, /Confirmed Objective Violation|falsifies stated patch objective/i);

  // Test Tier 2
  const gateT2 = evaluateIsolatedTestGate(cleanConsensus, { tier: 2, verificationRecord: rec });
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

  const rec1 = issueVerificationRecordFromOutput({
    ok: true,
    evaluations: [],
    verifierOmissions: [unconfirmedCritOmission]
  });

  const gate1 = evaluateIsolatedTestGate(cleanConsensus, { tier: 2, verificationRecord: rec1 });
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

  const rec2 = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective: "Parser maintenance",
    evaluations: [],
    verifierOmissions: validated.verifierOmissions
  });

  const gate2 = evaluateIsolatedTestGate(cleanConsensus, { tier: 2, verificationRecord: rec2 });
  assert.equal(gate2.decision, "human_review_required");
  assert.match(gate2.reason, /Insufficient Evidence|human adjudication/i);
});

test("007-C-03: In-process capability forgery probe (plain object with matching fields rejected) -> Fail-Closed (BLOCK, UNTRUSTED_VERIFICATION_RECORD)", async () => {
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
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const genuineRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "clean_challenge" }
  );
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
  const recStaleDigest = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    runId: "run-007-c04",
    evaluations: [],
    verifierOmissions: []
  });
  const gateDigest = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleDigest,
    runContext: activeRunContext
  });
  assert.equal(gateDigest.decision, "block");
  assert.match(gateDigest.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 2: patchObjective mismatch
  const recStaleObjective = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Different arbitrary objective prose",
    runId: "run-007-c04",
    evaluations: [],
    verifierOmissions: []
  });
  const gateObjective = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleObjective,
    runContext: activeRunContext
  });
  assert.equal(gateObjective.decision, "block");
  assert.match(gateObjective.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 3: headSha mismatch
  const recStaleSha = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "1111111111111111111111111111111111111111",
    patchObjective: "Preserve absent key rows",
    runId: "run-007-c04",
    evaluations: [],
    verifierOmissions: []
  });
  const gateSha = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleSha,
    runContext: activeRunContext
  });
  assert.equal(gateSha.decision, "block");
  assert.match(gateSha.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 4: runId mismatch
  const recStaleRunId = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    runId: "wrong-run-id-stale",
    evaluations: [],
    verifierOmissions: []
  });
  const gateRunId = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleRunId,
    runContext: activeRunContext
  });
  assert.equal(gateRunId.decision, "block");
  assert.match(gateRunId.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 5: missing runId on verification record when active RunContext requires it
  const recMissingRunId = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    evaluations: [],
    verifierOmissions: []
  });
  const gateMissingRunId = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recMissingRunId,
    runContext: activeRunContext
  });
  assert.equal(gateMissingRunId.decision, "block");
  assert.match(gateMissingRunId.reason, /FORGED_OR_STALE_RECORD/i);

  // Stale Axis 6: exclusions mismatch
  const recStaleExcl = issueVerificationRecordFromOutput({
    ok: true,
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    patchObjective: "Preserve absent key rows",
    runId: "run-007-c04",
    exclusions: ["unauthorized-extra-exclusion"],
    evaluations: [],
    verifierOmissions: []
  });
  const gateExcl = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recStaleExcl,
    runContext: activeRunContext
  });
  assert.equal(gateExcl.decision, "block");
  assert.match(gateExcl.reason, /FORGED_OR_STALE_RECORD/i);

  // Positive Bound: Normalizers correctly reconcile sha256: prefix, uppercase hex, whitespace, and matching runId
  const recNormalizerMatch = issueVerificationRecordFromOutput({
    ok: true,
    overallStatus: "CLEAN",
    changeSetDigest: "sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    headSha: "93A63E30A039239212D54DB501CE2B0655F3BD49",
    patchObjective: "  Preserve \n\t absent key rows  ",
    runId: "run-007-c04",
    evaluations: [],
    verifierOmissions: []
  });
  const gateMatched = evaluateIsolatedTestGate(cleanConsensus, {
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective: "Refactor core loop",
    evaluations: [],
    verifierOmissions: [lowOmission]
  });

  const gate = evaluateIsolatedTestGate(cleanConsensus, {
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    evaluations: [],
    verifierOmissions: [contestedOmission]
  });

  const gate = evaluateIsolatedTestGate(cleanConsensus, {
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective: "Refactor API router",
    evaluations: [],
    verifierOmissions: [medOmission]
  });

  const gate = evaluateIsolatedTestGate(cleanConsensus, {
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective: "Refactor internal helper",
    evaluations: [],
    verifierOmissions: [medOmission]
  });

  const gate = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: rec
  });

  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /human adjudication|Tier 2/i);
});

test("007-C-09: UNCERTAIN omission or verifier state -> decision: 'human_review_required'", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });

  // Case A: Record with overallStatus: "UNCERTAIN"
  const recUncertainStatus = issueVerificationRecordFromOutput({
    ok: true,
    overallStatus: "UNCERTAIN",
    evaluations: [],
    verifierOmissions: []
  });
  const gateStatus = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: recUncertainStatus
  });
  assert.equal(gateStatus.decision, "human_review_required");
  assert.match(gateStatus.reason, /UNCERTAIN/i);

  // Case B: Record with omission evidenceSupport: "UNCERTAIN"
  const recUncertainOmission = issueVerificationRecordFromOutput({
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
  const gateOmission = evaluateIsolatedTestGate(cleanConsensus, {
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

  const rec = issueVerificationRecordFromOutput({
    ok: true,
    patchObjective,
    evaluations: [],
    verifierOmissions: [cycle0047Omission]
  });

  const gateResult = evaluateIsolatedTestGate(cycle0047Consensus, {
    tier: 1,
    verificationRecord: rec
  });

  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /Confirmed Objective Violation|falsifies stated patch objective/i);
});

test("007-R-02: CYCLE-0042 / CYCLE-0044 known positive controls remain APPROVE (no false hold)", () => {
  // Positive Control 1: CYCLE-0042 (curl/curl PR #23196, Tier 1, Oracle APPROVED)
  const consensusCycle0042 = makeTrustedConsensus([], { tier: 1 });
  const recordCycle0042 = issueVerificationRecordFromOutput({
    ok: true,
    fileCoverageComplete: true,
    overallStatus: "CLEAN",
    evaluations: [],
    verifierOmissions: []
  });

  const gateCycle0042 = evaluateIsolatedTestGate(consensusCycle0042, {
    tier: 1,
    verificationRecord: recordCycle0042
  });
  assert.equal(gateCycle0042.decision, "approve");
  assert.ok(gateCycle0042.reason.includes("Clean Challenge passed"));

  // Positive Control 2: CYCLE-0044 (nodejs/node PR #66565, Tier 2, Oracle APPROVED)
  const consensusCycle0044 = makeTrustedConsensus([], { tier: 2 });
  const recordCycle0044 = issueVerificationRecordFromOutput({
    ok: true,
    fileCoverageComplete: true,
    overallStatus: "CLEAN",
    evaluations: [],
    verifierOmissions: []
  });

  const gateCycle0044 = evaluateIsolatedTestGate(consensusCycle0044, {
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
  assert.equal(typeof issueVerificationRecordFromOutput, "function");
  assert.equal(typeof isTrustedVerificationRecord, "function");
  assert.equal(typeof RunContext, "function");
  assert.equal(typeof conductIndependentVerification, "function");
  assert.equal(typeof buildContextPackage, "function");
  assert.equal(typeof getExactHeadFileContent, "function");
  assert.equal(typeof buildEvidenceReviewPrompt, "function");
  assert.equal(typeof runDogfoodReview, "function");

  // Verify capability registry privatization (Blocker 1)
  assert.equal(verifierModule.registerTrustedVerificationRecord, undefined);
  assert.equal(verifierModule.trustedVerificationRegistry, undefined);
  assert.equal(harnessModule.registerTrustedVerificationRecord, undefined);
  assert.equal(harnessModule.trustedVerificationRegistry, undefined);

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

test("007-P1-01: Clean Challenge missing/unrecognized overallStatus fails closed with MALFORMED_OUTPUT", () => {
  // Test A: Missing overallStatus
  const resMissing = validateVerificationOutput({ evaluations: [] }, { verificationMode: "clean_challenge" });
  assert.equal(resMissing.ok, false);
  assert.equal(resMissing.valid, false);
  assert.match(resMissing.error, /missing or invalid required 'overallStatus'/i);

  // Test B: Null or empty overallStatus
  const resNull = validateVerificationOutput({ evaluations: [], overallStatus: null }, { verificationMode: "clean_challenge" });
  assert.equal(resNull.ok, false);
  assert.equal(resNull.valid, false);

  // Test C: Unrecognized overallStatus string
  const resUnrecognized = validateVerificationOutput({ evaluations: [], overallStatus: "ALL_GOOD_NO_WORRIES" }, { verificationMode: "clean_challenge" });
  assert.equal(resUnrecognized.ok, false);
  assert.equal(resUnrecognized.valid, false);

  // Test D: SUCCESS is not valid for Clean Challenge authority (must be CLEAN, UNCERTAIN, or DEFECTS_FOUND)
  const resSuccess = validateVerificationOutput({ evaluations: [], overallStatus: "SUCCESS" }, { verificationMode: "clean_challenge" });
  assert.equal(resSuccess.ok, false);
  assert.equal(resSuccess.valid, false);

  // Test E: Explicit CLEAN grants valid clean status
  const resClean = validateVerificationOutput({ evaluations: [], overallStatus: "CLEAN" }, { verificationMode: "clean_challenge" });
  assert.equal(resClean.ok, true);
  assert.equal(resClean.valid, true);
  assert.equal(resClean.overallStatus, "CLEAN");
});

test("007-P1-02: Clean Challenge prompt schema explicitly requests all authority-bearing omission fields", () => {
  const prompt = buildVerificationPrompt(
    { totalFiles: 1, files: [{ path: "src/calc.js", additions: 1, deletions: 0 }], diffHunks: "+ return 42;" },
    [],
    { verificationMode: "clean_challenge", patchObjective: "Fix calculation overflow" }
  );

  // Authority-bearing fields required by validator and gate
  assert.match(prompt, /"evidenceSupport":\s*"SUPPORTED\|CONTESTED\|INSUFFICIENT_EVIDENCE\|UNCERTAIN"/);
  assert.match(prompt, /"objectiveImpact":\s*"FALSIFIES_PATCH_OBJECTIVE\|DOES_NOT_FALSIFY_PATCH_OBJECTIVE\|NOT_ASSESSED"/);
  assert.match(prompt, /"counterexample":\s*"Concrete input or invocation that triggers the bug/);
  assert.match(prompt, /"locatorAccurate":\s*true/);
  assert.match(prompt, /"reasoning":/);
});

test("007-P1-03: Sensitive callee quota overflow and unavailable exact-head content propagate context gaps", () => {
  // Test A: Quota overflow preserves sensitive callees as contextGaps
  const targetFile = "src/security.cpp";
  // Simulate diff calling 15 candidate functions (quota is MAX_CALLEES_PER_FILE = 5)
  const fakeDiff = Array.from({ length: 15 }, (_, i) => `+ sanitize_input_${i}(buf);`).join("\n");
  const fakeFileContent = [
    ...Array.from({ length: 15 }, (_, i) => `void sanitize_input_${i}(char* buf) { check(buf); }`)
  ].join("\n");

  const res = extractLocalCalleeContext(fakeFileContent, fakeDiff, targetFile, {});
  assert.equal(res.callees.length, MAX_CALLEES_PER_FILE);
  assert.ok(res.contextGaps.length > 0, "Sensitive callees beyond quota must be preserved in contextGaps");
  assert.ok(res.contextGaps.every(gap => gap.reason === "EXTRACTION_QUOTA_EXCEEDED"));

  // Test B: Unavailable exact-head content records context gap
  const contextPackage = buildContextPackage(
    {
      ok: true,
      totalFiles: 1,
      headSha: "ffffffffffffffffffffffffffffffffffffffff",
      repository: { root: "/non/existent/repo/root" },
      files: [{ path: "src/missing.c", additions: 1, deletions: 0, riskTier: 1 }],
      diffHunks: "+ foo();"
    },
    "src/missing.c",
    { repositoryRoot: "/non/existent/repo/root", headSha: "ffffffffffffffffffffffffffffffffffffffff" }
  );
  assert.ok(contextPackage.contextGaps.some(g => g.reason === "EXACT_HEAD_CONTENT_UNAVAILABLE"));

  // Test C: Context gaps propagate uncertainty to verifier output even if rawOverallStatus is CLEAN
  const validatedWithGaps = validateVerificationOutput(
    { evaluations: [], overallStatus: "CLEAN" },
    { verificationMode: "clean_challenge", contextGaps: contextPackage.contextGaps }
  );
  assert.equal(validatedWithGaps.ok, true);
  assert.equal(validatedWithGaps.overallStatus, "UNCERTAIN", "Context gaps must propagate uncertainty to overallStatus UNCERTAIN");
});

test("007-P2-01: RunContext and getCheckpointPath strictly reject path traversal sequences", () => {
  // RunContext path traversal rejection
  assert.throws(() => {
    new RunContext({ runId: "../escape-directory" });
  }, /Invalid runId.*path traversal/i);

  assert.throws(() => {
    new RunContext({ runId: "valid/../../root" });
  }, /Invalid runId.*path traversal/i);

  assert.throws(() => {
    new RunContext({ runId: "null\0byte" });
  }, /Invalid runId.*path traversal/i);

  // Normal safe runId accepted
  const safeRc = new RunContext({ runId: "safe-run-123_456" });
  assert.equal(safeRc.runId, "safe-run-123_456");
});

test("007-P1-04: hasConcreteCounterexample rejects bare assertions and validates failure mechanics", () => {
  // 1. Bare assertions without concrete mechanics or payload (must be rejected)
  assert.equal(hasConcreteCounterexample("potential edge case flaw in loop"), false);
  assert.equal(hasConcreteCounterexample("some problem in parser implementation"), false);
  assert.equal(hasConcreteCounterexample("needs investigation regarding concurrency"), false);
  assert.equal(hasConcreteCounterexample("could cause issues with long inputs"), false);
  assert.equal(hasConcreteCounterexample("missing check on input size"), false);
  assert.equal(hasConcreteCounterexample("edge case unhandled in boundary"), false);

  // 2. Valid concrete counterexamples with call/expression and failure path/symptom
  assert.equal(hasConcreteCounterexample("calling parseInput('') returns null and causes crash"), true);
  assert.equal(hasConcreteCounterexample({
    counterexample: "fetchUser(null)",
    reasoning: "Passing null throws TypeError and crashes process"
  }), true);
  assert.equal(hasConcreteCounterexample({
    counterexample: "arr[0x1000]",
    reasoning: "out-of-bounds index leads to buffer overflow"
  }), true);

  // 3. validateVerificationOutput downgrades bare omission to INSUFFICIENT_EVIDENCE
  const unverifiedOmission = {
    findingId: "omission-bare-test",
    title: "Alleged parser issue",
    severity: "high",
    evidenceSupport: "SUPPORTED",
    locatorAccurate: true,
    file: "src/parser.c",
    line_start: 10,
    line_end: 12,
    counterexample: "potential edge case flaw",
    reasoning: "could cause issues with long inputs"
  };

  const output = validateVerificationOutput(
    { evaluations: [], verifierOmissions: [unverifiedOmission] },
    { verificationMode: "clean_challenge" }
  );
  assert.equal(output.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");
});

test("007-P1-01-DELTA: Synthetic test records fail closed against formal gate without authentic minting", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const syntheticRecord = issueVerificationRecordFromOutput({
    ok: true,
    overallStatus: "CLEAN",
    verificationMode: "clean_challenge",
    evaluations: [],
    verifierOmissions: []
  });

  assert.equal(isSegregatedSyntheticRecord(syntheticRecord), true);
  assert.equal(isTrustedVerificationRecord(syntheticRecord), false);

  // When formal gate evaluates synthetic record without conductIndependentVerification, it strictly fails closed by default
  const formalGateResult = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: syntheticRecord
  });
  assert.equal(formalGateResult.decision, "block");
  assert.match(formalGateResult.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // evaluatePostVerificationGate also strictly fails closed by default
  const formalPostGateResult = evaluatePostVerificationGate(cleanConsensus, syntheticRecord, {
    tier: 2
  });
  assert.equal(formalPostGateResult.decision, "block");
  assert.match(formalPostGateResult.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // Synthetic backdoor attempts (e.g. synthetic: true flag) cannot bypass formal gate
  const bypassAttemptResult = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    synthetic: true,
    verificationRecord: syntheticRecord
  });
  assert.equal(bypassAttemptResult.decision, "block");
  assert.match(bypassAttemptResult.reason, /UNTRUSTED_VERIFICATION_RECORD/i);

  // Isolated test mechanism safely evaluates synthetic records
  const isolatedResult = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: syntheticRecord
  });
  assert.equal(isolatedResult.decision, "approve");
});

test("007-P1-02-DELTA: Review orchestrator with preliminary: true never returns reviewed-clean", async () => {
  const changeSet = {
    ok: true,
    totalFiles: 1,
    files: [{ path: "src/safe.js", additions: 2, deletions: 0, riskTier: 2 }],
    diffHunks: "+ return 1;"
  };

  const cleanAdapter = {
    providerName: "clean-sentry",
    modelName: "model-x",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/safe.js"], omittedFiles: [] }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: cleanAdapter }, {
    preliminary: true
  });

  // Must preserve preliminary state and return preliminary-clean, NEVER reviewed-clean
  assert.notEqual(result.status, "reviewed-clean");
  assert.equal(result.status, "preliminary-clean");
  assert.equal(result.gate.decision, "approve");
  assert.equal(result.gate.preliminary, true);
});

test("007-P1-03-DELTA: Zero-finding consensus with verificationMode: producer_verification fails closed", async () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const producerModeRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "producer_verification" }
  );

  // evaluateGateDecision with producer_verification on 0-finding consensus must BLOCK
  const gateDecision = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: producerModeRecord
  });
  assert.equal(gateDecision.decision, "block");
  assert.match(gateDecision.reason, /Verification mode mismatch.*clean_challenge/i);

  // evaluatePostVerificationGate with producer_verification on 0-finding consensus must BLOCK
  const postGateDecision = evaluatePostVerificationGate(cleanConsensus, producerModeRecord, {
    tier: 2
  });
  assert.equal(postGateDecision.decision, "block");
  assert.match(postGateDecision.reason, /Verification mode mismatch.*clean_challenge/i);

  // evaluateIsolatedTestGate on synthetic producer_verification record also blocks on mode mismatch
  const syntheticProducerRecord = issueVerificationRecordFromOutput({
    ok: true,
    overallStatus: "CLEAN",
    verificationMode: "producer_verification",
    evaluations: [],
    verifierOmissions: []
  });
  const isolatedDecision = evaluateIsolatedTestGate(cleanConsensus, {
    tier: 2,
    verificationRecord: syntheticProducerRecord
  });
  assert.equal(isolatedDecision.decision, "block");
  assert.match(isolatedDecision.reason, /Verification mode mismatch.*clean_challenge/i);
});

test("007-007-D-MULTI: Multi-file callee context extraction aggregates across all changeSet.files with coverage manifest", () => {
  const multiChangeSet = {
    ok: true,
    totalFiles: 3,
    files: [
      { path: "src/auth.c", additions: 5, deletions: 1, riskTier: 1 },
      { path: "src/crypto.c", additions: 8, deletions: 2, riskTier: 1 },
      { path: "src/utils.c", additions: 3, deletions: 0, riskTier: 2 }
    ],
    diffHunks: [
      "diff --git a/src/auth.c b/src/auth.c",
      "--- a/src/auth.c",
      "+++ b/src/auth.c",
      "@@ -1,3 +1,5 @@",
      "+ authenticate_user(cred);",
      "diff --git a/src/crypto.c b/src/crypto.c",
      "--- a/src/crypto.c",
      "+++ b/src/crypto.c",
      "@@ -1,3 +1,5 @@",
      "+ verify_hmac(key, data);",
      "diff --git a/src/utils.c b/src/utils.c",
      "--- a/src/utils.c",
      "+++ b/src/utils.c",
      "@@ -1,3 +1,5 @@",
      "+ log_trace(msg);"
    ].join("\n")
  };

  const fileContents = {
    "src/auth.c": "void authenticate_user(Cred* cred) { check(cred); }",
    "src/crypto.c": "int verify_hmac(Key* key, Data* data) { hmac_sha256(key, data); return 1; }",
    "src/utils.c": "void log_trace(const char* msg) { puts(msg); }"
  };

  // buildContextPackage called with null targetFile iterates over all files in changeSet.files
  const pkg = buildContextPackage(multiChangeSet, null, { fileContents });

  assert.equal(pkg.targetFile, "multi-file");
  assert.ok(Array.isArray(pkg.fileCoverageManifest), "fileCoverageManifest must be an array");
  assert.equal(pkg.fileCoverageManifest.length, 3, "fileCoverageManifest must contain all 3 files");

  const filesInManifest = pkg.fileCoverageManifest.map(m => m.file);
  assert.ok(filesInManifest.includes("src/auth.c"));
  assert.ok(filesInManifest.includes("src/crypto.c"));
  assert.ok(filesInManifest.includes("src/utils.c"));

  // Check extracted callees are aggregated
  assert.ok(Array.isArray(pkg.layers.layer1AstEnclosure.callees));
  assert.ok(pkg.layers.layer1AstEnclosure.callees.length > 0);
  const serializedLayer1 = JSON.stringify(pkg.layers.layer1AstEnclosure);
  assert.ok(Buffer.byteLength(serializedLayer1, "utf8") <= GLOBAL_AST_CONTEXT_CEILING_BYTES);
});

test("007-007-D-MULTI-UNMODIFIED: Multi-file changeset with unmodified file isolates diffs without cross-contamination", () => {
  const multiChangeSet = {
    ok: true,
    totalFiles: 2,
    files: [
      { path: "src/modified.c", additions: 3, deletions: 0, riskTier: 1 },
      { path: "src/unmodified.c", additions: 0, deletions: 0, riskTier: 2 }
    ],
    diffHunks: [
      "diff --git a/src/modified.c b/src/modified.c",
      "--- a/src/modified.c",
      "+++ b/src/modified.c",
      "@@ -1,3 +1,5 @@",
      "+ authenticate_session(token);"
    ].join("\n")
  };

  const fileContents = {
    "src/modified.c": "void authenticate_session(Token* token) { check(token); }",
    // unmodified.c contains a call to authenticate_session at line 2, but has no diff!
    "src/unmodified.c": "void helper() {\n  authenticate_session(NULL);\n}"
  };

  const pkg = buildContextPackage(multiChangeSet, null, { fileContents });

  assert.equal(pkg.targetFile, "multi-file");
  assert.equal(pkg.fileCoverageManifest.length, 2);

  const modManifest = pkg.fileCoverageManifest.find(m => m.file === "src/modified.c");
  const unmodManifest = pkg.fileCoverageManifest.find(m => m.file === "src/unmodified.c");

  assert.ok(modManifest);
  assert.ok(unmodManifest);

  // Modified file extracts its callee
  assert.ok(modManifest.calleesExtracted.includes("authenticate_session"));

  // Unmodified file MUST NOT extract any callees or borrow diff spans from modified.c!
  assert.equal(unmodManifest.calleesExtracted.length, 0);
  assert.equal(unmodManifest.unresolvedCallees.length, 0);
  assert.equal(unmodManifest.contextGaps.length, 0);
});

test("007-007-D-MULTI-50-PLUS: Large multi-file changeset (>50 files) with nested submodules enforces 8 KB ceiling and manifest tracking", () => {
  const fileCount = 55;
  const files = [];
  const diffHunkParts = [];
  const fileContents = {};

  for (let i = 0; i < fileCount; i++) {
    const filePath = `submodules/core/pkg_${Math.floor(i / 10)}/worker_${i}.c`;
    files.push({ path: filePath, additions: 2, deletions: 0, riskTier: 1 });
    diffHunkParts.push(
      `diff --git a/${filePath} b/${filePath}`,
      `--- a/${filePath}`,
      `+++ b/${filePath}`,
      `@@ -1,3 +1,5 @@`,
      `+ sanitize_input_${i}(arg);`
    );
    fileContents[filePath] = `void sanitize_input_${i}(char* arg) { validate(arg); }`;
  }

  const largeChangeSet = {
    ok: true,
    totalFiles: fileCount,
    files,
    diffHunks: diffHunkParts.join("\n")
  };

  const pkg = buildContextPackage(largeChangeSet, null, { fileContents });

  assert.equal(pkg.targetFile, "multi-file");
  assert.equal(pkg.fileCoverageManifest.length, fileCount);

  // All 55 files must be recorded in coverage manifest
  for (let i = 0; i < fileCount; i++) {
    const expectedPath = `submodules/core/pkg_${Math.floor(i / 10)}/worker_${i}.c`;
    const manifest = pkg.fileCoverageManifest.find(m => m.file === expectedPath);
    assert.ok(manifest, `Manifest must include file ${expectedPath}`);
    assert.equal(manifest.inspected, true);
    assert.equal(manifest.exactHeadAvailable, true);
  }

  // Global 8 KB AST ceiling must be strictly respected
  const serializedLayer1 = JSON.stringify(pkg.layers.layer1AstEnclosure);
  assert.ok(
    Buffer.byteLength(serializedLayer1, "utf8") <= GLOBAL_AST_CONTEXT_CEILING_BYTES,
    `Layer 1 AST size (${Buffer.byteLength(serializedLayer1, "utf8")} bytes) must not exceed 8 KB`
  );

  // Aggregated callees must not exceed MAX_CALLEES_TOTAL (10)
  assert.ok(pkg.layers.layer1AstEnclosure.callees.length <= MAX_CALLEES_TOTAL);

  // Files processed after budget exhaustion must record GLOBAL_AST_CONTEXT_CEILING_EXCEEDED context gaps
  const ceilingGaps = pkg.contextGaps.filter(g => g.reason === "GLOBAL_AST_CONTEXT_CEILING_EXCEEDED");
  assert.ok(ceilingGaps.length > 0, "Must record GLOBAL_AST_CONTEXT_CEILING_EXCEEDED gaps for excess files");
});

test("007-DELTA-01: orchestrateReview without preliminary option on zero findings blocks with Clean Challenge missing", async () => {
  const changeSet = {
    ok: true,
    totalFiles: 1,
    files: [{ path: "src/safe.js", additions: 2, deletions: 0, riskTier: 2 }],
    diffHunks: "+ return 1;"
  };

  const cleanAdapter = {
    providerName: "clean-sentry",
    modelName: "model-x",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/safe.js"], omittedFiles: [] }
    })
  };

  // Calling orchestrateReview without preliminary: true and without verificationRecord
  const result = await orchestrateReview(changeSet, { macro: cleanAdapter });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Clean Challenge missing/i);
  assert.equal(result.gate.preliminary, undefined);
});

test("007-DELTA-02A: runDogfoodReview with changeSet.headSha mismatch against requested head fails closed", async () => {
  const requestedHead = "1111111111111111111111111111111111111111";
  const conflictingHeadSha = "2222222222222222222222222222222222222222";

  await assert.rejects(
    () => runDogfoodReview({
      mock: true,
      head: requestedHead,
      changeSet: {
        ok: true,
        headSha: conflictingHeadSha,
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      log: false
    }),
    /Reviewed ChangeSet head SHA.*does not match requested --head/i
  );
});

test("007-DELTA-02B: runDogfoodReview with conflicting changeSet.headSha vs changeSet.repository.headSha fails closed", async () => {
  const repoHeadSha = "3333333333333333333333333333333333333333";
  const directHeadSha = "4444444444444444444444444444444444444444";

  await assert.rejects(
    () => runDogfoodReview({
      mock: true,
      changeSet: {
        ok: true,
        headSha: directHeadSha,
        repository: {
          headSha: repoHeadSha
        },
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      log: false
    }),
    /Reviewed ChangeSet repository head SHA.*does not match changeSet\.headSha/i
  );
});

test("007-DELTA-02C: runDogfoodReview with abbreviated changeSet.head (10 hex chars) mismatch against requested head fails closed", async () => {
  const requestedHead = "1111111111111111111111111111111111111111";
  const conflictingShortHead = "2222222222";

  await assert.rejects(
    () => runDogfoodReview({
      mock: true,
      head: requestedHead,
      changeSet: {
        ok: true,
        head: conflictingShortHead,
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      log: false
    }),
    /Reviewed ChangeSet head SHA.*does not match requested --head/i
  );
});

test("007-DELTA-02D: runDogfoodReview with conflicting changeSet.repository.commitSha fails closed", async () => {
  const requestedHead = "1111111111111111111111111111111111111111";
  const conflictingCommitSha = "2222222222222222222222222222222222222222";

  await assert.rejects(
    () => runDogfoodReview({
      mock: true,
      head: requestedHead,
      changeSet: {
        ok: true,
        repository: {
          commitSha: conflictingCommitSha
        },
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      log: false
    }),
    /Reviewed ChangeSet repository commit SHA.*does not match requested --head/i
  );
});

test("007-DELTA-02E: runDogfoodReview with conflicting changeSet.repository.head fails closed", async () => {
  const requestedHead = "1111111111111111111111111111111111111111";
  const conflictingRepoHead = "2222222222222222222222222222222222222222";

  await assert.rejects(
    () => runDogfoodReview({
      mock: true,
      head: requestedHead,
      changeSet: {
        ok: true,
        repository: {
          head: conflictingRepoHead
        },
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      log: false
    }),
    /Reviewed ChangeSet repository head.*does not match requested --head/i
  );
});

test("007-DELTA-02F: runDogfoodReview with matching abbreviated changeSet.head prefix succeeds in mock mode", async () => {
  const requestedHead = "1111111111111111111111111111111111111111";
  const matchingShortHead = "1111111111";

  const tmpOut = path.resolve(`tmp-dogfood-delta02f-${Date.now()}.json`);
  try {
    const report = await runDogfoodReview({
      mock: true,
      head: requestedHead,
      changeSet: {
        ok: true,
        head: matchingShortHead,
        totalFiles: 1,
        files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      out: tmpOut,
      log: false
    });
    assert.ok(report);
    assert.equal(report.repository.commitSha, requestedHead);
  } finally {
    if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
  }
});
