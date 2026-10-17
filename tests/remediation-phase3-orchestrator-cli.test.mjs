/**
 * Phase 3 Remediation Acceptance Test Suite (PR #39)
 *
 * Implements authoritative negative regression contracts PHASE3-NEG-01 through PHASE3-NEG-05
 * and positive control contract PHASE3-POS-01 as specified in PR #39 remediation dispatch.
 *
 * Test Matrix:
 *   PHASE3-NEG-01: Loose/trimmed diff digest mismatch fails closed in buildCanonicalRunContext and blocks Gate
 *   PHASE3-NEG-02: Conflicting patchObjective across caller options, nested objectiveContract, and ChangeSet fails closed with runContextMismatched / Gate BLOCK
 *   PHASE3-NEG-03: Stale verification record from prior run (mismatched runId) or record missing runId is rejected as replay and blocks Gate
 *   PHASE3-NEG-04: Falsified tier: 0, tier: null, or negative tier fails closed and cannot downgrade Tier 1 risk scale or evade dual sentry / omission blocks
 *   PHASE3-NEG-05: triad-flow review --verify-with with 0 findings invokes Clean Challenge; missing verifier or blocked Clean Challenge fails closed with exit code 1; invalid verifier flag fails with exit code 2
 *   PHASE3-POS-01: Authentic matching RunContext, valid tier, and successful Clean Challenge verification evaluate to reviewed-clean (exit code 0)
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import * as reviewOrchestrator from "../src/adapters/review-orchestrator.mjs";
const { orchestrateReview, buildCanonicalRunContext } = reviewOrchestrator;

import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { REVIEW_RUN_STATUS } from "../src/core/review-run-report.mjs";
import { RunContext } from "../src/core/harness.mjs";
import { normalizeLineEndings } from "../src/core/canonical-digest.mjs";
import {
  conductIndependentVerification,
  createMockVerifierAdapter
} from "../src/core/independent-verifier.mjs";

// ============================================================================
// Fixtures & Test Helpers
// ============================================================================

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function createTestChangeSet(overrides = {}) {
  const diffHunks = overrides.diffHunks !== undefined
    ? overrides.diffHunks
    : "diff --git a/src/auth/token.mjs b/src/auth/token.mjs\n--- a/src/auth/token.mjs\n+++ b/src/auth/token.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;\n";
  const normDiff = normalizeLineEndings(diffHunks);
  const contentDigest = overrides.contentDigest !== undefined
    ? overrides.contentDigest
    : crypto.createHash("sha256").update(normDiff, "utf8").digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    headSha: "a".repeat(40),
    contentDigest,
    totalFiles: 1,
    totalAdditions: 15,
    totalDeletions: 2,
    files: [
      { path: "src/auth/token.mjs", additions: 15, deletions: 2, riskTier: 1 }
    ],
    diffHunks,
    patchObjective: "Harden authentication token verification",
    ...overrides
  };
}

function createCleanReviewAdapter(role = "macro") {
  const provider = role === "macro" ? "claude" : "agy";
  const family = role === "macro" ? "anthropic" : "google";
  return {
    providerName: provider,
    family,
    modelName: `${provider}-default`,
    executeReview: async ({ runId, changeSet }) => ({
      ok: true,
      status: "success",
      findings: [],
      providerIdentity: {
        provider,
        family,
        model: `${provider}-default`,
        transport: "cli"
      },
      coverage: {
        coveredFiles: (changeSet.files || []).map(f => f.path),
        omittedFiles: []
      }
    })
  };
}

async function runCliHelper(args, options = {}) {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const exitCode = await runCli(args, { stdout, stderr }, options);
  return { exitCode, stdout: stdout.buffer, stderr: stderr.buffer };
}

// ============================================================================
// PHASE3-NEG-01: Loose/Trimmed Diff Digest Strict Binding
// ============================================================================

test("PHASE3-NEG-01-01: buildCanonicalRunContext rejects verification record with loose/trimmed diff digest", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const diffWithTrailingSpaces = "diff --git a/src/auth/token.mjs b/src/auth/token.mjs\n--- a/src/auth/token.mjs\n+++ b/src/auth/token.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;   \n";
  const changeSet = createTestChangeSet({ diffHunks: diffWithTrailingSpaces });
  const trimmedDigest = crypto.createHash("sha256").update(diffWithTrailingSpaces.trim(), "utf8").digest("hex");
  const vr = {
    runId: "run-001",
    headSha: changeSet.headSha,
    contentDigest: trimmedDigest,
    overallStatus: "CLEAN",
    verificationMode: "clean_challenge"
  };
  const rc = buildCanonicalRunContext(changeSet, { verificationRecord: vr }, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null when verification record has loose/trimmed digest");
});

test("PHASE3-NEG-01-02: orchestrateReview blocks gate when verification record diff digest is trimmed", async () => {
  const diffWithTrailingSpaces = "diff --git a/src/auth/token.mjs b/src/auth/token.mjs\n--- a/src/auth/token.mjs\n+++ b/src/auth/token.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;   \n";
  const changeSet = createTestChangeSet({ diffHunks: diffWithTrailingSpaces });
  const trimmedDigest = crypto.createHash("sha256").update(diffWithTrailingSpaces.trim(), "utf8").digest("hex");
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const trimmedChangeSet = { ...changeSet, diffHunks: diffWithTrailingSpaces.trim(), contentDigest: trimmedDigest };
  const trustedVr = await conductIndependentVerification(trimmedChangeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "run-001",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: "run-001",
    verificationRecord: trustedVr
  });
  assert.equal(res.gate.decision, "block", "Gate must block when verification record diff digest is trimmed");
  assert.equal(res.status, "incomplete", "Status must be incomplete on trimmed diff digest mismatch");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i, "Gate reason must identify binding mismatch");
});

test("PHASE3-NEG-01-03: changeSet declared contentDigest with trimmed diff digest fails closed", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const diffWithTrailingSpaces = "diff --git a/src/auth/token.mjs b/src/auth/token.mjs\n--- a/src/auth/token.mjs\n+++ b/src/auth/token.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;   \n";
  const trimmedDigest = crypto.createHash("sha256").update(diffWithTrailingSpaces.trim(), "utf8").digest("hex");
  const csTampered = createTestChangeSet({
    diffHunks: diffWithTrailingSpaces,
    contentDigest: trimmedDigest
  });
  const rc = buildCanonicalRunContext(csTampered, {}, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null when changeSet declared contentDigest matches trimmed digest");
});

// ============================================================================
// PHASE3-NEG-02: Deterministic Objective Conflict Fail-Closed
// ============================================================================

test("PHASE3-NEG-02-01: Conflicting options.patchObjective vs changeSet.patchObjective fails closed", async () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const changeSet = createTestChangeSet({ patchObjective: "Add dark mode toggle" });
  const rc = buildCanonicalRunContext(changeSet, { patchObjective: "Sanitize SQL injection in user controller" }, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null on conflicting patchObjective across options and changeSet");

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const vr = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "run-001",
    headSha: changeSet.headSha,
    patchObjective: "Add dark mode toggle"
  });
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: "run-001",
    patchObjective: "Sanitize SQL injection in user controller",
    verificationRecord: vr
  });
  assert.equal(res.gate.decision, "block");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("PHASE3-NEG-02-02: Conflicting options.patchObjective vs options.objectiveContract.objective fails closed", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const changeSet = createTestChangeSet();
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "Fix CVE-2026-1001",
    objectiveContract: { objective: "Update documentation links" }
  }, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null when options.patchObjective conflicts with options.objectiveContract");
});

test("PHASE3-NEG-02-03: Conflicting options.runContext.patchObjective vs options.patchObjective fails closed", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const changeSet = createTestChangeSet();
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "Benign doc fix",
    runContext: { patchObjective: "Harden token authorization" }
  }, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null when options.runContext conflicts with options.patchObjective");
});

test("PHASE3-NEG-02-04: Conflicting changeSet.patchObjective vs changeSet.objectiveContract.objective fails closed", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const csConflicting = createTestChangeSet({
    patchObjective: "Sanitize inputs",
    objectiveContract: { objective: "Optimize cache TTL" }
  });
  const rc = buildCanonicalRunContext(csConflicting, {}, "run-001");
  assert.equal(rc, null, "buildCanonicalRunContext must return null when changeSet has conflicting internal objectives");
});

test("PHASE3-NEG-02-05: Non-conflicting objectives with differing surrounding whitespace and casing normalize identically and pass", () => {
  assert.equal(typeof buildCanonicalRunContext, "function", "buildCanonicalRunContext must be exported from review-orchestrator.mjs");
  const cs = createTestChangeSet({ patchObjective: "Harden authentication token verification" });
  const rc = buildCanonicalRunContext(cs, {
    patchObjective: "  harden authentication token verification  "
  }, "run-001");
  assert.ok(rc !== null, "Matching objectives after normalizeObjective must not fail closed");
  assert.equal(rc.patchObjective, "harden authentication token verification");
});

// ============================================================================
// PHASE3-NEG-03: Active Run ID Sovereign Binding & Replay Blocking
// ============================================================================

test("PHASE3-NEG-03-01: Stale verification record with prior runId differing from active options.runId is blocked as replay", async () => {
  const changeSet = createTestChangeSet();
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const staleRecord = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "stale-run-uuid-001",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: "active-run-uuid-002",
    verificationRecord: staleRecord
  });
  assert.equal(res.gate.decision, "block", "Replay of stale verification record must be blocked");
  assert.equal(res.status, "incomplete", "Status must be incomplete when verification record runId mismatches");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("PHASE3-NEG-03-02: Stale verification record with auto-minted active runId is blocked as replay", async () => {
  const changeSet = createTestChangeSet();
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const staleRecord = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "stale-run-uuid-001",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  // Caller does NOT supply options.runId; orchestrateReview generates a fresh UUID.
  const res = await orchestrateReview(changeSet, adapters, {
    verificationRecord: staleRecord
  });
  assert.equal(res.gate.decision, "block", "Stale verification record must not hijack auto-minted active runId");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("PHASE3-NEG-03-03: Verification record missing runId (null/omitted) fails closed and blocks Gate", async () => {
  const changeSet = createTestChangeSet();
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  // conductIndependentVerification without runId mints an authentic record lacking runId
  const recordWithoutRunId = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  assert.equal(recordWithoutRunId.runId, undefined, "Minted record must lack runId");
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: "active-run-uuid-003",
    verificationRecord: recordWithoutRunId
  });
  assert.equal(res.gate.decision, "block", "Verification record missing runId must fail closed");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("PHASE3-NEG-03-04: Caller options.runContext with mismatched runId fails closed and blocks Gate", async () => {
  const changeSet = createTestChangeSet();
  const mismatchedRunContext = new RunContext({
    runId: "foreign-run-uuid-999",
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: changeSet.patchObjective
  });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const validVr = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "active-run-uuid-004",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: "active-run-uuid-004",
    runContext: mismatchedRunContext,
    verificationRecord: validVr
  });
  assert.equal(res.gate.decision, "block", "Mismatched options.runContext.runId must fail closed");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("PHASE3-NEG-03-05: Verification record missing runId fails closed when caller omits options.runId", async () => {
  const changeSet = createTestChangeSet();
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  // conductIndependentVerification without runId mints an authentic record lacking runId
  const recordWithoutRunId = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  assert.equal(recordWithoutRunId.runId, undefined, "Minted record must lack runId");

  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  // Standard invocation path: caller does NOT supply options.runId; orchestrator auto-mints runId.
  const res = await orchestrateReview(changeSet, adapters, {
    verificationRecord: recordWithoutRunId
  });
  assert.equal(res.gate.decision, "block", "Verification record missing runId without caller options.runId must fail closed");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

// ============================================================================
// PHASE3-NEG-04: Tier 0 / Null / Negative Downgrade Prevention
// ============================================================================

test("PHASE3-NEG-04-01: Explicit tier: null on Tier 1 changeSet fails closed with INVALID_OR_DOWNGRADED_TIER", async () => {
  const changeSet = createTestChangeSet(); // Tier 1 changeSet
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: null });
  assert.equal(res.gate.decision, "block", "Explicit tier: null must fail closed");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i, "Gate reason must specify INVALID_OR_DOWNGRADED_TIER");
});

test("PHASE3-NEG-04-02: Explicit tier: 0 fails closed with INVALID_OR_DOWNGRADED_TIER", async () => {
  const changeSet = createTestChangeSet();
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: 0 });
  assert.equal(res.gate.decision, "block", "Explicit tier: 0 must fail closed");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i, "Gate reason must specify INVALID_OR_DOWNGRADED_TIER");
});

test("PHASE3-NEG-04-03: Explicit negative tier (tier: -1) fails closed with INVALID_OR_DOWNGRADED_TIER", async () => {
  const changeSet = createTestChangeSet();
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: -1 });
  assert.equal(res.gate.decision, "block", "Explicit negative tier must fail closed");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i, "Gate reason must specify INVALID_OR_DOWNGRADED_TIER");
});

test("PHASE3-NEG-04-04: Explicit non-numeric/NaN tier fails closed with INVALID_OR_DOWNGRADED_TIER", async () => {
  const changeSet = createTestChangeSet();
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: "tier-zero" });
  assert.equal(res.gate.decision, "block", "Explicit non-numeric tier string must fail closed");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i, "Gate reason must specify INVALID_OR_DOWNGRADED_TIER");
});

test("PHASE3-NEG-04-05: Single sentry evasion attempt with tier: 0 on Tier 1 changeSet fails closed", async () => {
  const changeSet = createTestChangeSet(); // Tier 1 changeSet
  // Single adapter provided (attempting to trigger single sentry mode)
  const adapters = { macro: createCleanReviewAdapter("macro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: 0 });
  assert.equal(res.gate.decision, "block", "Single sentry evasion with tier: 0 must block");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
});

test("PHASE3-NEG-04-06: Explicit Symbol tier fails closed with INVALID_OR_DOWNGRADED_TIER and status incomplete without throwing", async () => {
  const changeSet = createTestChangeSet();
  const adapters = { macro: createCleanReviewAdapter("macro"), micro: createCleanReviewAdapter("micro") };
  const res = await orchestrateReview(changeSet, adapters, { tier: Symbol("1") });
  assert.equal(res.gate.decision, "block", "Explicit Symbol tier must fail closed");
  assert.equal(res.status, "incomplete", "Status must be incomplete on illegal Symbol tier");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i, "Gate reason must specify INVALID_OR_DOWNGRADED_TIER");
});

// ============================================================================
// PHASE3-NEG-05: CLI Review Clean Challenge Integration & Exit Code Integrity
// ============================================================================

test("PHASE3-NEG-05-01: Shell metacharacters/command injection in --verify-with fails with exit code 2 (USAGE_ERROR)", async () => {
  const changeSet = createTestChangeSet();
  const { exitCode, stderr } = await runCliHelper(["review", "--verify-with=claude;cat /etc/passwd"], {
    getChangeSet: () => changeSet
  });
  assert.equal(exitCode, EXIT_CODES.USAGE_ERROR, "Shell metacharacters in --verify-with must exit with code 2");
  assert.match(stderr, /\[USAGE ERROR\]/i, "Stderr must indicate usage error");
});

test("PHASE3-NEG-05-02: Unsupported provider in --verify-with fails with exit code 2 (USAGE_ERROR)", async () => {
  const changeSet = createTestChangeSet();
  const { exitCode, stderr } = await runCliHelper(["review", "--verify-with=unsupported-ai-bot"], {
    getChangeSet: () => changeSet
  });
  assert.equal(exitCode, EXIT_CODES.USAGE_ERROR, "Unsupported verifier provider must exit with code 2");
  assert.match(stderr, /\[USAGE ERROR\]/i, "Stderr must indicate usage error");
});

test("PHASE3-NEG-05-03: Review with 0 findings and missing --verify-with fails closed with exit code 1 (GATE_BLOCKED)", async () => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  const { exitCode, stderr } = await runCliHelper(["review"], {
    getChangeSet: () => changeSet,
    reviewAdapters
  });
  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED, "Review with 0 findings without verifier must exit with code 1");
  assert.match(stderr, /Gate Decision: BLOCK|Clean Challenge missing/i);
});

test("PHASE3-NEG-05-04: Clean Challenge verifier discovers blocking omission -> fails closed with exit code 1 (GATE_BLOCKED)", async () => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  let verifierInvoked = false;
  const mockOmissionVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      verifierInvoked = true;
      return {
        ok: true,
        overallStatus: "CONTESTED",
        evaluations: [],
        verifierOmissions: [
          {
            title: "Bypass authentication token validation",
            file: "src/auth/token.mjs",
            line_start: 1,
            line_end: 2,
            severity: "critical",
            evidenceSupport: "SUPPORTED",
            objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
            locatorAccurate: true,
            reasoning: "Passing empty token string bypasses check at line 2"
          }
        ]
      };
    }
  });

  const { exitCode, stderr } = await runCliHelper(["review", "--verify-with=claude"], {
    getChangeSet: () => changeSet,
    reviewAdapters,
    verifierAdapter: mockOmissionVerifier
  });
  assert.equal(verifierInvoked, true, "Clean Challenge verifier adapter must be invoked when consensus has 0 findings");
  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED, "Review with blocking omission discovered must exit with code 1");
  assert.match(stderr, /Gate Decision: BLOCK/i);
});

test("PHASE3-NEG-05-05: Clean Challenge verifier execution failure or timeout fails closed with exit code 1 (GATE_BLOCKED)", async () => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  let verifierInvoked = false;
  const mockFailingVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      verifierInvoked = true;
      return {
        ok: false,
        overallStatus: "UNCERTAIN",
        error: "Verifier connection timed out after 30000ms"
      };
    }
  });

  const { exitCode, stderr } = await runCliHelper(["review", "--verify-with=claude"], {
    getChangeSet: () => changeSet,
    reviewAdapters,
    verifierAdapter: mockFailingVerifier
  });
  assert.equal(verifierInvoked, true, "Verifier adapter must be invoked");
  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED, "Verifier timeout/failure must fail closed with exit code 1");
  assert.match(stderr, /Gate Decision: BLOCK/i);
});

// ============================================================================
// PHASE3-POS-01: End-to-End Positive Control Contract
// ============================================================================

test("PHASE3-POS-01-01: Orchestrator level: matching RunContext, valid tier, and CLEAN verification evaluate to reviewed-clean", async () => {
  const changeSet = createTestChangeSet();
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const activeRunId = "pos-orchestrator-run-001";
  const validCleanRecord = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: activeRunId,
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective
  });
  const adapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  const res = await orchestrateReview(changeSet, adapters, {
    runId: activeRunId,
    tier: 1,
    verificationRecord: validCleanRecord
  });
  assert.equal(res.gate.decision, "approve", "Gate must approve on authentic clean challenge");
  assert.equal(res.status, "reviewed-clean", "Status must be reviewed-clean");
  assert.match(res.gate.reason, /Clean Challenge passed/i);
});

test("PHASE3-POS-01-02: CLI level text format: --verify-with=claude with clean consensus evaluates to reviewed-clean (exit code 0)", async () => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  let verifierInvoked = false;
  const mockCleanVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      verifierInvoked = true;
      return {
        ok: true,
        fileCoverageComplete: true,
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  });

  const { exitCode, stderr } = await runCliHelper(["review", "--verify-with=claude"], {
    getChangeSet: () => changeSet,
    reviewAdapters,
    verifierAdapter: mockCleanVerifier
  });
  assert.equal(verifierInvoked, true, "Clean Challenge verifier adapter must be invoked");
  assert.equal(exitCode, EXIT_CODES.SUCCESS, "Clean review with verified Clean Challenge must exit with code 0");
  assert.match(stderr, /Gate Decision: APPROVE/i);
  assert.match(stderr, /reviewed-clean/i);
});

test("PHASE3-POS-01-03: CLI level json format: --verify-with=claude --format=json outputs approved report with exit code 0", async () => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  const mockCleanVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const { exitCode, stdout, stderr } = await runCliHelper(["review", "--verify-with=claude", "--format=json"], {
    getChangeSet: () => changeSet,
    reviewAdapters,
    verifierAdapter: mockCleanVerifier
  });
  assert.equal(exitCode, EXIT_CODES.SUCCESS, "CLI JSON review must exit with code 0");
  assert.ok(stdout.length > 0, "Stdout must contain JSON report");
  const report = JSON.parse(stdout);
  assert.equal(report.exitCode, EXIT_CODES.SUCCESS);
  assert.equal(report.status, REVIEW_RUN_STATUS.REVIEWED_CLEAN);
  assert.equal(report.gate.decision, "approve");
});
