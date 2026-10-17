/**
 * Adversarial Stress-Test Suite for PR #39 Phase 3 Remediation (R1, R2, R3)
 * Agent: challenger_9_1
 * Role: EMPIRICAL CHALLENGER
 *
 * Probes:
 * 1. Diff digest binding (R1): Trailing spaces, tabs, trailing newlines, CRLF, Buffer, tampered declared digests.
 * 2. Deterministic objective conflict (R2): Case variations, partial overlaps, empty/whitespace strings, nested contract matrix.
 * 3. Sovereign run ID & anti-replay (R3): Prior run replays, missing/null/empty runIds, auto-minted runId binding, caller option overrides.
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  orchestrateReview,
  buildCanonicalRunContext
} from "../src/adapters/review-orchestrator.mjs";
import { RunContext, normalizeDigest, normalizeObjective } from "../src/core/harness.mjs";
import { normalizeLineEndings } from "../src/core/canonical-digest.mjs";
import {
  conductIndependentVerification,
  createMockVerifierAdapter
} from "../src/core/independent-verifier.mjs";

// ============================================================================
// Fixtures & Helpers
// ============================================================================

function createAdversarialChangeSet(overrides = {}) {
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

function createCleanAdapter(role = "macro") {
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

function getDualAdapters() {
  return {
    macro: createCleanAdapter("macro"),
    micro: createCleanAdapter("micro")
  };
}

async function createCleanVerificationRecord(changeSet, options = {}) {
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  return conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: changeSet.headSha,
    patchObjective: changeSet.patchObjective,
    ...options
  });
}

// ============================================================================
// Group 1: Diff Digest Binding (R1)
// ============================================================================

test("ADV-R1-01: Diff with trailing spaces cannot match trimmed diff digest", async () => {
  const diffWithSpaces = "diff --git a/a.mjs b/a.mjs\n--- a/a.mjs\n+++ b/a.mjs\n@@ -1,1 +1,2 @@\n+const x = 1;    \n";
  const changeSet = createAdversarialChangeSet({ diffHunks: diffWithSpaces });
  const trimmedDigest = crypto.createHash("sha256").update(diffWithSpaces.trim(), "utf8").digest("hex");

  const vr = await createCleanVerificationRecord(changeSet, { runId: "r1-01" });
  // Tamper vr to use trimmed digest
  const tamperedVr = { ...vr, changeSetDigest: trimmedDigest, contentDigest: trimmedDigest };

  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-01", verificationRecord: tamperedVr });
  assert.equal(rc, null, "Trimmed diff digest must be rejected by buildCanonicalRunContext");

  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    runId: "r1-01",
    verificationRecord: tamperedVr
  });
  assert.equal(res.gate.decision, "block", "Gate must block on trimmed diff digest mismatch");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R1-02: Diff with trailing tabs cannot match stripped digest", async () => {
  const diffWithTabs = "diff --git a/a.mjs b/a.mjs\n--- a/a.mjs\n+++ b/a.mjs\n@@ -1,1 +1,2 @@\n+const x = 1;\t\t\n";
  const changeSet = createAdversarialChangeSet({ diffHunks: diffWithTabs });
  const strippedDiff = "diff --git a/a.mjs b/a.mjs\n--- a/a.mjs\n+++ b/a.mjs\n@@ -1,1 +1,2 @@\n+const x = 1;\n";
  const strippedDigest = crypto.createHash("sha256").update(strippedDiff, "utf8").digest("hex");

  const vr = await createCleanVerificationRecord(changeSet, { runId: "r1-02" });
  const tamperedVr = { ...vr, changeSetDigest: strippedDigest, contentDigest: strippedDigest };

  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-02", verificationRecord: tamperedVr });
  assert.equal(rc, null, "Stripped tab diff digest must be rejected");
});

test("ADV-R1-03: Diff with extra trailing newlines cannot match trimmed newlines digest", async () => {
  const baseDiff = "diff --git a/a.mjs b/a.mjs\n--- a/a.mjs\n+++ b/a.mjs\n@@ -1,1 +1,2 @@\n+const x = 1;\n";
  const diffWithExtraNL = baseDiff + "\n\n\n";
  const changeSet = createAdversarialChangeSet({ diffHunks: diffWithExtraNL });
  const baseDigest = crypto.createHash("sha256").update(baseDiff, "utf8").digest("hex");

  const vr = await createCleanVerificationRecord(changeSet, { runId: "r1-03" });
  const tamperedVr = { ...vr, changeSetDigest: baseDigest, contentDigest: baseDigest };

  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-03", verificationRecord: tamperedVr });
  assert.equal(rc, null, "Extra trailing newlines diff digest must not match base digest");
});

test("ADV-R1-04: CRLF line endings normalize identically to LF line endings and support rawDiffDigest", async () => {
  const diffCRLF = "diff --git a/a.mjs b/a.mjs\r\n--- a/a.mjs\r\n+++ b/a.mjs\r\n@@ -1,1 +1,2 @@\r\n+const x = 1;\r\n";
  const changeSetCRLF = createAdversarialChangeSet({ diffHunks: diffCRLF });

  const vr = await createCleanVerificationRecord(changeSetCRLF, { runId: "r1-04" });
  const rc = buildCanonicalRunContext(changeSetCRLF, { runId: "r1-04", verificationRecord: vr });
  assert.notEqual(rc, null, "CRLF diff must normalize to LF and match computed digest");
  assert.equal(rc.contentDigest, normalizeDigest(vr.changeSetDigest), "Normalized digest must bind to verification record digest");

  // Raw CRLF physical byte digest binding check (R1)
  const rawDigest = crypto.createHash("sha256").update(diffCRLF, "utf8").digest("hex");
  const vrRaw = { ...vr, changeSetDigest: rawDigest, contentDigest: rawDigest };
  const rcRaw = buildCanonicalRunContext(changeSetCRLF, { runId: "r1-04", verificationRecord: vrRaw });
  assert.notEqual(rcRaw, null, "Raw CRLF physical byte digest must be accepted without unexpected null fail-closed");
});

test("ADV-R1-05: Buffer diffHunks normalize and bind identically to string", async () => {
  const diffStr = "diff --git a/a.mjs b/a.mjs\n+const x = 1;\n";
  const diffBuf = Buffer.from(diffStr, "utf8");
  const changeSet = createAdversarialChangeSet({ diffHunks: diffBuf });

  const vr = await createCleanVerificationRecord(changeSet, { runId: "r1-05" });
  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-05", verificationRecord: vr });
  assert.notEqual(rc, null, "Buffer diffHunks must be supported in buildCanonicalRunContext");
  assert.equal(rc.contentDigest, normalizeDigest(vr.changeSetDigest));
});

test("ADV-R1-06: Tampered changeSet.contentDigest with trimmed digest fails closed", async () => {
  const rawDiff = "diff --git a/a.mjs b/a.mjs\n+const x = 1;\n\n";
  const trimmedDigest = crypto.createHash("sha256").update(rawDiff.trim(), "utf8").digest("hex");
  const changeSet = createAdversarialChangeSet({
    diffHunks: rawDiff,
    contentDigest: trimmedDigest
  });

  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-06" });
  assert.equal(rc, null, "Declared contentDigest matching only trimmed diff must fail closed");
});

test("ADV-R1-07: Tampered changeSet.changeSetDigest with trimmed digest fails closed", async () => {
  const rawDiff = "diff --git a/a.mjs b/a.mjs\n+const x = 1;\n\n";
  const trimmedDigest = crypto.createHash("sha256").update(rawDiff.trim(), "utf8").digest("hex");
  const changeSet = createAdversarialChangeSet({
    diffHunks: rawDiff,
    changeSetDigest: trimmedDigest
  });

  const rc = buildCanonicalRunContext(changeSet, { runId: "r1-07" });
  assert.equal(rc, null, "Declared changeSetDigest matching only trimmed diff must fail closed");
});

// ============================================================================
// Group 2: Deterministic Objective Conflict Fail-Closed (R2)
// ============================================================================

test("ADV-R2-01: Direct semantic conflict between options and changeSet objectives fails closed", () => {
  const changeSet = createAdversarialChangeSet({ patchObjective: "Fix authentication bypass" });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "Improve logging performance"
  });
  assert.equal(rc, null, "Semantic objective conflict must fail closed");
});

test("ADV-R2-02: Substring objective conflict fails closed", () => {
  const changeSet = createAdversarialChangeSet({ patchObjective: "Harden token" });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "Harden token verification"
  });
  assert.equal(rc, null, "Substring objective mismatch must fail closed");
});

test("ADV-R2-03: Case variations and surrounding/inner whitespace normalize identically", () => {
  const changeSet = createAdversarialChangeSet({
    patchObjective: "  HARDEN   TOKEN   VERIFICATION  \n"
  });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "harden token verification",
    objectiveContract: { objective: "Harden   Token Verification\t" }
  });
  assert.notEqual(rc, null, "Identical normalized objectives across casing and whitespace must pass");
  assert.equal(rc.patchObjective.toLowerCase(), "harden token verification");
});

test("ADV-R2-04: Cross-source objective matrix conflict permutations", () => {
  const cs = createAdversarialChangeSet();

  // options.objectiveContract vs changeSet.objectiveContract
  assert.equal(buildCanonicalRunContext(cs, {
    objectiveContract: { objective: "Objective Alpha" },
    runContext: null
  }, null), null, "changeSet.patchObjective vs options.objectiveContract conflict must fail closed");

  // options.runContext.patchObjective vs changeSet.patchObjective
  assert.equal(buildCanonicalRunContext(cs, {
    runContext: { patchObjective: "Different Objective" }
  }), null, "options.runContext.patchObjective vs changeSet.patchObjective must fail closed");

  // options.runContext.objectiveContract vs options.patchObjective
  assert.equal(buildCanonicalRunContext(cs, {
    patchObjective: cs.patchObjective,
    runContext: { objectiveContract: { objective: "Different Nested" } }
  }), null, "options.runContext.objectiveContract vs options.patchObjective must fail closed");

  // changeSet.objectiveContract vs options.patchObjective
  const csWithContract = createAdversarialChangeSet({
    patchObjective: "Same Objective",
    objectiveContract: { objective: "Conflicting Nested In ChangeSet" }
  });
  assert.equal(buildCanonicalRunContext(csWithContract, {
    patchObjective: "Same Objective"
  }), null, "changeSet.objectiveContract vs patchObjective must fail closed");
});

test("ADV-R2-05: Empty string in one objective source does not conflict with non-empty", () => {
  const changeSet = createAdversarialChangeSet({ patchObjective: "Valid Objective" });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "",
    objectiveContract: { objective: "   " }
  });
  assert.notEqual(rc, null, "Empty and whitespace-only objectives must not conflict with valid objective");
  assert.equal(rc.patchObjective, "Valid Objective");
});

test("ADV-R2-06: All 6 sources present and identical normalize and pass", () => {
  const obj = "Secure Token Protocol";
  const changeSet = createAdversarialChangeSet({
    patchObjective: obj,
    objectiveContract: { objective: "  secure   token protocol  " }
  });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: "SECURE TOKEN PROTOCOL",
    objectiveContract: { objective: "Secure Token Protocol" },
    runContext: {
      patchObjective: "secure token protocol",
      objectiveContract: { objective: "Secure Token Protocol\n" }
    }
  });
  assert.notEqual(rc, null, "All 6 matching sources must pass");
  assert.equal(rc.patchObjective.toLowerCase(), "secure token protocol");
});

test("ADV-R2-07: 5 sources matching and 1 conflicting fails closed", () => {
  const obj = "Secure Token Protocol";
  const changeSet = createAdversarialChangeSet({
    patchObjective: obj,
    objectiveContract: { objective: obj }
  });
  const rc = buildCanonicalRunContext(changeSet, {
    patchObjective: obj,
    objectiveContract: { objective: obj },
    runContext: {
      patchObjective: obj,
      objectiveContract: { objective: "ROGUE CONFLICTING OBJECTIVE" }
    }
  });
  assert.equal(rc, null, "Single dissenting source among 6 must fail closed");
});

test("ADV-R2-08: Malformed objectiveContract values handled without uncaught throw", () => {
  const changeSet = createAdversarialChangeSet();
  assert.doesNotThrow(() => {
    buildCanonicalRunContext(changeSet, {
      objectiveContract: 12345,
      patchObjective: changeSet.patchObjective
    });
  });
  assert.doesNotThrow(() => {
    buildCanonicalRunContext(changeSet, {
      objectiveContract: { objective: null },
      patchObjective: changeSet.patchObjective
    });
  });
});

// ============================================================================
// Group 3: Sovereign Run ID & Anti-Replay (R3)
// ============================================================================

test("ADV-R3-01: Replay of record from prior run against explicit caller runId fails closed", async () => {
  const changeSet = createAdversarialChangeSet();
  const priorVr = await createCleanVerificationRecord(changeSet, { runId: "run-2026-prior-001" });

  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    runId: "run-2026-active-002",
    verificationRecord: priorVr
  });
  assert.equal(res.gate.decision, "block", "Replay against explicit caller runId must be blocked");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R3-02: Replay of record from prior run against auto-minted runId fails closed", async () => {
  const changeSet = createAdversarialChangeSet();
  const priorVr = await createCleanVerificationRecord(changeSet, { runId: "run-2026-prior-002" });

  // Caller supplies NO runId
  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    verificationRecord: priorVr
  });
  assert.equal(res.gate.decision, "block", "Replay against auto-minted runId must be blocked");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R3-03: Verification record missing runId against explicit caller runId fails closed", async () => {
  const changeSet = createAdversarialChangeSet();
  const vrWithoutRunId = await createCleanVerificationRecord(changeSet);
  assert.equal(vrWithoutRunId.runId, undefined);

  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    runId: "run-2026-active-003",
    verificationRecord: vrWithoutRunId
  });
  assert.equal(res.gate.decision, "block", "Record missing runId against caller runId must block");
  assert.equal(res.status, "incomplete");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R3-04-EMPIRICAL-PROBE: Verification record missing runId against auto-minted runId", async () => {
  const changeSet = createAdversarialChangeSet();
  const vrWithoutRunId = await createCleanVerificationRecord(changeSet);
  assert.equal(vrWithoutRunId.runId, undefined, "Record must lack runId");

  const rc = buildCanonicalRunContext(changeSet, { verificationRecord: vrWithoutRunId }, "minted-active-uuid");
  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    verificationRecord: vrWithoutRunId
  });

  // Empirical observation of the vulnerability:
  // Under R3, a verification record supplied without a valid runId MUST fail closed (BLOCK).
  // Here, res.gate.decision is 'approve' and res.status is 'reviewed-clean' because boundRunId is coerced to null.
  assert.equal(res.gate.decision, "block", "Record missing runId against auto-minted runId must fail closed");
  assert.equal(res.status, "incomplete", "Status must be incomplete when record lacks runId");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R3-05: Mismatched caller options.runContext.runId fails closed", async () => {
  const changeSet = createAdversarialChangeSet();
  const vr = await createCleanVerificationRecord(changeSet, { runId: "active-run-005" });
  const foreignRc = new RunContext({
    runId: "foreign-detached-run-id",
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: changeSet.patchObjective
  });

  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    runId: "active-run-005",
    runContext: foreignRc,
    verificationRecord: vr
  });
  assert.equal(res.gate.decision, "block", "Mismatched options.runContext.runId must fail closed");
  assert.match(res.gate.reason, /FORGED_OR_STALE_RECORD/i);
});

test("ADV-R3-06: Legitimate matching runId across all options passes cleanly (Positive Control)", async () => {
  const changeSet = createAdversarialChangeSet();
  const runId = "legitimate-active-run-006";
  const vr = await createCleanVerificationRecord(changeSet, { runId });
  const rc = new RunContext({
    runId,
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: changeSet.patchObjective
  });

  const res = await orchestrateReview(changeSet, getDualAdapters(), {
    runId,
    runContext: rc,
    verificationRecord: vr
  });
  assert.equal(res.gate.decision, "approve", "Valid matching RunContext and verification record must approve");
  assert.equal(res.status, "reviewed-clean");
});
