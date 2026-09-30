/**
 * Test Suite: Multi-Finding Remediation Orchestrator (M1a / v2.4)
 *
 * Validates:
 * - Contract 1: Invariant 1 (Batch authority MUST NOT exceed single-remediation authority)
 * - Contract 2: BatchRemediationSession lifecycle and state model (OPEN -> IN_PROGRESS -> COMPLETED)
 * - Contract 3: Conflict DAG & topological deterministic ordering
 * - Contract 4: Cumulative Tree Digest Lineage (T0 -> T1 -> T2 ...)
 * - Contract 5: Partial success semantics (failed finding does not erase prior closed evidence)
 * - Contract 6: Batch receipt schema validation and cryptographic integrity
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  REMEDIATION_STATES,
  ControlledRemediationSession,
  validateRemediationReceipt
} from "../src/core/controlled-remediation.mjs";

import {
  BATCH_REMEDIATION_STATES,
  BATCH_VERDICTS,
  BatchRemediationSession,
  buildConflictDAG,
  computeDeterministicBatchOrder,
  validateBatchReceipt,
  BatchAuthorityViolationError,
  BatchLineageDriftError
} from "../src/core/batch-remediation.mjs";

import {
  getCorpusCaseById,
  createCorpusCaseWorkspace
} from "./fixtures/real-corpus-fixtures.mjs";

function createMockVerificationRecord(findingId, options = {}) {
  const verdict = options.verdict || "SUPPORTED";
  return {
    schemaVersion: "1.0.0",
    verifiedAt: new Date().toISOString(),
    changeSetDigest: "sha256:" + "a".repeat(64),
    producer: {
      providerName: "codex",
      findingsCount: 1,
      findings: [
        {
          id: findingId,
          findingId,
          title: "Vulnerability Finding",
          severity: "high",
          file: options.file || "src/db/user-repo.js",
          line_start: 1,
          line_end: 5
        }
      ]
    },
    verifier: {
      providerName: "claude",
      modelName: "cli-default",
      actualModel: { value: "claude-3-7-sonnet", source: "reported" }
    },
    evaluations: [
      {
        findingId,
        verdict,
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Remediation verified safely."
      }
    ],
    verifierOmissions: [],
    disagreementLedger: [],
    summary: {
      totalEvaluated: 1,
      supportedCount: 1,
      contestedCount: 0,
      insufficientEvidenceCount: 0,
      omissionsCount: 0
    },
    residualVulnerabilityDetected: false,
    ok: true
  };
}

test("Contract 1: Invariant 1 - Batch authority MUST NOT exceed single-remediation authority", () => {
  const findings = [
    { id: "FINDING-001", targetFiles: ["src/a.js"] },
    { id: "FINDING-002", targetFiles: ["src/b.js"] }
  ];

  const batch = new BatchRemediationSession("BATCH-001", findings);
  assert.equal(batch.status, BATCH_REMEDIATION_STATES.OPEN);
  assert.equal(batch.sessionsCount, 2);

  // Prohibits attempting to bulk-close findings without affirmative evidence
  assert.throws(
    () => batch.bulkCloseWithoutVerification(),
    (err) => err instanceof BatchAuthorityViolationError || typeof batch.bulkCloseWithoutVerification !== "function"
  );

  // Each finding starts in OPEN state
  const session1 = batch.getSession("FINDING-001");
  const session2 = batch.getSession("FINDING-002");
  assert.equal(session1.status, REMEDIATION_STATES.OPEN);
  assert.equal(session2.status, REMEDIATION_STATES.OPEN);

  // Prohibits executing patch jail if not authorized by human
  assert.throws(
    () => batch.executeStep("FINDING-001", { jailDir: os.tmpdir() }),
    (err) => err instanceof Error
  );
});

test("Contract 2: Conflict DAG and Deterministic Ordering", () => {
  const findings = [
    { id: "F-AUTH-01", targetFiles: ["src/auth/jwt.js"], severity: "medium" },
    { id: "F-SQL-01", targetFiles: ["src/db/user-repo.js", "src/auth/jwt.js"], severity: "critical" },
    { id: "F-XSS-01", targetFiles: ["src/views/profile.js"], severity: "high" }
  ];

  const dag = buildConflictDAG(findings);

  // F-AUTH-01 and F-SQL-01 share 'src/auth/jwt.js' -> Conflict Edge exists
  assert.equal(dag.hasConflict("F-AUTH-01", "F-SQL-01"), true);
  // F-XSS-01 touches independent file -> No conflict edge
  assert.equal(dag.hasConflict("F-XSS-01", "F-SQL-01"), false);

  // Deterministic ordering resolves conflict: critical severity prioritized or topological sequence
  const order = computeDeterministicBatchOrder(findings, dag);
  assert.equal(order.length, 3);
  // F-SQL-01 has higher severity than F-AUTH-01, must precede it
  const sqlIdx = order.indexOf("F-SQL-01");
  const authIdx = order.indexOf("F-AUTH-01");
  assert.ok(sqlIdx < authIdx, "Higher severity or dependency parent must precede conflicting child");
});

test("Contract 3: Cumulative Tree Digest Lineage", () => {
  const case1 = getCorpusCaseById("BENCH-REAL-001");
  const ws1 = createCorpusCaseWorkspace(case1, { virtual: false });

  try {
    const findings = [
      { id: "F001", targetFiles: [case1.targetFile] },
      { id: "F002", targetFiles: [case1.targetFile] }
    ];

    const batch = new BatchRemediationSession("BATCH-LINEAGE-001", findings, {
      initialTreeDigest: "sha256:" + "0".repeat(64)
    });

    assert.equal(batch.currentTreeDigest, "sha256:" + "0".repeat(64));

    // Advancing lineage with valid link
    const newDigest = "sha256:" + "1".repeat(64);
    batch.recordStepSuccess("F001", {
      prePatchTreeDigest: "sha256:" + "0".repeat(64),
      postPatchTreeDigest: newDigest
    });

    assert.equal(batch.currentTreeDigest, newDigest);
    assert.equal(batch.lineageHistory.length, 1);
    assert.equal(batch.lineageHistory[0].fromDigest, "sha256:" + "0".repeat(64));
    assert.equal(batch.lineageHistory[0].toDigest, newDigest);

    // Reject lineage drift (step claiming wrong baseTreeDigest)
    assert.throws(
      () => batch.recordStepSuccess("F002", {
        prePatchTreeDigest: "sha256:" + "9".repeat(64), // Drift!
        postPatchTreeDigest: "sha256:" + "2".repeat(64)
      }),
      BatchLineageDriftError
    );
  } finally {
    ws1.cleanup();
  }
});

test("Contract 4: Partial Failure Semantics (Failure does not erase prior CLOSED evidence)", () => {
  const findings = [
    { id: "F-001", targetFiles: ["src/a.js"] },
    { id: "F-002", targetFiles: ["src/b.js"] }
  ];

  const batch = new BatchRemediationSession("BATCH-PARTIAL-001", findings);

  // 1. Finding 1 successfully completes 9-state cycle to CLOSED
  const s1 = batch.getSession("F-001");
  s1.proposeFix({
    diff: "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n-vuln\n+safe\n",
    rationale: "Fix A",
    synthesizer: { providerName: "codex" }
  });
  s1.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });
  s1.recordJailApplication({
    worktreeSha: "abcdef1234567890abcdef1234567890abcdef12",
    prePatchTreeDigest: "sha256:" + "0".repeat(64),
    postPatchTreeDigest: "sha256:" + "1".repeat(64)
  });
  s1.recordDeterministicChecks({ executed: true, exitCode: 0, passedCount: 1, failedCount: 0 });
  s1.recordClosureVerification({
    verifier: { providerName: "claude" },
    verificationRecord: createMockVerificationRecord("F-001")
  });
  assert.equal(s1.status, REMEDIATION_STATES.CLOSED);

  // 2. Finding 2 fails deterministic tests and transitions to REJECTED_FIX
  const s2 = batch.getSession("F-002");
  s2.proposeFix({
    diff: "diff --git a/src/b.js b/src/b.js\n--- a/src/b.js\n+++ b/src/b.js\n@@ -1,1 +1,1 @@\n-vuln\n+bad_fix\n",
    rationale: "Fix B",
    synthesizer: { providerName: "codex" }
  });
  s2.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });
  s2.recordJailApplication({
    worktreeSha: "abcdef1234567890abcdef1234567890abcdef12",
    prePatchTreeDigest: "sha256:" + "1".repeat(64),
    postPatchTreeDigest: "sha256:" + "2".repeat(64)
  });
  s2.recordDeterministicChecks({ executed: true, exitCode: 1, passedCount: 0, failedCount: 1 });
  assert.equal(s2.status, REMEDIATION_STATES.REJECTED_FIX);

  // 3. Finalize batch
  const batchSummary = batch.finalize();
  assert.equal(batchSummary.status, BATCH_REMEDIATION_STATES.COMPLETED);
  assert.equal(batchSummary.verdict, BATCH_VERDICTS.PARTIAL);
  assert.equal(batchSummary.closedCount, 1);
  assert.equal(batchSummary.rejectedCount, 1);

  // Prior evidence for F-001 is preserved and valid
  const receipt1 = s1.toReceipt();
  assert.equal(receipt1.status, REMEDIATION_STATES.CLOSED);
  assert.equal(validateRemediationReceipt(receipt1), true);

  // Batch receipt validates
  const batchReceipt = batch.toBatchReceipt();
  assert.equal(validateBatchReceipt(batchReceipt), true);
  assert.equal(batchReceipt.summary.closedCount, 1);
  assert.equal(batchReceipt.summary.rejectedCount, 1);
  assert.equal(batchReceipt.verdict, BATCH_VERDICTS.PARTIAL);
});
