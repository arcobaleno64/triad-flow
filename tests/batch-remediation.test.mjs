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
import { execFileSync } from "node:child_process";

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

test("Contract 5: Real Worktree Ephemeral Jail Sequential Execution and Lineage", () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-jail-repo-"));
  const gitExec = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
    cwd: tmpRepo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });

  try {
    gitExec(["init", "-q"]);
    fs.mkdirSync(path.join(tmpRepo, "src"), { recursive: true });
    fs.writeFileSync(path.join(tmpRepo, "src/sql.js"), "const query = 'SELECT * FROM users WHERE id = ' + id;\n", "utf8");
    fs.writeFileSync(path.join(tmpRepo, "src/auth.js"), "const secret = 'hardcoded_jwt_secret_123';\n", "utf8");
    gitExec(["add", "."]);
    gitExec(["-c", "user.name=test", "-c", "user.email=test@test.com", "commit", "-q", "-m", "initial"]);

    const headSha = gitExec(["rev-parse", "HEAD"]).trim();

    const patch1 = [
      "diff --git a/src/sql.js b/src/sql.js",
      "--- a/src/sql.js",
      "+++ b/src/sql.js",
      "@@ -1,1 +1,2 @@",
      "-const query = 'SELECT * FROM users WHERE id = ' + id;",
      "+const query = 'SELECT * FROM users WHERE id = ?';",
      "+return db.query(query, [id]);"
    ].join("\n") + "\n";

    const patch2 = [
      "diff --git a/src/auth.js b/src/auth.js",
      "--- a/src/auth.js",
      "+++ b/src/auth.js",
      "@@ -1,1 +1,2 @@",
      "-const secret = 'hardcoded_jwt_secret_123';",
      "+const secret = process.env.JWT_SECRET;",
      "+if (!secret) throw new Error('Missing secret');"
    ].join("\n") + "\n";

    const findings = [
      { id: "F-SQL-01", targetFiles: ["src/sql.js"], severity: "critical" },
      { id: "F-AUTH-01", targetFiles: ["src/auth.js"], severity: "high" }
    ];

    const batch = new BatchRemediationSession("BATCH-E2E-001", findings);

    // 1. Propose & Authorize both
    const s1 = batch.getSession("F-SQL-01");
    s1.proposeFix({ diff: patch1, rationale: "Parameterized SQL", synthesizer: { providerName: "codex" } });
    s1.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });

    const s2 = batch.getSession("F-AUTH-01");
    s2.proposeFix({ diff: patch2, rationale: "Env Secret", synthesizer: { providerName: "codex" } });
    s2.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });

    // 2. Execute Batch in Ephemeral Jail Worktree
    const batchTrial = batch.executeBatchInJailWorktree(tmpRepo, {
      baseSha: headSha,
      testRunnerFn: (jailDir, { findingId }) => {
        if (findingId === "F-SQL-01") {
          const sqlContent = fs.readFileSync(path.join(jailDir, "src/sql.js"), "utf8");
          assert.ok(sqlContent.includes("SELECT * FROM users WHERE id = ?"));
        } else if (findingId === "F-AUTH-01") {
          const authContent = fs.readFileSync(path.join(jailDir, "src/auth.js"), "utf8");
          assert.ok(authContent.includes("process.env.JWT_SECRET"));
          // Invariant: earlier patch F-SQL-01 must still be present in the worktree!
          const sqlContent = fs.readFileSync(path.join(jailDir, "src/sql.js"), "utf8");
          assert.ok(sqlContent.includes("SELECT * FROM users WHERE id = ?"));
        }
        return { exitCode: 0, passedCount: 1, failedCount: 0 };
      }
    });

    assert.equal(batchTrial.executionResults.length, 2);
    assert.equal(batch.lineageHistory.length, 2);
    assert.ok(batchTrial.aggregateDiff.includes("SELECT * FROM users WHERE id = ?"));
    assert.ok(batchTrial.aggregateDiff.includes("process.env.JWT_SECRET"));

    // 3. Record Independent Verification for both
    s1.recordClosureVerification({
      verifier: { providerName: "claude" },
      verificationRecord: createMockVerificationRecord("F-SQL-01", { file: "src/sql.js" })
    });
    s2.recordClosureVerification({
      verifier: { providerName: "claude" },
      verificationRecord: createMockVerificationRecord("F-AUTH-01", { file: "src/auth.js" })
    });

    // 4. Batch Receipt Schema 1.0.0
    const batchReceipt = batch.toBatchReceipt();
    assert.equal(batchReceipt.status, BATCH_REMEDIATION_STATES.COMPLETED);
    assert.equal(batchReceipt.verdict, BATCH_VERDICTS.ALL_CLOSED);
    assert.equal(batchReceipt.summary.closedCount, 2);
    assert.equal(validateBatchReceipt(batchReceipt), true);

    // 5. Assert authoritative repository was untouched!
    const origSql = fs.readFileSync(path.join(tmpRepo, "src/sql.js"), "utf8");
    assert.ok(origSql.includes("WHERE id = ' + id"));
  } finally {
    try {
      fs.rmSync(tmpRepo, { recursive: true, force: true });
    } catch {
      // Windows lock ignore
    }
  }
});

test("Contract 6: Ephemeral Jail Partial Failure and Rollback Invariant", () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-rollback-repo-"));
  const gitExec = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
    cwd: tmpRepo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });

  try {
    gitExec(["init", "-q"]);
    fs.mkdirSync(path.join(tmpRepo, "src"), { recursive: true });
    fs.writeFileSync(path.join(tmpRepo, "src/a.js"), "const a = 1;\n", "utf8");
    fs.writeFileSync(path.join(tmpRepo, "src/b.js"), "const b = 1;\n", "utf8");
    gitExec(["add", "."]);
    gitExec(["-c", "user.name=test", "-c", "user.email=test@test.com", "commit", "-q", "-m", "initial"]);

    const headSha = gitExec(["rev-parse", "HEAD"]).trim();

    const patchA = "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n-const a = 1;\n+const a = 2;\n";
    const patchB = "diff --git a/src/b.js b/src/b.js\n--- a/src/b.js\n+++ b/src/b.js\n@@ -1,1 +1,1 @@\n-const b = 1;\n+const b = 99;\n";

    const findings = [
      { id: "F-A", targetFiles: ["src/a.js"], severity: "critical" },
      { id: "F-B", targetFiles: ["src/b.js"], severity: "high" }
    ];

    const batch = new BatchRemediationSession("BATCH-ROLLBACK-001", findings);

    const sA = batch.getSession("F-A");
    sA.proposeFix({ diff: patchA, rationale: "Fix A", synthesizer: { providerName: "codex" } });
    sA.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });

    const sB = batch.getSession("F-B");
    sB.proposeFix({ diff: patchB, rationale: "Fix B", synthesizer: { providerName: "codex" } });
    sB.authorizePatch({ authorizer: { identity: "sec-lead@triad.flow", type: "human" } });

    // Execute in Jail: F-A passes, but F-B fails test runner!
    const batchTrial = batch.executeBatchInJailWorktree(tmpRepo, {
      baseSha: headSha,
      testRunnerFn: (jailDir, { findingId }) => {
        if (findingId === "F-A") {
          return { exitCode: 0, passedCount: 1, failedCount: 0 };
        }
        // F-B regression!
        return { exitCode: 1, passedCount: 0, failedCount: 1, regressionDetected: true };
      }
    });

    assert.equal(sA.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
    assert.equal(sB.status, REMEDIATION_STATES.REJECTED_FIX);

    // Closure verification conducted only on F-A
    sA.recordClosureVerification({
      verifier: { providerName: "claude" },
      verificationRecord: createMockVerificationRecord("F-A", { file: "src/a.js" })
    });
    assert.equal(sA.status, REMEDIATION_STATES.CLOSED);

    // Finalized batch reflects PARTIAL
    const receipt = batch.toBatchReceipt();
    assert.equal(receipt.status, BATCH_REMEDIATION_STATES.COMPLETED);
    assert.equal(receipt.verdict, BATCH_VERDICTS.PARTIAL);
    assert.equal(receipt.summary.closedCount, 1);
    assert.equal(receipt.summary.rejectedCount, 1);

    // Aggregate diff contains only successful patch A
    assert.ok(batchTrial.aggregateDiff.includes("const a = 2"));
    assert.ok(!batchTrial.aggregateDiff.includes("const b = 99"));
  } finally {
    try {
      fs.rmSync(tmpRepo, { recursive: true, force: true });
    } catch {
      // Windows lock ignore
    }
  }
});


