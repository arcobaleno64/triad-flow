/**
 * Test Suite: Controlled Remediation Engine & Patch Jail Sandbox (v2.3)
 *
 * Validates TF-SPEC-REMEDIATION-v1.0.0:
 * - 8-State lifecycle transitions and Monotonic Defense enforcement.
 * - Patch Jail worktree isolation and target file boundary enforcement.
 * - Goodhart anti-degradation evasion detection.
 * - Anti-thrashing stop rules (max 2 attempts).
 * - Remediation receipt generation, validation, and cryptographic digests.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  REMEDIATION_SCHEMA_VERSION,
  SUPPORTED_REMEDIATION_SCHEMA_MAJOR,
  REMEDIATION_STATES,
  MAX_REMEDIATION_ATTEMPTS,
  parseSchemaMajorVersion,
  parseUnifiedDiff,
  validatePatchScope,
  scanAntiDegradationViolations,
  validateRemediationTransition,
  computeTreeDigest,
  createPatchJailWorktree,
  cleanupPatchJailWorktree,
  applyPatchInJail,
  buildRemediationReceipt,
  validateRemediationReceipt,
  computeRemediationReceiptDigest,
  ControlledRemediationSession,
  UnsupportedRemediationSchemaError,
  RemediationValidationError,
  RemediationTransitionError,
  PatchJailSecurityError,
  PatchJailExecutionError,
  AntiThrashingLimitExceededError
} from "../src/core/controlled-remediation.mjs";

import {
  getCorpusCaseById,
  createCorpusCaseWorkspace
} from "./fixtures/real-corpus-fixtures.mjs";

test("Contract 1: Schema Major Version Parsing and Enforcement", () => {
  assert.equal(parseSchemaMajorVersion("1.0.0"), 1);
  assert.equal(parseSchemaMajorVersion("1.2.0"), 1);
  assert.equal(parseSchemaMajorVersion("2.0.0"), 2);
  assert.equal(parseSchemaMajorVersion("v1.0.0"), 1);

  // Validate supported schema major
  assert.equal(SUPPORTED_REMEDIATION_SCHEMA_MAJOR, 1);

  // Rejection of unsupported schema major in receipt validation
  assert.throws(
    () => validateRemediationReceipt({ schemaVersion: "2.0.0" }),
    UnsupportedRemediationSchemaError
  );
});

test("Contract 2: Monotonic Defense & State Transitions", () => {
  // 1. Prohibit synthesizer/model from self-verifying or jumping straight to CLOSED
  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.CLOSED, {
      actorType: "model"
    }),
    RemediationTransitionError
  );

  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.FIX_PROPOSED, REMEDIATION_STATES.CLOSED, {
      actorType: "synthesizer"
    }),
    RemediationTransitionError
  );

  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.FIXED_PENDING_VERIFY, REMEDIATION_STATES.CLOSED, {
      actorType: "synthesizer",
      isSelfVerification: true
    }),
    RemediationTransitionError
  );

  // 2. Prohibit model from authorizing patch
  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.FIX_PROPOSED, REMEDIATION_STATES.PATCH_AUTHORIZED, {
      actorType: "model"
    }),
    RemediationTransitionError
  );

  // 3. Prohibit model from waiving finding
  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.WAIVED, {
      actorType: "model",
      expiryTimestamp: "2026-12-31T00:00:00Z"
    }),
    RemediationTransitionError
  );

  // 4. WAIVED requires expiryTimestamp
  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.WAIVED, {
      actorType: "human",
      authorizer: { identity: "admin" }
    }),
    RemediationTransitionError
  );

  // 5. Valid transition sequence: OPEN -> FIX_PROPOSED -> PATCH_AUTHORIZED -> PATCH_APPLIED_IN_JAIL -> FIXED_PENDING_VERIFY -> CLOSED
  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.FIX_PROPOSED, {
      actor: "claude",
      actorType: "synthesizer",
      attempts: 1
    }),
    true
  );

  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.FIX_PROPOSED, REMEDIATION_STATES.PATCH_AUTHORIZED, {
      actor: "lead",
      actorType: "human",
      authorizer: { identity: "lead@security" }
    }),
    true
  );

  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.PATCH_AUTHORIZED, REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL, {
      actor: "orchestrator",
      jail: {
        prePatchTreeDigest: "sha256:" + "a".repeat(64),
        postPatchTreeDigest: "sha256:" + "b".repeat(64)
      }
    }),
    true
  );

  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL, REMEDIATION_STATES.FIXED_PENDING_VERIFY, {
      actor: "test-runner",
      deterministicChecks: { exitCode: 0, regressionDetected: false }
    }),
    true
  );

  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.FIXED_PENDING_VERIFY, REMEDIATION_STATES.CLOSED, {
      actor: "claude-verifier",
      actorType: "verifier",
      closureVerification: {
        verdict: "SUPPORTED",
        residualVulnerabilityDetected: false
      }
    }),
    true
  );
});

test("Contract 3: Anti-Thrashing Guardrail (Max 2 Attempts)", () => {
  // First attempt allowed
  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.FIX_PROPOSED, {
      attempts: 1
    }),
    true
  );

  // Second attempt allowed
  assert.equal(
    validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.FIX_PROPOSED, {
      attempts: 2
    }),
    true
  );

  // Third attempt fails closed with AntiThrashingLimitExceededError
  assert.throws(
    () => validateRemediationTransition(REMEDIATION_STATES.OPEN, REMEDIATION_STATES.FIX_PROPOSED, {
      findingId: "TEST-FINDING-001",
      attempts: 3
    }),
    AntiThrashingLimitExceededError
  );
});

test("Contract 4: Target File Boundary & Forbidden Manifest Enforcement", () => {
  const targetFiles = ["src/db/user-repo.js"];

  // 1. Valid patch within bounds
  const validDiff = [
    "diff --git a/src/db/user-repo.js b/src/db/user-repo.js",
    "--- a/src/db/user-repo.js",
    "+++ b/src/db/user-repo.js",
    "@@ -10,2 +10,3 @@",
    "- const query = 'SELECT * FROM users WHERE id = ' + id;",
    "+ const query = 'SELECT * FROM users WHERE id = ?';",
    "+ return db.query(query, [id]);"
  ].join("\n");

  const validated = validatePatchScope(validDiff, targetFiles);
  assert.deepEqual(validated.targetFiles, ["src/db/user-repo.js"]);
  assert.equal(validated.additions, 2);
  assert.equal(validated.deletions, 1);
  assert.match(validated.patchDiffDigest, /^sha256:[a-f0-9]{64}$/);

  // 2. Reject patch touching files outside declared targetFiles
  const outOfScopeDiff = [
    "diff --git a/src/auth/jwt.js b/src/auth/jwt.js",
    "--- a/src/auth/jwt.js",
    "+++ b/src/auth/jwt.js",
    "@@ -1,1 +1,1 @@",
    "+ const secret = 'fixed';"
  ].join("\n");

  assert.throws(
    () => validatePatchScope(outOfScopeDiff, targetFiles),
    PatchJailSecurityError
  );

  // 3. Reject patch touching CI/CD workflows
  const cicdDiff = [
    "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml",
    "--- a/.github/workflows/ci.yml",
    "+++ b/.github/workflows/ci.yml",
    "@@ -1,1 +1,1 @@",
    "+ - run: npm test"
  ].join("\n");

  assert.throws(
    () => validatePatchScope(cicdDiff, [".github/workflows/ci.yml"]),
    PatchJailSecurityError
  );

  // 4. Reject patch touching package.json or lockfiles
  const pkgDiff = [
    "diff --git a/package.json b/package.json",
    "--- a/package.json",
    "+++ b/package.json",
    "@@ -1,1 +1,1 @@",
    "+ \"test\": \"exit 0\""
  ].join("\n");

  assert.throws(
    () => validatePatchScope(pkgDiff, ["package.json"]),
    PatchJailSecurityError
  );
});

test("Contract 5: Goodhart Anti-Degradation Evasion Detection", () => {
  const targetFiles = ["tests/user.test.js"];

  // 1. Evasion via it.skip
  const skipDiff = [
    "diff --git a/tests/user.test.js b/tests/user.test.js",
    "--- a/tests/user.test.js",
    "+++ b/tests/user.test.js",
    "@@ -10,2 +10,2 @@",
    "- it('validates user', () => {",
    "+ it.skip('validates user', () => {"
  ].join("\n");

  const violations1 = scanAntiDegradationViolations(skipDiff);
  assert.equal(violations1.length, 1);
  assert.equal(violations1[0].type, "test-skipping");

  assert.throws(
    () => validatePatchScope(skipDiff, targetFiles),
    PatchJailSecurityError
  );

  // 2. Evasion via @ts-ignore
  const tsIgnoreDiff = [
    "diff --git a/src/db/user-repo.js b/src/db/user-repo.js",
    "--- a/src/db/user-repo.js",
    "+++ b/src/db/user-repo.js",
    "@@ -10,1 +10,2 @@",
    "+ // @ts-ignore",
    "+ const x = id.invalidMethod();"
  ].join("\n");

  const violations2 = scanAntiDegradationViolations(tsIgnoreDiff);
  assert.equal(violations2.length, 1);
  assert.equal(violations2[0].type, "ts-suppress");

  assert.throws(
    () => validatePatchScope(tsIgnoreDiff, ["src/db/user-repo.js"]),
    PatchJailSecurityError
  );
});

test("Contract 6: Tree Digest Determinism", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tree-test-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "file1.txt"), "hello world\r\n", "utf8");
    fs.mkdirSync(path.join(tmpDir, "sub"));
    fs.writeFileSync(path.join(tmpDir, "sub", "file2.js"), "const a = 1;\n", "utf8");

    const digest1 = computeTreeDigest(tmpDir);
    const digest2 = computeTreeDigest(tmpDir);

    assert.match(digest1, /^sha256:[a-f0-9]{64}$/);
    assert.equal(digest1, digest2);

    // Modify a file and verify digest changes
    fs.writeFileSync(path.join(tmpDir, "file1.txt"), "hello modified world\n", "utf8");
    const digest3 = computeTreeDigest(tmpDir);
    assert.notEqual(digest1, digest3);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 7: Controlled Remediation Session Controller Lifecycle", () => {
  const session = new ControlledRemediationSession("FINDING-BENCH-001", ["src/service.js"], {
    producer: { providerName: "agy", modelName: "cli-default" }
  });

  assert.equal(session.status, REMEDIATION_STATES.OPEN);

  // Propose fix
  const diff = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -1,1 +1,2 @@",
    "+ const safe = sanitize(input);"
  ].join("\n");

  session.proposeFix({ diff, rationale: "Sanitize unsanitized input" });
  assert.equal(session.status, REMEDIATION_STATES.FIX_PROPOSED);
  assert.equal(session.attempts, 1);

  // Authorize patch
  session.authorizePatch({ authorizer: { identity: "sec-admin@triad.flow", type: "human" } });
  assert.equal(session.status, REMEDIATION_STATES.PATCH_AUTHORIZED);

  // Jail Application
  session.recordJailApplication({
    worktreeSha: "abc1234",
    prePatchTreeDigest: "sha256:" + "1".repeat(64),
    postPatchTreeDigest: "sha256:" + "2".repeat(64)
  });
  assert.equal(session.status, REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL);

  // Test Runner Green
  session.recordDeterministicChecks({ exitCode: 0, passedCount: 10, failedCount: 0 });
  assert.equal(session.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);

  // Independent Verifier Confirms Closure
  session.recordClosureVerification({
    verificationRecord: {
      verdict: "SUPPORTED",
      summary: { supportedCount: 1, contestedCount: 0 },
      residualVulnerabilityDetected: false
    }
  });
  assert.equal(session.status, REMEDIATION_STATES.CLOSED);

  // Generate Immutable Receipt
  const receipt = session.toReceipt();
  assert.equal(receipt.status, REMEDIATION_STATES.CLOSED);
  assert.equal(receipt.schemaVersion, "1.0.0");
  assert.equal(receipt.findingId, "FINDING-BENCH-001");
  assert.equal(Object.isFrozen(receipt), true);

  const receiptDigest = computeRemediationReceiptDigest(receipt);
  assert.match(receiptDigest, /^sha256:[a-f0-9]{64}$/);
});

test("Contract 8: Remediation Receipt Schema 1.0.0 Validation", () => {
  const validReceipt = buildRemediationReceipt({
    findingId: "FINDING-VALID-001",
    status: REMEDIATION_STATES.CLOSED,
    actors: {
      producer: { providerName: "agy", modelName: "cli-default" },
      synthesizer: { providerName: "claude", modelName: "opusplan" },
      verifier: { providerName: "claude", modelName: "cli-default" },
      authorizer: { identity: "lead@security", type: "human" }
    },
    patch: {
      patchDiffDigest: "sha256:" + "a".repeat(64),
      targetFiles: ["src/app.js"],
      additions: 5,
      deletions: 2,
      rationale: "Fixed buffer overflow"
    },
    jail: {
      worktreeSha: "e9f8a7",
      prePatchTreeDigest: "sha256:" + "b".repeat(64),
      postPatchTreeDigest: "sha256:" + "c".repeat(64),
      isolatedExecutionPass: true
    },
    deterministicChecks: {
      testCommand: "npm test",
      exitCode: 0,
      passedCount: 42,
      failedCount: 0,
      regressionDetected: false
    },
    closureVerification: {
      verified: true,
      verificationRecordDigest: "sha256:" + "d".repeat(64),
      verdict: "SUPPORTED",
      residualVulnerabilityDetected: false
    },
    history: [
      { from: "OPEN", to: "FIX_PROPOSED", at: "2026-09-30T00:00:00Z", actor: "claude" },
      { from: "FIX_PROPOSED", to: "CLOSED", at: "2026-09-30T00:01:00Z", actor: "lead" }
    ]
  });

  assert.equal(validateRemediationReceipt(validReceipt), true);

  // Missing findingId throws validation error
  assert.throws(
    () => buildRemediationReceipt({ findingId: "" }),
    RemediationValidationError
  );

  // Corrupted digest throws validation error
  assert.throws(
    () => validateRemediationReceipt({
      ...validReceipt,
      patch: { ...validReceipt.patch, patchDiffDigest: "not-a-sha256" }
    }),
    RemediationValidationError
  );
});

test("Contract 9: Ephemeral Git Worktree Patch Jail Sandbox Lifecycle", () => {
  // Create a minimal real git repository in tmpdir
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-jail-repo-"));
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_NAME: "Jail Test",
    GIT_AUTHOR_EMAIL: "jail@triad.flow",
    GIT_COMMITTER_NAME: "Jail Test",
    GIT_COMMITTER_EMAIL: "jail@triad.flow"
  };

  const gitExec = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
    cwd: tmpRepo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: gitEnv,
    windowsHide: true
  });

  try {
    gitExec(["init", "-q"]);
    fs.writeFileSync(path.join(tmpRepo, "vuln.js"), "const query = 'SELECT * FROM users WHERE id = ' + id;\n", "utf8");
    gitExec(["add", "."]);
    gitExec(["-c", "user.name=test", "-c", "user.email=test@test", "commit", "-q", "-m", "initial"]);

    const headSha = gitExec(["rev-parse", "HEAD"]).trim();

    // 1. Create Patch Jail worktree
    const jail = createPatchJailWorktree(tmpRepo, { baseSha: headSha });
    assert.equal(fs.existsSync(jail.jailPath), true);

    // 2. Apply patch in Jail
    const patchDiff = [
      "diff --git a/vuln.js b/vuln.js",
      "--- a/vuln.js",
      "+++ b/vuln.js",
      "@@ -1,1 +1,2 @@",
      "-const query = 'SELECT * FROM users WHERE id = ' + id;",
      "+const query = 'SELECT * FROM users WHERE id = ?';",
      "+return db.query(query, [id]);"
    ].join("\n");

    const jailResult = applyPatchInJail(jail.jailPath, patchDiff, ["vuln.js"]);
    assert.equal(jailResult.applied, true);
    assert.match(jailResult.prePatchTreeDigest, /^sha256:[a-f0-9]{64}$/);
    assert.match(jailResult.postPatchTreeDigest, /^sha256:[a-f0-9]{64}$/);
    assert.notEqual(jailResult.prePatchTreeDigest, jailResult.postPatchTreeDigest);

    // Assert main repo working tree was not touched
    const mainRepoContent = fs.readFileSync(path.join(tmpRepo, "vuln.js"), "utf8");
    assert.equal(mainRepoContent, "const query = 'SELECT * FROM users WHERE id = ' + id;\n");

    // 3. Cleanup Patch Jail
    jail.cleanup();
    assert.equal(fs.existsSync(jail.jailPath), false);
  } finally {
    try {
      fs.rmSync(tmpRepo, { recursive: true, force: true });
    } catch {
      // Windows lock ignore
    }
  }
});

test("Contract 10: End-to-End Controlled Remediation Proof-of-Concept on BENCH-REAL-001", () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(caseDef, "BENCH-REAL-001 fixture exists");

  // 1. Create real physical workspace from caseDef (vulnerable HEAD)
  const workspace = createCorpusCaseWorkspace(caseDef, { virtual: false });

  try {
    // Assert repository immutability before remediation
    workspace.assertImmutability();

    // 2. Initialize Controlled Remediation Session
    const session = new ControlledRemediationSession(
      "BENCH-REAL-001-FINDING-001",
      [caseDef.targetFile],
      {
        producer: { providerName: "agy", modelName: "cli-default" }
      }
    );
    assert.equal(session.status, REMEDIATION_STATES.OPEN);

    // 3. Synthesizer synthesizes candidate patch diff
    const candidateDiff = [
      "diff --git a/src/db/user-repo.js b/src/db/user-repo.js",
      "--- a/src/db/user-repo.js",
      "+++ b/src/db/user-repo.js",
      "@@ -6,6 +6,6 @@",
      "   async findUserById(id) {",
      "-    // Construct query for user record",
      "-    const query = \"SELECT id, username, email FROM users WHERE id = '\" + id + \"'\";",
      "-    return this.db.query(query);",
      "+    // Parameterized query execution",
      "+    const query = \"SELECT id, username, email FROM users WHERE id = ?\";",
      "+    return this.db.query(query, [id]);",
      "   }",
      " }"
    ].join("\n") + "\n";

    session.proposeFix({
      diff: candidateDiff,
      rationale: "Replaced string concatenation with parameterized query placeholder to prevent SQL injection.",
      synthesizer: { providerName: "claude", modelName: "opusplan" }
    });
    assert.equal(session.status, REMEDIATION_STATES.FIX_PROPOSED);

    // 4. Human Security Lead reviews diff and signs authorization
    session.authorizePatch({
      authorizer: { identity: "sec-lead@triad.flow", type: "human" },
      signature: "sig-auth-20260930-abc"
    });
    assert.equal(session.status, REMEDIATION_STATES.PATCH_AUTHORIZED);

    // 5. Execute Trial inside Ephemeral Git Worktree Patch Jail
    const jailTrial = session.executeInJailWorktree(workspace.dir, {
      baseSha: workspace.headSha,
      testRunnerFn: (jailDir) => {
        // Assert patched file in jail contains parameterized query
        const patchedCode = fs.readFileSync(path.join(jailDir, "src/db/user-repo.js"), "utf8");
        assert.ok(patchedCode.includes("SELECT id, username, email FROM users WHERE id = ?"));
        assert.ok(!patchedCode.includes("'" + " + id + " + "'"));
        return {
          testCommand: "node --test tests/unit/user-repo.test.js",
          exitCode: 0,
          passedCount: 8,
          failedCount: 0
        };
      }
    });

    assert.equal(jailTrial.jailResult.applied, true);
    assert.equal(session.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);

    // 6. Independent Heterogeneous Verifier reviews diff and confirms closure
    session.recordClosureVerification({
      verifier: { providerName: "claude", modelName: "cli-default" },
      verificationRecord: {
        verdict: "SUPPORTED",
        digest: "sha256:" + "f".repeat(64),
        evaluations: [
          {
            findingId: "BENCH-REAL-001-FINDING-001",
            verdict: "SUPPORTED",
            locatorAccurate: true,
            typeAccurate: true,
            severityAccurate: true,
            reasoning: "Candidate diff converts raw string concatenation to parameterized binding, neutralizing CWE-89 without side effects."
          }
        ],
        summary: {
          totalEvaluated: 1,
          supportedCount: 1,
          contestedCount: 0,
          insufficientEvidenceCount: 0,
          omissionsCount: 0
        },
        residualVulnerabilityDetected: false
      }
    });

    assert.equal(session.status, REMEDIATION_STATES.CLOSED);

    // 7. Generate & validate canonical remediation receipt Schema 1.0.0
    const receipt = session.toReceipt();
    assert.equal(receipt.schemaVersion, "1.0.0");
    assert.equal(receipt.status, "CLOSED");
    assert.equal(receipt.findingId, "BENCH-REAL-001-FINDING-001");
    assert.equal(receipt.actors.producer.providerName, "agy");
    assert.equal(receipt.actors.synthesizer.providerName, "claude");
    assert.equal(receipt.actors.verifier.providerName, "claude");
    assert.equal(receipt.actors.authorizer.identity, "sec-lead@triad.flow");
    assert.deepEqual(receipt.patch.targetFiles, ["src/db/user-repo.js"]);
    assert.equal(receipt.deterministicChecks.exitCode, 0);
    assert.equal(receipt.closureVerification.verified, true);
    assert.equal(receipt.closureVerification.verdict, "SUPPORTED");
    assert.equal(receipt.history.length, 5);

    const receiptDigest = computeRemediationReceiptDigest(receipt);
    assert.match(receiptDigest, /^sha256:[a-f0-9]{64}$/);

    // 8. Prove Primary Workspace Immutability: host repo was untouched!
    workspace.assertImmutability();
  } finally {
    workspace.cleanup();
  }
});

