import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  evaluateIsolatedTestPostVerificationGate,
  issueVerificationRecordFromOutput,
  isTrustedVerificationRecord,
  RunContext
} from "../src/core/harness.mjs";
import {
  registerTrustedContextPackage,
  isTrustedContextPackage,
  validateContextPackageAuthenticity,
  evaluateContextPackageBinding,
  conductIndependentVerification,
  createMockVerifierAdapter,
  isTrustedCleanApproval
} from "../src/core/independent-verifier.mjs";
import { executeStagedReview } from "../src/adapters/staged-review.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";
import { collectMutationSnapshot, normalizeGitPath } from "../src/core/git-collector.mjs";
import { getTrustedRegistryKey, buildContextPackage } from "../src/core/context-builder.mjs";

function setupGitRepo() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "schema2-e2e-"));
  const git = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", "-c", "core.autocrlf=false", ...args], {
    cwd: tmpDir,
    encoding: "utf8",
    windowsHide: true
  });
  git(["init"]);
  git(["config", "user.name", "Triad E2E"]);
  git(["config", "user.email", "e2e@triad-flow.dev"]);
  return { tmpDir, git };
}

function makeCleanConsensus() {
  const rawReports = {
    agy: { provider: "agy", executionStatus: "success", fileCoverageComplete: true, findings: [] },
    claude: { provider: "claude", executionStatus: "success", fileCoverageComplete: true, findings: [] },
    codex: { provider: "codex", executionStatus: "success", fileCoverageComplete: true, findings: [] }
  };
  return aggregateConsensus(rawReports, { policy: "TRI_PARTY_HETEROGENEOUS", tier: 2 });
}

test("SCHEMA2-E2E-01: Register with superset manifest package is rejected", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    const changeSet = {
      headSha,
      files: [{ path: "fileA.js" }, { path: "fileB.js" }],
      repository: { root: tmpDir }
    };

    // Superset package contains fileC.js which is not in ChangeSet
    const supersetPkg = {
      schemaVersion: "2.0.0",
      headSha,
      targetFile: "multi-file",
      contentDigest: "a".repeat(64),
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileB.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileC.js", inspected: true, exactHeadAvailable: false, calleesExtracted: [] }
      ],
      layers: { layer0Diff: "" },
      budgetAccounting: { consumedBytes: 100 }
    };

    const registered = registerTrustedContextPackage(supersetPkg, {
      repositoryRoot: tmpDir,
      headSha,
      changeSet
    });

    assert.equal(registered, null, "Registration must return null for superset package");
    assert.equal(isTrustedContextPackage(supersetPkg), false, "Superset package must not gain Registry trust");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-02: executeStagedReview with non-set-equal package enforces layered status & gate block", async () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 2;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 2;\n");
    const diffHunks = git(["diff"]);
    const digest = crypto.createHash("sha256").update(diffHunks.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet = {
      schemaVersion: "1.0.0",
      headSha,
      diffHunks,
      files: [
        { path: "fileA.js", additions: 1, deletions: 0 },
        { path: "fileB.js", additions: 1, deletions: 0 }
      ],
      repository: { root: tmpDir }
    };

    // Non-set-equal package: manifest only contains fileA.js
    const nonSetEqualPkg = {
      schemaVersion: "2.0.0",
      headSha,
      targetFile: "multi-file",
      contentDigest: digest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks },
      budgetAccounting: { consumedBytes: 100 }
    };

    const mockReviewAdapter = new CliReviewAdapter({
      command: "mock",
      providerName: "claude",
      family: "anthropic",
      modelName: "claude-3-5-sonnet",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["fileA.js", "fileB.js"], omittedFiles: [] },
          providerIdentity: { provider: "claude", family: "anthropic", model: "claude-3-5-sonnet" }
        })
      })
    });
    const result = await executeStagedReview(changeSet, mockReviewAdapter, {
      cwd: tmpDir,
      headSha,
      contextPackage: nonSetEqualPkg
    });

    // 1. Layered check: executionStatus === SUCCESS
    assert.equal(result.executionStatus, EXECUTION_STATUS.SUCCESS, "Adapter must complete execution lifecycle");

    // 2. Context Gap check: EXACT_HEAD_CONTEXT_FAILED present and cannot be cleared
    assert.ok(
      result.contextGaps?.some(g => g.code === "EXACT_HEAD_CONTEXT_FAILED"),
      "EXACT_HEAD_CONTEXT_FAILED must be recorded in contextGaps"
    );

    // 3. Independent verifier flags UNCERTAIN
    const mockVerifierAdapter = createMockVerifierAdapter("claude");
    const verificationRecord = await conductIndependentVerification(
      changeSet,
      [],
      mockVerifierAdapter,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: nonSetEqualPkg,
        contextGaps: result.contextGaps,
        options: { patchObjective: "Clean verification" }
      }
    );
    assert.equal(verificationRecord.overallStatus, "UNCERTAIN", "Verifier must flag UNCERTAIN when context gaps are present");

    // 4. Gate decision evaluates strictly to block
    const runContext = new RunContext({
      repo: "triad-flow",
      headSha,
      contentDigest: digest,
      patchObjective: "Clean verification"
    });
    const gateResult = evaluateGateDecision(
      { findings: [], quorumReached: true },
      {
        verificationRecord,
        runContext,
        contextGaps: result.contextGaps,
        isCleanChallengeRequired: true
      }
    );
    assert.equal(gateResult.decision, "block", "Gate decision must strictly evaluate to 'block'");
    assert.notEqual(gateResult.decision, "human_review_required", "Relaxation to human_review_required is prohibited");
    assert.equal(isTrustedCleanApproval(gateResult, verificationRecord), false, "Zero clean approval authority issued");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-03: Physical diff [A, B, C], caller truncates ChangeSet and Manifest to [A, B] -> rejected", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileC.js"), "export const c = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial"]);
    const baseSha = git(["rev-parse", "HEAD"]).trim();

    // Modify all three files physically
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 2;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 2;\n");
    fs.writeFileSync(path.join(tmpDir, "fileC.js"), "export const c = 2;\n");
    git(["add", "."]);
    git(["commit", "-m", "Modify all 3"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    // Physical snapshot contains 3 files
    const snapshot = collectMutationSnapshot(tmpDir, {
      scopeMode: "revision_range",
      baseSha,
      headSha
    });
    assert.equal(snapshot.files.length, 3, "Physical Git snapshot reflects all 3 modified files");

    // Caller truncates ChangeSet and Manifest to [A, B]
    const truncatedChangeSet = {
      headSha,
      baseSha,
      files: [{ path: "fileA.js" }, { path: "fileB.js" }],
      repository: { root: tmpDir }
    };
    const truncatedPkg = {
      schemaVersion: "2.0.0",
      headSha,
      baseSha,
      targetFile: "multi-file",
      contentDigest: "c".repeat(64),
      repositoryRoot: tmpDir,
      mutationSnapshotHash: "fake-hash",
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileB.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: "" },
      budgetAccounting: { consumedBytes: 100 }
    };

    // Registration against authentic Git collector fails closed
    const registered = registerTrustedContextPackage(truncatedPkg, {
      repositoryRoot: tmpDir,
      headSha,
      baseSha,
      changeSet: truncatedChangeSet
    });
    assert.equal(registered, null, "Registration must fail closed when provenance does not match physical tree");
    assert.equal(isTrustedContextPackage(truncatedPkg), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-04: Duplicate manifest path B during registration -> returns null", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    const changeSet = {
      headSha,
      files: [{ path: "fileA.js" }, { path: "fileB.js" }],
      repository: { root: tmpDir }
    };

    const duplicateManifestPkg = {
      schemaVersion: "2.0.0",
      headSha,
      targetFile: "multi-file",
      contentDigest: "d".repeat(64),
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileB.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileB.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: "" },
      budgetAccounting: { consumedBytes: 100 }
    };

    const registered = registerTrustedContextPackage(duplicateManifestPkg, {
      repositoryRoot: tmpDir,
      headSha,
      changeSet
    });
    assert.equal(registered, null, "registerTrustedContextPackage must reject duplicate manifest paths");
    assert.equal(isTrustedContextPackage(duplicateManifestPkg), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-05: Caller falsifies changeSet.files against Git snapshot -> Gate evaluates to block", async () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    // Physical files are fileA.js and fileB.js, but caller falsifies to fileFake.js
    const falsifiedChangeSet = {
      headSha,
      files: [{ path: "fileA.js" }, { path: "fileFake.js" }],
      repository: { root: tmpDir }
    };

    const pkg = {
      schemaVersion: "2.0.0",
      headSha,
      targetFile: "multi-file",
      contentDigest: "e".repeat(64),
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileFake.js", inspected: true, exactHeadAvailable: false, calleesExtracted: [] }
      ],
      layers: { layer0Diff: "" },
      budgetAccounting: { consumedBytes: 100 }
    };

    const adapter = createMockVerifierAdapter("claude");
    const verificationRecord = await conductIndependentVerification(
      falsifiedChangeSet,
      [],
      adapter,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: pkg
      }
    );

    const runContext = new RunContext({
      repo: "triad-flow",
      headSha,
      contentDigest: "e".repeat(64),
      patchObjective: "Test falsified ChangeSet"
    });

    const gate = evaluateGateDecision(
      [],
      [{ code: "EXACT_HEAD_CONTEXT_FAILED", reason: "Falsified ChangeSet" }],
      {
        verificationRecord,
        runContext,
        isCleanChallengeRequired: true
      }
    );

    assert.equal(gate.decision, "block", "Falsified ChangeSet must evaluate to 'block'");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-06: Package registered for Repo X replayed for Repo Y evaluates to cache miss", () => {
  const keyX = getTrustedRegistryKey({
    repoId: "repo-x",
    scopeMode: "revision_range",
    baseSha: "1".repeat(40),
    headSha: "2".repeat(40),
    changeSet: { files: [{ path: "fileA.js" }] },
    diffHunks: "+ const a = 1;\n",
    snapshotHash: "hash-x"
  });

  const keyY = getTrustedRegistryKey({
    repoId: "repo-y",
    scopeMode: "working_tree",
    baseSha: "3".repeat(40),
    headSha: "4".repeat(40),
    changeSet: { files: [{ path: "fileB.js" }] },
    diffHunks: "+ const b = 2;\n",
    snapshotHash: "hash-y"
  });

  assert.notEqual(keyX, keyY, "Provenance keys for different repositories and scopes must not collide");
  assert.equal(typeof keyX, "string");
  assert.equal(keyX.length, 64);
  assert.equal(typeof keyY, "string");
  assert.equal(keyY.length, 64);
});

test("SCHEMA2-E2E-07: Comprehensive Authority & Freshness Rejection", async () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n");
    git(["add", "."]);
    git(["commit", "-m", "Initial commit"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();

    // Subcase (a): Unbound / synthetic record rejected
    const syntheticRecord = issueVerificationRecordFromOutput({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    });
    assert.equal(isTrustedVerificationRecord(syntheticRecord), false, "Synthetic record must not be trusted");
    const cleanConsensus = makeCleanConsensus();
    const gateA = evaluateGateDecision(cleanConsensus, {
      verificationRecord: syntheticRecord,
      isCleanChallengeRequired: true
    });
    assert.equal(gateA.decision, "block", "Subcase (a): Synthetic record must evaluate to 'block'");
    assert.equal(isTrustedCleanApproval(gateA), false);

    // Subcase (b): Preliminary pass carries 0 release authority
    const preliminaryGate = evaluateGateDecision(cleanConsensus, {
      preliminary: true,
      isCleanChallengeRequired: true
    });
    assert.equal(preliminaryGate.preliminary, true);
    assert.equal(isTrustedCleanApproval(preliminaryGate), false, "Preliminary pass carries zero release authority");

    // Subcase (c): Dynamic WeakMap snapshot freshness re-verification & authentic Clean Approval
    // Stage a modification in index
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 2;\n");
    git(["add", "fileA.js"]);

    const stagedChangeSet = {
      schemaVersion: "1.0.0",
      headSha,
      scopeMode: "staged",
      diffHunks: git(["diff", "--cached"]),
      files: [{ path: "fileA.js", additions: 1, deletions: 0, staged: true }],
      repository: { root: tmpDir }
    };

    const stagedPkg = buildContextPackage(stagedChangeSet, null, {
      headSha,
      repositoryRoot: tmpDir,
      scopeMode: "staged"
    });

    const mockVerifier = createMockVerifierAdapter("claude", {
      overallStatus: "CLEAN",
      evaluations: []
    });

    // Authentically mint genuineRecord through the production verifier pipeline
    const genuineRecord = await conductIndependentVerification(
      stagedChangeSet,
      [],
      mockVerifier,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: stagedPkg,
        verificationMode: "clean_challenge"
      }
    );

    // Positive assertion: Unmutated record retains authentic capability
    assert.equal(
      isTrustedVerificationRecord(genuineRecord),
      true,
      "Subcase (c) Positive: Unmutated record retains trusted capability"
    );

    // Positive Gate release authority: Authentic Clean Challenge yields clean approval
    const runContext = new RunContext({
      headSha,
      contentDigest: genuineRecord.changeSetDigest
    });
    const genuineGate = evaluateGateDecision(cleanConsensus, {
      verificationRecord: genuineRecord,
      isCleanChallengeRequired: true,
      runContext
    });
    assert.equal(genuineGate.decision, "approve");
    assert.equal(
      isTrustedCleanApproval(genuineGate, genuineRecord),
      true,
      "Subcase (c) Positive: Authentic Clean Challenge yields trusted clean approval"
    );

    // Negative Counterexample Assertions (SCHEMA2-LC-F02 Counterexample Regression):
    assert.equal(
      isTrustedCleanApproval({ decision: "approve", preliminary: false }),
      false,
      "Negative Counterexample 1: Plain unauthenticated gate decision is rejected fail-closed"
    );
    assert.equal(
      isTrustedCleanApproval({ decision: "approve", preliminary: false }, { schemaVersion: "1.0.0" }),
      false,
      "Negative Counterexample 2: Forged record without registry authority is rejected fail-closed"
    );
    assert.equal(
      isTrustedCleanApproval({ decision: "approve", preliminary: false }, syntheticRecord),
      false,
      "Negative Counterexample 3: Synthetic record is rejected from clean approval authority"
    );

    // Reviewer R3 Counterexample 1: Authentic Record with overallStatus: "UNCERTAIN" + forged approve decision
    const mockUncertainVerifier = createMockVerifierAdapter("claude", {
      overallStatus: "UNCERTAIN",
      evaluations: []
    });
    const uncertainRecord = await conductIndependentVerification(
      stagedChangeSet,
      [],
      mockUncertainVerifier,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: stagedPkg,
        verificationMode: "clean_challenge"
      }
    );
    assert.equal(isTrustedVerificationRecord(uncertainRecord), true, "Authentic uncertain record has registry identity");
    assert.equal(uncertainRecord.overallStatus, "UNCERTAIN");
    assert.equal(
      isTrustedCleanApproval({ decision: "approve", preliminary: false, reason: "Clean Challenge passed" }, uncertainRecord),
      false,
      "Reviewer R3: Authentic UNCERTAIN record + forged approve decision strictly rejected"
    );
    assert.equal(
      isTrustedCleanApproval({
        decision: "approve",
        preliminary: false,
        reason: "Clean Challenge passed: zero findings and zero verified omissions.",
        criticals: [],
        advisoryFindings: []
      }, uncertainRecord),
      false,
      "Reviewer R3: Authentic UNCERTAIN record + canonical approve decision strictly rejected"
    );

    // Reviewer R3 Counterexample 2: Authentic Record with overallStatus: "DEFECTS_FOUND" + forged approve decision
    const mockDefectsVerifier = createMockVerifierAdapter("claude", {
      overallStatus: "DEFECTS_FOUND",
      evaluations: []
    });
    const defectsRecord = await conductIndependentVerification(
      stagedChangeSet,
      [],
      mockDefectsVerifier,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: stagedPkg,
        verificationMode: "clean_challenge"
      }
    );
    assert.equal(isTrustedVerificationRecord(defectsRecord), true, "Authentic defects record has registry identity");
    assert.equal(defectsRecord.overallStatus, "DEFECTS_FOUND");
    assert.equal(
      isTrustedCleanApproval({
        decision: "approve",
        preliminary: false,
        reason: "Clean Challenge passed: zero findings and zero verified omissions.",
        criticals: [],
        advisoryFindings: []
      }, defectsRecord),
      false,
      "Reviewer R3: Authentic DEFECTS_FOUND record + forged approve decision strictly rejected"
    );

    // Reviewer R4 Counterexample: Authentic CLEAN Record + forged full Canonical approve Decision (without actual gate invoked)
    const freshCleanVerifier = createMockVerifierAdapter("claude", {
      overallStatus: "CLEAN",
      evaluations: []
    });
    const uninvokedCleanRecord = await conductIndependentVerification(
      stagedChangeSet,
      [],
      freshCleanVerifier,
      {
        repositoryRoot: tmpDir,
        headSha,
        contextPackage: stagedPkg,
        verificationMode: "clean_challenge"
      }
    );
    assert.equal(isTrustedVerificationRecord(uninvokedCleanRecord), true, "Record has trusted registry capability");
    assert.equal(uninvokedCleanRecord.overallStatus, "CLEAN");

    const forgedCanonicalDecision = {
      decision: "approve",
      preliminary: false,
      criticals: [],
      advisoryFindings: [],
      reason: "Clean Challenge passed: zero findings and zero verified omissions."
    };

    assert.equal(
      isTrustedCleanApproval(forgedCanonicalDecision, uninvokedCleanRecord),
      false,
      "Reviewer R4: Authentic CLEAN Record + forged full Canonical approve Decision without gate invocation strictly rejected"
    );

    // Reviewer R5 Counterexample 1: External same-name function spoofing evaluateGateDecision
    function spoofedEvaluateGateDecision() {
      return isTrustedVerificationRecord(uninvokedCleanRecord);
    }
    spoofedEvaluateGateDecision();
    assert.equal(
      isTrustedCleanApproval(forgedCanonicalDecision, uninvokedCleanRecord),
      false,
      "Reviewer R5: External function spoofing is strictly rejected without harness attestation"
    );

    // Reviewer R5 Counterexample 2: True Gate executed returning 'block', caller constructs fake canonical approve
    const blockingConsensusReport = {
      findings: [{
        title: "Critical Vulnerability in review",
        severity: "critical",
        type: "SECURITY_VULNERABILITY"
      }],
      quorumReached: true,
      verdict: "needs-attention"
    };
    const blockGateResult = evaluatePostVerificationGate(blockingConsensusReport, uninvokedCleanRecord);
    assert.equal(blockGateResult.decision, "block");
    assert.equal(
      isTrustedCleanApproval(blockGateResult, uninvokedCleanRecord),
      false,
      "Reviewer R5: Genuine block gate decision cannot yield clean approval"
    );
    assert.equal(
      isTrustedCleanApproval(forgedCanonicalDecision, uninvokedCleanRecord),
      false,
      "Reviewer R5: Fake approve constructed after real gate blocks is strictly rejected"
    );

    // Reviewer R5 Counterexample 3: Synthetic test gate (evaluateIsolatedTestPostVerificationGate) cannot mint formal authority
    const syntheticGateResult = evaluateIsolatedTestPostVerificationGate(cleanConsensus, uninvokedCleanRecord);
    assert.equal(syntheticGateResult.decision, "approve");
    assert.equal(
      isTrustedCleanApproval(syntheticGateResult, uninvokedCleanRecord),
      false,
      "Reviewer R5: Synthetic test gate evaluation cannot mint formal release authority"
    );

    // Reviewer R5 Counterexample 4: Post-issuance decision tampering invalidates approval
    const tamperedApproveDecision = {
      ...genuineGate,
      reason: "Tampered reason post-issuance"
    };
    assert.equal(
      isTrustedCleanApproval(tamperedApproveDecision, genuineRecord),
      false,
      "Reviewer R5: Post-issuance tampered decision object fails closed"
    );

    // Reviewer R6 Counterexample (SCHEMA2-LC-F02-R6-01): preliminary: true with legitimate CLEAN Record
    const preliminaryWithCleanRecord = evaluateGateDecision(cleanConsensus, {
      preliminary: true,
      verificationRecord: uninvokedCleanRecord,
      isCleanChallengeRequired: true
    });
    assert.equal(preliminaryWithCleanRecord.decision, "approve");
    assert.equal(preliminaryWithCleanRecord.preliminary, true, "Must preserve preliminary: true semantics");
    assert.equal(
      isTrustedCleanApproval(preliminaryWithCleanRecord, uninvokedCleanRecord),
      false,
      "Reviewer R6: preliminary: true with legitimate CLEAN Record strictly carries zero release authority"
    );

    const postVerificationPreliminary = evaluatePostVerificationGate(cleanConsensus, uninvokedCleanRecord, {
      preliminary: true,
      runContext
    });
    assert.equal(postVerificationPreliminary.decision, "approve");
    assert.equal(postVerificationPreliminary.preliminary, true);
    assert.equal(
      isTrustedCleanApproval(postVerificationPreliminary, uninvokedCleanRecord),
      false,
      "Reviewer R6: evaluatePostVerificationGate with preliminary: true carries zero release authority"
    );

    // Now, mutate fileA.js in the working tree / staged state (file drift)
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 3; // mutated\n");
    git(["add", "fileA.js"]); // Changes index hash!

    // Negative assertion: Post-issuance file drift invalidates record
    assert.equal(
      isTrustedVerificationRecord(genuineRecord),
      false,
      "Subcase (c) Negative: Post-issuance drift must invalidate trusted capability"
    );

    const gateC = evaluateGateDecision(cleanConsensus, {
      verificationRecord: genuineRecord,
      isCleanChallengeRequired: true
    });
    assert.equal(gateC.decision, "block", "Gate blocks fail-closed when snapshot has drifted");
    assert.equal(
      isTrustedCleanApproval(gateC, genuineRecord),
      false,
      "Post-drift gate decision is denied clean approval authority"
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-E2E-08: Legacy Schema v1.0.0 package supplied to review -> downgrade rejected", () => {
  const legacyPkg = {
    schemaVersion: "1.0.0",
    headSha: "1".repeat(40),
    targetFile: "fileA.js",
    contentDigest: "f".repeat(64),
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: { layer0Diff: "" },
    budgetAccounting: { consumedBytes: 100 }
  };

  const isAuthentic = validateContextPackageAuthenticity(legacyPkg, {
    requiredSchemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    repositoryRoot: "/repo"
  });

  assert.equal(isAuthentic, false, "Legacy Schema v1.0.0 package must be rejected when v2.0.0 is required");
});
