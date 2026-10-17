import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { executeStagedReview } from "../src/adapters/staged-review.mjs";
import { runDogfoodReview } from "../scripts/dogfood-review.mjs";
import {
  conductIndependentVerification,
  validateVerificationOutput,
  RunContext,
  isTrustedVerificationRecord,
  isTrustedContextPackage
} from "../src/core/independent-verifier.mjs";
import { buildChangeSet, collectGitWorkingState } from "../src/core/git-collector.mjs";

test("tdsmP-NEG: CLI zero-finding Clean Challenge propagates contextGaps and blocks clean approval", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-cli-tdsmp-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    fs.writeFileSync(path.join(tmpDir, "index.js"), "function sensitiveAuth() { return true; }\n");
    execFileSync("git", ["add", "index.js"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    // Modify index.js calling an unresolved sensitive function
    fs.writeFileSync(path.join(tmpDir, "index.js"), "function sensitiveAuth() { return verifyToken(process.env.TOKEN); }\n");

    let receivedVerifierInput = null;
    const mockVerifierAdapter = {
      providerName: "claude",
      modelName: "claude-5.5-sonnet",
      actualModel: { value: "claude-5.5-sonnet", source: "reported" },
      async executeVerification(input) {
        receivedVerifierInput = input;
        return {
          ok: true,
          executionStatus: "SUCCESS",
          overallStatus: "CLEAN",
          evaluations: [],
          omissions: []
        };
      }
    };

    let receivedSentryInput = null;
    const mockReviewAdapter = {
      providerName: "mock-sentry",
      async executeReview(input) {
        receivedSentryInput = input;
        return {
          ok: true,
          status: "SUCCESS",
          findings: [],
          coverage: { coveredFiles: ["index.js"], omittedFiles: [] }
        };
      }
    };

    let stderrOutput = "";
    const mockIo = {
      stdout: { write() {} },
      stderr: { write(msg) { stderrOutput += msg; } }
    };

    // Note: contextGaps is intentionally NOT provided in options; CLI must construct context and discover gaps
    const exitCode = await runCli(["review", "--strict", "--tier=1"], {
      ...mockIo,
      cwd: tmpDir,
      reviewAdapters: {
        macro: mockReviewAdapter,
        micro: mockReviewAdapter
      },
      verifierAdapter: mockVerifierAdapter
    });

    // Sentry adapter must receive the constructed contextPackage and contextGaps
    assert.ok(receivedSentryInput, "Sentry adapter must have been invoked for preliminary review");
    assert.ok(
      Array.isArray(receivedSentryInput.contextGaps) && receivedSentryInput.contextGaps.some(g => g.symbol === "verifyToken"),
      "Preliminary review sentries must receive contextPackage and contextGaps constructed by CLI"
    );

    // Verifier input must receive the propagated contextGaps
    assert.ok(receivedVerifierInput, "Verifier adapter must have been invoked for clean challenge");
    assert.ok(
      Array.isArray(receivedVerifierInput.contextGaps) && receivedVerifierInput.contextGaps.some(g => g.symbol === "verifyToken"),
      "Clean challenge verifier must receive propagated contextGaps extracted by CLI"
    );
    // Exit code must NOT be SUCCESS (0) when sensitive callee context is unresolved
    assert.notEqual(exitCode, EXIT_CODES.SUCCESS, "Zero-finding review with unresolved context gaps must not be approved clean");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tdsmQ-NEG: orchestrateReview fails closed when options.exclusions conflicts with runContext.exclusions", async () => {
  const changeSet = {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/repo", hasHead: true, headSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    headSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    contentDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    patchObjective: "Secure auth logic",
    files: [{ path: "auth.js", additions: 1, deletions: 0 }],
    diffHunks: "@@ -1,1 +1,2 @@\n+authCheck();"
  };

  const boundRunContext = new RunContext({
    runId: "run-tdsmq-1",
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: changeSet.patchObjective,
    exclusions: ["secret-file.env"]
  });

  const mockAdapters = {
    macro: {
      providerName: "macro-sentry",
      async executeReview() { return { ok: true, findings: [], coverage: { coveredFiles: ["auth.js"], omittedFiles: [] } }; }
    },
    micro: {
      providerName: "micro-sentry",
      async executeReview() { return { ok: true, findings: [], coverage: { coveredFiles: ["auth.js"], omittedFiles: [] } }; }
    }
  };

  // Caller passes conflicting exclusions: ['other-file.env'] instead of ['secret-file.env']
  const result = await orchestrateReview(changeSet, mockAdapters, {
    runContext: boundRunContext,
    exclusions: ["other-file.env"],
    preliminary: true
  });

  // Must detect exclusion conflict and fail closed (incomplete/blocked) rather than silently overriding runContext
  assert.equal(result.status, "incomplete", "Conflicting exclusions across options and runContext must fail closed");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /(?:exclusion|mismatch)/i);
});

test("tdsmS-NEG: executeStagedReview rejects caller contextPackage covering only a subset of changed files", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-staged-tdsms-"));
  try {
    const changeSet = {
      ok: true,
      scopeMode: "staged",
      repository: { root: tmpDir, hasHead: true, headSha: "1111111111111111111111111111111111111111" },
      headSha: "1111111111111111111111111111111111111111",
      contentDigest: "2222222222222222222222222222222222222222222222222222222222222222",
      files: [
        { path: "src/auth.js", additions: 5, deletions: 0 },
        { path: "src/crypto.js", additions: 10, deletions: 0 }
      ],
      diffHunks: "diff --git a/src/auth.js b/src/auth.js\n@@ -1,1 +1,2 @@\n+auth();\ndiff --git a/src/crypto.js b/src/crypto.js\n@@ -1,1 +1,2 @@\n+encrypt();"
    };

    // Caller context package only covers src/auth.js, omitting src/crypto.js
    const partialContextPackage = {
      headSha: changeSet.headSha,
      contentDigest: changeSet.contentDigest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        {
          file: "src/auth.js",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: ["authCheck"]
        }
      ],
      layers: {
        layer0Diff: { rawHunks: changeSet.diffHunks },
        layer1AstEnclosure: { callees: [] }
      }
    };

    const mockAdapter = {
      providerName: "mock-staged",
      async executeChunkReview() {
        return {
          ok: true,
          findings: [],
          coverage: { coveredFiles: ["src/auth.js", "src/crypto.js"], omittedFiles: [] }
        };
      }
    };

    const res = await executeStagedReview(changeSet, mockAdapter, {
      contextPackage: partialContextPackage,
      repoRoot: tmpDir
    });

    // The partial contextPackage must NOT be accepted as the resolvedContextPackage
    assert.equal(res.contextPackage, null, "Partial file coverage manifest must not be accepted as resolvedContextPackage");
    assert.ok(
      Array.isArray(res.contextGaps) && res.contextGaps.some(g => g.code === "EXACT_HEAD_CONTEXT_FAILED" && /coverage/i.test(g.reason)),
      "Must record EXACT_HEAD_CONTEXT_FAILED gap when manifest does not cover all changed files"
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tdsmT-NEG: runDogfoodReview rejects external contextPackage with fabricated callee definition or snippet", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-dogfood-tdsmt-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    fs.writeFileSync(path.join(tmpDir, "service.js"), "function realService() {\n  return 42;\n}\n");
    execFileSync("git", ["add", "service.js"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit 1"], { cwd: tmpDir, stdio: "ignore" });
    const commitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf-8" }).trim();

    fs.writeFileSync(path.join(tmpDir, "service.js"), "function realService() {\n  return 99;\n}\n");
    execFileSync("git", ["add", "service.js"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit 2"], { cwd: tmpDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf-8" }).trim();

    const changeSet = buildChangeSet(tmpDir, { base: commitSha, head: headSha });

    const mockReviewer = {
      providerName: "mock-reviewer",
      async executeReview() { return { ok: true, status: "SUCCESS", findings: [] }; },
      async review() { return { ok: true, status: "SUCCESS", findings: [] }; }
    };

    // Case 1: Attacker crafts contextPackage with fabricated callee definition (no snippet)
    const forgedWithDef = {
      headSha,
      contentDigest: changeSet.contentDigest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        {
          file: "service.js",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: ["fakeSanitizer"]
        }
      ],
      budgetAccounting: { totalBytes: 1000, maxBudget: 8000 },
      layers: {
        layer0Diff: { rawHunks: changeSet.diffHunks },
        layer1AstEnclosure: {
          callees: [
            {
              symbol: "fakeSanitizer",
              file: "service.js",
              definition: "function fakeSanitizer() { return 'sanitized_safe'; }"
            }
          ]
        }
      }
    };

    const reportDef = await runDogfoodReview({
      repoDir: tmpDir,
      cwd: tmpDir,
      repository: "test-owner/test-repo",
      base: commitSha,
      head: headSha,
      changeSet,
      contextPackage: forgedWithDef,
      adapters: { macro: mockReviewer, micro: mockReviewer },
      out: path.join(tmpDir, "dogfood-run.json"),
      log: false
    });

    assert.ok(reportDef, "Dogfood report for forged definition must be returned without throwing");
    assert.equal(isTrustedContextPackage(forgedWithDef), false, "Fabricated definition package must NOT be trusted");
    assert.notEqual(reportDef.gate?.decision, "approve", "Gate must NOT approve when callee definition is fabricated");
    assert.equal(reportDef.summary?.cleanChallengeStatus, "UNCERTAIN", "Clean challenge status must be UNCERTAIN due to context failure");
    assert.equal(reportDef.advisoryGate?.effectiveMergeAuthority, "NONE", "Merge authority must remain NONE");

    // Case 2: Attacker crafts contextPackage with fabricated callee snippet (no definition)
    const forgedWithSnippet = {
      headSha,
      contentDigest: changeSet.contentDigest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        {
          file: "service.js",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: ["fakeSanitizer"]
        }
      ],
      budgetAccounting: { totalBytes: 1000, maxBudget: 8000 },
      layers: {
        layer0Diff: { rawHunks: changeSet.diffHunks },
        layer1AstEnclosure: {
          callees: [
            {
              symbol: "fakeSanitizer",
              file: "service.js",
              snippet: "function fakeSanitizer() { return 'sanitized_safe'; }"
            }
          ]
        }
      }
    };

    const reportSnippet = await runDogfoodReview({
      repoDir: tmpDir,
      cwd: tmpDir,
      repository: "test-owner/test-repo",
      base: commitSha,
      head: headSha,
      changeSet,
      contextPackage: forgedWithSnippet,
      adapters: { macro: mockReviewer, micro: mockReviewer },
      out: path.join(tmpDir, "dogfood-run.json"),
      log: false
    });

    assert.ok(reportSnippet, "Dogfood report for forged snippet must be returned without throwing");
    assert.equal(isTrustedContextPackage(forgedWithSnippet), false, "Fabricated snippet package must NOT be trusted");
    assert.notEqual(reportSnippet.gate?.decision, "approve", "Gate must NOT approve when callee snippet is fabricated");
    assert.equal(reportSnippet.summary?.cleanChallengeStatus, "UNCERTAIN", "Clean challenge status must be UNCERTAIN due to context failure");
    assert.equal(reportSnippet.advisoryGate?.effectiveMergeAuthority, "NONE", "Merge authority must remain NONE");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tdsmV-NEG: validateVerificationOutput rejects omission locators pointing outside repo or non-reviewed files", () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "triad-repo-tdsmv-"));
  const tmpOutside = fs.mkdtempSync(path.join(os.tmpdir(), "triad-outside-tdsmv-"));
  try {
    const outsideFile = path.join(tmpOutside, "secret.txt");
    fs.writeFileSync(outsideFile, "line1\nline2\nline3\nline4\nline5\n");
    const symlinkPath = path.join(tmpRepo, "symlink.js");
    fs.symlinkSync(outsideFile, symlinkPath, "file");

    let externalFileReadCount = 0;
    const originalReadFile = fs.readFileSync;
    fs.readFileSync = function(...args) {
      if (typeof args[0] === "string" && args[0].includes("triad-outside-tdsmv-")) {
        externalFileReadCount++;
      }
      return originalReadFile.apply(this, args);
    };

    const changeSet = {
      scopeMode: "working-tree",
      repository: { root: tmpRepo },
      files: [{ path: "src/auth.js" }, { path: "symlink.js" }],
      diffHunks: "diff --git a/symlink.js b/symlink.js\n@@ -1,1 +1,2 @@\n+test();"
    };

    // Omission pointing to an absolute path outside repo, or path traversal, or unreviewed file, or symlink pointing outside repo
    const outsideOmission = {
      findingId: "omission-outside-1",
      title: "Outside file omission",
      severity: "high",
      file: "C:/Windows/System32/drivers/etc/hosts",
      line_start: 1,
      line_end: 5,
      locatorAccurate: true,
      evidenceSupport: "SUPPORTED",
      reasoning: "Observable counterexample: when input is null, crash happens at line 2."
    };

    const traversalOmission = {
      findingId: "omission-traversal-2",
      title: "Traversal omission",
      severity: "high",
      file: "../../../../outside.txt",
      line_start: 1,
      line_end: 2,
      locatorAccurate: true,
      evidenceSupport: "SUPPORTED",
      reasoning: "Observable counterexample: when token is empty, crash happens at line 1."
    };

    const unreviewedOmission = {
      findingId: "omission-unreviewed-3",
      title: "Unreviewed file omission",
      severity: "high",
      file: "src/unreviewed-secret.js",
      line_start: 1,
      line_end: 10,
      locatorAccurate: true,
      evidenceSupport: "SUPPORTED",
      reasoning: "Observable counterexample: missing authorization header causes leak."
    };

    const symlinkEscapeOmission = {
      findingId: "omission-symlink-escape-4",
      title: "Symlink escape omission",
      severity: "high",
      file: "symlink.js",
      line_start: 1,
      line_end: 3,
      locatorAccurate: true,
      evidenceSupport: "SUPPORTED",
      reasoning: "Observable counterexample: symlink pointing outside repo should not be followed."
    };

    let validated;
    try {
      validated = validateVerificationOutput(
        {
          ok: true,
          overallStatus: "DEFECTS_FOUND",
          evaluations: [],
          verifierOmissions: [outsideOmission, traversalOmission, unreviewedOmission, symlinkEscapeOmission]
        },
        {
          changeSet,
          scopeMode: "working-tree",
          verificationMode: "clean_challenge"
        }
      );
    } finally {
      fs.readFileSync = originalReadFile;
    }

    assert.equal(validated.ok, true);
    // 0 external file reads must have occurred (physical boundary enforced before read)
    assert.equal(externalFileReadCount, 0, "Must execute exactly 0 external file reads when symlink points outside repository");
    // All four omissions must have locatorAccurate false and evidenceSupport downgraded to INSUFFICIENT_EVIDENCE
    for (const om of validated.verifierOmissions) {
      assert.equal(om.locatorAccurate, false, `Omission for ${om.file} must not have valid locator accuracy`);
      assert.equal(om.evidenceSupport, "INSUFFICIENT_EVIDENCE", `Omission for ${om.file} must be downgraded to INSUFFICIENT_EVIDENCE`);
    }
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
    fs.rmSync(tmpOutside, { recursive: true, force: true });
  }
});

test("tdsmY-NEG: buildChangeSet in working-tree and staged scopes distinguishes baseCommitSha and does not attach base as headSha", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-cs-tdsmy-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    fs.writeFileSync(path.join(tmpDir, "file.txt"), "committed line\n");
    execFileSync("git", ["add", "file.txt"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Base commit"], { cwd: tmpDir, stdio: "ignore" });
    const baseCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf-8" }).trim();

    // Now modify file.txt in working tree (uncommitted)
    fs.writeFileSync(path.join(tmpDir, "file.txt"), "committed line\nuncommitted line\n");

    const cs = buildChangeSet(tmpDir, { scopeMode: "working-tree" });
    assert.equal(cs.ok, true);
    assert.equal(cs.scopeMode, "working-tree");

    // The base commit MUST be recorded as baseCommitSha
    assert.equal(cs.baseCommitSha, baseCommit, "Base commit must be recorded as baseCommitSha");
    assert.equal(cs.repository.baseCommitSha, baseCommit, "repository.baseCommitSha must preserve the base commit");

    // The working tree diff must NOT masquerade as an exact-head commit matching baseCommit!
    assert.notEqual(cs.headSha, baseCommit, "Working-tree changeSet.headSha must NOT masquerade as baseCommitSha");
    assert.notEqual(cs.repository.headSha, baseCommit, "Working-tree repository.headSha must NOT masquerade as baseCommitSha");
    assert.match(cs.contentIdentity, /^working-tree:[a-f0-9]{64}$/, "Working-tree must expose contentIdentity based on contentDigest");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
