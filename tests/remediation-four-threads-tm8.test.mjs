import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import {
  conductIndependentVerification,
  isTrustedContextPackage,
  registerTrustedContextPackage,
  validateContextPackageAuthenticity,
  isContextPackageBoundToChangeSet,
  isTrustedVerificationRecord,
  isSegregatedSyntheticRecord
} from "../src/core/independent-verifier.mjs";
import {
  findQualifiedFunctionDefinitions,
  stripCommentsAndStrings,
  extractCandidateCallSymbols,
  extractLocalCalleeContext
} from "../src/core/context-builder.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

// ============================================================================
// Thread tm8Ko: Context Authentication in conductIndependentVerification
// ============================================================================

test("tm8Ko-NEGATIVE: conductIndependentVerification rejects unauthenticated contextPackage, omits it from prompt, emits EXACT_HEAD_CONTEXT_FAILED gap, and refuses CLEAN", async () => {
  const forgedContext = {
    headSha: "0000000000000000000000000000000000000000",
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [{
          file: "src/auth.js",
          name: "authorizeUser",
          kind: "function",
          startLine: 1,
          endLine: 5,
          headerCode: "function authorizeUser() { return true; }",
          bodySnippet: "return true;"
        }]
      }
    }
  };

  const changeSet = {
    headSha: "0000000000000000000000000000000000000000",
    diffHunks: "--- a/src/auth.js\n+++ b/src/auth.js\n@@ -1,1 +1,1 @@\n- old\n+ new",
    files: [{ path: "src/auth.js", additions: 1, deletions: 1 }]
  };

  let capturedPrompt = "";
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  const record = await conductIndependentVerification(changeSet, [], mockAdapter, {
    contextPackage: forgedContext
  });

  assert.equal(capturedPrompt.includes("authorizeUser"), false, "Prompt must not include unauthenticated context package snippets");
  assert.equal(record.overallStatus, "UNCERTAIN", "Overall status must fail closed to UNCERTAIN when context package is unauthenticated");
  assert.equal(isTrustedVerificationRecord(record), true, "Record produced by conductIndependentVerification is an authentic in-process record holding UNCERTAIN status");
});

test("tm8Ko-NEGATIVE-SYNTHETIC: synthetic or mock verification cannot bypass context authentication and records are segregated", async () => {
  const forgedContext = {
    headSha: "0000000000000000000000000000000000000000",
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [{
          file: "src/auth.js",
          name: "forgedSnippet",
          kind: "function",
          startLine: 1,
          endLine: 5,
          headerCode: "function forgedSnippet() { return true; }",
          bodySnippet: "return true;"
        }]
      }
    }
  };

  const changeSet = {
    headSha: "0000000000000000000000000000000000000000",
    diffHunks: "--- a/src/auth.js\n+++ b/src/auth.js\n@@ -1,1 +1,1 @@\n- old\n+ new",
    files: [{ path: "src/auth.js", additions: 1, deletions: 1 }]
  };

  let capturedPrompt = "";
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  // Run with allowSynthetic: true
  const recordSynthetic = await conductIndependentVerification(changeSet, [], mockAdapter, {
    contextPackage: forgedContext,
    allowSynthetic: true
  });
  assert.equal(capturedPrompt.includes("forgedSnippet"), false, "Prompt must not include unauthenticated context package even with allowSynthetic");
  assert.equal(recordSynthetic.overallStatus, "UNCERTAIN", "Overall status must fail closed to UNCERTAIN");
  assert.equal(isTrustedVerificationRecord(recordSynthetic), false, "Synthetic record must never be in trustedVerificationRegistry");
  assert.equal(isSegregatedSyntheticRecord(recordSynthetic), true, "Synthetic record must be registered in segregatedSyntheticRegistry");

  // Run with mock: true
  capturedPrompt = "";
  const recordMock = await conductIndependentVerification(changeSet, [], mockAdapter, {
    contextPackage: forgedContext,
    mock: true
  });
  assert.equal(capturedPrompt.includes("forgedSnippet"), false, "Prompt must not include unauthenticated context package even with mock: true");
  assert.equal(isTrustedVerificationRecord(recordMock), false, "Mock record must never be in trustedVerificationRegistry");
  assert.equal(isSegregatedSyntheticRecord(recordMock), true, "Mock record must be in segregatedSyntheticRegistry");
});

test("tm8Ko-POSITIVE: conductIndependentVerification accepts authentic registered isTrustedContextPackage and renders it in prompt", async () => {
  const repo = process.cwd();
  const validFile = "src/core/independent-verifier.mjs";
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const content = execFileSync("git", ["show", `${headSha}:${validFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const lines = content.split("\n");
  const realSnippet = "export function isTrustedContextPackage(candidate)";
  const fnLineIdx = lines.findIndex(l => l.includes(realSnippet));
  assert.ok(fnLineIdx >= 0, "Sanity: function must exist at HEAD");

  const diffHunks = `diff --git a/${validFile} b/${validFile}\n--- a/${validFile}\n+++ b/${validFile}\n@@ -1,3 +1,3 @@\n-// test\n+// modified\n`;
  const contentDigest = crypto.createHash("sha256").update(diffHunks).digest("hex");

  const validPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest,
    targetFile: validFile,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: crypto.createHash("sha256").update(content).digest("hex"),
        calleesExtracted: ["isTrustedContextPackage"]
      }
    ],
    layers: {
      layer0Diff: diffHunks,
      layer1AstEnclosure: {
        callees: [
          {
            symbol: "isTrustedContextPackage",
            file: validFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            definition: realSnippet
          }
        ],
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            parameters: ["candidate"],
            headerCode: lines[fnLineIdx].trim(),
            bodySnippet: realSnippet
          }
        ],
        enclosingClasses: []
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  const changeSet = {
    headSha,
    repository: { root: repo },
    diffHunks,
    files: [{ path: validFile, additions: 1, deletions: 1 }]
  };

  const registered = registerTrustedContextPackage(validPkg, {
    repositoryRoot: repo,
    headSha,
    diffHunks,
    changeSet
  });
  assert.ok(registered, "Package must register successfully with authentic git evidence");
  assert.ok(isTrustedContextPackage(registered), "Registered package must be trusted");

  let capturedPrompt = "";
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  const record = await conductIndependentVerification(changeSet, [], mockAdapter, {
    contextPackage: registered
  });

  assert.equal(capturedPrompt.includes("export function isTrustedContextPackage(candidate)"), true, "Prompt must include authenticated context package");
  assert.equal(record.overallStatus, "CLEAN", "Authenticated clean verification preserves CLEAN overallStatus");
  assert.equal(isTrustedVerificationRecord(record), true, "Authenticated verification record must be in trustedVerificationRegistry");
  assert.equal(isSegregatedSyntheticRecord(record), false, "Authenticated verification record must not be in segregatedSyntheticRegistry");
});

test("tm8Ko-NEGATIVE-CROSS-CHANGESET-REUSE: conductIndependentVerification rejects pre-registered contextPackage from Diff A when verifying Diff B", async () => {
  const repo = process.cwd();
  const validFile = "src/core/independent-verifier.mjs";
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const content = execFileSync("git", ["show", `${headSha}:${validFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const lines = content.split("\n");
  const realSnippet = "export function isTrustedContextPackage(candidate)";
  const fnLineIdx = lines.findIndex(l => l.includes(realSnippet));

  // ChangeSet A and its authentic registered context package
  const diffHunksA = `diff --git a/${validFile} b/${validFile}\n--- a/${validFile}\n+++ b/${validFile}\n@@ -1,3 +1,3 @@\n-// diffA\n+// modifiedA\n`;
  const contentDigestA = crypto.createHash("sha256").update(diffHunksA).digest("hex");

  const validPkgA = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: contentDigestA,
    targetFile: validFile,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: crypto.createHash("sha256").update(content).digest("hex"),
        calleesExtracted: ["isTrustedContextPackage"]
      }
    ],
    layers: {
      layer0Diff: diffHunksA,
      layer1AstEnclosure: {
        callees: [],
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            parameters: ["candidate"],
            headerCode: lines[fnLineIdx].trim(),
            bodySnippet: realSnippet
          }
        ],
        enclosingClasses: []
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  const changeSetA = {
    headSha,
    repository: { root: repo },
    diffHunks: diffHunksA,
    files: [{ path: validFile, additions: 1, deletions: 1 }]
  };

  const registeredA = registerTrustedContextPackage(validPkgA, {
    repositoryRoot: repo,
    headSha,
    diffHunks: diffHunksA,
    changeSet: changeSetA
  });
  assert.ok(registeredA && isTrustedContextPackage(registeredA), "Package A must be registered as trusted");

  // Attempt to reuse registeredA for ChangeSet B (different diff)
  const diffHunksB = `diff --git a/${validFile} b/${validFile}\n--- a/${validFile}\n+++ b/${validFile}\n@@ -1,3 +1,3 @@\n-// diffB\n+// modifiedB\n`;
  const changeSetB = {
    headSha,
    repository: { root: repo },
    diffHunks: diffHunksB,
    files: [{ path: validFile, additions: 1, deletions: 1 }]
  };

  let capturedPrompt = "";
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  const record = await conductIndependentVerification(changeSetB, [], mockAdapter, {
    contextPackage: registeredA
  });

  assert.equal(capturedPrompt.includes("export function isTrustedContextPackage(candidate)"), false, "Prompt must not include context package from mismatched changeSet");
  assert.equal(record.overallStatus, "UNCERTAIN", "Verification must fail closed to UNCERTAIN when context package is not bound to changeSet");
  assert.ok(record.contextGaps?.some(g => g.code === "EXACT_HEAD_CONTEXT_FAILED" && g.symbol === "cross-changeset-context-mismatch"), "Must emit cross-changeset-context-mismatch gap");
});

test("tm8Ko-NEGATIVE-32CHAR-DIGEST: 32-character digest package cannot bypass ChangeSet binding or obtain Trusted CLEAN Record", async () => {
  const repo = process.cwd();
  const validFile = "src/core/independent-verifier.mjs";
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const content = execFileSync("git", ["show", `${headSha}:${validFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const lines = content.split("\n");
  const realSnippet = "export function isTrustedContextPackage(candidate)";
  const fnLineIdx = lines.findIndex(l => l.includes(realSnippet));

  const diffHunksA = `diff --git a/${validFile} b/${validFile}\n--- a/${validFile}\n+++ b/${validFile}\n@@ -1,3 +1,3 @@\n-// diffA\n+// modifiedA\n`;
  const digest32 = crypto.createHash("md5").update(diffHunksA).digest("hex"); // 32 chars
  assert.equal(digest32.length, 32);

  const pkg32 = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: digest32,
    targetFile: validFile,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: crypto.createHash("sha256").update(content).digest("hex"),
        calleesExtracted: ["isTrustedContextPackage"]
      }
    ],
    layers: {
      layer1AstEnclosure: {
        callees: [],
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            parameters: ["candidate"],
            headerCode: lines[fnLineIdx].trim(),
            bodySnippet: realSnippet
          }
        ],
        enclosingClasses: []
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  // 1. Authenticity validation must reject 32-char digest even without diffHunks in evidence
  const isAuthValid = validateContextPackageAuthenticity(pkg32, {
    repositoryRoot: repo,
    headSha
  });
  assert.equal(isAuthValid, false, "validateContextPackageAuthenticity must reject 32-char digest (only 64-char SHA-256 permitted)");

  // 2. ChangeSet binding check must fail closed when digest is 32 chars (invalid SHA-256)
  const diffHunksB = `diff --git a/${validFile} b/${validFile}\n--- a/${validFile}\n+++ b/${validFile}\n@@ -1,3 +1,3 @@\n-// diffB\n+// modifiedB\n`;
  const changeSetB = {
    headSha,
    repository: { root: repo },
    diffHunks: diffHunksB,
    files: [{ path: validFile, additions: 1, deletions: 1 }]
  };
  const isBound = isContextPackageBoundToChangeSet(pkg32, changeSetB, headSha);
  assert.equal(isBound, false, "isContextPackageBoundToChangeSet must reject 32-char digest package");

  // 3. When passed to conductIndependentVerification, 32-char package must fail closed to UNCERTAIN
  let capturedPrompt = "";
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  const record = await conductIndependentVerification(changeSetB, [], mockAdapter, {
    contextPackage: pkg32
  });

  assert.equal(capturedPrompt.includes("export function isTrustedContextPackage(candidate)"), false, "Prompt must not include 32-char digest context package");
  assert.equal(record.overallStatus, "UNCERTAIN", "Verification must fail closed to UNCERTAIN for 32-char digest package");
  assert.ok(record.contextGaps?.some(g => g.code === "EXACT_HEAD_CONTEXT_FAILED"), "Must emit EXACT_HEAD_CONTEXT_FAILED gap");
});

test("tm8Ko-NEGATIVE-POSITIVE-DIGEST-BOUNDS: missing digest, non-hex digest, and ungrounded changeSet fail closed; valid SHA-256 with declared digest succeeds", () => {
  const headSha = "a".repeat(40);
  const diffHunks = "--- a/file.js\n+++ b/file.js\n@@ -1 +1 @@\n-old\n+new\n";
  const matchingDigest = crypto.createHash("sha256").update(diffHunks).digest("hex");

  const basePkg = {
    headSha,
    contentDigest: matchingDigest,
    targetFile: "file.js"
  };

  const changeSet = {
    headSha,
    diffHunks,
    files: [{ path: "file.js" }]
  };

  // 1. Missing or empty digest fails closed
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: "" }, changeSet, headSha), false);
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: null }, changeSet, headSha), false);
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: undefined }, changeSet, headSha), false);

  // 2. Non-hex or invalid length digest fails closed
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: "not-a-digest" }, changeSet, headSha), false);
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: "c".repeat(32) }, changeSet, headSha), false);
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: "c".repeat(63) }, changeSet, headSha), false);
  assert.equal(isContextPackageBoundToChangeSet({ ...basePkg, contentDigest: "c".repeat(65) }, changeSet, headSha), false);

  // 3. Absent diffHunks without declared changeSet digest fails closed
  const changeSetNoDiffNoDigest = { headSha, files: [{ path: "file.js" }] };
  assert.equal(isContextPackageBoundToChangeSet(basePkg, changeSetNoDiffNoDigest, headSha), false);

  // 4. Absent diffHunks with conflicting declared digest fails closed
  const changeSetNoDiffConflicting = { headSha, contentDigest: "d".repeat(64), files: [{ path: "file.js" }] };
  assert.equal(isContextPackageBoundToChangeSet(basePkg, changeSetNoDiffConflicting, headSha), false);

  // 5. Absent diffHunks with matching declared digest succeeds
  const changeSetNoDiffMatching = { headSha, contentDigest: matchingDigest, files: [{ path: "file.js" }] };
  assert.equal(isContextPackageBoundToChangeSet(basePkg, changeSetNoDiffMatching, headSha), true);

  // 6. Valid SHA-256 matching physical diff succeeds
  assert.equal(isContextPackageBoundToChangeSet(basePkg, changeSet, headSha), true);
});

// ============================================================================
// Thread tm8Kl: Receiver Resolution Before Matching PascalCase Class
// ============================================================================

test("tm8Kl-NEGATIVE: findQualifiedFunctionDefinitions rejects comment-only constructors, different class instances, and ambiguous assignments", () => {
  const codeCommentOnly = [
    "class Auth {",
    "  authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "// const auth = new Auth();",
    "auth.authorize(user);"
  ];

  const matchesComment = findQualifiedFunctionDefinitions(codeCommentOnly, "auth", "authorize");
  assert.deepEqual(matchesComment, [], "Must not bind class Auth when constructor is commented out");

  const codeInstanceSecure = [
    "class Auth {",
    "  authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "class SecureAuth {",
    "  authorize(user) {",
    "    if (!user.isAdmin) throw new Error('forbidden');",
    "    return true;",
    "  }",
    "}",
    "",
    "const auth = new SecureAuth();",
    "auth.authorize(user);"
  ];

  const matchesSecure = findQualifiedFunctionDefinitions(codeInstanceSecure, "auth", "authorize");
  assert.deepEqual(matchesSecure, [], "Must not bind class Auth when auth receiver is an instance of SecureAuth");

  const codeAmbiguous = [
    "class Auth {",
    "  authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "const auth = new Auth();",
    "const auth = new SecureAuth();",
    "auth.authorize(user);"
  ];

  const matchesAmbiguous = findQualifiedFunctionDefinitions(codeAmbiguous, "auth", "authorize");
  assert.deepEqual(matchesAmbiguous, [], "Must not bind class Auth when constructor assignment is ambiguous");
});

test("tm8Kl-POSITIVE: findQualifiedFunctionDefinitions matches class when receiver is an authentic instance or explicitly PascalCase", () => {
  const codeProvableInstance = [
    "class Auth {",
    "  authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "const auth = new Auth();",
    "auth.authorize(user);"
  ];

  const matchesInstance = findQualifiedFunctionDefinitions(codeProvableInstance, "auth", "authorize");
  assert.equal(matchesInstance.length, 1, "Must bind class Auth when receiver is provably instantiated via new Auth()");
  assert.equal(matchesInstance[0].startLine, 2);
  assert.equal(matchesInstance[0].endLine, 4);

  const codePascal = [
    "class Auth {",
    "  static authorize(user) {",
    "    return true;",
    "  }",
    "}"
  ];

  const matches1 = findQualifiedFunctionDefinitions(codePascal, "Auth", "authorize");
  assert.equal(matches1.length, 1, "Must bind class Auth when qualifier is explicitly PascalCase 'Auth'");
  assert.equal(matches1[0].startLine, 2);
  assert.equal(matches1[0].endLine, 4);
});

test("tm8Kl-NEGATIVE-CROSS-SCOPE-RECEIVER: receiver in enclosing function with parameter shadows outer instantiation, preserves EXTERNAL_CALLEE_UNRESOLVED, and preserves context gap", () => {
  const code = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "function makeSample() {",
    "  const auth = new Auth();",
    "  return auth;",
    "}",
    "",
    "function review(auth, user) {",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call to findQualifiedFunctionDefinitions with callLine 11
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 11 });
  assert.deepEqual(matchesWithLine, [], "Must not bind class Auth when auth is a parameter of enclosing function review(auth, user)");

  // 2. Direct call to findQualifiedFunctionDefinitions without options (call site inferred or Default-Deny)
  const matchesWithoutOptions = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesWithoutOptions, [], "Must not bind class Auth when auth at call site is a parameter of review()");

  // 3. extractLocalCalleeContext must keep callee unextracted, emit EXTERNAL_CALLEE_UNRESOLVED, and preserve contextGap: 1
  const fileContent = code.join("\n");
  const diffHunks = [
    "@@ -9,4 +9,4 @@",
    " function review(auth, user) {",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(fileContent, diffHunks, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract Auth.authorize as a resolved callee when auth is a parameter");
  assert.equal(result.unresolvedCallees.length, 1, "Must record exactly 1 unresolved callee");
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1, "Must preserve context gap when sensitive callee is unresolved");
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-POSITIVE-SCOPED-RECEIVER: correctly binds class when receiver is instantiated in same function or at top-level module scope without parameter shadowing", () => {
  // Case A: Instantiated inside the same function
  const codeLocalInst = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "function review(user) {",
    "  const auth = new Auth();",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesLocal = findQualifiedFunctionDefinitions(codeLocalInst, "auth", "authorize", { callLine: 7 });
  assert.equal(matchesLocal.length, 1, "Must bind class Auth when instantiated inside the same function");
  assert.equal(matchesLocal[0].startLine, 2);

  // Case B: Instantiated at top-level module scope
  const codeTopLevel = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(user) {",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesTopLevel = findQualifiedFunctionDefinitions(codeTopLevel, "auth", "authorize", { callLine: 8 });
  assert.equal(matchesTopLevel.length, 1, "Must bind class Auth when instantiated at top-level module scope");
  assert.equal(matchesTopLevel[0].startLine, 2);

  // Case C: Instantiated at top-level, but shadowed by parameter in review(auth, user) -> MUST NOT BIND
  const codeShadowed = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(auth, user) {",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesShadowed = findQualifiedFunctionDefinitions(codeShadowed, "auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesShadowed, [], "Must not bind class Auth when top-level instance is shadowed by parameter auth");
});

test("tm8Kl-NEGATIVE-ANCESTOR-PARAMETER-SHADOWING: nested function receiver shadows outer instantiation via ancestor function parameter", () => {
  const codeA = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "const auth = new Auth();",
    "",
    "function review(auth, user) {",
    "  function nested() {",
    "    return auth.authorize(user);",
    "  }",
    "  return nested();",
    "}"
  ];

  // 1. Direct call to findQualifiedFunctionDefinitions with callLine 8 (inside nested())
  const matches = findQualifiedFunctionDefinitions(codeA, "auth", "authorize", { callLine: 8 });
  assert.deepEqual(matches, [], "Must not bind class Auth when auth is a parameter of ancestor enclosing function review()");

  // 2. Direct call without callLine (inferred call site at line 8)
  const matchesInferred = findQualifiedFunctionDefinitions(codeA, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site has ancestor parameter auth");

  // 3. extractLocalCalleeContext preserves EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diffA = [
    "@@ -7,4 +7,4 @@",
    "   function nested() {",
    "+    return auth.authorize(user);",
    "   }"
  ].join("\n");

  const result = extractLocalCalleeContext(codeA.join("\n"), diffA, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract Auth.authorize when auth is an ancestor parameter");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("tm8Kl-NEGATIVE-BLOCK-SCOPED-VARIABLE-ISOLATION: inner block declaration does not leak into subsequent statements", () => {
  const codeB = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "class SecureAuth {",
    "  authorize(user) { return false; }",
    "}",
    "const auth = new SecureAuth();",
    "",
    "function review(user) {",
    "  if (user) {",
    "    const auth = new Auth();",
    "  }",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call to findQualifiedFunctionDefinitions with callLine 13
  const matches = findQualifiedFunctionDefinitions(codeB, "auth", "authorize", { callLine: 13 });
  assert.deepEqual(matches, [], "Must not bind class Auth when new Auth() is confined to an unrelated inner block");

  // 2. Direct call without callLine (inferred call site at line 13)
  const matchesInferred = findQualifiedFunctionDefinitions(codeB, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site is outside inner block");

  const diffB = [
    "@@ -13,2 +13,2 @@",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(codeB.join("\n"), diffB, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract Auth.authorize when auth is from an inner block");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("tm8Kl-NEGATIVE-DESTRUCTURING-PARAMETER-SHADOWING: destructuring parameter { auth } shadows outer instance, preserves EXTERNAL_CALLEE_UNRESOLVED and contextGap", () => {
  const code = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review({ auth }, user) {",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with callLine 8
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesWithLine, [], "Must not bind class Auth when auth is a destructuring parameter");

  // 2. Direct call without callLine (inferred call site)
  const matchesInferred = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site has destructuring parameter auth");

  // 3. extractLocalCalleeContext must keep callee unextracted and emit EXTERNAL_CALLEE_UNRESOLVED
  const diff = [
    "@@ -7,3 +7,3 @@",
    " function review({ auth }, user) {",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract Auth.authorize when shadowed by destructuring parameter");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-ARROW-FUNCTION-SHADOWING: arrow function parameter (auth) shadows outer instance, preserves EXTERNAL_CALLEE_UNRESOLVED and contextGap", () => {
  const code = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "const review = (auth) => auth.authorize(user);"
  ];

  // 1. Direct call with callLine 7
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 7 });
  assert.deepEqual(matchesWithLine, [], "Must not bind class Auth when auth is an arrow function parameter");

  // 2. Direct call without callLine
  const matchesInferred = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site is in arrow function");

  // 3. extractLocalCalleeContext
  const diff = [
    "@@ -6,2 +6,2 @@",
    "+const review = (auth) => auth.authorize(user);"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract Auth.authorize in arrow function scope");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-REASSIGNMENT-SHADOWING: let declaration with reassignment rejects binding, preserves EXTERNAL_CALLEE_UNRESOLVED and contextGap", () => {
  const code = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "class SecureAuth {",
    "  authorize(user) { return false; }",
    "}",
    "",
    "let auth = new Auth();",
    "auth = new SecureAuth();",
    "",
    "function review(user) {",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with callLine 12
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 12 });
  assert.deepEqual(matchesWithLine, [], "Must not bind class Auth when auth is declared with let and reassigned");

  // 2. Direct call without callLine
  const matchesInferred = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site has reassigned receiver");

  // 3. extractLocalCalleeContext
  const diff = [
    "@@ -11,3 +11,3 @@",
    " function review(user) {",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract callee when receiver has been reassigned");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-CATCH-BLOCK-SHADOWING: catch (auth) block shadows outer instance, preserves EXTERNAL_CALLEE_UNRESOLVED and contextGap", () => {
  const code = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(user) {",
    "  try {",
    "    doSomething();",
    "  } catch (auth) {",
    "    return auth.authorize(user);",
    "  }",
    "}"
  ];

  // 1. Direct call with callLine 11
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 11 });
  assert.deepEqual(matchesWithLine, [], "Must not bind class Auth when auth is a catch parameter");

  // 2. Direct call without callLine
  const matchesInferred = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must not bind class Auth when inferred call site is in catch block");

  // 3. extractLocalCalleeContext
  const diff = [
    "@@ -10,3 +10,3 @@",
    "   } catch (auth) {",
    "+    return auth.authorize(user);",
    "   }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract callee when inside catch (auth)");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-PASCAL-CASE-INSTANCE-METHOD: PascalCase Auth.authorize(user) rejects non-static instance method and accepts only static method", () => {
  const codeInstanceOnly = [
    "class Auth {",
    "  authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "Auth.authorize(user);"
  ];

  // 1. Must reject non-static instance method when called via PascalCase Auth.authorize
  const matchesNonStatic = findQualifiedFunctionDefinitions(codeInstanceOnly, "Auth", "authorize");
  assert.deepEqual(matchesNonStatic, [], "Must reject instance method when qualifier is PascalCase Auth");

  // 2. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -6,2 +6,2 @@",
    "+Auth.authorize(user);"
  ].join("\n");

  const result = extractLocalCalleeContext(codeInstanceOnly.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not extract non-static method for PascalCase call");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "Auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "Auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");

  // 3. Positive control: static authorize(user) MUST be matched
  const codeStatic = [
    "class Auth {",
    "  static authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "Auth.authorize(user);"
  ];
  const matchesStatic = findQualifiedFunctionDefinitions(codeStatic, "Auth", "authorize");
  assert.equal(matchesStatic.length, 1, "Must accept explicit static method for PascalCase Auth");
  assert.equal(matchesStatic[0].startLine, 2);
  assert.equal(matchesStatic[0].endLine, 4);
});

test("tm8Kl-NEGATIVE-COMMENTED-DEFINITIONS: findQualifiedFunctionDefinitions rejects block-commented static methods, classes, and prototype definitions", () => {
  // 1. Block-commented static method in class
  const codeStaticComment = [
    "class Auth {",
    "  /*",
    "  static authorize(user) { return true; }",
    "  */",
    "  noop() {}",
    "}",
    "",
    "Auth.authorize(user);"
  ];
  const matchesStaticComment = findQualifiedFunctionDefinitions(codeStaticComment, "Auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesStaticComment, [], "Must reject static method inside block comment");

  // 2. Block-commented class
  const codeClassComment = [
    "/*",
    "class Auth {",
    "  static authorize(user) { return true; }",
    "}",
    "*/",
    "",
    "Auth.authorize(user);"
  ];
  const matchesClassComment = findQualifiedFunctionDefinitions(codeClassComment, "Auth", "authorize", { callLine: 7 });
  assert.deepEqual(matchesClassComment, [], "Must reject class declaration inside block comment");

  // 3. Block-commented prototype definition
  const codeProtoComment = [
    "/*",
    "auth.prototype.authorize = function(user) { return true; };",
    "*/",
    "",
    "auth.authorize(user);"
  ];
  const matchesProtoComment = findQualifiedFunctionDefinitions(codeProtoComment, "auth", "authorize", { callLine: 5 });
  assert.deepEqual(matchesProtoComment, [], "Must reject prototype assignment inside block comment");
});

test("tm8Kl-NEGATIVE-DESTRUCTURING-LOCAL-AND-REASSIGNMENT: rejects destructuring let/const declarations and destructuring reassignments", () => {
  // 1. Destructuring let in function body shadows outer instance
  const codeDestructLet = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(req, user) {",
    "  let { auth } = req;",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesDestructLet = findQualifiedFunctionDefinitions(codeDestructLet, "auth", "authorize", { callLine: 9 });
  assert.deepEqual(matchesDestructLet, [], "Must reject when receiver is shadowed by let { auth }");

  // 2. Destructuring const in function body shadows outer instance
  const codeDestructConst = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(req, user) {",
    "  const { auth } = req;",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesDestructConst = findQualifiedFunctionDefinitions(codeDestructConst, "auth", "authorize", { callLine: 9 });
  assert.deepEqual(matchesDestructConst, [], "Must reject when receiver is shadowed by const { auth }");

  // 3. Destructuring reassignment
  const codeDestructReassign = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function review(req, user) {",
    "  ({ auth } = req);",
    "  return auth.authorize(user);",
    "}"
  ];
  const matchesDestructReassign = findQualifiedFunctionDefinitions(codeDestructReassign, "auth", "authorize", { callLine: 9 });
  assert.deepEqual(matchesDestructReassign, [], "Must reject when receiver is mutated via ({ auth } = req)");

  // 4. Generator function destructuring parameter
  const codeGenFn = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "function* review({ auth }, user) {",
    "  yield auth.authorize(user);",
    "}"
  ];
  const matchesGenFn = findQualifiedFunctionDefinitions(codeGenFn, "auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesGenFn, [], "Must reject when receiver is shadowed in generator function parameter");

  // 5. Function expression destructuring parameter
  const codeFnExpr = [
    "class Auth {",
    "  authorize(user) { return true; }",
    "}",
    "",
    "const auth = new Auth();",
    "",
    "const review = function({ auth }, user) {",
    "  return auth.authorize(user);",
    "};"
  ];
  const matchesFnExpr = findQualifiedFunctionDefinitions(codeFnExpr, "auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesFnExpr, [], "Must reject when receiver is shadowed in function expression parameter");
});

// ============================================================================
// Thread tm8Kn: Preserve Calls Inside Template Interpolations
// ============================================================================

test("tm8Kn-NEGATIVE: stripCommentsAndStrings preserves calls inside template interpolations and extractCandidateCallSymbols detects sensitive callees", () => {
  const line = "return `allowed: ${authorizeUser(user)}`;";
  const stripped = stripCommentsAndStrings(line);
  assert.equal(stripped.includes("authorizeUser(user)"), true, "Stripped code must preserve interpolation expression");
  assert.equal(stripped.includes("allowed:"), false, "Stripped code must suppress literal template text");

  const calls = extractCandidateCallSymbols(line);
  assert.equal(calls.length, 1, "Must extract 1 call from template interpolation");
  assert.equal(calls[0].symbol, "authorizeUser");
  assert.equal(calls[0].isSensitive, true);
  assert.equal(calls[0].category, "security");
});

test("tm8Kn-NEGATIVE-MULTILINE-TEMPLATE: plain text inside multi-line template literal is not extracted as candidate call", () => {
  const multilineDiff = [
    "@@ -10,3 +10,4 @@",
    " const template = `",
    "+  some text before",
    "+  falseLabelAuthorize(user)",
    "+  some text after`;"
  ].join("\n");

  const calls = extractCandidateCallSymbols(multilineDiff);
  assert.equal(calls.length, 0, "Must not extract plain call text from within a multi-line template literal");
});

test("tm8Kn-POSITIVE-MULTILINE-TEMPLATE: interpolations inside multi-line template literals are preserved and extracted", () => {
  const multilineDiff = [
    "@@ -10,3 +10,4 @@",
    " const template = `",
    "+  some text before",
    "+  ${realAuthorizeUser(user)}",
    "+  some text after`;"
  ].join("\n");

  const calls = extractCandidateCallSymbols(multilineDiff);
  assert.equal(calls.length, 1, "Must extract calls from interpolations inside multi-line template literals");
  assert.equal(calls[0].symbol, "realAuthorizeUser");
});

test("tm8Kn-POSITIVE: stripCommentsAndStrings handles nested interpolations, regular strings, and escaped interpolations correctly", () => {
  const plainTemplate = "return `plain string with no interpolation`;";
  assert.equal(stripCommentsAndStrings(plainTemplate).trim(), "return ;", "Plain template string is completely suppressed");

  const regularString = 'const msg = "regular string"; authorize(msg);';
  const strippedRegular = stripCommentsAndStrings(regularString);
  assert.equal(strippedRegular.includes("regular string"), false, "Regular double-quote strings are stripped");
  assert.equal(strippedRegular.includes("authorize(msg)"), true, "Code outside strings is preserved");

  const escapedInterpolation = "return `literal: \\${escaped(call)} and ${realCall()}`;";
  const strippedEscaped = stripCommentsAndStrings(escapedInterpolation);
  assert.equal(strippedEscaped.includes("escaped(call)"), false, "Escaped interpolation must remain treated as literal string");
  assert.equal(strippedEscaped.includes("realCall()"), true, "Real interpolation must be preserved");

  const nestedInterpolation = "return `nested: ${format(`${innerCall()}`)}`;";
  const strippedNested = stripCommentsAndStrings(nestedInterpolation);
  assert.equal(strippedNested.includes("format"), true);
  assert.equal(strippedNested.includes("innerCall()"), true);
});

// ============================================================================
// Thread tm8Kq: Reject Malformed Tier Flags in CLI
// ============================================================================

test("tm8Kq-NEGATIVE: runCli rejects malformed --tier string, bare --tier, and non-integer tier with USAGE_ERROR", async () => {
  const stderrOutputs = [];
  const fakeIo = {
    stdout: { write: () => {} },
    stderr: { write: (msg) => stderrOutputs.push(msg) }
  };

  const invalidTiers = [
    "--tier=invalid_tier",
    "--tier=1.5",
    "--tier=0",
    "--tier=-1",
    "--tier=5",
    "--tier=99"
  ];

  for (const flag of invalidTiers) {
    stderrOutputs.length = 0;
    const code = await runCli(["review", flag, "--plan-only"], fakeIo);
    assert.equal(code, EXIT_CODES.USAGE_ERROR, `${flag} must return USAGE_ERROR`);
    assert.ok(stderrOutputs.some(s => s.includes("Invalid --tier")), `Must write usage error for ${flag}`);
  }

  // Space-separated tests
  for (const val of ["abc", "0", "-1", "5", "100"]) {
    stderrOutputs.length = 0;
    const code = await runCli(["review", "--tier", val, "--plan-only"], fakeIo);
    assert.equal(code, EXIT_CODES.USAGE_ERROR, `--tier ${val} must return USAGE_ERROR`);
    assert.ok(stderrOutputs.some(s => s.includes("Invalid --tier")), `Must write usage error for --tier ${val}`);
  }

  // Bare flag
  stderrOutputs.length = 0;
  const codeBare = await runCli(["review", "--tier", "--plan-only"], fakeIo);
  assert.equal(codeBare, EXIT_CODES.USAGE_ERROR, "Bare --tier without value must return USAGE_ERROR");
});

test("tm8Kq-POSITIVE: runCli accepts valid integer tier flags strictly within 1..4 without usage error", async () => {
  const stderrOutputs = [];
  const fakeIo = {
    stdout: { write: () => {} },
    stderr: { write: (msg) => stderrOutputs.push(msg) }
  };

  for (const t of [1, 2, 3, 4]) {
    stderrOutputs.length = 0;
    const code1 = await runCli(["doctor", `--tier=${t}`], fakeIo);
    assert.ok(code1 === EXIT_CODES.SUCCESS || code1 === EXIT_CODES.GATE_BLOCKED, `Valid --tier=${t} must not return USAGE_ERROR`);
    assert.ok(!stderrOutputs.some(s => s.includes("Invalid --tier")), `No invalid tier error for --tier=${t}`);

    stderrOutputs.length = 0;
    const code2 = await runCli(["doctor", "--tier", String(t)], fakeIo);
    assert.ok(code2 === EXIT_CODES.SUCCESS || code2 === EXIT_CODES.GATE_BLOCKED, `Valid --tier ${t} must not return USAGE_ERROR`);
    assert.ok(!stderrOutputs.some(s => s.includes("Invalid --tier")), `No invalid tier error for --tier ${t}`);
  }
});

test("tm8Kl-NEGATIVE-PASCAL-PARAM-SHADOWING: PascalCase Auth shadowed by function parameter Auth must reject binding and preserve context gap", () => {
  const code = [
    "class Auth {",
    "  static authorize(user) { return true; }",
    "}",
    "",
    "function review(Auth, user) {",
    "  return Auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 6
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 6 });
  assert.deepEqual(matchesWithLine, [], "Must reject PascalCase binding when shadowed by function parameter");

  // 2. Direct call without options (inferred call site or file-wide scan)
  const matchesInferred = findQualifiedFunctionDefinitions(code, "Auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must reject PascalCase binding when parameter shadows class name anywhere in file");

  // 3. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -5,3 +5,3 @@",
    " function review(Auth, user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind shadowed parameter Auth as class definition");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "Auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "Auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-PASCAL-LOCAL-CONST-SHADOWING: PascalCase Auth shadowed by local const Auth must reject binding and preserve context gap", () => {
  const code = [
    "class Auth {",
    "  static authorize(user) { return true; }",
    "}",
    "",
    "function review(user) {",
    "  const Auth = getAuth();",
    "  return Auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 7
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 7 });
  assert.deepEqual(matchesWithLine, [], "Must reject PascalCase binding when shadowed by local const Auth");

  // 2. Direct call without options
  const matchesInferred = findQualifiedFunctionDefinitions(code, "Auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must reject PascalCase binding when local const shadows class name");

  // 3. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -5,4 +5,4 @@",
    " function review(user) {",
    "   const Auth = getAuth();",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.ok(!result.callees.some(c => c.symbol === "authorize" || c.name === "authorize"), "Must not bind shadowed local const Auth as class definition");

  const authUnresolved = result.unresolvedCallees.find(c => c.symbol === "authorize" && c.qualifier === "Auth");
  assert.ok(authUnresolved, "Must preserve Auth.authorize in unresolvedCallees");
  assert.equal(authUnresolved.reason, "EXTERNAL_CALLEE_UNRESOLVED");

  const authGap = result.contextGaps.find(g => g.symbol === "authorize" && g.qualifier === "Auth");
  assert.ok(authGap, "Must preserve Auth.authorize contextGap");
  assert.equal(authGap.reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(authGap.category, "security");
});

test("tm8Kl-NEGATIVE-CROSS-FUNCTION-PROPERTY-ASSIGNMENT: property assignment in setup(auth) does not prove receiver identity for review(auth) and preserves context gap", () => {
  const code = [
    "function setup(auth) {",
    "  auth.authorize = function(user) { return true; };",
    "}",
    "",
    "function review(auth, user) {",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 6 (inside review)
  const matchesWithLine = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 6 });
  assert.deepEqual(matchesWithLine, [], "Must reject property assignment from different function setup(auth)");

  // 2. Direct call without options
  const matchesInferred = findQualifiedFunctionDefinitions(code, "auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must reject unverified property assignment on function parameter");

  // 3. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -5,3 +5,3 @@",
    " function review(auth, user) {",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind cross-function property assignment as receiver definition");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-CONDITIONAL-PROPERTY-ASSIGNMENT: property assignment inside if (false) does not prove runtime method presence and preserves context gap", () => {
  const code = [
    "function review(user) {",
    "  const auth = {};",
    "",
    "  if (false) {",
    "    auth.authorize = function(user) {",
    "      return true;",
    "    };",
    "  }",
    "",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 10 (inside review)
  const matches = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 10 });
  assert.deepEqual(matches, [], "Must reject property assignment inside conditional branch in verification mode");

  // 2. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -9,3 +9,3 @@",
    "   }",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind conditional property assignment as trusted callee");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-UNCALLED-CLOSURE-PROPERTY-ASSIGNMENT: property assignment inside uncalled nested closure does not prove runtime method presence and preserves context gap", () => {
  const code = [
    "function review(user) {",
    "  const auth = {};",
    "",
    "  function setup() {",
    "    auth.authorize = function(user) {",
    "      return true;",
    "    };",
    "  }",
    "",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 10
  const matches = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 10 });
  assert.deepEqual(matches, [], "Must reject property assignment inside uncalled closure in verification mode");

  // 2. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -9,3 +9,3 @@",
    "   }",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind uncalled closure property assignment as trusted callee");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-OVERWRITTEN-PROPERTY-ASSIGNMENT: property assignment subsequently overwritten by undefined does not prove runtime method presence and preserves context gap", () => {
  const code = [
    "function review(user) {",
    "  const auth = {};",
    "",
    "  auth.authorize = function(user) {",
    "    return true;",
    "  };",
    "  auth.authorize = undefined;",
    "",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Direct call with explicit callLine 9
  const matches = findQualifiedFunctionDefinitions(code, "auth", "authorize", { callLine: 9 });
  assert.deepEqual(matches, [], "Must reject overwritten property assignment in verification mode");

  // 2. extractLocalCalleeContext must preserve EXTERNAL_CALLEE_UNRESOLVED and contextGap: 1
  const diff = [
    "@@ -8,3 +8,3 @@",
    "   auth.authorize = undefined;",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind overwritten property assignment as trusted callee");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-CONSERVATIVE-TRADEOFF-FLAT-PROPERTY-ASSIGNMENT: ad-hoc property assignment on plain object fails closed in verification mode and preserves candidate search", () => {
  const codeLocalProp = [
    "function review(user) {",
    "  const auth = {};",
    "  auth.authorize = function(user) { return true; };",
    "  return auth.authorize(user);",
    "}"
  ];

  // 1. Verification Mode: Default-Deny fails closed to avoid False Cleans on conditional/overwritten assignments
  const matchesVerification = findQualifiedFunctionDefinitions(codeLocalProp, "auth", "authorize", { callLine: 4 });
  assert.deepEqual(matchesVerification, [], "Must fail-closed on ad-hoc object property assignment in verification mode");

  const diffLocalProp = [
    "@@ -3,3 +3,3 @@",
    "   auth.authorize = function(user) { return true; };",
    "+  return auth.authorize(user);",
    " }"
  ].join("\n");
  const resultLocalProp = extractLocalCalleeContext(codeLocalProp.join("\n"), diffLocalProp, "src/auth.js");
  assert.equal(resultLocalProp.callees.length, 0, "Ad-hoc property assignment on plain object must not be extracted as trusted callee");
  assert.equal(resultLocalProp.unresolvedCallees.length, 1);
  assert.equal(resultLocalProp.unresolvedCallees[0].symbol, "authorize");
  assert.equal(resultLocalProp.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(resultLocalProp.contextGaps.length, 1);
  assert.equal(resultLocalProp.contextGaps[0].symbol, "authorize");
  assert.equal(resultLocalProp.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  // 2. Candidate Search Mode: Preserves DIRECT_PROP_DEF_REGEX search capability
  const matchesCandidate = findQualifiedFunctionDefinitions(codeLocalProp, "auth", "authorize", { candidateSearchOnly: true });
  assert.equal(matchesCandidate.length, 1, "Candidate search mode preserves candidate definition search capability");
  assert.equal(matchesCandidate[0].startLine, 3);
  assert.equal(matchesCandidate[0].endLine, 3);
});

test("tm8Kl-POSITIVE-PASCAL-UNSHADOWED: unshadowed PascalCase static call binds properly", () => {
  const codePascal = [
    "class Auth {",
    "  static authorize(user) { return true; }",
    "}",
    "",
    "function review(user) {",
    "  return Auth.authorize(user);",
    "}"
  ];
  const matchesPascal = findQualifiedFunctionDefinitions(codePascal, "Auth", "authorize", { callLine: 6 });
  assert.equal(matchesPascal.length, 1, "Must bind unshadowed class Auth static authorize method");
  assert.equal(matchesPascal[0].startLine, 2);
  assert.equal(matchesPascal[0].endLine, 2);

  const diffPascal = [
    "@@ -5,3 +5,3 @@",
    " function review(user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");
  const resultPascal = extractLocalCalleeContext(codePascal.join("\n"), diffPascal, "src/auth.js");
  assert.equal(resultPascal.callees.length, 1);
  assert.equal(resultPascal.unresolvedCallees.length, 0);
  assert.equal(resultPascal.contextGaps.length, 0);
});

test("tm8Kl-NEGATIVE-PROTOTYPE-STATIC-CONFUSION: Auth.prototype.authorize must not match static Auth.authorize call, preserves EXTERNAL_CALLEE_UNRESOLVED and context gap", () => {
  const code = [
    "function Auth() {}",
    "",
    "Auth.prototype.authorize = function(user) {",
    "  return true;",
    "};",
    "",
    "function review(user) {",
    "  return Auth.authorize(user);",
    "}"
  ];

  // 1. Direct call in default verification mode returns []
  const matchesVerification = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 8 });
  assert.deepEqual(matchesVerification, [], "Must reject Prototype method definition for static Auth.authorize call in verification mode");

  // 2. Direct call without callLine also returns [] in verification mode
  const matchesInferred = findQualifiedFunctionDefinitions(code, "Auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must reject unverified prototype assignment in default verification mode");

  // 3. Candidate search mode preserves candidate definition search capability
  const matchesCandidate = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { candidateSearchOnly: true });
  assert.equal(matchesCandidate.length, 1, "Candidate search mode preserves candidate prototype definition");
  assert.equal(matchesCandidate[0].startLine, 3);
  assert.equal(matchesCandidate[0].endLine, 5);

  // 4. extractLocalCalleeContext preserves EXTERNAL_CALLEE_UNRESOLVED and context gap: 1
  const diff = [
    "@@ -7,3 +7,3 @@",
    " function review(user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind Prototype definition as trusted callee for static call");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "Auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "Auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-NEGATIVE-UNCALLED-CLOSURE-PROTOTYPE-ASSIGNMENT: Prototype assignment inside uncalled closure must not match static call and preserves context gap", () => {
  const code = [
    "function Auth() {}",
    "",
    "function setup() {",
    "  Auth.prototype.authorize = function(user) {",
    "    return true;",
    "  };",
    "}",
    "",
    "function review(user) {",
    "  return Auth.authorize(user);",
    "}"
  ];

  // 1. Direct call in default verification mode returns []
  const matches = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 10 });
  assert.deepEqual(matches, [], "Must reject prototype assignment inside uncalled setup() closure in verification mode");

  // 2. extractLocalCalleeContext preserves EXTERNAL_CALLEE_UNRESOLVED and context gap: 1
  const diff = [
    "@@ -9,3 +9,3 @@",
    " function review(user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0);
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "Auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "Auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-POSITIVE-CPP-SCOPE-DEFINITION: C++ scope definition Class::method binds properly in verification mode", () => {
  const codeCpp = [
    "class Auth {",
    "public:",
    "  bool authorize(const User& user);",
    "};",
    "",
    "bool Auth::authorize(const User& user) {",
    "  return true;",
    "}"
  ];

  const matches = findQualifiedFunctionDefinitions(codeCpp, "Auth", "authorize");
  assert.equal(matches.length, 1, "Must bind C++ out-of-line method definition Auth::authorize");
  assert.equal(matches[0].startLine, 6);
  assert.equal(matches[0].endLine, 8);
});

test("tm8Kl-NEGATIVE-NESTED-CLASS-STATIC-METHOD: static method in nested class must not match outer class call, preserves EXTERNAL_CALLEE_UNRESOLVED and context gap", () => {
  const code = [
    "class Auth {",
    "  static init() {",
    "    class Hidden {",
    "      static authorize(user) {",
    "        return true;",
    "      }",
    "    }",
    "    return Hidden;",
    "  }",
    "}",
    "",
    "function review(user) {",
    "  return Auth.authorize(user);",
    "}"
  ];

  // 1. findQualifiedFunctionDefinitions with explicit callLine 13 returns []
  const matches = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 13 });
  assert.deepEqual(matches, [], "Must reject static method of nested class Hidden for outer Auth.authorize call");

  // 2. findQualifiedFunctionDefinitions without options also returns []
  const matchesInferred = findQualifiedFunctionDefinitions(code, "Auth", "authorize");
  assert.deepEqual(matchesInferred, [], "Must reject nested class static method without explicit callLine");

  // 3. extractLocalCalleeContext preserves EXTERNAL_CALLEE_UNRESOLVED and context gap: 1
  const diff = [
    "@@ -12,3 +12,3 @@",
    " function review(user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 0, "Must not bind nested Hidden static method as Auth static method");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "authorize");
  assert.equal(result.unresolvedCallees[0].qualifier, "Auth");
  assert.equal(result.unresolvedCallees[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  assert.equal(result.contextGaps.length, 1);
  assert.equal(result.contextGaps[0].symbol, "authorize");
  assert.equal(result.contextGaps[0].qualifier, "Auth");
  assert.equal(result.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.equal(result.contextGaps[0].category, "security");
});

test("tm8Kl-POSITIVE-DIRECT-STATIC-METHOD-WITH-NESTED-CLASS: direct static method binds correctly while nested class static method is ignored", () => {
  const code = [
    "class Auth {",
    "  static init() {",
    "    class Hidden {",
    "      static authorize(user) {",
    "        return false;",
    "      }",
    "    }",
    "    return Hidden;",
    "  }",
    "",
    "  static authorize(user) {",
    "    return true;",
    "  }",
    "}",
    "",
    "function review(user) {",
    "  return Auth.authorize(user);",
    "}"
  ];

  const matches = findQualifiedFunctionDefinitions(code, "Auth", "authorize", { callLine: 18 });
  assert.equal(matches.length, 1, "Must bind direct static authorize method of Auth");
  assert.equal(matches[0].startLine, 11);
  assert.equal(matches[0].endLine, 13);

  const diff = [
    "@@ -17,3 +17,3 @@",
    " function review(user) {",
    "+  return Auth.authorize(user);",
    " }"
  ].join("\n");

  const result = extractLocalCalleeContext(code.join("\n"), diff, "src/auth.js");
  assert.equal(result.callees.length, 1);
  assert.equal(result.unresolvedCallees.length, 0);
  assert.equal(result.contextGaps.length, 0);
});
