import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import {
  executeStagedReview,
  evaluateCoverageContract
} from "../src/adapters/staged-review.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import {
  registerTrustedContextPackage,
  isTrustedContextPackage,
  validateContextPackageAuthenticity
} from "../src/core/independent-verifier.mjs";
import {
  buildContextPackage,
  safeReadWorkingTreeFile,
  findFunctionDefinitions,
  findBraceScopeEnd,
  extractBoundedFunctionSnippet,
  extractCandidateCallSymbols,
  extractLocalCalleeContext,
  MAX_WORKING_TREE_FILE_BYTES
} from "../src/core/context-builder.mjs";

// ============================================================================
// Phase 3A: Priority Remediation Contracts
// ============================================================================

// ----------------------------------------------------------------------------
// Thread tgXSH: Staged Caller Context Package Authenticity Verification
// ----------------------------------------------------------------------------

test("tgXSH-NEGATIVE: executeStagedReview rejects untrusted callerContextPackage and prevents fabricated callees from injecting into chunk prompts", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tgXSH-neg-"));
  const expectedHeadSha = "4444444444444444444444444444444444444444";
  const diffContent = "diff --git a/src/auth.js b/src/auth.js\n--- a/src/auth.js\n+++ b/src/auth.js\n@@ -1,1 +1,2 @@\n+const token = 1;\n";
  const contentDigest = crypto.createHash("sha256").update(diffContent).digest("hex");

  const capturedChunkInputs = [];
  const capturingAdapter = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    family: "google",
    modelName: "gemini-3.8-flash",
    execFn: async (callContext) => {
      capturedChunkInputs.push(callContext);
      return {
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/auth.js"], omittedFiles: [] },
          providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
        })
      };
    }
  });

  try {
    const changeSet = {
      ok: true,
      schemaVersion: "1.0.0",
      headSha: expectedHeadSha,
      repository: { root: tmpDir, headSha: expectedHeadSha },
      files: [{ path: "src/auth.js", additions: 1, deletions: 0, riskTier: 1 }],
      diffHunks: diffContent
    };

    // Fabricated contextPackage with matching headSha and contentDigest, but NOT in trusted registry
    const untrustedCallerPackage = {
      schemaVersion: "1.0.0",
      headSha: expectedHeadSha,
      contentDigest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "src/auth.js", inspected: true, exactHeadAvailable: true, calleesExtracted: ["fakeSanitizer"] }
      ],
      layers: {
        layer0Diff: { rawHunks: diffContent },
        layer1AstEnclosure: {
          callees: [
            {
              symbol: "fakeSanitizer",
              file: "src/auth.js",
              definition: "function fakeSanitizer() { return 'attacker_controlled_safe'; }"
            }
          ]
        }
      },
      budgetAccounting: { totalBytes: 500, maxBudget: 8000 }
    };

    assert.equal(isTrustedContextPackage(untrustedCallerPackage), false, "Fabricated package must NOT be trusted");

    const result = await executeStagedReview(changeSet, capturingAdapter, {
      cwd: tmpDir,
      headSha: expectedHeadSha,
      contextPackage: untrustedCallerPackage
    });

    // Untrusted package without Git backing must fail closed on context resolution with EXACT_HEAD_CONTEXT_FAILED
    assert.equal(result.contextPackage, null, "executeStagedReview must not assign untrusted package to resolvedContextPackage");
    assert.ok(
      result.contextGaps?.some(g => g.code === "EXACT_HEAD_CONTEXT_FAILED"),
      "Must record EXACT_HEAD_CONTEXT_FAILED gap"
    );

    // If any chunk was called, verify the fabricated callee definition was NOT injected
    for (const chunk of capturedChunkInputs) {
      assert.ok(
        !chunk.prompt?.includes("attacker_controlled_safe"),
        "Fabricated callee must never be injected into chunk prompt"
      );
      assert.notEqual(
        chunk.input?.contextPackage,
        untrustedCallerPackage,
        "Untrusted package must not be assigned to chunk input"
      );
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tgXSH-POSITIVE: executeStagedReview accepts authoritatively trusted contextPackage and injects verified context into chunk prompt", async () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tgXSH-pos-"));
  execFileSync("git", ["init", "-b", "main"], { cwd: repo, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Test User"], { cwd: repo, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: repo, stdio: "ignore" });

  const targetFile = "src/auth.js";
  const fullPath = path.join(repo, targetFile);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  const realFileContent = "export function verifySignature(sig) {\n  return sig.valid === true;\n}\n";
  fs.writeFileSync(fullPath, realFileContent);
  execFileSync("git", ["add", targetFile], { cwd: repo, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "Initial commit"], { cwd: repo, stdio: "ignore" });
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const diffContent = "--- a/src/auth.js\n+++ b/src/auth.js\n@@ -1,2 +1,3 @@\n export function verifySignature(sig) {\n+  const s = verifySignature(sig);\n";

  const capturedChunkInputs = [];
  const capturingAdapter = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    family: "google",
    modelName: "gemini-3.8-flash",
    execFn: async (callContext) => {
      capturedChunkInputs.push(callContext);
      return {
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: [targetFile], omittedFiles: [] },
          providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
        })
      };
    }
  });

  try {
    const changeSet = {
      ok: true,
      schemaVersion: "1.0.0",
      headSha,
      repository: { root: repo, headSha, name: "arcobaleno64/triad-flow" },
      files: [{ path: targetFile, additions: 1, deletions: 0, riskTier: 1 }],
      diffHunks: diffContent
    };

    // Authentic buildContextPackage creates genuine Git-backed package and registers it
    const authenticPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: repo,
      headSha,
      runId: "tgXSH-pos-run"
    });

    assert.equal(isTrustedContextPackage(authenticPkg), true, "Authentic package must be trusted");

    const result = await executeStagedReview(changeSet, capturingAdapter, {
      cwd: repo,
      headSha,
      contextPackage: authenticPkg
    });

    assert.equal(result.ok, true, "executeStagedReview must succeed with authentic trusted package");
    assert.equal(result.status, "completed");
    assert.ok(capturedChunkInputs.length > 0, "Chunk must be reviewed");
    assert.equal(capturedChunkInputs[0].input.contextPackage, authenticPkg, "Chunk must receive authentic trusted package");
    assert.match(capturedChunkInputs[0].prompt, /verifySignature/, "Chunk prompt must receive authentic context");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

// ----------------------------------------------------------------------------
// Thread tgXSI: Manifest Global Coverage Verification
// ----------------------------------------------------------------------------

test("tgXSI-NEGATIVE: registerTrustedContextPackage rejects packages with unmanifested callees or unmanifested enclosing functions", () => {
  const repo = process.cwd();
  const validFile = "src/core/independent-verifier.mjs";
  const validContent = fs.readFileSync(path.join(repo, validFile), "utf8");
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

  // Case 1: Callee references an unmanifested file path
  const unmanifestedCalleePkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        callees: [
          { symbol: "secretAuth", file: "src/unmanifested.js", definition: "function secretAuth() {}" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(unmanifestedCalleePkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with callee from unmanifested file"
  );
  assert.equal(
    registerTrustedContextPackage(unmanifestedCalleePkg, { repositoryRoot: repo, headSha }),
    null,
    "registerTrustedContextPackage must return null for unmanifested callee"
  );

  // Case 2: Callee references a manifest entry with exactHeadAvailable: false
  const unavailableCalleePkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: false, exactHeadUnavailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        callees: [
          { symbol: "secretAuth", file: validFile, definition: "function secretAuth() {}" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(unavailableCalleePkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package when manifest file has exactHeadAvailable: false"
  );

  // Case 3: Enclosing function references an unmanifested file
  const unmanifestedFnPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        enclosingFunctions: [
          { name: "fakeEnclosure", file: "src/unmanifested-enclosure.js", bodySnippet: "function fakeEnclosure() {}" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(unmanifestedFnPkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with enclosing function from unmanifested file"
  );

  // Case 4: Callee snippet does not physically exist in the authentic Git object
  const nonExistentSnippetPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: ["fakeFunctionNeverInGit"] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        callees: [
          { symbol: "fakeFunctionNeverInGit", file: validFile, definition: "function fakeFunctionNeverInGit() { return 'evil'; }" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(nonExistentSnippetPkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with callee snippet not in authentic Git content"
  );

  // Case 5: Callee using 'path' instead of 'file' with fabricated snippet must NOT bypass Git verification
  const pathBypassPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        callees: [
          { symbol: "fakeBypass", path: validFile, definition: "function fakeBypass() { return 'ATTACKER_INJECTED'; }" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(pathBypassPkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with fabricated callee using 'path' property"
  );

  // Case 6: Enclosing class without file or referencing unmanifested file must be rejected
  const unmanifestedClassPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        enclosingClasses: [
          { name: "UnmanifestedClass", file: "src/unmanifested-class.js", bodySnippet: "class UnmanifestedClass {}" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(unmanifestedClassPkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with enclosing class from unmanifested file"
  );

  // Case 7: Enclosing class snippet does not physically exist in Git object
  const nonExistentClassSnippetPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "1".repeat(64),
    fileCoverageManifest: [
      { file: validFile, inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        enclosingClasses: [
          { name: "FakeClassNeverInGit", file: validFile, bodySnippet: "class FakeClassNeverInGit { evil() {} }" }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(nonExistentClassSnippetPkg, { repositoryRoot: repo, headSha }),
    false,
    "validateContextPackageAuthenticity must reject package with enclosing class snippet not in Git"
  );

  // Case 8: Enclosing class with real manifest, valid sourceDigest, valid contentDigest,
  // and only { name, file, startLine, endLine } (no snippet/definition) where class name is forged
  const headValidContent = execFileSync("git", ["show", `${headSha}:${validFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const validSourceDigest = crypto.createHash("sha256").update(headValidContent).digest("hex");
  const realDiff = "diff --git a/src/core/independent-verifier.mjs b/src/core/independent-verifier.mjs\n@@ -1,1 +1,1 @@\n";
  const realDiffDigest = crypto.createHash("sha256").update(realDiff).digest("hex");

  const forgedClassMetadataOnlyPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingClasses: [
          {
            name: "ForgedAllowEverythingSecurityPolicy",
            file: validFile,
            startLine: 1,
            endLine: 3
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(forgedClassMetadataOnlyPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject forged class metadata { name, file, startLine, endLine } even when snippet is omitted and digests match"
  );
  assert.equal(
    registerTrustedContextPackage(forgedClassMetadataOnlyPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null for forged class metadata"
  );
  assert.equal(
    isTrustedContextPackage(forgedClassMetadataOnlyPkg),
    false,
    "isTrustedContextPackage must be false for forged class metadata"
  );

  // Case 9: Enclosing function with forged headerCode and omitted bodySnippet must be rejected
  const forgedFnMetadataOnlyPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "forgedBypassAuth",
            kind: "function",
            file: validFile,
            startLine: 1,
            endLine: 3,
            headerCode: "function forgedBypassAuth() { return true; }"
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    registerTrustedContextPackage(forgedFnMetadataOnlyPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null for forged enclosing function headerCode"
  );
  assert.equal(
    isTrustedContextPackage(forgedFnMetadataOnlyPkg),
    false,
    "isTrustedContextPackage must be false for forged enclosing function headerCode"
  );

  // Case 10 (Reproduced Defect): Enclosing function with forged name ("ForgedAllowEverythingSecurityPolicy"),
  // omitted headerCode, valid line bounds, and a REAL bodySnippet from independent-verifier.mjs
  const headValidLines = headValidContent.split("\n");
  const realFnSnippet = "export function isTrustedContextPackage(candidate)";
  const realFnLineIdx = headValidLines.findIndex(l => l.includes(realFnSnippet));
  assert.ok(realFnLineIdx >= 0, "Sanity: real snippet must exist in committed independent-verifier.mjs");

  const forgedFnNameWithRealSnippetPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "ForgedAllowEverythingSecurityPolicy",
            kind: "function",
            file: validFile,
            startLine: realFnLineIdx + 1,
            endLine: realFnLineIdx + 3,
            bodySnippet: realFnSnippet
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(forgedFnNameWithRealSnippetPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject forged fn.name paired with a real bodySnippet"
  );
  assert.equal(
    registerTrustedContextPackage(forgedFnNameWithRealSnippetPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null when fn.name is forged even if bodySnippet exists in Git"
  );
  assert.equal(
    isTrustedContextPackage(forgedFnNameWithRealSnippetPkg),
    false,
    "isTrustedContextPackage must be false when fn.name does not match the authentic Git declaration"
  );

  // Case 11: Enclosing function using anonymous_L prefix at a line that is NOT an anonymous function declaration
  const forgedAnonPrefixPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: `anonymous_L${realFnLineIdx + 1}`,
            kind: "function",
            file: validFile,
            startLine: realFnLineIdx + 1,
            endLine: realFnLineIdx + 3
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(forgedAnonPrefixPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject anonymous_L prefix when line is not an anonymous function declaration"
  );
  assert.equal(
    registerTrustedContextPackage(forgedAnonPrefixPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null for forged anonymous_L enclosure"
  );

  // Case 12: Real function name paired with mismatched startLine/endLine or snippet from a different function
  const forgedFnLineMismatchPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: 1,
            endLine: 5,
            bodySnippet: headValidLines[0]
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(forgedFnLineMismatchPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject real fn.name placed at wrong startLine/endLine"
  );

  // Case 13 (Reproduced Parameter Bypass): Real function name, real startLine/endLine, real bodySnippet,
  // omitted headerCode, and forged fn.parameters (e.g. ["candidate", "overrideSecurity = true", "ALLOW_ALL = true"])
  const forgedFnParamsPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: realFnLineIdx + 1,
            endLine: realFnLineIdx + 3,
            parameters: ["candidate", "overrideSecurity = true", "ALLOW_ALL = true"],
            bodySnippet: headValidLines[realFnLineIdx].trim()
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(forgedFnParamsPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject forged fn.parameters even when headerCode is omitted and name/lines/snippet are real"
  );
  assert.equal(
    registerTrustedContextPackage(forgedFnParamsPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null when fn.parameters do not match authentic Git declaration"
  );
  assert.equal(
    isTrustedContextPackage(forgedFnParamsPkg),
    false,
    "isTrustedContextPackage must be false when fn.parameters are forged"
  );

  // Case 14 (Stretched endLine Boundary Bypass): Real function name and startLine,
  // but endLine stretched past the function's true closing brace to attribute a subsequent function's snippet
  const stretchedEndLinePkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validFile,
            startLine: realFnLineIdx + 1,
            endLine: Math.min(headValidLines.length, realFnLineIdx + 150),
            bodySnippet: headValidLines[Math.min(headValidLines.length - 1, realFnLineIdx + 50)].trim()
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(stretchedEndLinePkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must reject fn.endLine stretched beyond the authentic brace scope end of the function"
  );
  assert.equal(
    registerTrustedContextPackage(stretchedEndLinePkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null when fn.endLine exceeds authentic function scope boundary"
  );

  // Case 15 (Reproduced Frozen Metadata Bypass): Pre-frozen enclosingFunction missing headerCode and parameters
  const frozenIncompleteFn = Object.freeze({
    name: "isTrustedContextPackage",
    kind: "function",
    file: validFile,
    startLine: realFnLineIdx + 1,
    endLine: realFnLineIdx + 3,
    bodySnippet: realFnSnippet
  });
  const frozenIncompleteFnPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: realDiffDigest,
    fileCoverageManifest: [
      {
        file: validFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: validSourceDigest,
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: { rawHunks: realDiff },
      layer1AstEnclosure: {
        enclosingFunctions: [frozenIncompleteFn]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  assert.equal(
    validateContextPackageAuthenticity(frozenIncompleteFnPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    false,
    "validateContextPackageAuthenticity must fail closed when pre-frozen fn omits headerCode/parameters and cannot be canonically hydrated"
  );
  assert.equal(
    registerTrustedContextPackage(frozenIncompleteFnPkg, {
      repositoryRoot: repo,
      headSha,
      diffHunks: realDiff
    }),
    null,
    "registerTrustedContextPackage must return null for pre-frozen fn lacking canonical fields"
  );
  assert.equal(
    isTrustedContextPackage(frozenIncompleteFnPkg),
    false,
    "isTrustedContextPackage must be false for pre-frozen fn lacking canonical fields"
  );

  // Case 16: Sealed / non-extensible / read-only property enclosingFunction missing canonical fields must fail closed without throwing
  const sealedIncompleteFn = Object.seal({
    name: "isTrustedContextPackage",
    kind: "function",
    file: validFile,
    startLine: realFnLineIdx + 1,
    endLine: realFnLineIdx + 3,
    bodySnippet: realFnSnippet
  });
  const readOnlyHeaderFn = {
    name: "isTrustedContextPackage",
    kind: "function",
    file: validFile,
    startLine: realFnLineIdx + 1,
    endLine: realFnLineIdx + 3,
    parameters: ["candidate"],
    bodySnippet: realFnSnippet
  };
  Object.defineProperty(readOnlyHeaderFn, "headerCode", {
    value: "",
    writable: false,
    configurable: false,
    enumerable: true
  });

  for (const [label, fnCandidate] of [["sealed", sealedIncompleteFn], ["read-only headerCode", readOnlyHeaderFn]]) {
    const candidatePkg = {
      schemaVersion: "1.0.0",
      headSha,
      repositoryRoot: repo,
      contentDigest: realDiffDigest,
      fileCoverageManifest: [
        {
          file: validFile,
          inspected: true,
          exactHeadAvailable: true,
          sourceDigest: validSourceDigest,
          calleesExtracted: []
        }
      ],
      layers: {
        layer0Diff: { rawHunks: realDiff },
        layer1AstEnclosure: {
          enclosingFunctions: [fnCandidate]
        }
      },
      budgetAccounting: { consumedBytes: 100 }
    };

    assert.equal(
      registerTrustedContextPackage(candidatePkg, {
        repositoryRoot: repo,
        headSha,
        diffHunks: realDiff
      }),
      null,
      `registerTrustedContextPackage must return null without throwing for ${label} fn missing canonical fields`
    );
    assert.equal(
      isTrustedContextPackage(candidatePkg),
      false,
      `isTrustedContextPackage must be false for ${label} fn missing canonical fields`
    );
  }
});

test("tgXSI-POSITIVE: registerTrustedContextPackage accepts packages where all callees, enclosing functions (function, method, arrow), and enclosing classes map to valid manifest entries and exist in Git", () => {
  const repo = process.cwd();
  const validVerifierFile = "src/core/independent-verifier.mjs";
  const validAdapterFile = "src/adapters/cli-transport.mjs";
  const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  const verifierContent = execFileSync("git", ["show", `${headSha}:${validVerifierFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");
  const adapterContent = execFileSync("git", ["show", `${headSha}:${validAdapterFile}`], { cwd: repo, encoding: "utf8" }).replace(/\r\n/g, "\n");

  // Locate real function in independent-verifier.mjs at HEAD
  const verifierLines = verifierContent.split("\n");
  const realSnippet = "export function isTrustedContextPackage(candidate)";
  const fnLineIdx = verifierLines.findIndex(l => l.includes(realSnippet));
  assert.ok(fnLineIdx >= 0, "Sanity: function must exist in independent-verifier.mjs at HEAD");

  // Locate real class CliReviewAdapter, method executeReview, and arrow function abortHandler in cli-transport.mjs at HEAD
  const adapterLines = adapterContent.split("\n");
  const clsLineIdx = adapterLines.findIndex(l => /^\s*export\s+class\s+CliReviewAdapter\b/.test(l));
  assert.ok(clsLineIdx >= 0, "Sanity: class CliReviewAdapter must exist in cli-transport.mjs at HEAD");
  const methodLineIdx = adapterLines.findIndex(l => /^\s*async\s+executeReview\s*\(/.test(l));
  assert.ok(methodLineIdx >= 0, "Sanity: method executeReview must exist in cli-transport.mjs at HEAD");
  const arrowLineIdx = adapterLines.findIndex(l => /^\s*const\s+abortHandler\s*=\s*\(\)\s*=>\s*\{/.test(l));
  assert.ok(arrowLineIdx >= 0, "Sanity: arrow function abortHandler must exist in cli-transport.mjs at HEAD");

  // Pre-frozen complete function entry with all canonical fields already verified and present
  const completeFrozenArrowFn = Object.freeze({
    name: "abortHandler",
    kind: "arrow",
    file: validAdapterFile,
    startLine: arrowLineIdx + 1,
    endLine: arrowLineIdx + 3,
    parameters: Object.freeze([]),
    headerCode: adapterLines[arrowLineIdx].trim(),
    bodySnippet: adapterLines.slice(arrowLineIdx, arrowLineIdx + 2).join("\n").trim()
  });

  const validPkg = {
    schemaVersion: "1.0.0",
    headSha,
    repositoryRoot: repo,
    contentDigest: "2".repeat(64),
    fileCoverageManifest: [
      {
        file: validVerifierFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: crypto.createHash("sha256").update(verifierContent).digest("hex"),
        calleesExtracted: ["isTrustedContextPackage"]
      },
      {
        file: validAdapterFile,
        inspected: true,
        exactHeadAvailable: true,
        sourceDigest: crypto.createHash("sha256").update(adapterContent).digest("hex"),
        calleesExtracted: []
      }
    ],
    layers: {
      layer0Diff: "",
      layer1AstEnclosure: {
        callees: [
          {
            symbol: "isTrustedContextPackage",
            file: validVerifierFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            definition: realSnippet
          }
        ],
        enclosingFunctions: [
          {
            name: "isTrustedContextPackage",
            kind: "function",
            file: validVerifierFile,
            startLine: fnLineIdx + 1,
            endLine: fnLineIdx + 3,
            parameters: ["candidate"],
            bodySnippet: realSnippet
          },
          completeFrozenArrowFn,
          {
            name: "executeReview",
            kind: "method",
            file: validAdapterFile,
            startLine: methodLineIdx + 1,
            endLine: methodLineIdx + 10,
            parameters: ["rawInput"],
            headerCode: adapterLines[methodLineIdx].trim(),
            bodySnippet: adapterLines.slice(methodLineIdx, methodLineIdx + 3).join("\n").trim()
          }
        ],
        enclosingClasses: [
          {
            name: "CliReviewAdapter",
            file: validAdapterFile,
            startLine: clsLineIdx + 1,
            endLine: clsLineIdx + 20
          }
        ]
      }
    },
    budgetAccounting: { consumedBytes: 100 }
  };

  const registered = registerTrustedContextPackage(validPkg, { repositoryRoot: repo, headSha });
  assert.equal(registered, validPkg, "Package with genuine Git-backed callees, enclosingFunctions (including complete pre-frozen entry), and enclosingClasses must register");
  assert.equal(isTrustedContextPackage(validPkg), true, "Registered package must be trusted");
  assert.equal(
    validPkg.layers.layer1AstEnclosure.enclosingFunctions[0].headerCode,
    verifierLines[fnLineIdx].trim(),
    "Registered mutable enclosingFunction without headerCode must have canonical headerCode hydrated from verified Git line"
  );
});

// ----------------------------------------------------------------------------
// Thread tgXSK: Working Tree Repository Containment and File Size Ceiling
// ----------------------------------------------------------------------------

test("tgXSK-NEGATIVE: safeReadWorkingTreeFile and buildContextPackage block path traversal, symlink escapes, and oversized files", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tgXSK-repo-"));
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tgXSK-outside-"));

  try {
    // 1. Path traversal escape (..)
    const traversalPath = "../outside-secret.txt";
    const resTraversal = safeReadWorkingTreeFile(repo, traversalPath);
    assert.equal(resTraversal.ok, false, "Must reject path traversal");
    assert.equal(resTraversal.reason, "REPOSITORY_PATH_ESCAPE");

    // 2. Absolute path escape outside repo
    const outsideFile = path.join(outsideDir, "secret.txt");
    fs.writeFileSync(outsideFile, "super_sensitive_token");
    const resAbs = safeReadWorkingTreeFile(repo, outsideFile);
    assert.equal(resAbs.ok, false, "Must reject absolute path escaping repoRoot");
    assert.equal(resAbs.reason, "REPOSITORY_PATH_ESCAPE");

    // 3. Symlink pointing outside repo
    const symlinkPath = path.join(repo, "symlink_escape.txt");
    let symlinkCreated = false;
    try {
      fs.symlinkSync(outsideFile, symlinkPath, "file");
      symlinkCreated = true;
    } catch {
      // On Windows without SeCreateSymbolicLinkPrivilege, symlinks might fail; test if created
    }

    if (symlinkCreated) {
      const resSymlink = safeReadWorkingTreeFile(repo, "symlink_escape.txt");
      assert.equal(resSymlink.ok, false, "Must reject symlink escaping repository boundary");
      assert.equal(resSymlink.reason, "REPOSITORY_PATH_ESCAPE");
    }

    // 4. Oversized file exceeding ceiling
    const largeFile = path.join(repo, "large.txt");
    const largeContent = Buffer.alloc(MAX_WORKING_TREE_FILE_BYTES + 1024, "A");
    fs.writeFileSync(largeFile, largeContent);

    const resLarge = safeReadWorkingTreeFile(repo, "large.txt");
    assert.equal(resLarge.ok, false, "Must reject oversized file exceeding 2 MB ceiling");
    assert.equal(resLarge.reason, "REPOSITORY_PATH_ESCAPE");
    assert.equal(resLarge.content, null, "Must not read oversized content");

    // 5. buildContextPackage integration on escaped path fails closed
    const changeSet = {
      scopeMode: "working-tree",
      files: [{ path: outsideFile, additions: 1, deletions: 0 }],
      diffHunks: "+ some change\n"
    };

    const pkg = buildContextPackage(changeSet, null, { repositoryRoot: repo });
    assert.equal(pkg.ok, false, "buildContextPackage must fail closed on repository escape");
    assert.equal(pkg.error?.code, "REPOSITORY_PATH_ESCAPE");
    assert.ok(pkg.contextGaps.some(g => g.reason === "REPOSITORY_PATH_ESCAPE" || g.code === "REPOSITORY_PATH_ESCAPE"));

    // 6. Multi-file changeset: file 1 escapes, file 2 is valid -> escape gap isolated to file 1, package fails closed
    const validFileInside = path.join(repo, "src", "inside.js");
    fs.mkdirSync(path.dirname(validFileInside), { recursive: true });
    fs.writeFileSync(validFileInside, "export const inside = true;\n");

    const multiFileChangeSet = {
      scopeMode: "working-tree",
      files: [
        { path: outsideFile, additions: 1, deletions: 0 },
        { path: "src/inside.js", additions: 1, deletions: 0 }
      ],
      diffHunks: "diff --git a/outside.txt b/outside.txt\n+outside\ndiff --git a/src/inside.js b/src/inside.js\n+inside\n"
    };

    const multiPkg = buildContextPackage(multiFileChangeSet, null, { repositoryRoot: repo });
    assert.equal(multiPkg.ok, false, "Multi-file package with one escape must fail closed");
    assert.equal(multiPkg.error?.code, "REPOSITORY_PATH_ESCAPE");
    const escapeGaps = multiPkg.contextGaps.filter(g => g.code === "REPOSITORY_PATH_ESCAPE" || g.reason === "REPOSITORY_PATH_ESCAPE");
    assert.ok(escapeGaps.some(g => g.file === outsideFile), "Outside file must have escape gap");
    assert.ok(!escapeGaps.some(g => g.file === "src/inside.js"), "Valid file inside repo must NOT have escape gap");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("tgXSK-POSITIVE: safeReadWorkingTreeFile and buildContextPackage read valid repository files under ceiling", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tgXSK-repo-pos-"));

  try {
    const validFile = path.join(repo, "src", "index.js");
    fs.mkdirSync(path.dirname(validFile), { recursive: true });
    fs.writeFileSync(validFile, "export function hello() { return 'world'; }\n");

    const res = safeReadWorkingTreeFile(repo, "src/index.js");
    assert.equal(res.ok, true, "Valid file inside repo must read successfully");
    assert.equal(res.exists, true);
    assert.match(res.content, /hello\(\)/);

    const changeSet = {
      scopeMode: "working-tree",
      files: [{ path: "src/index.js", additions: 1, deletions: 0 }],
      diffHunks: "--- a/src/index.js\n+++ b/src/index.js\n@@ -1 +1,2 @@\n+const x = 1;\n"
    };

    const pkg = buildContextPackage(changeSet, null, { repositoryRoot: repo });
    assert.equal(pkg.ok, true, "buildContextPackage must succeed for valid contained file");
    assert.ok(!pkg.contextGaps.some(g => g.reason === "REPOSITORY_PATH_ESCAPE"));
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

// ============================================================================
// Phase 3B: Context Integrity Remediation Contracts
// ============================================================================

// ----------------------------------------------------------------------------
// Thread tgXSQ: Brace Matcher Function Body Start Localization
// ----------------------------------------------------------------------------

test("tgXSQ-NEGATIVE: parameter destructuring braces do not cause premature function closure and unclosed functions output incomplete", () => {
  // Case 1: Function with parameter destructuring: ({ role, tenantId }) { ... }
  // Parameter closing brace '}' on line 1 must not be mistaken for function body end
  const lines = [
    "export function authorizeUser({ role, tenantId }) {",
    "  if (role !== 'admin') {",
    "    throw new Error('Forbidden');",
    "  }",
    "  return { authorized: true, tenantId };",
    "}"
  ];

  const defs = findFunctionDefinitions(lines, "authorizeUser");
  assert.equal(defs.length, 1, "Must find exactly one function definition");
  assert.equal(defs[0].startLine, 1);
  assert.equal(defs[0].endLine, 6, "End line must be line 6, not line 1 truncated at parameter brace '}'");

  // Case 2: Unclosed function body must return extractionMode: 'incomplete', never 'full_body'
  const unclosedLines = [
    "export function authorizeUser({ role, tenantId }) {",
    "  if (role !== 'admin') {",
    "    return false;"
    // Note: missing closing brace
  ];

  const snippet = extractBoundedFunctionSnippet(unclosedLines, 1, 3);
  assert.equal(snippet.extractionMode, "incomplete", "Unclosed function must output incomplete, never full_body");
});

test("tgXSQ-POSITIVE: complete function with parameter destructuring extracts full_body scope correctly", () => {
  const lines = [
    "function processPayload({ data, options = {} }) {",
    "  const sanitized = sanitize(data);",
    "  return sanitized;",
    "}"
  ];

  const defs = findFunctionDefinitions(lines, "processPayload");
  assert.equal(defs.length, 1);
  assert.equal(defs[0].startLine, 1);
  assert.equal(defs[0].endLine, 4);

  const snippet = extractBoundedFunctionSnippet(lines, 1, 4);
  assert.equal(snippet.extractionMode, "full_body", "Complete closed function must report full_body");
  assert.match(snippet.definition, /processPayload/);
  assert.match(snippet.definition, /sanitize\(data\)/);

  // Case 2: Parameter destructuring with return type annotation like ': { valid: boolean } {'
  const typedLines = [
    "export function verifyAccess({ user }): { valid: boolean } {",
    "  const valid = Boolean(user?.admin);",
    "  return { valid };",
    "}"
  ];

  const typedDefs = findFunctionDefinitions(typedLines, "verifyAccess");
  assert.equal(typedDefs.length, 1, "Must find exactly one function definition for typed function");
  assert.equal(typedDefs[0].startLine, 1);
  assert.equal(typedDefs[0].endLine, 4, "Must not truncate at return type annotation brace");

  const typedSnippet = extractBoundedFunctionSnippet(typedLines, 1, 4);
  assert.equal(typedSnippet.extractionMode, "full_body", "Typed function must extract as full_body");
  assert.match(typedSnippet.definition, /verifyAccess/);
  assert.match(typedSnippet.definition, /return \{ valid \};/);
});

// ----------------------------------------------------------------------------
// Thread tgXSN: Multi-Line Call Expression Recognition & Context Gap Emission
// ----------------------------------------------------------------------------

test("tgXSN-NEGATIVE: call expressions split across added lines are recognized and produce context gaps when unresolved", () => {
  // Sensitive call 'verifySessionToken' split across added lines
  const diffHunks = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -10,3 +10,6 @@",
    " const existing = 1;",
    "+const token = verifySessionToken",
    "+  (credentials, options);",
    " const next = 2;"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);
  const verifyCand = candidates.find(c => c.symbol === "verifySessionToken");

  assert.ok(verifyCand, "Multi-line call 'verifySessionToken' must be extracted as candidate");
  assert.equal(verifyCand.isAdded, true, "Must be marked as added");
  assert.equal(verifyCand.isSensitive, true, "Must be classified as sensitive (auth category)");

  // When 'verifySessionToken' is external/unresolved in source, extractLocalCalleeContext must emit context gap
  const fileContent = "const existing = 1;\nconst next = 2;\n";
  const { contextGaps, callees } = extractLocalCalleeContext(fileContent, diffHunks, "src/service.js");

  assert.ok(
    contextGaps.some(g => g.symbol === "verifySessionToken"),
    "Multi-line sensitive call must emit context gap when definition is unresolved"
  );
  assert.equal(callees.length, 0, "No callee extracted when unresolved");

  // Case 2: Replacement function where function name is on added line and '(' is on unchanged context line
  const replacementDiff = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -20,3 +20,3 @@",
    "-const legacyToken = oldAuth",
    "+const legacyToken = verifySessionToken",
    "   (credentials);"
  ].join("\n");

  const replacementCandidates = extractCandidateCallSymbols(replacementDiff);
  const repCand = replacementCandidates.find(c => c.symbol === "verifySessionToken");
  assert.ok(repCand, "Replacement call with context line '(' must be extracted as candidate");
  assert.equal(repCand.isAdded, true);
  assert.equal(repCand.isSensitive, true);

  const repContext = extractLocalCalleeContext(fileContent, replacementDiff, "src/service.js");
  assert.ok(
    repContext.contextGaps.some(g => g.symbol === "verifySessionToken"),
    "Replacement sensitive call must emit context gap when unresolved"
  );

  // Case 3: Chained / leading dot call on added line
  const chainedDiff = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -30,3 +30,4 @@",
    " const authService = getService();",
    "+authService",
    "+  .verifySessionToken",
    "+  (credentials);"
  ].join("\n");

  const chainedCandidates = extractCandidateCallSymbols(chainedDiff);
  const chainCand = chainedCandidates.find(c => c.symbol === "verifySessionToken");
  assert.ok(chainCand, "Chained multi-line call '.verifySessionToken' must be extracted as candidate");
  assert.equal(chainCand.isQualified, true, "Must be classified as qualified call");
  assert.equal(chainCand.isSensitive, true, "Must be classified as sensitive");
});

test("tgXSN-POSITIVE: declarations, comments, and non-calls across added lines are NOT falsely classified as multi-line calls", () => {
  const diffHunks = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -1,4 +1,10 @@",
    "+// verifySessionToken",
    "+// (commented out call)",
    "+function verifySessionToken",
    "+(credentials) { return true; }",
    "+const authResult = verifySessionToken;",
    "+const sum = x +",
    "+(y);"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);

  // 1. Comments must not be candidates
  assert.ok(!candidates.some(c => c.lineText.includes("//")), "Comments must not be candidates");

  // 2. Function declaration 'function verifySessionToken\n(credentials)' must NOT be a call candidate
  const declCandidate = candidates.find(c => c.lineText.startsWith("function"));
  assert.equal(declCandidate, undefined, "Function declaration must not be candidate call");

  // 3. 'const authResult = verifySessionToken;' ends with semicolon, not a call
  const assignmentCand = candidates.find(c => c.lineText.includes("authResult ="));
  assert.equal(assignmentCand, undefined, "Assignment ending with semicolon must not be call candidate");
});
