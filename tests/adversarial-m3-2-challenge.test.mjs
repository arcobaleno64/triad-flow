/**
 * Adversarial Stress-Test Suite for LOOP2-SYSTEMIC-REMEDIATION-007 Milestone 3 (Challenger m3_2)
 * Agent: challenger_m3_2
 * Role: EMPIRICAL CHALLENGER
 *
 * Specific Focus Areas:
 * 1. Empty files, files with no functions, syntax errors in target file.
 * 2. Callee size exceeding limits (> 30 lines, > 2000 bytes, > 5/file, > 10 total, > 8000 bytes AST).
 * 3. Functions with multiline signatures (C++, JS/TS, Python) and nested closures/classes.
 * 4. Invalid or non-existent headSha handling (fails gracefully without unhandled exceptions).
 * 5. Dual visibility: verify sentry prompt (buildEvidenceReviewPrompt) and verifier prompt
 *    (buildVerificationPrompt) receive identical context package XML and context gaps.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  extractChangedLineSpans,
  extractAstEnclosures,
  extractModuleScope,
  extractCallGraphContext,
  allocateContextBudget,
  buildContextPackage,
  extractCandidateCallSymbols,
  findFunctionDefinitions,
  extractBoundedFunctionSnippet,
  extractLocalCalleeContext,
  findBraceScopeEnd,
  classifySensitiveCategory,
  GLOBAL_AST_CONTEXT_CEILING_BYTES,
  MAX_CALLEES_PER_FILE,
  MAX_CALLEES_TOTAL,
  MAX_SNIPPET_LINES,
  MAX_SNIPPET_BYTES,
  DEFAULT_BUDGET_CONFIG
} from "../src/core/context-builder.mjs";

import {
  getExactHeadFileContent,
  clearExactHeadCache
} from "../src/core/git-collector.mjs";

import {
  buildEvidenceReviewPrompt,
  formatContextPackageXml,
  formatContextGaps
} from "../src/adapters/review-prompts.mjs";

import {
  buildVerificationPrompt
} from "../src/core/independent-verifier.mjs";

test("Challenger M3.2 - Probe 1: Empty files and whitespace-only files", () => {
  // Empty content
  const emptyAst = extractAstEnclosures("");
  assert.equal(emptyAst.enclosingFunctions.length, 0);
  assert.equal(emptyAst.enclosingClasses.length, 0);

  const emptyCallees = extractLocalCalleeContext("", "+ doSomething()", "empty.js");
  assert.deepEqual(emptyCallees.callees, []);
  assert.deepEqual(emptyCallees.unresolvedCallees, []);
  assert.deepEqual(emptyCallees.contextGaps, []);

  const emptyScope = extractModuleScope("");
  assert.deepEqual(emptyScope.imports, []);
  assert.deepEqual(emptyScope.exports, []);
  assert.deepEqual(emptyScope.topLevelConstants, []);

  // Whitespace only
  const wsContent = "   \n\t\r\n   \n   ";
  const wsAst = extractAstEnclosures(wsContent);
  assert.equal(wsAst.enclosingFunctions.length, 0);

  const wsPkg = buildContextPackage(
    { diffHunks: "+ helper()", files: [{ path: "empty.js" }] },
    "empty.js",
    { fileContents: { "empty.js": wsContent } }
  );
  assert.ok(wsPkg);
  assert.equal(wsPkg.layers.layer1AstEnclosure.enclosingFunctions.length, 0);
  assert.ok(Array.isArray(wsPkg.contextGaps));
});

test("Challenger M3.2 - Probe 2: Files with no functions (JSON, markdown, pure constants)", () => {
  const jsonContent = JSON.stringify({ name: "triad-flow", version: "1.0.0", active: true }, null, 2);
  const astJson = extractAstEnclosures(jsonContent);
  assert.equal(astJson.enclosingFunctions.length, 0);
  assert.equal(astJson.enclosingClasses.length, 0);

  const constantsContent = `
    // Configuration constants only
    const TIMEOUT_MS = 5000;
    const MAX_RETRIES = 3;
    export const DEFAULT_HOST = "127.0.0.1";
  `;
  const astConst = extractAstEnclosures(constantsContent);
  assert.equal(astConst.enclosingFunctions.length, 0);

  const scopeConst = extractModuleScope(constantsContent);
  assert.ok(scopeConst.exports.some(e => e.includes("DEFAULT_HOST")));
  assert.ok(scopeConst.topLevelConstants.some(c => c.includes("TIMEOUT_MS")));

  const pkg = buildContextPackage(
    { diffHunks: "@@ -1,1 +1,2 @@\n+ const PORT = 8080;", files: [{ path: "config.js" }] },
    "config.js",
    { fileContents: { "config.js": constantsContent } }
  );
  assert.equal(pkg.layers.layer1AstEnclosure.enclosingFunctions.length, 0);
  assert.equal(pkg.layers.layer1AstEnclosure.callees.length, 0);
});

test("Challenger M3.2 - Probe 3: Syntax errors and unclosed constructs in target file", () => {
  // 1. Unclosed opening brace
  const unclosed = [
    "function brokenRoutine() {",
    "  if (true) {",
    "    return -1;"
  ];
  const endLine = findBraceScopeEnd(unclosed, 0);
  assert.equal(endLine, unclosed.length, "findBraceScopeEnd gracefully bounds to EOF for unclosed opening brace");

  // 2. Extra closing brace
  const extraClosing = `
    function okRoutine() {
      return 1;
    }
    }
  `;
  const astExtra = extractAstEnclosures(extraClosing);
  assert.equal(astExtra.enclosingFunctions.length, 1);
  assert.equal(astExtra.enclosingFunctions[0].name, "okRoutine");

  // 3. Unclosed multi-line block comment
  const unclosedComment = [
    "/* unterminated block comment",
    "   still in comment",
    "function commentFake() {",
    "  return 0;",
    "}"
  ];
  const astComment = extractAstEnclosures(unclosedComment.join("\n"));
  assert.ok(Array.isArray(astComment.enclosingFunctions));

  // 4. Broken candidate definitions do not throw
  const brokenCode = "function () { { { ;;; ;;;";
  assert.doesNotThrow(() => {
    extractAstEnclosures(brokenCode);
    extractLocalCalleeContext(brokenCode, "+ brokenRoutine();", "file.js");
  });
});

test("Challenger M3.2 - Probe 4: Callee size limits (> 30 lines, > 2000 bytes, ceilings)", () => {
  // 1. Long function (> 30 lines): must extract signature + guards + closing brace (<= 60 lines)
  const longFuncLines = [
    "bool evaluateCondition(const Field & value_field) {"
  ];
  for (let i = 2; i <= 60; i++) {
    if (i === 5) {
      longFuncLines.push("    if (isMapValueDefault(value_field)) return false;");
    } else if (i === 10) {
      longFuncLines.push("    assert(!value_field.isNull());");
    } else {
      longFuncLines.push(`    const auto step_${i} = transformValue(${i});`);
    }
  }
  longFuncLines.push("    return true;");
  longFuncLines.push("}");

  const snippet = extractBoundedFunctionSnippet(longFuncLines, 1, longFuncLines.length);
  assert.equal(snippet.extractionMode, "signature_and_guards");
  assert.ok(snippet.lines <= MAX_SNIPPET_LINES, `Snippet lines must be <= ${MAX_SNIPPET_LINES}`);
  assert.ok(snippet.bytes <= MAX_SNIPPET_BYTES, `Snippet bytes must be <= ${MAX_SNIPPET_BYTES}`);
  assert.ok(snippet.definition.includes("evaluateCondition"));
  assert.ok(snippet.definition.includes("isMapValueDefault"));
  assert.ok(snippet.definition.includes("/* ... [remainder of function body elided for context bounds] ... */"));
  assert.ok(snippet.definition.trim().endsWith("}"), "Preserves closing brace");

  // 2. Extreme snippet size (> 2000 bytes): strictly bounded by MAX_SNIPPET_BYTES
  const wideLines = [
    "function wideFunction(param) {"
  ];
  for (let i = 2; i <= 40; i++) {
    wideLines.push(`    // ${"W".repeat(300)}`);
  }
  wideLines.push("    return param;");
  wideLines.push("}");

  const wideSnippet = extractBoundedFunctionSnippet(wideLines, 1, wideLines.length);
  assert.ok(wideSnippet.bytes <= MAX_SNIPPET_BYTES, `Wide snippet must not exceed ${MAX_SNIPPET_BYTES} bytes`);

  // 3. Per-file callee limit (MAX_CALLEES_PER_FILE = 5)
  const fileLines = [];
  for (let i = 1; i <= 10; i++) {
    fileLines.push(`int callee_${i}() { return ${i}; }`);
  }
  const fileSource = fileLines.join("\n");
  const diffCalls = "@@ -1,1 +1,10 @@\n" + Array.from({ length: 10 }, (_, i) => `+ callee_${i + 1}();`).join("\n");

  const fileResult = extractLocalCalleeContext(fileSource, diffCalls, "file.cpp");
  assert.equal(fileResult.callees.length, MAX_CALLEES_PER_FILE, `Must cap at MAX_CALLEES_PER_FILE (${MAX_CALLEES_PER_FILE})`);

  // 4. ChangeSet total callee limit (MAX_CALLEES_TOTAL = 10)
  const totalResult = extractLocalCalleeContext(fileSource, diffCalls, "file2.cpp", {
    extractedCalleesCount: 8
  });
  assert.equal(totalResult.callees.length, 2, "Must cap at MAX_CALLEES_TOTAL (10) when running total is 8");

  // 5. Global AST context ceiling (GLOBAL_AST_CONTEXT_CEILING_BYTES = 8000 bytes)
  const diffHunks = "@@ -1,1 +1,5 @@\n+ int x = 1;\n+ int y = 2;";
  const hugeCallees = [];
  for (let i = 0; i < 8; i++) {
    hugeCallees.push({
      symbol: `huge_fn_${i}`,
      definition: `int huge_fn_${i}() {\n    /* ${"B".repeat(1500)} */\n    return ${i};\n}`,
      lines: 20,
      bytes: 1550,
      startLine: i * 20,
      endLine: (i + 1) * 20
    });
  }

  const rawLayers = {
    layer0Diff: { rawHunks: diffHunks, byteLength: Buffer.byteLength(diffHunks, "utf8"), additions: 2, deletions: 0 },
    layer1AstEnclosure: {
      adapterName: "builtin-semantic",
      enclosingFunctions: [],
      enclosingClasses: [],
      callees: hugeCallees,
      unresolvedCallees: []
    },
    layer2ModuleScope: { imports: [], exports: [], topLevelConstants: [] },
    layer3CallGraph: { callers: [], callees: [] }
  };

  const budgeted = allocateContextBudget(rawLayers);
  // Diff must be 100% preserved
  assert.equal(budgeted.layers.layer0Diff.rawHunks, diffHunks, "Layer 0 diff hunks must never be truncated or displaced");
  // Layer 1 AST must be within 8000 bytes
  const layer1Bytes = Buffer.byteLength(JSON.stringify(budgeted.layers.layer1AstEnclosure), "utf8");
  assert.ok(layer1Bytes <= GLOBAL_AST_CONTEXT_CEILING_BYTES, `Layer 1 bytes (${layer1Bytes}) must be <= ${GLOBAL_AST_CONTEXT_CEILING_BYTES}`);
});

test("Challenger M3.2 - Probe 5: Multiline signatures and nested closures", () => {
  // 1. C++ multiline signature
  const cppMultiline = [
    "bool",
    "traverseMapElementValueNode(",
    "    const ASTFunction * index_column_node,",
    "    const Field & value_field,",
    "    const Block & header)",
    "{",
    "    if (isMapValueDefault(value_field, header))",
    "        return false;",
    "    return true;",
    "}"
  ];

  const cppDefs = findFunctionDefinitions(cppMultiline, "traverseMapElementValueNode");
  assert.equal(cppDefs.length, 1, "Detects multiline C++ function definition");
  assert.equal(cppDefs[0].startLine, 2);
  assert.equal(cppDefs[0].endLine, 10);

  const cppSnippet = extractBoundedFunctionSnippet(cppMultiline, cppDefs[0].startLine, cppDefs[0].endLine);
  assert.equal(cppSnippet.extractionMode, "full_body");
  assert.ok(cppSnippet.definition.includes("isMapValueDefault"));

  // 2. JS multiline async function
  const jsMultiline = [
    "export async function executeDistributedWorkflow(",
    "  coordinatorInstance,",
    "  workflowContext,",
    "  executionTimeoutMs",
    ") {",
    "  if (!coordinatorInstance) throw new Error('missing coordinator');",
    "  return coordinatorInstance.start(workflowContext);",
    "}"
  ];

  const jsDefs = findFunctionDefinitions(jsMultiline, "executeDistributedWorkflow");
  assert.equal(jsDefs.length, 1, "Detects multiline JS function declaration");
  assert.equal(jsDefs[0].startLine, 1);
  assert.equal(jsDefs[0].endLine, 8);

  // 3. Arrow functions:
  // 3a. Single-line arrow header extracts correctly
  const singleLineArrow = [
    "const calculateChecksum = (bufferPayload, initialSeed) => {",
    "  return bufferPayload.length + initialSeed;",
    "};"
  ];
  const singleArrowDefs = findFunctionDefinitions(singleLineArrow, "calculateChecksum");
  assert.equal(singleArrowDefs.length, 1);
  assert.equal(singleArrowDefs[0].startLine, 1);
  assert.equal(singleArrowDefs[0].endLine, 3);

  // 3b. Multiline arrow where '=>' is delayed to a later line
  // Note: Line 281 in context-builder.mjs skips lines with '=' that lack '=>', 'function', or '{'.
  // This causes multiline arrows to evaluate as 0 definitions, safely falling back to UNRESOLVED_SYMBOL (fail-closed).
  const arrowMultiline = [
    "const calculateChecksumMultiline = (",
    "  bufferPayload,",
    "  initialSeed",
    ") => {",
    "  return bufferPayload.length + initialSeed;",
    "};"
  ];
  const arrowDefs = findFunctionDefinitions(arrowMultiline, "calculateChecksumMultiline");
  assert.equal(arrowDefs.length, 0, "Multiline arrow with delayed '=>' returns 0 definitions, safely triggering UNRESOLVED_SYMBOL");

  // 4. Nested closures and callback braces
  const nestedCode = `
    function processContainer(items) {
      const helper = (x) => {
        if (x > 0) {
          return { value: x * 2 };
        }
        return null;
      };
      return items.map(helper);
    }
  `;
  const nestedLines = nestedCode.split("\n");
  const outerDefs = findFunctionDefinitions(nestedLines, "processContainer");
  assert.equal(outerDefs.length, 1);
  assert.equal(outerDefs[0].startLine, 2);
  assert.equal(outerDefs[0].endLine, 10);
});

test("Challenger M3.2 - Probe 6: Invalid or non-existent headSha handling", () => {
  clearExactHeadCache();
  const repoRoot = path.resolve(".");

  // 1. Non-hex or invalid format SHAs -> fails gracefully returning null (no throw)
  assert.equal(getExactHeadFileContent(repoRoot, "", "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, null, "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, undefined, "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, "HEAD~1", "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, "master", "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, "short123", "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, "zzz".repeat(15), "package.json"), null);

  // 2. Non-existent 40-character hex commit SHA -> fails gracefully returning null (no throw)
  const fakeSha = "0123456789abcdef0123456789abcdef01234567";
  const fakeResult = getExactHeadFileContent(repoRoot, fakeSha, "package.json");
  assert.equal(fakeResult, null, "Must return null for non-existent commit SHA without throwing");

  // 3. Null repoRoot or null filePath -> returns null
  assert.equal(getExactHeadFileContent(null, fakeSha, "package.json"), null);
  assert.equal(getExactHeadFileContent(repoRoot, fakeSha, null), null);

  // 4. Non-existent file in repository -> returns null
  const validHead = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const nonExistentFile = getExactHeadFileContent(repoRoot, validHead, "does/not/exist.cpp");
  assert.equal(nonExistentFile, null, "Must return null for non-existent file path without throwing");
});

test("Challenger M3.2 - Probe 7: Dual visibility prompt symmetry between sentry and verifier", () => {
  const changeSet = {
    scopeMode: "target-branch",
    contentDigest: "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    diffHunks: `
@@ -50,6 +50,12 @@
 void handleRequest(Request & req) {
+    if (isMapValueDefault(req.field)) return;
+    validateBounds(req.limit);
+    unresolvedDynamicDispatch();
     process(req);
 }
`,
    files: [{ path: "src/handler.cpp", additions: 3, deletions: 0 }],
    patchObjective: "Handle default map values without dropping keys"
  };

  const contextPackage = {
    targetFile: "src/handler.cpp",
    layers: {
      layer0Diff: { rawHunks: changeSet.diffHunks, byteLength: 250 },
      layer1AstEnclosure: {
        enclosingFunctions: [
          {
            name: "handleRequest",
            kind: "function",
            startLine: 50,
            endLine: 65,
            headerCode: "void handleRequest(Request & req) {",
            bodySnippet: "if (isMapValueDefault(req.field)) return;"
          }
        ],
        enclosingClasses: [],
        callees: [
          {
            symbol: "isMapValueDefault",
            definition: "bool isMapValueDefault(const Field & f) {\n    return f.isDefault();\n}",
            lines: 3,
            bytes: 62,
            startLine: 200,
            endLine: 202
          }
        ],
        unresolvedCallees: [
          {
            symbol: "validateBounds",
            reason: "AMBIGUOUS_SYMBOL",
            file: "src/handler.cpp",
            line: 52
          },
          {
            symbol: "unresolvedDynamicDispatch",
            reason: "MACRO_OR_DYNAMIC",
            file: "src/handler.cpp",
            line: 53
          }
        ]
      },
      layer2ModuleScope: {
        imports: ["#include <handler.h>"],
        exports: ["void handleRequest(Request & req);"],
        topLevelConstants: []
      },
      layer3CallGraph: {
        callers: [{ file: "src/main.cpp", line: 10, callerName: "main" }],
        callees: [{ functionName: "isMapValueDefault", signature: "isMapValueDefault(...)" }]
      }
    },
    contextGaps: [
      {
        symbol: "validateBounds",
        reason: "AMBIGUOUS_SYMBOL",
        file: "src/handler.cpp",
        line: 52,
        category: "input_validation",
        impact: "Ambiguous definition on input validation path"
      }
    ]
  };

  // Build Sentry Prompt (buildEvidenceReviewPrompt)
  const sentryPrompt = buildEvidenceReviewPrompt(
    changeSet,
    "macro",
    DEFAULT_BUDGET_CONFIG,
    contextPackage,
    { patchObjective: changeSet.patchObjective }
  );

  // Build Verifier Prompt (buildVerificationPrompt)
  const verifierPrompt = buildVerificationPrompt(
    changeSet,
    [],
    {
      contextPackage,
      verificationMode: "clean_challenge",
      patchObjective: changeSet.patchObjective
    }
  );

  // 1. Verify that BOTH prompts contain the exact formatContextPackageXml result
  const expectedContextXml = formatContextPackageXml(contextPackage);
  assert.ok(expectedContextXml.length > 0);
  assert.ok(sentryPrompt.includes(expectedContextXml), "Sentry prompt contains exact contextPackage XML");
  assert.ok(verifierPrompt.includes(expectedContextXml), "Verifier prompt contains exact contextPackage XML");

  // 2. Verify that BOTH prompts contain the exact formatContextGaps result
  const expectedGapsBlock = formatContextGaps(contextPackage.contextGaps);
  assert.ok(expectedGapsBlock.length > 0);
  assert.ok(sentryPrompt.includes(expectedGapsBlock), "Sentry prompt contains exact contextGaps block");
  assert.ok(verifierPrompt.includes(expectedGapsBlock), "Verifier prompt contains exact contextGaps block");

  // 3. Verify XML enclosures are identical in structure
  assert.ok(sentryPrompt.includes('<enclosing_context targetFile="src/handler.cpp">'));
  assert.ok(verifierPrompt.includes('<enclosing_context targetFile="src/handler.cpp">'));

  assert.ok(sentryPrompt.includes('<local_callees targetFile="src/handler.cpp">'));
  assert.ok(verifierPrompt.includes('<local_callees targetFile="src/handler.cpp">'));

  assert.ok(sentryPrompt.includes('<callee symbol="isMapValueDefault" startLine="200" endLine="202" lines="3" bytes="62">'));
  assert.ok(verifierPrompt.includes('<callee symbol="isMapValueDefault" startLine="200" endLine="202" lines="3" bytes="62">'));

  // 4. Verify context gaps section header and instructions are present in both
  assert.ok(sentryPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(verifierPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(sentryPrompt.includes("MANDATORY UNCERTAINTY INSTRUCTION:"));
  assert.ok(verifierPrompt.includes("MANDATORY UNCERTAINTY INSTRUCTION:"));
});

test("Challenger M3.2 - Probe 8: Sensitive category classification and gap promotion", () => {
  // Classification checks
  assert.equal(classifySensitiveCategory("isMapValueDefault"), "default_values");
  assert.equal(classifySensitiveCategory("fallbackHandler"), "default_values");
  assert.equal(classifySensitiveCategory("absentKeyDefault"), "default_values");
  assert.equal(classifySensitiveCategory("zeroCheck"), "default_values");

  assert.equal(classifySensitiveCategory("validateInputs"), "input_validation");
  assert.equal(classifySensitiveCategory("checkBounds"), "input_validation");
  assert.equal(classifySensitiveCategory("assertNonNull"), "input_validation");
  assert.equal(classifySensitiveCategory("sanitizeInput"), "input_validation");

  assert.equal(classifySensitiveCategory("errorHandler"), "error_handling");
  assert.equal(classifySensitiveCategory("failSafe"), "error_handling");
  assert.equal(classifySensitiveCategory("abortOperation"), "error_handling");
  assert.equal(classifySensitiveCategory("catchBlock"), "error_handling");

  assert.equal(classifySensitiveCategory("authGuard"), "security");
  assert.equal(classifySensitiveCategory("tokenValidator"), "security");

  assert.equal(classifySensitiveCategory("mathSinCos"), null);

  // Macro sensitive category promotion
  const fileWithMacro = `
    #define isMapValueDefault(v) ((v) == 0)
    int main() { return 0; }
  `;
  const diffMacro = "@@ -1,1 +1,1 @@\n+ isMapValueDefault(val);";
  const macroResult = extractLocalCalleeContext(fileWithMacro, diffMacro, "main.cpp");
  assert.equal(macroResult.unresolvedCallees.length, 1);
  assert.equal(macroResult.unresolvedCallees[0].reason, "MACRO_OR_DYNAMIC");
  assert.equal(macroResult.contextGaps.length, 1);
  assert.equal(macroResult.contextGaps[0].symbol, "isMapValueDefault");
  assert.equal(macroResult.contextGaps[0].category, "default_values");
});
