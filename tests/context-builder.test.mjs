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
  stripCommentsAndStrings,
  findFunctionDefinitions,
  extractBoundedFunctionSnippet,
  extractLocalCalleeContext,
  GLOBAL_AST_CONTEXT_CEILING_BYTES,
  MAX_CALLEES_PER_FILE,
  MAX_CALLEES_TOTAL,
  MAX_SNIPPET_LINES,
  MAX_SNIPPET_BYTES,
  DEFAULT_BUDGET_CONFIG,
  SAFE_ARGV_THRESHOLD_BYTES,
  findFunctionDeclarations,
  findTypeDefinitions,
  extractDirectIncludePaths
} from "../src/core/context-builder.mjs";
import { getExactHeadFileContent, clearExactHeadCache } from "../src/core/git-collector.mjs";
import { buildEvidenceReviewPrompt, formatContextPackageXml, formatContextGaps } from "../src/adapters/review-prompts.mjs";
import { buildVerificationPrompt, conductIndependentVerification, validateContextPackageAuthenticity, evaluateContextPackageBinding } from "../src/core/independent-verifier.mjs";
import { evaluateGateDecision, evaluatePostVerificationGate } from "../src/core/harness.mjs";
import { isTrustedConsensus } from "../src/core/consensus-state.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";

test("extractChangedLineSpans parses unified diff hunk headers correctly", () => {
  const hunks = [
    "@@ -10,5 +12,8 @@",
    "+ line1",
    "+ line2",
    "@@ -40 +45,2 @@"
  ].join("\n");

  const spans = extractChangedLineSpans(hunks);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].start, 12);
  assert.equal(spans[0].end, 19);
  assert.equal(spans[1].start, 45);
  assert.equal(spans[1].end, 46);
});

test("extractAstEnclosures identifies functions, methods, and classes", () => {
  const code = `
import fs from "fs";

export class DataProcessor {
  constructor(options) {
    this.options = options;
  }

  processItem(item) {
    return item.value * 2;
  }
}

export async function computeHash(data, salt) {
  const hash = crypto.createHash("sha256");
  return hash.update(data + salt).digest("hex");
}

const formatOutput = (raw) => {
  return String(raw).trim();
};
`;

  const enclosures = extractAstEnclosures(code);
  assert.equal(enclosures.adapterName, "builtin-semantic");
  assert.ok(enclosures.enclosingClasses.some(c => c.name === "DataProcessor"));
  assert.ok(enclosures.enclosingFunctions.some(f => f.name === "computeHash" && f.kind === "function"));
  assert.ok(enclosures.enclosingFunctions.some(f => f.name === "processItem" && f.kind === "method"));
  assert.ok(enclosures.enclosingFunctions.some(f => f.name === "formatOutput" && f.kind === "arrow"));
});

test("extractModuleScope extracts imports, exports, and top-level constants", () => {
  const code = `
import path from "node:path";
const crypto = require("node:crypto");

export const MAX_RETRY_COUNT = 5;
const BUFFER_LIMIT_BYTES = 1024;

export function helper() {}
module.exports = { helper };
`;

  const scope = extractModuleScope(code);
  assert.ok(scope.imports.some(i => i.includes("node:path")));
  assert.ok(scope.imports.some(i => i.includes("require")));
  assert.ok(scope.exports.some(e => e.includes("export function helper")));
  assert.ok(scope.exports.some(e => e.includes("module.exports")));
  assert.ok(scope.topLevelConstants.some(c => c.includes("MAX_RETRY_COUNT")));
});

test("allocateContextBudget enforces deterministic budget ratio and layer eviction order", () => {
  const rawLayers = {
    layer0Diff: { rawHunks: "diff-content", byteLength: 12 },
    layer1AstEnclosure: {
      adapterName: "builtin-semantic",
      enclosingFunctions: [{ name: "fn1", bodySnippet: "console.log(123);" }]
    },
    layer2ModuleScope: {
      imports: ["import x from 'x';"],
      exports: ["export const a = 1;"],
      topLevelConstants: ["CONST_A = 1"]
    },
    layer3CallGraph: {
      callers: [{ file: "a.js", line: 1, callerName: "main" }],
      callees: [{ functionName: "sub", signature: "sub()" }]
    }
  };

  // Extremely tight budget to trigger evictions
  const tightConfig = {
    maxInputBytes: 2048,
    frameBytes: 1500,
    layer0Ratio: 0.50,
    layer1Ratio: 0.30,
    layer2Ratio: 0.10,
    layer3Ratio: 0.10
  };

  const budgeted = allocateContextBudget(rawLayers, tightConfig);
  assert.ok(budgeted.budgetAccounting);
  assert.ok(budgeted.budgetAccounting.consumedBytes <= tightConfig.maxInputBytes);
});

test("buildContextPackage produces valid ContextPackage and plans Windows transport", () => {
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/sample.js", additions: 10, deletions: 2 }],
    diffHunks: "+ function add(a, b) { return a + b; }"
  };

  const fileContents = {
    "src/sample.js": "function add(a, b) {\n  return a + b;\n}\n"
  };

  const pkg = buildContextPackage(cs, "src/sample.js", { fileContents });
  assert.equal(pkg.schemaVersion, "1.0.0");
  assert.equal(pkg.targetFile, "src/sample.js");
  assert.ok(pkg.layers.layer0Diff);
  assert.ok(pkg.layers.layer1AstEnclosure);
  assert.ok(pkg.transportPlan);
  assert.equal(typeof pkg.transportPlan.requiresStdin, "boolean");
});

test("getExactHeadFileContent extracts committed file content from Git object database with caching and working tree isolation", () => {
  clearExactHeadCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-exact-head-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    fs.mkdirSync(path.join(tmpDir, "src"), { recursive: true });
    const filePath = "src/calc.js";
    const fullPath = path.join(tmpDir, filePath);
    const committedContent = "export function multiply(a, b) {\n  return a * b;\n}\n";
    fs.writeFileSync(fullPath, committedContent);

    execFileSync("git", ["add", filePath], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial commit"], { cwd: tmpDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // Dirty the working tree file with uncommitted modifications
    fs.writeFileSync(fullPath, "export function multiply(a, b) { return 0; /* DIRTY */ }\n");

    // Exact-head extraction must strictly return the COMMITTED content, completely ignoring the dirty working tree!
    const extracted = getExactHeadFileContent(tmpDir, headSha, filePath);
    assert.equal(extracted, committedContent);

    // Verify in-memory cache hit
    const cached = getExactHeadFileContent(tmpDir, headSha, filePath);
    assert.equal(cached, committedContent);

    // Non-existent file returns null without crashing
    const missing = getExactHeadFileContent(tmpDir, headSha, "src/nonexistent.js");
    assert.equal(missing, null);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("007-D-01: Exact-head callee extraction from head SHA (fixture & CYCLE-0047)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-007-d-01-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    const targetFile = "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp";
    const fullPath = path.join(tmpDir, targetFile);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    // Construct source file where callee definition is >500 lines away from call site
    const fillerLines = Array.from({ length: 800 }, (_, i) => `// filler line ${i}`).join("\n");
    const sourceCode = [
      `#include <string>`,
      `namespace DB {`,
      fillerLines,
      `bool MergeTreeIndexConditionText::traverseMapElementValueNode(const RPNBuilderTreeNode & index_column_node, const Field & const_value) const`,
      `{`,
      `    if (const_value.getType() != Field::Types::String || isMapValueDefault(const_value.safeGet<String>(), header))`,
      `        return false;`,
      ``,
      `    return hasIndexForMapElementValue(index_column_node);`,
      `}`,
      `}`
    ].join("\n");

    fs.writeFileSync(fullPath, sourceCode);
    execFileSync("git", ["add", targetFile], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Add condition text index"], { cwd: tmpDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // Dirty or remove working tree file to prove zero reliance on disk
    fs.writeFileSync(fullPath, "// dirty file with empty contents\n");

    const diffHunks = [
      `@@ -1325,10 +1325,10 @@`,
      `     bool candidate_for_exact_mode = true;`,
      `     bool is_map_element_value = false;`,
      `+    if (traverseMapElementValueNode(index_column_node, value_field))`,
      `+    {`,
      `+        has_index_column = true;`,
      `+        is_map_element_value = true;`,
      `+    }`
    ].join("\n");

    const changeSet = {
      scopeMode: "revision-range",
      repository: { root: tmpDir, headSha },
      files: [{ path: targetFile, additions: 4, deletions: 0 }],
      diffHunks
    };

    const pkg = buildContextPackage(changeSet, targetFile, {
      repositoryRoot: tmpDir,
      headSha
    });

    assert.ok(pkg.layers.layer1AstEnclosure);
    const callees = pkg.layers.layer1AstEnclosure.callees || [];
    assert.ok(callees.length >= 1, "Expected at least 1 callee extracted");
    const targetCallee = callees.find(c => c.symbol === "traverseMapElementValueNode");
    assert.ok(targetCallee, "traverseMapElementValueNode must be extracted");
    assert.ok(targetCallee.definition.includes("isMapValueDefault(const_value.safeGet<String>(), header)"));
    assert.ok(targetCallee.lines <= 30);
    assert.ok(targetCallee.bytes <= 2000);
    assert.equal(targetCallee.extractionMode, "full_body");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("007-D-02: Unresolved callee propagated as context gap -> Verifier UNCERTAIN -> HUMAN_REVIEW_REQUIRED", async () => {
  const code = [
    `#define CHECK_MAP_DEFAULT(val, header) ((val) == 0)`,
    `void process() {`,
    `  return;`,
    `}`
  ].join("\n");

  const diffHunks = [
    `@@ -50,5 +50,5 @@`,
    `+ if (CHECK_MAP_DEFAULT(needle, header)) return false;`
  ].join("\n");

  const targetFile = "src/index.cpp";
  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const fileContents = { [targetFile]: code };
  const pkg = buildContextPackage(changeSet, targetFile, { fileContents });

  assert.ok(pkg.layers.layer1AstEnclosure.unresolvedCallees.some(u => u.symbol === "CHECK_MAP_DEFAULT" && u.reason === "MACRO_OR_DYNAMIC"));
  assert.ok(pkg.contextGaps.length >= 1, "Expected macro on sensitive default path to be promoted to contextGaps");
  const gap = pkg.contextGaps.find(g => g.symbol === "CHECK_MAP_DEFAULT");
  assert.ok(gap);
  assert.equal(gap.category, "default_values");

  // Verify prompt dual visibility: both sentry and verifier prompts render [UNRESOLVED CODE CONTEXT GAPS]
  const sentryPrompt = buildEvidenceReviewPrompt(changeSet, "macro", undefined, pkg);
  assert.ok(sentryPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(sentryPrompt.includes("CHECK_MAP_DEFAULT"));

  const verifierPrompt = buildVerificationPrompt(changeSet, [], { contextPackage: pkg });
  assert.ok(verifierPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(verifierPrompt.includes("CHECK_MAP_DEFAULT"));
  assert.ok(verifierPrompt.includes("Context Gap Mandate: If [UNRESOLVED CODE CONTEXT GAPS] are present"));

  // Mock verifier that adheres to Context Gap Mandate and outputs overallStatus: "UNCERTAIN"
  const mockVerifierAdapter = {
    executeVerification: async () => ({
      overallStatus: "UNCERTAIN",
      evaluations: [],
      verifierOmissions: [
        {
          title: "Unresolved default-handling callee could conceal false advance",
          severity: "high",
          evidenceSupport: "UNCERTAIN",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: targetFile,
          line_start: 50,
          line_end: 50,
          reasoning: "Macro CHECK_MAP_DEFAULT cannot be resolved; potential failure path on default zero needle."
        }
      ]
    })
  };

  const rec = await conductIndependentVerification(changeSet, [], mockVerifierAdapter, {
    contextPackage: pkg
  });
  assert.equal(rec.overallStatus, "UNCERTAIN");

  // Untrusted plain mock is rejected by formal gate (fail-closed control)
  const untrustedGate = evaluatePostVerificationGate({ findings: [] }, rec);
  assert.equal(untrustedGate.decision, "block");
  assert.match(untrustedGate.reason, /UNTRUSTED_OR_MISSING_CONSENSUS|Untrusted or missing consensus/i);

  // Authentic trusted consensus routes UNCERTAIN to human_review_required
  const trustedConsensus = aggregateConsensus({
    agy: { provider: "agy", executionStatus: "success", fileCoverageComplete: true, findings: [] },
    claude: { provider: "claude", executionStatus: "success", fileCoverageComplete: true, findings: [] },
    codex: { provider: "codex", executionStatus: "success", fileCoverageComplete: true, findings: [] }
  }, { policy: "TRI_PARTY_HETEROGENEOUS", tier: 2 });
  assert.equal(isTrustedConsensus(trustedConsensus), true);
  assert.equal(trustedConsensus.quorumReached, true);

  // Harness gate evaluation routes UNCERTAIN to human_review_required
  const gate = evaluatePostVerificationGate(trustedConsensus, rec, { tier: 2 });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /UNCERTAIN/i);
});

test("007-D-03: Context size exceeds 8 KB ceiling -> bounded extraction preserves diff", () => {
  // Construct a large diff (Layer 0) that must not be truncated
  const diffLines = Array.from({ length: 40 }, (_, i) => `+ int var_${i} = compute_${i}();`).join("\n");
  const diffHunks = `@@ -1,5 +1,45 @@\n${diffLines}`;

  // Construct a massive source file with 15 functions, each >50 lines long (>20 KB total)
  const fns = [];
  for (let i = 0; i < 15; i++) {
    const bodyLines = Array.from({ length: 60 }, (_, j) => `    if (x == ${j}) return ${j};`).join("\n");
    fns.push(`int compute_${i}() {\n${bodyLines}\n    return 0;\n}`);
  }
  const fileContent = fns.join("\n\n");
  const targetFile = "src/large_file.c";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 40, deletions: 0 }],
    diffHunks
  };

  const fileContents = { [targetFile]: fileContent };
  const pkg = buildContextPackage(changeSet, targetFile, { fileContents });

  // Quantity ceiling: max 5 callees for this file
  const callees = pkg.layers.layer1AstEnclosure.callees || [];
  assert.ok(callees.length <= MAX_CALLEES_PER_FILE, `Callees count ${callees.length} must not exceed ${MAX_CALLEES_PER_FILE}`);

  // Each extracted long callee is bounded to <= 60 lines and <= 2,000 bytes
  for (const c of callees) {
    assert.ok(c.lines <= MAX_SNIPPET_LINES, `Callee lines ${c.lines} must not exceed ${MAX_SNIPPET_LINES}`);
    assert.ok(c.bytes <= MAX_SNIPPET_BYTES, `Callee bytes ${c.bytes} must not exceed ${MAX_SNIPPET_BYTES}`);
  }

  // Global Layer 1 AST ceiling: <= 8,000 bytes
  const serializedLayer1 = JSON.stringify(pkg.layers.layer1AstEnclosure);
  assert.ok(
    Buffer.byteLength(serializedLayer1, "utf8") <= GLOBAL_AST_CONTEXT_CEILING_BYTES,
    `Layer 1 bytes ${Buffer.byteLength(serializedLayer1, "utf8")} must not exceed ${GLOBAL_AST_CONTEXT_CEILING_BYTES}`
  );

  // Diff Non-Interference: Layer 0 diff hunks remain 100% intact!
  assert.equal(pkg.layers.layer0Diff.rawHunks, diffHunks, "Diff hunks must never be truncated or displaced");
});

test("Ambiguous overload is recorded as AMBIGUOUS_SYMBOL and promoted to contextGaps on sensitive path", () => {
  const code = [
    `bool validateToken(int token) { return token > 0; }`,
    `bool validateToken(const std::string & token) { return !token.empty(); }`
  ].join("\n");

  const diffHunks = `@@ -10,3 +10,3 @@\n+ if (validateToken(tok)) { return true; }`;
  const targetFile = "src/auth.cpp";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, { fileContents: { [targetFile]: code } });
  const unresolved = pkg.layers.layer1AstEnclosure.unresolvedCallees;
  assert.ok(unresolved.some(u => u.symbol === "validateToken" && u.reason === "AMBIGUOUS_SYMBOL"));

  // Promoted to contextGaps because validate is an input_validation domain
  const gap = pkg.contextGaps.find(g => g.symbol === "validateToken");
  assert.ok(gap, "validateToken overload must be promoted to contextGaps");
  assert.equal(gap.reason, "AMBIGUOUS_SYMBOL");
  assert.equal(gap.category, "input_validation");
});

test("Non-sensitive callee not in file remains in unresolvedCallees but is NOT promoted to contextGaps", () => {
  const code = `void doWork() { return; }`;
  const diffHunks = `@@ -10,3 +10,3 @@\n+ logOutputMessage(msg);`;
  const targetFile = "src/worker.cpp";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, { fileContents: { [targetFile]: code } });
  assert.ok(pkg.layers.layer1AstEnclosure.unresolvedCallees.some(u => u.symbol === "logOutputMessage"));
  assert.equal(pkg.contextGaps.length, 0, "Non-sensitive callee must not be promoted to contextGaps");
});

test("formatContextPackageXml formats <callee_definitions> and <local_callees>", () => {
  const pkg = {
    targetFile: "src/sample.cpp",
    layers: {
      layer1AstEnclosure: {
        enclosingClasses: [],
        enclosingFunctions: [],
        callees: [
          {
            symbol: "helperFunc",
            lines: 5,
            bytes: 50,
            definition: "int helperFunc() { return 42; }"
          }
        ]
      }
    }
  };

  const xml = formatContextPackageXml(pkg);
  assert.ok(xml.includes("<callee_definitions>"));
  assert.ok(xml.includes("<local_callees"));
  assert.ok(xml.includes(`<callee symbol="helperFunc"`));
  assert.ok(xml.includes("int helperFunc() { return 42; }"));
});

test("CYCLE-0047 real repository extraction when local clickhouse path is present", (t) => {
  const clickhouseRoot = "C:/Users/arcobaleno/Documents/Code/clickhouse";
  if (!fs.existsSync(clickhouseRoot)) {
    t.skip("External clickhouse repository not present on this machine.");
    return;
  }

  const headSha = "18f9c9d0db2fb7374b0545f3fa9542809107702a";
  const targetFile = "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp";

  const diffHunks = [
    `@@ -1325,10 +1325,10 @@`,
    `     bool candidate_for_exact_mode = true;`,
    `     bool is_map_element_value = false;`,
    `+    if (traverseMapElementValueNode(index_column_node, value_field))`,
    `+    {`,
    `+        has_index_column = true;`,
    `+        is_map_element_value = true;`,
    `+    }`
  ].join("\n");

  const changeSet = {
    scopeMode: "revision-range",
    repository: { root: clickhouseRoot, headSha },
    files: [{ path: targetFile, additions: 4, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, {
    repositoryRoot: clickhouseRoot,
    headSha
  });

  const callees = pkg.layers.layer1AstEnclosure.callees || [];
  const targetCallee = callees.find(c => c.symbol === "traverseMapElementValueNode");
  assert.ok(targetCallee, "traverseMapElementValueNode must be extracted from exact HEAD commit");
  assert.ok(targetCallee.definition.includes("bool MergeTreeIndexConditionText::traverseMapElementValueNode"));
  assert.ok(targetCallee.definition.includes("isMapValueDefault(const_value.safeGet<String>(), header)"));
  assert.equal(targetCallee.lines, 11);
  assert.ok(targetCallee.bytes <= 700);
});

test("stripCommentsAndStrings: correctly strips regex literals with escaped slashes and char classes", () => {
  const line = '  if (/^(?:none|n\\/?a|na|no reasoning(?: provided)?)\\.?$/i.test(trimmed)) return false;';
  const stripped = stripCommentsAndStrings(line);
  assert.equal(stripped, "  if (i.test(trimmed)) return false;");

  const candidates = extractCandidateCallSymbols(`@@ -1,5 +1,5 @@\n+${line}`);
  assert.equal(candidates.some(c => c.symbol === "reasoning"), false);
});

test("Cross-File Symbol Extraction: Multi-file changeSet resolves callee in sibling file (Tier 2)", () => {
  const serviceCode = [
    `import { validateCredentials } from "./validator.js";`,
    `export function login(user, pass) {`,
    `  if (!validateCredentials(user, pass)) {`,
    `    return false;`,
    `  }`,
    `  return true;`,
    `}`
  ].join("\n");

  const validatorCode = [
    `export function validateCredentials(user, pass) {`,
    `  if (!user || !pass) {`,
    `    return false;`,
    `  }`,
    `  return user.length >= 3 && pass.length >= 8;`,
    `}`
  ].join("\n");

  const diffHunks = [
    `diff --git a/src/auth/service.js b/src/auth/service.js`,
    `--- a/src/auth/service.js`,
    `+++ b/src/auth/service.js`,
    `@@ -2,3 +2,4 @@`,
    `+  if (!validateCredentials(user, pass)) {`,
    `+    return false;`,
    `+  }`
  ].join("\n");

  const changeSet = {
    scopeMode: "working-tree",
    files: [
      { path: "src/auth/service.js", additions: 2, deletions: 0 },
      { path: "src/auth/validator.js", additions: 0, deletions: 0 }
    ],
    diffHunks
  };

  const fileContents = {
    "src/auth/service.js": serviceCode,
    "src/auth/validator.js": validatorCode
  };

  const pkg = buildContextPackage(changeSet, undefined, { fileContents });

  assert.ok(pkg.ok, "Context package build must succeed");
  const callees = pkg.layers.layer1AstEnclosure.callees || [];
  const resolved = callees.find(c => c.symbol === "validateCredentials");
  assert.ok(resolved, "validateCredentials must be resolved from sibling file src/auth/validator.js");
  assert.equal(resolved.file, "src/auth/validator.js");
  assert.equal(resolved.callingFile, "src/auth/service.js");
  assert.ok(resolved.definition.includes("export function validateCredentials"));
  assert.equal(resolved.extractionMode, "full_body");

  // Crucial: not promoted to contextGaps because it is fully resolved!
  const gap = pkg.contextGaps.find(g => g.symbol === "validateCredentials");
  assert.equal(gap, undefined, "Fully resolved callee must NOT be promoted to contextGaps");
  assert.equal(pkg.contextGaps.length, 0, "Zero context gaps expected when all sensitive callees resolve");
});

test("Cross-File Symbol Extraction: Direct header include at HEAD resolves macro (Tier 3) without header in PR changeSet manifest", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-cross-header-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    const headerRelPath = "include/sec_defs.h";
    const sourceRelPath = "src/session.c";

    const headerFull = path.join(tmpDir, headerRelPath);
    const sourceFull = path.join(tmpDir, sourceRelPath);
    fs.mkdirSync(path.dirname(headerFull), { recursive: true });
    fs.mkdirSync(path.dirname(sourceFull), { recursive: true });

    const headerContent = [
      `#ifndef SEC_DEFS_H`,
      `#define SEC_DEFS_H`,
      `#define ENFORCE_SESSION_AUTH(sess) ((sess) != NULL && (sess)->is_authenticated != 0)`,
      `#endif`
    ].join("\n");

    const sourceContent = [
      `#include "include/sec_defs.h"`,
      `bool verifySession(Session *sess) {`,
      `    if (!ENFORCE_SESSION_AUTH(sess)) {`,
      `        return false;`,
      `    }`,
      `    return true;`,
      `}`
    ].join("\n");

    fs.writeFileSync(headerFull, headerContent);
    fs.writeFileSync(sourceFull, sourceContent);
    execFileSync("git", ["add", headerRelPath, sourceRelPath], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Initial commit with security header and session file"], { cwd: tmpDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // Modify working tree source file
    fs.writeFileSync(sourceFull, sourceContent + "\n// modified\n");

    const diffHunks = [
      `diff --git a/src/session.c b/src/session.c`,
      `--- a/src/session.c`,
      `+++ b/src/session.c`,
      `@@ -2,4 +2,5 @@`,
      `+    if (!ENFORCE_SESSION_AUTH(sess)) {`,
      `+        return false;`,
      `+    }`
    ].join("\n");

    // PR ChangeSet only touches src/session.c! include/sec_defs.h is NOT in changeSet.files
    const changeSet = {
      scopeMode: "revision-range",
      repository: { root: tmpDir, headSha },
      files: [{ path: sourceRelPath, additions: 2, deletions: 0 }],
      diffHunks
    };

    const pkg = buildContextPackage(changeSet, sourceRelPath, {
      repositoryRoot: tmpDir,
      headSha
    });

    assert.ok(pkg.ok, "Package build must succeed");
    const callees = pkg.layers.layer1AstEnclosure.callees || [];
    const macroCallee = callees.find(c => c.symbol === "ENFORCE_SESSION_AUTH");
    assert.ok(macroCallee, "Macro ENFORCE_SESSION_AUTH must be extracted from exact HEAD header");
    assert.equal(macroCallee.file, headerRelPath);
    assert.equal(macroCallee.isHeaderCallee, true);
    assert.ok(macroCallee.definition.includes("#define ENFORCE_SESSION_AUTH"));

    // Gap is resolved!
    const gap = pkg.contextGaps.find(g => g.symbol === "ENFORCE_SESSION_AUTH");
    assert.equal(gap, undefined, "Header-resolved macro must not create a contextGap");

    // Strict Set Equality preserved: manifest only contains PR files (src/session.c)
    const binding = evaluateContextPackageBinding(pkg, changeSet, headSha);
    assert.equal(binding.bound, true, "Package must bind strictly to changeSet without scope mismatch");

    // Verifier authenticity succeeds against Git HEAD without header in manifest
    const isAuthentic = validateContextPackageAuthenticity(pkg, {
      repositoryRoot: tmpDir,
      headSha,
      changeSet
    });
    assert.equal(isAuthentic, true, "validateContextPackageAuthenticity must accept authentic header callee");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Cross-File Symbol Extraction: Truly non-existent symbol on sensitive path fails closed to UNRESOLVED_SYMBOL in contextGaps", () => {
  const code = [
    `#include "include/sec_defs.h"`,
    `bool handleRequest(Request *req) {`,
    `    return true;`,
    `}`
  ].join("\n");

  const diffHunks = [
    `@@ -2,3 +2,4 @@`,
    `+ if (!validateUntrustedToken(req->token)) return false;`
  ].join("\n");

  const targetFile = "src/handler.c";
  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, {
    fileContents: { [targetFile]: code }
  });

  const unresolved = pkg.layers.layer1AstEnclosure.unresolvedCallees;
  assert.ok(unresolved.some(u => u.symbol === "validateUntrustedToken" && u.reason === "UNRESOLVED_SYMBOL"));

  const gap = pkg.contextGaps.find(g => g.symbol === "validateUntrustedToken");
  assert.ok(gap, "Missing sensitive callee must fail closed into contextGaps");
  assert.equal(gap.reason, "UNRESOLVED_SYMBOL");
  assert.equal(gap.category, "input_validation");
});

test("Cross-File Symbol Extraction: Ambiguous cross-file definition fails closed to AMBIGUOUS_SYMBOL in contextGaps", () => {
  const callerCode = [
    `export function dispatch(req) {`,
    `  if (!authenticate(req)) return null;`,
    `  return "ok";`,
    `}`
  ].join("\n");

  const sibling1Code = [
    `export function authenticate(req) {`,
    `  return req.headers.authorization !== undefined;`,
    `}`
  ].join("\n");

  const sibling2Code = [
    `export function authenticate(req) {`,
    `  return req.session !== null;`,
    `}`
  ].join("\n");

  const diffHunks = [
    `diff --git a/src/dispatcher.js b/src/dispatcher.js`,
    `--- a/src/dispatcher.js`,
    `+++ b/src/dispatcher.js`,
    `@@ -1,3 +1,4 @@`,
    `+ if (!authenticate(req)) return null;`
  ].join("\n");

  const changeSet = {
    scopeMode: "working-tree",
    files: [
      { path: "src/dispatcher.js", additions: 1, deletions: 0 },
      { path: "src/auth_bearer.js", additions: 0, deletions: 0 },
      { path: "src/auth_session.js", additions: 0, deletions: 0 }
    ],
    diffHunks
  };

  const fileContents = {
    "src/dispatcher.js": callerCode,
    "src/auth_bearer.js": sibling1Code,
    "src/auth_session.js": sibling2Code
  };

  const pkg = buildContextPackage(changeSet, undefined, { fileContents });

  const unresolved = pkg.layers.layer1AstEnclosure.unresolvedCallees;
  assert.ok(unresolved.some(u => u.symbol === "authenticate" && u.reason === "AMBIGUOUS_SYMBOL"), "Must record AMBIGUOUS_SYMBOL");

  const gap = pkg.contextGaps.find(g => g.symbol === "authenticate");
  assert.ok(gap, "Ambiguous symbol must fail closed into contextGaps");
  assert.equal(gap.reason, "AMBIGUOUS_SYMBOL");
});

test("Cross-File Symbol Extraction: Direct header include at HEAD resolves C/C++ function signature without CALLEE_TRUNCATED_ELIDED gap", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-header-signature-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    const headerRelPath = "include/auth_api.h";
    const sourceRelPath = "src/service.c";

    const headerFull = path.join(tmpDir, headerRelPath);
    const sourceFull = path.join(tmpDir, sourceRelPath);
    fs.mkdirSync(path.dirname(headerFull), { recursive: true });
    fs.mkdirSync(path.dirname(sourceFull), { recursive: true });

    const headerContent = [
      `#ifndef AUTH_API_H`,
      `#define AUTH_API_H`,
      `bool validateUser(User *u);`,
      `#endif`
    ].join("\n");

    const sourceContent = [
      `#include "include/auth_api.h"`,
      `bool handleLogin(User *u) {`,
      `    if (!validateUser(u)) {`,
      `        return false;`,
      `    }`,
      `    return true;`,
      `}`
    ].join("\n");

    fs.writeFileSync(headerFull, headerContent, "utf8");
    fs.writeFileSync(sourceFull, sourceContent, "utf8");
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Initial commit with header and source"], { cwd: tmpDir, stdio: "ignore" });

    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    const diffHunks = [
      `diff --git a/src/service.c b/src/service.c`,
      `--- a/src/service.c`,
      `+++ b/src/service.c`,
      `@@ -2,4 +2,5 @@`,
      `+    if (!validateUser(u)) {`,
      `+        return false;`,
      `+    }`
    ].join("\n");

    const changeSet = {
      scopeMode: "revision-range",
      repository: { root: tmpDir, headSha },
      files: [{ path: sourceRelPath, additions: 2, deletions: 0 }],
      diffHunks
    };

    const pkg = buildContextPackage(changeSet, sourceRelPath, {
      repositoryRoot: tmpDir,
      headSha
    });

    assert.ok(pkg.ok, "Package build must succeed");
    const callees = pkg.layers.layer1AstEnclosure.callees || [];
    const sigCallee = callees.find(c => c.symbol === "validateUser");
    assert.ok(sigCallee, "Function signature validateUser must be extracted from header at HEAD");
    assert.equal(sigCallee.file, headerRelPath);
    assert.equal(sigCallee.isHeaderCallee, true);
    assert.equal(sigCallee.extractionMode, "signature");
    assert.ok(sigCallee.definition.includes("bool validateUser(User *u);"));

    // Critical: zero context gaps! CALLEE_TRUNCATED_ELIDED must NOT be emitted
    const gap = pkg.contextGaps.find(g => g.symbol === "validateUser");
    assert.equal(gap, undefined, "Header-resolved signature must NOT emit CALLEE_TRUNCATED_ELIDED gap");
    assert.equal(pkg.contextGaps.length, 0, "Expected zero context gaps");

    // Authenticity validation passes with physical Git HEAD backing
    const isAuthentic = validateContextPackageAuthenticity(pkg, {
      repositoryRoot: tmpDir,
      headSha,
      changeSet
    });
    assert.equal(isAuthentic, true, "validateContextPackageAuthenticity must accept authentic header signature");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Cross-File Symbol Extraction: Multiline function signature in header preserves return type and accurate startLine", () => {
  const headerContent = [
    `#ifndef AUTH_H`,
    `#define AUTH_H`,
    `extern const char *`,
    `validateToken(const char *raw_token);`,
    `#endif`
  ].join("\n");

  const hLines = headerContent.split("\n");
  const decls = findFunctionDeclarations(hLines, "validateToken");
  assert.equal(decls.length, 1);
  assert.equal(decls[0].startLine, 3);
  assert.equal(decls[0].endLine, 4);
  assert.ok(decls[0].snippet.definition.includes("extern const char *"));
  assert.ok(decls[0].snippet.definition.includes("validateToken"));
});

test("Cross-File Symbol Extraction: Typedef struct and primitive typedef extraction", () => {
  const cHeader = [
    `typedef uint64_t EpochTimestamp;`,
    ``,
    `typedef struct {`,
    `    int id;`,
    `    char name[64];`,
    `} UserRecord;`,
    ``,
    `typedef struct session_s {`,
    `    UserRecord *user;`,
    `    bool active;`,
    `} Session;`
  ].join("\n");

  const lines = cHeader.split("\n");

  const epochDef = findTypeDefinitions(lines, "EpochTimestamp");
  assert.equal(epochDef.length, 1);
  assert.ok(epochDef[0].snippet.definition.includes("typedef uint64_t EpochTimestamp;"));

  const userDef = findTypeDefinitions(lines, "UserRecord");
  assert.equal(userDef.length, 1);
  assert.equal(userDef[0].startLine, 3);
  assert.equal(userDef[0].endLine, 6);
  assert.ok(userDef[0].snippet.definition.includes("typedef struct {"));
  assert.ok(userDef[0].snippet.definition.includes("UserRecord;"));

  const sessionDef = findTypeDefinitions(lines, "Session");
  assert.equal(sessionDef.length, 1);
  assert.equal(sessionDef[0].startLine, 8);
  assert.equal(sessionDef[0].endLine, 11);
  assert.ok(sessionDef[0].snippet.definition.includes("typedef struct session_s {"));
  assert.ok(sessionDef[0].snippet.definition.includes("Session;"));
});

test("Cross-File Symbol Extraction: Include paths with backslashes and include/ directory convention", () => {
  const fileContent = [
    `#include "include\\sec_defs.h"`,
    `#include "common.h"`,
    `import { helper } from "src/utils/helper";`
  ].join("\n");

  const paths = extractDirectIncludePaths(fileContent, "src/worker.c");
  assert.ok(paths.includes("include/sec_defs.h"), "Backslash paths must be normalized to forward slashes");
  assert.ok(paths.includes("src/common.h"), "Must include candidate relative to calling dir");
  assert.ok(paths.includes("common.h"), "Must include candidate relative to repo root");
  assert.ok(paths.includes("include/common.h"), "Must include candidate in include/ subdirectory");
  assert.ok(paths.includes("src/utils/helper") || paths.includes("src/utils/helper.js"), "Must include src/ paths");
});

test("Standard Library Callee Symbols: memcmp, memcpy, strlen are exempted from UNRESOLVED_SYMBOL and contextGaps", () => {
  const cCode = [
    `#include <string.h>`,
    `#include <stdlib.h>`,
    `bool compareTokens(const char *a, const char *b, size_t n) {`,
    `    if (memcmp(a, b, n) == 0) return true;`,
    `    void *buf = malloc(n);`,
    `    if (!buf) return false;`,
    `    memcpy(buf, a, n);`,
    `    free(buf);`,
    `    return false;`,
    `}`
  ].join("\n");

  const diffHunks = [
    `@@ -10,10 +10,10 @@`,
    `+    if (memcmp(a, b, n) == 0) return true;`,
    `+    void *buf = malloc(n);`,
    `+    memcpy(buf, a, n);`,
    `+    free(buf);`
  ].join("\n");

  const targetFile = "src/crypto_utils.c";
  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 4, deletions: 0 }],
    diffHunks
  };

  const fileContents = { [targetFile]: cCode };
  const pkg = buildContextPackage(changeSet, targetFile, { fileContents });

  assert.equal(pkg.contextGaps.length, 0, "Standard library functions (memcmp, malloc, memcpy, free) must not enter contextGaps");
  const unres = pkg.layers.layer1AstEnclosure?.unresolvedCallees || [];
  assert.ok(!unres.some(u => u.symbol === "memcmp"), "memcmp must not be marked UNRESOLVED_SYMBOL");
  assert.ok(!unres.some(u => u.symbol === "malloc"), "malloc must not be marked UNRESOLVED_SYMBOL");
  assert.ok(!unres.some(u => u.symbol === "memcpy"), "memcpy must not be marked UNRESOLVED_SYMBOL");
  assert.ok(!unres.some(u => u.symbol === "free"), "free must not be marked UNRESOLVED_SYMBOL");
});

test("C Pointer Return Types: unsigned char *func is matched as definition and not call", () => {
  const code = [
    `unsigned char *lpUpgradeCompactBacklen(unsigned char *lp, size_t *size) {`,
    `    return lp;`,
    `}`
  ].join("\n");

  const lines = code.split("\n");
  const defs = findFunctionDefinitions(lines, "lpUpgradeCompactBacklen");
  assert.equal(defs.length, 1, "Must find definition with pointer return type");
  assert.equal(defs[0].startLine, 1);
  assert.equal(defs[0].endLine, 3);

  const diff = "+ unsigned char *lpUpgradeCompactBacklen(unsigned char *lp, size_t *size) {";
  const calls = extractCandidateCallSymbols(diff);
  assert.equal(calls.length, 0, "Function declaration header line must not be treated as a call to itself");
});




