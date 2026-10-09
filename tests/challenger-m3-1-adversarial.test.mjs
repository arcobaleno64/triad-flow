/**
 * Adversarial Stress-Test Suite for LOOP2-SYSTEMIC-REMEDIATION-007 Milestone 3
 * Agent: challenger_m3_1
 * Role: EMPIRICAL CHALLENGER
 *
 * Rigorously probes:
 * 1. Exact-Head Source Extraction & Dirty Working Tree Immunity (Spec §3.3.1)
 *    - Uncommitted modifications in working tree are ignored
 *    - Deleted working tree files resolve from commit
 *    - Untracked working tree files return null
 *    - Staged-only changes in index are ignored
 *    - Invalid/malformed/injection SHA parameters fail closed
 *    - Historical multi-commit resolution & cache partitioning
 * 2. Extraction Budget Ceilings & Bounded Snippets (Spec §3.3.3)
 *    - Max 5 callees per modified file
 *    - Max 10 callees across multi-file changeset
 *    - <= 30 lines extracts full body (<= 2000 bytes)
 *    - > 30 lines extracts signature + guards (<= 60 lines, <= 2000 bytes)
 *    - Global AST ceiling (<= 8,000 bytes)
 * 3. Deterministic Parsing & Context Gap Propagation (Spec §3.3.2)
 *    - AMBIGUOUS_SYMBOL for overloads
 *    - MACRO_OR_DYNAMIC for #define macros and dynamic calls
 *    - UNRESOLVED_SYMBOL for missing definitions
 *    - Sensitive paths promoted to contextGaps
 *    - Non-sensitive paths excluded from contextGaps
 *    - Dual visibility in Sentry and Verifier prompts
 * 4. Diff Non-Displacement Invariant (Spec §3.3.3)
 *    - Diff hunks retain absolute budget priority; AST context never displaces or truncates diff
 *    - Deterministic layer eviction hierarchy
 * 5. Downstream Gate Integration (Spec §3.1.1, §3.3.2)
 *    - Context gaps leading to UNCERTAIN status route to human_review_required
 * 6. Empirical Challenge Probes
 *    - Sensitivity classification regex behavior on camelCase non-initial tokens
 *    - Context budget allocation accounting when Layer 0 (diff) consumes > 50%
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
  buildVerificationPrompt,
  conductIndependentVerification
} from "../src/core/independent-verifier.mjs";
import { evaluatePostVerificationGate } from "../src/core/harness.mjs";

function setupTmpGitRepo() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-m3-1-adv-"));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "challenger_m3_1@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "M3.1 Challenger"], { cwd: tmpDir, stdio: "ignore" });
  return tmpDir;
}

// ============================================================================
// 1. EXACT-HEAD EXTRACTION & DIRTY WORKING TREE IMMUNITY
// ============================================================================

test("EXACT-HEAD-01: Extracts committed content while ignoring dirty uncommitted edits in working tree", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/engine.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });

    const committed = "function startEngine() { return true; }\n";
    fs.writeFileSync(full, committed);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit 1"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Dirty the working tree file with uncommitted edits
    fs.writeFileSync(full, "function startEngine() { return 'DIRTY_POISON'; }\n");

    const extracted = getExactHeadFileContent(repo, headSha, file);
    assert.equal(extracted, committed, "Extracted content must match commit exactly, ignoring dirty edits");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-02: Extracts committed content when working tree file is completely deleted", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/deleted_on_disk.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });

    const committed = "export const PI = 3.14159;\n";
    fs.writeFileSync(full, committed);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit file"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Delete file from disk
    fs.unlinkSync(full);
    assert.ok(!fs.existsSync(full));

    const extracted = getExactHeadFileContent(repo, headSha, file);
    assert.equal(extracted, committed, "Must extract from Git object database even if file does not exist on disk");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-03: Untracked file in working tree returns null for commit SHA", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    // Initial commit
    const initFile = "README.md";
    fs.writeFileSync(path.join(repo, initFile), "# Triad\n");
    execFileSync("git", ["add", initFile], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Create untracked file
    const untracked = "src/untracked.js";
    const full = path.join(repo, untracked);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, "console.log('untracked');\n");

    const extracted = getExactHeadFileContent(repo, headSha, untracked);
    assert.equal(extracted, null, "Untracked file absent in target commit must return null");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-04: Ignores staged changes in Git index and extracts strictly from commit object", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/staged_test.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });

    const committed = "function original() { return 1; }\n";
    fs.writeFileSync(full, committed);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "original"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Stage changes in index without committing
    fs.writeFileSync(full, "function original() { return 999; /* STAGED */ }\n");
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });

    const extracted = getExactHeadFileContent(repo, headSha, file);
    assert.equal(extracted, committed, "Index staging must not leak into exact-head commit extraction");
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-05: Malformed, non-hex, command-injection or null SHAs fail closed without throwing", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/dummy.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, "const x = 1;\n");
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "dummy"], { cwd: repo, stdio: "ignore" });

    const maliciousShas = [
      "",
      "   ",
      null,
      undefined,
      "../../../etc/passwd",
      "; rm -rf /",
      "HEAD~1",
      "master",
      "0".repeat(40),
      "not-a-valid-hex-sha",
      "g".repeat(40),
      "12345" // too short
    ];

    for (const badSha of maliciousShas) {
      const res = getExactHeadFileContent(repo, badSha, file);
      assert.equal(res, null, `Malformed SHA '${badSha}' must return null safely`);
    }
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-06: Historical multi-commit extraction resolves requested SHA and partitions cache", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/history.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });

    const v1 = "const VERSION = 1;\n";
    fs.writeFileSync(full, v1);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "v1"], { cwd: repo, stdio: "ignore" });
    const sha1 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    const v2 = "const VERSION = 2;\n";
    fs.writeFileSync(full, v2);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "v2"], { cwd: repo, stdio: "ignore" });
    const sha2 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    assert.equal(getExactHeadFileContent(repo, sha1, file), v1);
    assert.equal(getExactHeadFileContent(repo, sha2, file), v2);
    // Cached read verifies partition
    assert.equal(getExactHeadFileContent(repo, sha1, file), v1);
    assert.equal(getExactHeadFileContent(repo, sha2, file), v2);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("EXACT-HEAD-07: buildContextPackage extracts callee strictly from headSha when workspace is dirty", () => {
  clearExactHeadCache();
  const repo = setupTmpGitRepo();
  try {
    const file = "src/dispatcher.js";
    const full = path.join(repo, file);
    fs.mkdirSync(path.dirname(full), { recursive: true });

    const committedSource = [
      `export function helperValidation(input) {`,
      `  if (!input) return false;`,
      `  return true;`,
      `}`,
      `export function dispatch(req) {`,
      `  return helperValidation(req);`,
      `}`
    ].join("\n");

    fs.writeFileSync(full, committedSource);
    execFileSync("git", ["add", file], { cwd: repo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "add dispatcher"], { cwd: repo, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();

    // Poison working tree with a modified definition
    fs.writeFileSync(full, "export function helperValidation() { return 'POISON'; }\n");

    const diffHunks = `@@ -5,3 +5,3 @@\n+ return helperValidation(req);`;
    const changeSet = {
      scopeMode: "revision-range",
      repository: { root: repo, headSha },
      files: [{ path: file, additions: 1, deletions: 0 }],
      diffHunks
    };

    const pkg = buildContextPackage(changeSet, file, {
      repositoryRoot: repo,
      headSha
    });

    const callees = pkg.layers.layer1AstEnclosure.callees || [];
    assert.equal(callees.length, 1);
    assert.equal(callees[0].symbol, "helperValidation");
    assert.ok(callees[0].definition.includes("if (!input) return false;"));
    assert.ok(!callees[0].definition.includes("POISON"));
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

// ============================================================================
// 2. EXTRACTION BUDGET CEILINGS & BOUNDED SNIPPETS
// ============================================================================

test("BUDGET-01: Per-file quantity ceiling strictly caps at MAX_CALLEES_PER_FILE (5)", () => {
  const fns = [];
  for (let i = 1; i <= 10; i++) {
    fns.push(`function callee_${i}(x) { return x + ${i}; }`);
  }
  const fileContent = fns.join("\n\n");

  const diffCalls = [];
  for (let i = 1; i <= 8; i++) {
    diffCalls.push(`+ const res_${i} = callee_${i}(input);`);
  }
  const diffHunks = `@@ -1,5 +1,15 @@\n${diffCalls.join("\n")}`;

  const res = extractLocalCalleeContext(fileContent, diffHunks, "src/multi.js");
  assert.equal(res.callees.length, MAX_CALLEES_PER_FILE, `Must extract exactly ${MAX_CALLEES_PER_FILE} callees, not ${res.callees.length}`);
  assert.equal(res.callees[0].symbol, "callee_1");
  assert.equal(res.callees[4].symbol, "callee_5");
});

test("BUDGET-02: Global quantity ceiling strictly caps at MAX_CALLEES_TOTAL (10) across multi-file calls", () => {
  const fns = [];
  for (let i = 1; i <= 10; i++) {
    fns.push(`function func_${i}() { return ${i}; }`);
  }
  const fileContent = fns.join("\n");

  const diffCalls = Array.from({ length: 6 }, (_, i) => `+ func_${i + 1}();`).join("\n");
  const diffHunks = `@@ -1,3 +1,10 @@\n${diffCalls}`;

  // File 1: extracts 5
  const res1 = extractLocalCalleeContext(fileContent, diffHunks, "file1.js", { extractedCalleesCount: 0 });
  assert.equal(res1.callees.length, 5);

  // File 2: runningTotal is 5, extracts 5 (total reaches 10)
  const res2 = extractLocalCalleeContext(fileContent, diffHunks, "file2.js", { extractedCalleesCount: 5 });
  assert.equal(res2.callees.length, 5);

  // File 3: runningTotal is 10, cannot extract any more callees
  const res3 = extractLocalCalleeContext(fileContent, diffHunks, "file3.js", { extractedCalleesCount: 10 });
  assert.equal(res3.callees.length, 0, "When running total reaches MAX_CALLEES_TOTAL, 0 callees must be extracted");
});

test("BUDGET-03: Line-count cutoff <= 30 lines extracts full body; > 30 lines extracts signature + guards", () => {
  // 1. Function with exactly 30 lines
  const lines30 = [
    `function exactlyThirtyLines(val) {`,
    ...Array.from({ length: 28 }, (_, i) => `  const step_${i} = ${i};`),
    `}`
  ];
  assert.equal(lines30.length, 30);
  const snippet30 = extractBoundedFunctionSnippet(lines30, 1, 30);
  assert.equal(snippet30.extractionMode, "full_body");
  assert.equal(snippet30.lines, 30);
  assert.ok(snippet30.bytes <= MAX_SNIPPET_BYTES);
  assert.equal(snippet30.definition, lines30.join("\n"));

  // 2. Function with 31 lines
  const lines31 = [
    `function thirtyOneLines(val) {`,
    `  if (!val) return null;`,
    ...Array.from({ length: 28 }, (_, i) => `  const step_${i} = ${i};`),
    `}`
  ];
  assert.equal(lines31.length, 31);
  const snippet31 = extractBoundedFunctionSnippet(lines31, 1, 31);
  assert.equal(snippet31.extractionMode, "signature_and_guards");
  assert.ok(snippet31.definition.includes("/* ... [remainder of function body elided for context bounds] ... */"));
  assert.ok(snippet31.definition.includes("if (!val) return null;"));
  assert.ok(snippet31.definition.endsWith("}"));
  assert.ok(snippet31.lines <= MAX_SNIPPET_LINES);
  assert.ok(snippet31.bytes <= MAX_SNIPPET_BYTES);
});

test("BUDGET-04: Giant callee with large byte payload is bounded to MAX_SNIPPET_BYTES (2000)", () => {
  // Construct a 20-line function with huge strings exceeding 2000 bytes
  const largeStrings = Array.from({ length: 18 }, (_, i) => `  const s${i} = "${"X".repeat(150)}";`);
  const giantShortFn = [
    `function giantShort(a) {`,
    ...largeStrings,
    `}`
  ];
  assert.equal(giantShortFn.length, 20);
  const totalRawBytes = Buffer.byteLength(giantShortFn.join("\n"), "utf8");
  assert.ok(totalRawBytes > 2000, "Raw function must exceed 2000 bytes");

  const snippet = extractBoundedFunctionSnippet(giantShortFn, 1, 20);
  assert.ok(snippet.bytes <= MAX_SNIPPET_BYTES, `Snippet bytes ${snippet.bytes} must not exceed ${MAX_SNIPPET_BYTES}`);
});

test("BUDGET-05: Global Layer 1 AST ceiling strictly limits context to <= 8,000 bytes", () => {
  const diffHunks = `@@ -1,5 +1,5 @@\n+ callHugeFunction();`;

  // Create 5 massive callees each right at 1,900 bytes (total > 9,500 bytes)
  const callees = [];
  for (let i = 1; i <= 5; i++) {
    const lines = [
      `function huge_${i}() {`,
      `  if (check()) return false;`,
      `  /* ${"A".repeat(1700)} */`,
      `  return 0;`,
      `}`
    ].join("\n");
    callees.push({
      symbol: `huge_${i}`,
      definition: lines,
      lines: 5,
      bytes: Buffer.byteLength(lines, "utf8"),
      startLine: (i - 1) * 10 + 1,
      endLine: (i - 1) * 10 + 5,
      extractionMode: "full_body"
    });
  }

  const rawLayers = {
    layer0Diff: { rawHunks: diffHunks, byteLength: Buffer.byteLength(diffHunks, "utf8") },
    layer1AstEnclosure: {
      adapterName: "builtin-semantic",
      enclosingFunctions: [{ name: "fn", bodySnippet: "/* big */" }],
      enclosingClasses: [],
      callees,
      unresolvedCallees: []
    },
    layer2ModuleScope: { imports: [], exports: [], topLevelConstants: [] },
    layer3CallGraph: { callers: [], callees: [] }
  };

  const budgeted = allocateContextBudget(rawLayers, DEFAULT_BUDGET_CONFIG);
  const layer1Bytes = Buffer.byteLength(JSON.stringify(budgeted.layers.layer1AstEnclosure), "utf8");
  assert.ok(
    layer1Bytes <= GLOBAL_AST_CONTEXT_CEILING_BYTES,
    `Layer 1 AST context bytes ${layer1Bytes} must be <= ${GLOBAL_AST_CONTEXT_CEILING_BYTES}`
  );
});

// ============================================================================
// 3. DETERMINISTIC REASON CODES & SENSITIVE CONTEXT GAP PROPAGATION
// ============================================================================

test("PARSING-01: AMBIGUOUS_SYMBOL recorded for duplicate / overloaded function definitions", () => {
  const code = [
    `int compute(int a) { return a; }`,
    `double compute(double a) { return a * 1.5; }`
  ].join("\n");

  const diffHunks = `@@ -5,2 +5,2 @@\n+ int res = compute(arg);`;
  const res = extractLocalCalleeContext(code, diffHunks, "src/calc.cpp");

  assert.equal(res.callees.length, 0);
  assert.equal(res.unresolvedCallees.length, 1);
  assert.equal(res.unresolvedCallees[0].symbol, "compute");
  assert.equal(res.unresolvedCallees[0].reason, "AMBIGUOUS_SYMBOL");
});

test("PARSING-02: MACRO_OR_DYNAMIC recorded for #define macros and dynamic arrow calls", () => {
  const code = [
    `#define SANITIZE_INPUT(str) (clean(str))`,
    `void process() {}`
  ].join("\n");

  // Call 1: #define macro
  const diffHunks1 = `@@ -5,2 +5,2 @@\n+ SANITIZE_INPUT(val);`;
  const res1 = extractLocalCalleeContext(code, diffHunks1, "src/util.cpp");
  assert.ok(res1.unresolvedCallees.some(u => u.symbol === "SANITIZE_INPUT" && u.reason === "MACRO_OR_DYNAMIC"));

  // Call 2: dynamic dispatch via pointer ->
  const diffHunks2 = `@@ -10,2 +10,2 @@\n+ validator->checkBounds(val);`;
  const res2 = extractLocalCalleeContext(code, diffHunks2, "src/util.cpp");
  assert.ok(res2.unresolvedCallees.some(u => u.symbol === "checkBounds" && u.reason === "MACRO_OR_DYNAMIC"));
});

test("PARSING-03: UNRESOLVED_SYMBOL recorded when callee definition is not present in modified file", () => {
  const code = `function localTask() { return 1; }`;
  const diffHunks = `@@ -2,2 +2,2 @@\n+ const r = externalTransform(input);`;
  const res = extractLocalCalleeContext(code, diffHunks, "src/task.js");

  assert.equal(res.callees.length, 0);
  assert.ok(res.unresolvedCallees.some(u => u.symbol === "externalTransform" && u.reason === "UNRESOLVED_SYMBOL"));
});

test("GAPS-01: Sensitive execution paths are promoted to contextGaps across sensitive categories", () => {
  const code = `void dummy() {}`;

  const cases = [
    { call: `+ if (validateUserInput(x)) {}`, sym: "validateUserInput", category: "input_validation" },
    { call: `+ const def = defaultFallback();`, sym: "defaultFallback", category: "default_values" },
    { call: `+ if (errorHandler(err)) {}`, sym: "errorHandler", category: "error_handling" },
    { call: `+ if (checkAuthToken(tok)) {}`, sym: "checkAuthToken", category: "input_validation" }
  ];

  for (const c of cases) {
    const diffHunks = `@@ -1,2 +1,2 @@\n${c.call}`;
    const res = extractLocalCalleeContext(code, diffHunks, "src/handler.cpp");
    const gap = res.contextGaps.find(g => g.symbol === c.sym);
    assert.ok(gap, `Symbol '${c.sym}' must be promoted to contextGaps`);
    assert.equal(gap.category, c.category);
  }
});

test("GAPS-02: Non-sensitive execution paths remain in unresolvedCallees but are NOT promoted to contextGaps", () => {
  const code = `void dummy() {}`;
  const diffHunks = `@@ -1,2 +1,2 @@\n+ renderPrettyHtml(data);`;
  const res = extractLocalCalleeContext(code, diffHunks, "src/ui.cpp");

  assert.ok(res.unresolvedCallees.some(u => u.symbol === "renderPrettyHtml"));
  assert.equal(res.contextGaps.length, 0, "Non-sensitive UI call must not become a contextGap");
});

test("GAPS-03: Dual prompt visibility renders [UNRESOLVED CODE CONTEXT GAPS] in both Sentry and Verifier", () => {
  const contextPackage = {
    targetFile: "src/crypto.cpp",
    layers: {
      layer0Diff: { rawHunks: "+ verifyToken();" },
      layer1AstEnclosure: { callees: [], unresolvedCallees: [] }
    },
    contextGaps: [
      {
        symbol: "verifyToken",
        reason: "UNRESOLVED_SYMBOL",
        category: "security",
        file: "src/crypto.cpp",
        line: 10
      }
    ]
  };

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: "src/crypto.cpp", additions: 1, deletions: 0 }],
    diffHunks: "+ verifyToken();"
  };

  // 1. Sentry Prompt
  const sentryPrompt = buildEvidenceReviewPrompt(changeSet, "macro", undefined, contextPackage);
  assert.ok(sentryPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(sentryPrompt.includes("Symbol: 'verifyToken' (Reason: UNRESOLVED_SYMBOL) [Category: security] at src/crypto.cpp:10"));
  assert.ok(sentryPrompt.includes("MANDATORY UNCERTAINTY INSTRUCTION"));

  // 2. Verifier Prompt
  const verifierPrompt = buildVerificationPrompt(changeSet, [], { contextPackage });
  assert.ok(verifierPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(verifierPrompt.includes("Symbol: 'verifyToken' (Reason: UNRESOLVED_SYMBOL) [Category: security] at src/crypto.cpp:10"));
  assert.ok(verifierPrompt.includes("Context Gap Mandate: If [UNRESOLVED CODE CONTEXT GAPS] are present below"));
});

// ============================================================================
// 4. DIFF NON-DISPLACEMENT CONTRACT & EVICTION
// ============================================================================

test("DIFF-01: Diff hunks retain absolute budget priority; AST context never displaces or truncates diff", () => {
  const massiveDiff = Array.from({ length: 50 }, (_, i) => `+ int mutated_var_${i} = ${i};`).join("\n");
  const diffHunks = `@@ -1,10 +1,60 @@\n${massiveDiff}`;
  const diffBytes = Buffer.byteLength(diffHunks, "utf8");

  const rawLayers = {
    layer0Diff: { rawHunks: diffHunks, byteLength: diffBytes, additions: 50, deletions: 0 },
    layer1AstEnclosure: {
      adapterName: "builtin-semantic",
      enclosingFunctions: [{ name: "foo", bodySnippet: "/* 123 */" }],
      callees: [{ symbol: "callee", definition: "void callee() {}", lines: 1, bytes: 16 }]
    },
    layer2ModuleScope: {
      imports: ["import x from 'y';"],
      exports: ["export const z = 1;"],
      topLevelConstants: ["C = 1"]
    },
    layer3CallGraph: {
      callers: Array.from({ length: 30 }, (_, i) => ({ file: `a${i}.js`, line: 1, callerName: `main${i}` })),
      callees: [{ functionName: "sub", signature: "sub()" }]
    }
  };

  // Restrictive budget where Layer 3 exceeds its budget3 allocation (10%)
  const tightConfig = {
    maxInputBytes: diffBytes + 2500,
    frameBytes: 2000,
    layer0Ratio: 0.50,
    layer1Ratio: 0.30,
    layer2Ratio: 0.10,
    layer3Ratio: 0.10
  };

  const budgeted = allocateContextBudget(rawLayers, tightConfig);

  // Layer 0 diff is 100% preserved
  assert.equal(budgeted.layers.layer0Diff.rawHunks, diffHunks, "Layer 0 diff hunks must remain 100% bit-for-bit intact");
  assert.equal(budgeted.budgetAccounting.layer0Bytes, diffBytes);

  // Layer 3 is evicted because it exceeds its 10% slice
  assert.ok(budgeted.budgetAccounting.evictedLayers.includes("layer3CallGraph"), "Layer 3 should be evicted first");
});

// ============================================================================
// 5. DOWNSTREAM GATE INTEGRATION WITH UNCERTAIN STATUS
// ============================================================================

test("GATE-01: Context gap forcing Verifier UNCERTAIN status routes strictly to human_review_required", async () => {
  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: "src/auth.cpp", additions: 1, deletions: 0 }],
    diffHunks: "+ if (unresolvedSecurityCheck(tok)) return false;"
  };

  // Mock verifier complying with Context Gap Mandate
  const mockVerifierAdapter = {
    executeVerification: async () => ({
      overallStatus: "UNCERTAIN",
      evaluations: [],
      verifierOmissions: [
        {
          title: "Missing callee on critical security boundary",
          severity: "high",
          evidenceSupport: "UNCERTAIN",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: "src/auth.cpp",
          line_start: 1,
          line_end: 1,
          reasoning: "Definition of unresolvedSecurityCheck cannot be retrieved; cannot certify clean."
        }
      ]
    })
  };

  const record = await conductIndependentVerification(changeSet, [], mockVerifierAdapter, {
    verificationMode: "clean_challenge"
  });

  assert.equal(record.overallStatus, "UNCERTAIN");

  // Gate evaluation under Tier 1
  const gateTier1 = evaluatePostVerificationGate({ findings: [], tier: "tier1" }, record);
  assert.equal(gateTier1.decision, "human_review_required", "UNCERTAIN in Tier 1 must require human review");

  // Gate evaluation under Tier 2
  const gateTier2 = evaluatePostVerificationGate({ findings: [], tier: "tier2" }, record);
  assert.equal(gateTier2.decision, "human_review_required", "UNCERTAIN in Tier 2 must require human review");
});

// ============================================================================
// 6. EMPIRICAL CHALLENGE PROBES (DEFECT AND LIMITATION EVIDENCE)
// ============================================================================

test("CHALLENGE-01: Empirical probe documenting camelCase non-initial sensitivity classification blindspot", () => {
  // Functions with common prefixes like get, is, has, handle before the sensitive term
  const testWords = [
    { text: "getDefaultFallback", expected: null }, // missed by regex!
    { text: "isErrorStatus", expected: null },      // missed by regex!
    { text: "handleError", expected: null },        // missed by regex!
    { text: "hasPermission", expected: null },      // missed by regex!
    { text: "isMapValueDefault", expected: "default_values" } // passes only because explicitly hardcoded in regex
  ];

  for (const item of testWords) {
    const res = classifySensitiveCategory(item.text);
    assert.equal(res, item.expected, `classifySensitiveCategory('${item.text}') returns '${res}'`);
  }
});

test("CHALLENGE-02: Empirical probe documenting budget overflow when Layer 0 (diff) exceeds 50% ratio", () => {
  // When Layer 0 consumes 80% of budget, allocateContextBudget still allocates full 30%+10%+10% to other layers
  const rawLayers = {
    layer0Diff: { rawHunks: "D".repeat(8000), byteLength: 8000 },
    layer1AstEnclosure: { callees: [{ symbol: "f", definition: "A".repeat(1500) }] },
    layer2ModuleScope: { imports: ["B".repeat(500)] },
    layer3CallGraph: { callers: ["C".repeat(500)] }
  };
  const config = {
    maxInputBytes: 10000,
    frameBytes: 1000,
    layer0Ratio: 0.50,
    layer1Ratio: 0.30,
    layer2Ratio: 0.10,
    layer3Ratio: 0.10
  };

  const res = allocateContextBudget(rawLayers, config);
  // Empirical observation: consumedBytes exceeds allocatedBytes because availBudget does not subtract layer0Bytes
  assert.ok(res.budgetAccounting.consumedBytes > res.budgetAccounting.allocatedBytes, "Demonstrates consumedBytes overflow past allocatedBytes");
  assert.equal(res.budgetAccounting.evictedLayers.length, 0, "No layers evicted despite overall overflow");
});
