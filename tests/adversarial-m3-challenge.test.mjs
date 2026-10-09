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

import { getExactHeadFileContent, clearExactHeadCache } from "../src/core/git-collector.mjs";
import { buildEvidenceReviewPrompt, formatContextPackageXml, formatContextGaps } from "../src/adapters/review-prompts.mjs";
import { buildVerificationPrompt, conductIndependentVerification } from "../src/core/independent-verifier.mjs";
import { evaluatePostVerificationGate } from "../src/core/harness.mjs";

test("Adversarial M3.1: getExactHeadFileContent sanitization and injection prevention", () => {
  clearExactHeadCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-m3-adv-sha-"));
  try {
    // Malicious or malformed SHAs should return null immediately without spawning git
    assert.equal(getExactHeadFileContent(tmpDir, "; rm -rf /", "src/foo.js"), null);
    assert.equal(getExactHeadFileContent(tmpDir, "HEAD`calc`", "src/foo.js"), null);
    assert.equal(getExactHeadFileContent(tmpDir, "../../../etc/passwd", "src/foo.js"), null);
    assert.equal(getExactHeadFileContent(tmpDir, "   ", "src/foo.js"), null);
    assert.equal(getExactHeadFileContent(tmpDir, "12345", "src/foo.js"), null); // too short
    assert.equal(getExactHeadFileContent(null, "abcdef1234567890abcdef1234567890abcdef12", "src/foo.js"), null);
    assert.equal(getExactHeadFileContent(tmpDir, "abcdef1234567890abcdef1234567890abcdef12", null), null);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Adversarial M3.2: Exact-Head extraction completely isolates working tree deletes and mutations", () => {
  clearExactHeadCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-m3-adv-isolate-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    const filePath = "src/security_validator.cpp";
    const fullPath = path.join(tmpDir, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    const committedSource = [
      `#include <string>`,
      `bool validateAccess(const std::string & token) {`,
      `    if (token.empty() || token == "root") return false;`,
      `    return true;`,
      `}`
    ].join("\n");

    fs.writeFileSync(fullPath, committedSource);
    execFileSync("git", ["add", filePath], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Commit secure validator"], { cwd: tmpDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // Attack 1: Working tree file deleted!
    fs.unlinkSync(fullPath);
    assert.equal(fs.existsSync(fullPath), false);

    const fromGitDeleted = getExactHeadFileContent(tmpDir, headSha, filePath);
    assert.equal(fromGitDeleted, committedSource, "Must extract committed content even if file is deleted from working tree");

    // Attack 2: Working tree replaced with backdoor!
    fs.writeFileSync(fullPath, `bool validateAccess(const std::string &) { return true; /* BACKDOOR */ }`);
    clearExactHeadCache();
    const fromGitBackdoor = getExactHeadFileContent(tmpDir, headSha, filePath);
    assert.equal(fromGitBackdoor, committedSource, "Must strictly ignore backdoor in working tree");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Adversarial M3.3: Extreme function size truncation enforces <= 60 lines and <= 2000 bytes with closing brace", () => {
  // Construct a massive 1000-line function with multiple guard checks
  const lines = [
    `int parseComplexProtocolPacket(const uint8_t * buffer, size_t length) {`,
    `    if (!buffer) return -1;`,
    `    if (length < 4) return -2;`,
    `    if (isMapValueDefault(buffer, length)) return 0;`
  ];

  for (let i = 0; i < 995; i++) {
    lines.push(`    uint32_t intermediate_stage_${i} = compute_checksum_step(${i});`);
  }
  lines.push(`    return 100;`);
  lines.push(`}`);

  const snippet = extractBoundedFunctionSnippet(lines, 1, lines.length);

  assert.equal(snippet.extractionMode, "signature_and_guards");
  assert.ok(snippet.lines <= MAX_SNIPPET_LINES, `Snippet lines (${snippet.lines}) must be <= ${MAX_SNIPPET_LINES}`);
  assert.ok(snippet.bytes <= MAX_SNIPPET_BYTES, `Snippet bytes (${snippet.bytes}) must be <= ${MAX_SNIPPET_BYTES}`);
  assert.ok(snippet.definition.startsWith("int parseComplexProtocolPacket"));
  assert.ok(snippet.definition.includes("if (!buffer) return -1;"));
  assert.ok(snippet.definition.includes("/* ... [remainder of function body elided for context bounds] ... */"));
  assert.ok(snippet.definition.trim().endsWith("}"), "Must preserve the closing brace");
});

test("Adversarial M3.4: Budget allocation strictly prioritizes Layer 0 diff and collapses Layer 1 callees", () => {
  // Create an AST enclosure that exceeds the 8,000 bytes ceiling
  const callees = [];
  for (let i = 0; i < 10; i++) {
    callees.push({
      symbol: `callee_${i}`,
      definition: `void callee_${i}() {\n` + Array.from({ length: 80 }, (_, j) => `    step_${j}();`).join("\n") + `\n}`,
      lines: 82,
      bytes: 2000
    });
  }

  const rawLayers = {
    layer0Diff: { rawHunks: "@@ -1,5 +1,5 @@\n+ test_diff();", byteLength: 30 },
    layer1AstEnclosure: {
      adapterName: "builtin-semantic",
      enclosingFunctions: [],
      enclosingClasses: [],
      callees,
      unresolvedCallees: []
    }
  };

  const budgeted = allocateContextBudget(rawLayers, DEFAULT_BUDGET_CONFIG);

  // Layer 0 diff must be 100% preserved
  assert.equal(budgeted.layers.layer0Diff.rawHunks, rawLayers.layer0Diff.rawHunks);

  // Layer 1 AST must not exceed GLOBAL_AST_CONTEXT_CEILING_BYTES (8,000 bytes)
  const l1Bytes = Buffer.byteLength(JSON.stringify(budgeted.layers.layer1AstEnclosure), "utf8");
  assert.ok(l1Bytes <= GLOBAL_AST_CONTEXT_CEILING_BYTES, `Layer 1 bytes (${l1Bytes}) must not exceed 8000`);

  // Excessive callees were evicted to fit within ceiling
  assert.ok(budgeted.layers.layer1AstEnclosure.callees.length < 10);
});

test("Adversarial M3.5: Multiple overloads trigger AMBIGUOUS_SYMBOL and sensitive category promotion", () => {
  const code = [
    `bool sanitizeInput(int val) { return val >= 0; }`,
    `bool sanitizeInput(const char * val) { return val != nullptr && val[0] != '\\0'; }`,
    `bool sanitizeInput(const std::string & val) { return !val.empty(); }`
  ].join("\n");

  const diffHunks = `@@ -10,3 +10,3 @@\n+ if (!sanitizeInput(raw_arg)) return false;`;
  const targetFile = "src/sanitize.cpp";

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks
  };

  const pkg = buildContextPackage(changeSet, targetFile, { fileContents: { [targetFile]: code } });

  const unresolved = pkg.layers.layer1AstEnclosure.unresolvedCallees;
  const ambig = unresolved.find(u => u.symbol === "sanitizeInput");
  assert.ok(ambig, "Must detect sanitizeInput as unresolved");
  assert.equal(ambig.reason, "AMBIGUOUS_SYMBOL");

  // Since 'sanitizeInput' matches input_validation, it must be in contextGaps
  const gap = pkg.contextGaps.find(g => g.symbol === "sanitizeInput");
  assert.ok(gap, "Must promote ambiguous sanitizeInput to contextGaps");
  assert.equal(gap.category, "input_validation");
  assert.match(gap.impact, /Ambiguous overload/);
});

test("Adversarial M3.6: Dual Prompt Visibility & Verification Routing under Context Gap Mandate", async () => {
  const targetFile = "src/crypto_auth.cpp";
  const pkg = {
    targetFile,
    layers: {
      layer0Diff: { rawHunks: "@@ -1,3 +1,3 @@\n+ verify_signature(sig);" },
      layer1AstEnclosure: {
        enclosingClasses: [],
        enclosingFunctions: [],
        callees: [],
        unresolvedCallees: [
          { symbol: "verify_signature", reason: "UNRESOLVED_SYMBOL", file: targetFile, line: 2 }
        ]
      }
    },
    contextGaps: [
      {
        symbol: "verify_signature",
        reason: "UNRESOLVED_SYMBOL",
        file: targetFile,
        line: 2,
        category: "security",
        impact: "Security routine verify_signature definition not found in modified file"
      }
    ]
  };

  const changeSet = {
    scopeMode: "working-tree",
    files: [{ path: targetFile, additions: 1, deletions: 0 }],
    diffHunks: "@@ -1,3 +1,3 @@\n+ verify_signature(sig);",
    contextPackage: pkg
  };

  // 1. Verify prompt formatting
  const sentryPrompt = buildEvidenceReviewPrompt(changeSet, "macro", undefined, pkg);
  assert.ok(sentryPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(sentryPrompt.includes("verify_signature"));
  assert.ok(sentryPrompt.includes("Category: security"));

  const verifierPrompt = buildVerificationPrompt(changeSet, [], { contextPackage: pkg });
  assert.ok(verifierPrompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"));
  assert.ok(verifierPrompt.includes("verify_signature"));
  assert.ok(verifierPrompt.includes("Context Gap Mandate: If [UNRESOLVED CODE CONTEXT GAPS] are present"));

  // 2. Mock verifier returning UNCERTAIN due to context gap
  const mockAdapter = {
    executeVerification: async () => ({
      overallStatus: "UNCERTAIN",
      evaluations: [],
      verifierOmissions: [
        {
          title: "Potential security boundary bypass in unverified verify_signature",
          severity: "critical",
          evidenceSupport: "UNCERTAIN",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: targetFile,
          line_start: 2,
          line_end: 2,
          reasoning: "Implementation of verify_signature not in diff; cannot confirm whether empty signatures are accepted."
        }
      ]
    })
  };

  const rec = await conductIndependentVerification(changeSet, [], mockAdapter, {
    contextPackage: pkg
  });

  assert.equal(rec.overallStatus, "UNCERTAIN");
  const gate = evaluatePostVerificationGate({ findings: [] }, rec);
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /UNCERTAIN/i);
});
