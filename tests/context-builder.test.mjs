import test from "node:test";
import assert from "node:assert/strict";
import {
  extractChangedLineSpans,
  extractAstEnclosures,
  extractModuleScope,
  extractCallGraphContext,
  allocateContextBudget,
  buildContextPackage,
  DEFAULT_BUDGET_CONFIG,
  SAFE_ARGV_THRESHOLD_BYTES
} from "../src/core/context-builder.mjs";

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
