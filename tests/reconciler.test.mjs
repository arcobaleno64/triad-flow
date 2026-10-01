import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeCweToken,
  computeCanonicalFindingKey,
  areFindingsCorroborating,
  mergeFindings,
  reconcileFindings
} from "../src/core/reconciler.mjs";

test("normalizeCweToken handles numeric strings, prefixed strings, and titles", () => {
  assert.equal(normalizeCweToken("CWE-1321"), "cwe-1321");
  assert.equal(normalizeCweToken("1321"), "cwe-1321");
  assert.equal(normalizeCweToken("cwe_1333"), "cwe-1333");
  assert.equal(normalizeCweToken("", "Possible Prototype Pollution in deepMerge (CWE-1321)"), "cwe-1321");
  assert.equal(normalizeCweToken("", "Hardcoded API Key", "crypto"), "crypto");
});

test("computeCanonicalFindingKey generates file:lineBucket:cweToken", () => {
  const finding = {
    file: "src\\utils\\merge.js",
    line_start: 34,
    cwe: "CWE-1321"
  };

  // line 34 -> bucket Math.floor(34/15)*15 = 30
  const key = computeCanonicalFindingKey(finding);
  assert.equal(key, "src/utils/merge.js:30:cwe-1321");
});

test("areFindingsCorroborating matches within +/- 15 line sliding window", () => {
  const a = { file: "lib/ejs.js", line_start: 14, cwe: "CWE-94" };
  const b = { file: "lib/ejs.js", line_start: 15, cwe: "CWE-94" }; // cross-bucket 0 vs 15, diff = 1
  const c = { file: "lib/ejs.js", line_start: 45, cwe: "CWE-94" }; // far apart

  assert.ok(areFindingsCorroborating(a, b), "Adjacent boundary cliff (14 vs 15) must corroborate");
  assert.equal(areFindingsCorroborating(a, c), false, "Lines 14 and 45 should not corroborate");
});

test("mergeFindings preserves maximum severity and aggregates sources", () => {
  const f1 = {
    title: "Prototype Pollution Warning",
    severity: "medium",
    file: "src/merge.js",
    line_start: 20,
    cwe: "CWE-1321",
    evidenceSnippet: "target[key] = src[key];",
    sources: ["chunk-1"]
  };

  const f2 = {
    title: "Critical Prototype Pollution",
    severity: "critical",
    file: "src/merge.js",
    line_start: 22,
    cwe: "CWE-1321",
    evidenceSnippet: "target[key] = src[key];",
    sources: ["chunk-2"]
  };

  const merged = mergeFindings(f1, f2);
  assert.equal(merged.severity, "critical", "Critical must override medium");
  assert.equal(merged.corroborations, 2);
  assert.ok(merged.sources.includes("chunk-1"));
  assert.ok(merged.sources.includes("chunk-2"));
});

test("reconcileFindings deduplicates and orders findings deterministically", () => {
  const rawList = [
    { title: "Low issue", severity: "low", file: "src/b.js", line_start: 10, cwe: "CWE-20" },
    { title: "Critical issue", severity: "critical", file: "src/a.js", line_start: 5, cwe: "CWE-78" },
    { title: "Duplicate of Critical", severity: "high", file: "src/a.js", line_start: 6, cwe: "CWE-78" }
  ];

  const reconciled = reconcileFindings(rawList, "sentry-1");
  assert.equal(reconciled.length, 2, "Should deduplicate 3 raw findings into 2");
  assert.equal(reconciled[0].severity, "critical", "Critical finding must be first");
  assert.equal(reconciled[0].file, "src/a.js");
  assert.equal(reconciled[0].corroborations, 2);
});
