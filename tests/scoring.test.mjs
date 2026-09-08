import test from "node:test";
import assert from "node:assert/strict";
import {
  calculateMutationScore,
  verifyHeldOutBaseline,
  normalizeCanonicalPath,
  extractCweTokens,
  isCweMatched,
  isTypeMatched
} from "../src/core/scoring.mjs";

test("calculateMutationScore validates input ranges and rejects invalid/impossible values", () => {
  assert.equal(calculateMutationScore(20, 19), 95.0);
  assert.equal(calculateMutationScore(100, 100), 100.0);
  assert.equal(calculateMutationScore(100, 0), 0.0);
  assert.equal(calculateMutationScore(0, 0), null);

  assert.throws(() => calculateMutationScore(10, 11), RangeError);
  assert.throws(() => calculateMutationScore(-1, 0), RangeError);
  assert.throws(() => calculateMutationScore(10, -1), RangeError);
});

test("CWE matching enforces exact identifier boundaries (P1-01)", () => {
  const goldenCwe = "CWE-79";

  // 1. Substring collisions must NOT match
  const finding791 = { title: "CWE-791 unrelated vulnerability" };
  const finding790 = { title: "CWE-790 weakness" };
  assert.equal(isCweMatched(finding791, goldenCwe), false, "CWE-79 must NOT match CWE-791");
  assert.equal(isCweMatched(finding790, goldenCwe), false, "CWE-79 must NOT match CWE-790");

  // 2. Exact token matching in title or explicit field
  const findingExact = { title: "Reflected XSS (CWE-79)" };
  const findingExplicit = { cwe: "CWE-79", title: "XSS" };
  const findingLeadingZero = { cwe: "cwe-079", title: "XSS" };
  assert.equal(isCweMatched(findingExact, goldenCwe), true);
  assert.equal(isCweMatched(findingExplicit, goldenCwe), true);
  assert.equal(isCweMatched(findingLeadingZero, goldenCwe), true);
});

test("Type matching enforces token boundaries and alias hierarchy (P1-02)", () => {
  // 1. token vs tokenizer
  assert.equal(isTypeMatched({ title: "Tokenizer buffer overflow" }, "token"), false);
  assert.equal(isTypeMatched({ title: "Invalid auth token issue" }, "token"), true);

  // 2. auth vs author
  assert.equal(isTypeMatched({ title: "Missing author metadata" }, "auth"), false);
  assert.equal(isTypeMatched({ title: "Auth bypass vulnerability" }, "auth"), true);

  // 3. sql vs nosql
  assert.equal(isTypeMatched({ title: "NoSQL injection detected" }, "sql"), false);
  assert.equal(isTypeMatched({ title: "SQL injection flaw" }, "sql"), true);
});

test("verifyHeldOutBaseline handles duplicate golden IDs with index-qualified matching", () => {
  const goldens = [
    { id: "G-1", file: "src/auth.js", cwe: "CWE-89" },
    { id: "G-1", file: "src/auth.js", cwe: "CWE-79" }
  ];

  // Model catches both distinct vulnerabilities sharing the same ID
  const findingsBoth = [
    { file: "src/auth.js", cwe: "CWE-89" },
    { file: "src/auth.js", cwe: "CWE-79" }
  ];

  const resBoth = verifyHeldOutBaseline(findingsBoth, goldens);
  assert.equal(resBoth.totalGoldens, 2);
  assert.equal(resBoth.caughtGoldens, 2, "Must count both distinct instances without Set collapse");
  assert.equal(resBoth.recallRate, "100.0%");
  assert.equal(resBoth.passed, true);

  // Model catches only one of the duplicate ID goldens
  const findingsOne = [
    { file: "src/auth.js", cwe: "CWE-89" }
  ];
  const resOne = verifyHeldOutBaseline(findingsOne, goldens);
  assert.equal(resOne.caughtGoldens, 1);
  assert.equal(resOne.recallRate, "50.0%");
  assert.equal(resOne.passed, false);
});

test("normalizeCanonicalPath preserves filename whitespace and normalizes slashes", () => {
  assert.equal(normalizeCanonicalPath("./src/auth/jwt.ts"), "src/auth/jwt.ts");
  assert.equal(normalizeCanonicalPath("src\\auth\\jwt.ts"), "src/auth/jwt.ts");

  assert.notEqual(normalizeCanonicalPath(" auth.js"), normalizeCanonicalPath("auth.js"));
  assert.notEqual(normalizeCanonicalPath("auth.js "), normalizeCanonicalPath("auth.js"));
  assert.equal(normalizeCanonicalPath(" auth.js"), " auth.js");
});
