/**
 * Test Suite: Semantic Parser Adapter Architecture (M3 / v2.5)
 *
 * Validates the 5 formal contracts for Layer 2 Pluggable Semantic & AST Analysis:
 * - Contract 1: Constant branch bypass (including ternary `true ? a : b`, `if (true)`, `while (false)`) -> AST_SEMANTIC_VIOLATION.
 * - Contract 2: Empty `catch` block swallowing errors -> AST_SEMANTIC_VIOLATION.
 * - Contract 3: Explicit external parser unavailable -> AstAdapterUnavailableError (Fail-Closed, no silent fallback).
 * - Contract 4: ControlledRemediationSession with injected adapter blocks evasion patch during proposeFix, remaining in OPEN.
 * - Contract 5: Optional adapter absence never fabricates AST authority (truthful probe metadata) AND additive authority invariant (Layer 1 findings never erased).
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  BuiltinSemanticAdapter,
  AcornAstAdapter,
  BabelAstAdapter,
  AstAdapterUnavailableError,
  resolveAstAdapter,
  AST_ADAPTER_NAMES
} from "../src/core/semantic-parser-adapter.mjs";
import {
  BaseAstAdapter,
  EVASION_VIOLATION_TYPES,
  scanStructuralAntiEvasionViolations
} from "../src/core/anti-evasion-guard.mjs";
import {
  ControlledRemediationSession,
  REMEDIATION_STATES,
  PatchJailSecurityError
} from "../src/core/controlled-remediation.mjs";

test("Contract 1: Constant branch bypass, including ternary constant condition -> AST_SEMANTIC_VIOLATION", () => {
  const adapter = new BuiltinSemanticAdapter();

  // 1a. Ternary constant condition
  const ternaryDiff = [
    "diff --git a/src/auth.js b/src/auth.js",
    "--- a/src/auth.js",
    "+++ b/src/auth.js",
    "@@ -10,1 +10,1 @@",
    "+ const isAuthorized = true ? userRole : null;"
  ].join("\n");

  const ternaryRes = adapter.analyze({ diff: ternaryDiff, targetFile: "src/auth.js" });
  assert.equal(ternaryRes.ok, false);
  assert.ok(ternaryRes.violations.some(v => v.type === EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION));
  assert.match(ternaryRes.violations[0].description, /ternary constant condition/i);

  // 1b. if(true) and while(false)
  const branchDiff = [
    "diff --git a/src/worker.js b/src/worker.js",
    "--- a/src/worker.js",
    "+++ b/src/worker.js",
    "@@ -5,2 +5,2 @@",
    "+ if (true) { bypassSecurity(); }",
    "+ while (false) { deadCheck(); }"
  ].join("\n");

  const branchRes = adapter.analyze({ diff: branchDiff, targetFile: "src/worker.js" });
  assert.equal(branchRes.ok, false);
  assert.ok(branchRes.violations.length >= 2);
  assert.ok(branchRes.violations.every(v => v.type === EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION));
});

test("Contract 2: Empty or comment-only catch block swallowing errors -> AST_SEMANTIC_VIOLATION", () => {
  const adapter = new BuiltinSemanticAdapter();

  // 2a. Single-line empty catch
  const emptyCatchDiff = [
    "diff --git a/src/api.js b/src/api.js",
    "--- a/src/api.js",
    "+++ b/src/api.js",
    "@@ -20,2 +20,3 @@",
    "+ try { verifySignature(req); }",
    "+ catch (err) {}"
  ].join("\n");

  const res1 = adapter.analyze({ diff: emptyCatchDiff, targetFile: "src/api.js" });
  assert.equal(res1.ok, false);
  assert.ok(res1.violations.some(v => v.description.includes("empty catch block")));

  // 2b. Comment-only catch block
  const commentCatchDiff = [
    "diff --git a/src/api.js b/src/api.js",
    "--- a/src/api.js",
    "+++ b/src/api.js",
    "@@ -20,2 +20,3 @@",
    "+ try { authenticate(token); }",
    "+ catch (err) { // ignore error }",
    "+ catch (err2) { /* swallowed */ }"
  ].join("\n");

  const res2 = adapter.analyze({ diff: commentCatchDiff, targetFile: "src/api.js" });
  assert.equal(res2.ok, false);
  assert.ok(res2.violations.some(v => v.description.includes("empty catch block")));
});

test("Contract 3: Explicit external parser unavailable -> AstAdapterUnavailableError (Fail-Closed)", () => {
  // Explicit request for unavailable external engine without silent fallback
  assert.throws(
    () => resolveAstAdapter("babel"),
    (err) => err instanceof AstAdapterUnavailableError && err.adapterName === "babel" && err.message.includes("Silent fallback is prohibited")
  );

  assert.throws(
    () => resolveAstAdapter("acorn"),
    (err) => err instanceof AstAdapterUnavailableError && err.adapterName === "acorn" && err.message.includes("Silent fallback is prohibited")
  );

  // External adapter probe directly returns truthful unavailable metadata
  const babelAdapter = new BabelAstAdapter();
  const probe = babelAdapter.probe();
  assert.equal(probe.available, false);
  assert.equal(probe.analysisKind, "ast");
  assert.equal(probe.astBacked, true);
  assert.equal(probe.authority, "additive");
  assert.match(probe.reason, /not installed/i);
});

test("Contract 4: ControlledRemediationSession injected with adapter blocks evasion in OPEN state", () => {
  const adapter = new BuiltinSemanticAdapter();
  const session = new ControlledRemediationSession("FINDING-M3-001", ["src/auth.js"], {
    astAdapter: adapter
  });

  const ternaryEvasionPatch = [
    "diff --git a/src/auth.js b/src/auth.js",
    "--- a/src/auth.js",
    "+++ b/src/auth.js",
    "@@ -15,1 +15,1 @@",
    "+ const isValid = true ? true : checkToken(token);"
  ].join("\n");

  // proposeFix must fail-closed on anti-degradation / AST semantic violation
  assert.throws(
    () => session.proposeFix({
      diff: ternaryEvasionPatch,
      rationale: "Attempt to bypass token verification using ternary constant"
    }),
    (err) => err instanceof PatchJailSecurityError && err.message.includes("Anti-degradation check failed")
  );

  // Session remains in OPEN state, strictly prohibited from entering FIX_PROPOSED
  assert.equal(session.status, REMEDIATION_STATES.OPEN);
  assert.equal(session.patch, null);
});

test("Contract 5: Optional absence never fabricates AST authority & Additive authority invariant", () => {
  // 5a. Auto mode in absence of external parsers truthfully reports non-AST structural-semantic authority
  const autoAdapter = resolveAstAdapter("auto");
  assert.ok(autoAdapter instanceof BuiltinSemanticAdapter, "Auto mode falls back to BuiltinSemanticAdapter");
  const probe = autoAdapter.probe();
  assert.equal(probe.available, true);
  assert.equal(probe.analysisKind, "structural-semantic");
  assert.equal(probe.astBacked, false, "Must NOT claim astBacked=true without real AST parser");
  assert.equal(probe.authority, "additive");

  // 5b. Additive Authority Invariant:
  // Given Layer 1 has generated violations, even if an AST adapter returns clean ({ ok: true, violations: [] }),
  // the scan result MUST retain all Layer 1 violations without erasure.
  class MockCleanAstAdapter extends BaseAstAdapter {
    constructor() {
      super("mock-clean");
    }
    analyze() {
      return { ok: true, violations: [] };
    }
  }

  // Diff containing Layer 1 violation (assertion stripping + test skipping)
  const layer1ViolationDiff = [
    "diff --git a/tests/auth.test.js b/tests/auth.test.js",
    "--- a/tests/auth.test.js",
    "+++ b/tests/auth.test.js",
    "@@ -5,2 +5,2 @@",
    "- assert.equal(verifyAuth(token), true);",
    "+ test.skip('disabled assertion');"
  ].join("\n");

  const combinedViolations = scanStructuralAntiEvasionViolations(layer1ViolationDiff, {
    astAdapter: new MockCleanAstAdapter(),
    targetFiles: ["tests/auth.test.js"]
  });

  // Layer 1 violations must NOT be washed or erased by clean AST adapter
  assert.ok(combinedViolations.length >= 2, "Must retain all Layer 1 violations");
  assert.ok(combinedViolations.some(v => v.type === EVASION_VIOLATION_TYPES.TEST_SKIPPING));
  assert.ok(combinedViolations.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));
});
