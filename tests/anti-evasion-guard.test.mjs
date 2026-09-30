/**
 * Test Suite: Structural & Semantic Anti-Evasion Guard (M2 / v2.4)
 *
 * Validates:
 * - Contract 1: Assertion & Security Validation Stripping Detection
 * - Contract 2: Affirmative Replacement Allowed (valid remediation updates pass)
 * - Contract 3: Comment-Only Substitution Detection
 * - Contract 4: Trivial Constant Branch Bypass & Empty Error Swallowing Detection
 * - Contract 5: Test Suite Integrity Shield (unauthorized test alterations blocked)
 * - Contract 6: Legacy Anti-Degradation Evasion (.skip, xit, @ts-ignore, eslint-disable)
 * - Contract 7: Pluggable Layer 2 BaseAstAdapter Interface
 * - Contract 8: ControlledRemediationSession Integration (blocks proposeFix under evasion)
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  scanStructuralAntiEvasionViolations,
  checkAssertionStripping,
  checkCommentSubstitution,
  checkConstantBranchBypass,
  checkTestTampering,
  BaseAstAdapter,
  EVASION_VIOLATION_TYPES
} from "../src/core/anti-evasion-guard.mjs";

import {
  ControlledRemediationSession,
  validatePatchScope,
  PatchJailSecurityError,
  REMEDIATION_STATES
} from "../src/core/controlled-remediation.mjs";

test("Contract 1: Assertion & Security Validation Stripping Detection", () => {
  // 1. Stripping test assert
  const assertStrippingDiff = [
    "diff --git a/tests/user.test.js b/tests/user.test.js",
    "--- a/tests/user.test.js",
    "+++ b/tests/user.test.js",
    "@@ -10,3 +10,1 @@",
    "- assert.strictEqual(user.isAdmin, false);",
    "- assert.ok(tokenValid);",
    "+ console.log('test passed');"
  ].join("\n");

  const v1 = scanStructuralAntiEvasionViolations(assertStrippingDiff);
  assert.ok(v1.length >= 1);
  assert.ok(v1.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));
  assert.match(v1[0].description, /strips test assertion without equivalent replacement/i);

  // 2. Stripping security validation in source
  const secStrippingDiff = [
    "diff --git a/src/auth/jwt.js b/src/auth/jwt.js",
    "--- a/src/auth/jwt.js",
    "+++ b/src/auth/jwt.js",
    "@@ -25,2 +25,1 @@",
    "- if (!token || !jwt.verify(token, secret)) throw new Error('Unauthorized');",
    "+ const ok = true;"
  ].join("\n");

  const v2 = scanStructuralAntiEvasionViolations(secStrippingDiff);
  assert.ok(v2.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));
  assert.match(v2[0].description, /strips security validation check/i);

  // Throws PatchJailSecurityError in validatePatchScope
  assert.throws(
    () => validatePatchScope(secStrippingDiff, ["src/auth/jwt.js"]),
    PatchJailSecurityError
  );
});

test("Contract 2: Affirmative Replacement Allowed (valid remediations pass)", () => {
  // Legitimate update: old assertion replaced by improved assertion
  const validAssertUpdate = [
    "diff --git a/tests/user.test.js b/tests/user.test.js",
    "--- a/tests/user.test.js",
    "+++ b/tests/user.test.js",
    "@@ -10,2 +10,2 @@",
    "- assert.equal(user.id, 1);",
    "+ assert.strictEqual(user.id, 1);"
  ].join("\n");

  const v1 = scanStructuralAntiEvasionViolations(validAssertUpdate);
  assert.equal(v1.length, 0);

  // Legitimate update: parameterized query replacement
  const validSqlFix = [
    "diff --git a/src/db/user-repo.js b/src/db/user-repo.js",
    "--- a/src/db/user-repo.js",
    "+++ b/src/db/user-repo.js",
    "@@ -5,2 +5,2 @@",
    "- const query = 'SELECT * FROM users WHERE id = ' + id;",
    "+ const query = 'SELECT * FROM users WHERE id = ?';",
    "+ return db.query(query, [id]);"
  ].join("\n");

  const v2 = scanStructuralAntiEvasionViolations(validSqlFix);
  assert.equal(v2.length, 0);
  assert.doesNotThrow(() => validatePatchScope(validSqlFix, ["src/db/user-repo.js"]));
});

test("Contract 3: Comment-Only Substitution Detection", () => {
  const commentDiff = [
    "diff --git a/src/db/user-repo.js b/src/db/user-repo.js",
    "--- a/src/db/user-repo.js",
    "+++ b/src/db/user-repo.js",
    "@@ -10,2 +10,2 @@",
    "- const query = 'SELECT * FROM users WHERE id = ' + id;",
    "+ // TODO: fix vulnerability later",
    "+ /* temporary suppression */"
  ].join("\n");

  const violations = scanStructuralAntiEvasionViolations(commentDiff);
  assert.ok(violations.some(v => v.type === EVASION_VIOLATION_TYPES.COMMENT_ONLY_SUBSTITUTION));
  assert.match(violations[0].description, /substitutes only comments or whitespace/i);

  assert.throws(
    () => validatePatchScope(commentDiff, ["src/db/user-repo.js"]),
    (err) => err instanceof PatchJailSecurityError && err.message.includes("comments or whitespace")
  );
});

test("Contract 4: Trivial Constant Branch Bypass & Empty Error Swallowing Detection", () => {
  // 1. if (true) return early bypass
  const ifTrueDiff = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -5,1 +5,2 @@",
    "+ if (true) return null;",
    "  doVulnerableOperation();"
  ].join("\n");

  const v1 = scanStructuralAntiEvasionViolations(ifTrueDiff);
  assert.ok(v1.some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));

  // 2. Empty catch block
  const emptyCatchDiff = [
    "diff --git a/src/service.js b/src/service.js",
    "--- a/src/service.js",
    "+++ b/src/service.js",
    "@@ -15,3 +15,3 @@",
    "+ try { performAction(); }",
    "+ catch (err) {}",
    "+ return true;"
  ].join("\n");

  const v2 = scanStructuralAntiEvasionViolations(emptyCatchDiff);
  assert.ok(v2.some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));
  assert.match(v2[0].description, /swallows errors silently/i);
});

test("Contract 5: Test Suite Integrity Shield (Unauthorized test modification)", () => {
  const testTamperDiff = [
    "diff --git a/tests/user.test.js b/tests/user.test.js",
    "--- a/tests/user.test.js",
    "+++ b/tests/user.test.js",
    "@@ -1,1 +1,1 @@",
    "- const a = 1;",
    "+ const a = 2;"
  ].join("\n");

  // If targetFiles was only source file, tampering with tests is blocked
  const violations = scanStructuralAntiEvasionViolations(testTamperDiff, {
    targetFiles: ["src/user.js"]
  });

  assert.ok(violations.some(v => v.type === EVASION_VIOLATION_TYPES.TEST_TAMPERING));
  assert.match(violations[0].description, /Test Integrity Shield violation/i);

  assert.throws(
    () => validatePatchScope(testTamperDiff, ["src/user.js"]),
    (err) => err instanceof PatchJailSecurityError
  );
});

test("Contract 6: Legacy Anti-Degradation Evasion (.skip, xit, @ts-ignore, eslint-disable)", () => {
  const skipDiff = "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n+ it.skip('test', () => {});\n";
  const xitDiff = "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n+ xdescribe('suite', () => {});\n";
  const tsDiff = "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n+ // @ts-ignore\n";
  const eslintDiff = "diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n@@ -1,1 +1,1 @@\n+ /* eslint-disable */\n";

  assert.equal(scanStructuralAntiEvasionViolations(skipDiff)[0].type, EVASION_VIOLATION_TYPES.TEST_SKIPPING);
  assert.equal(scanStructuralAntiEvasionViolations(xitDiff)[0].type, EVASION_VIOLATION_TYPES.TEST_SKIPPING_X);
  assert.equal(scanStructuralAntiEvasionViolations(tsDiff)[0].type, EVASION_VIOLATION_TYPES.TS_SUPPRESS);
  assert.equal(scanStructuralAntiEvasionViolations(eslintDiff)[0].type, EVASION_VIOLATION_TYPES.ESLINT_SUPPRESS);
});

test("Contract 7: Pluggable Layer 2 BaseAstAdapter Interface", () => {
  class MockCustomAstAdapter extends BaseAstAdapter {
    constructor() {
      super("mock-custom-adapter");
    }

    analyze({ diff, targetFile }) {
      if (diff.includes("SUSPICIOUS_KEYWORD")) {
        return {
          ok: false,
          violations: [
            {
              type: "semantic-evasion",
              description: "Custom AST parser detected prohibited semantic keyword."
            }
          ]
        };
      }
      return { ok: true, violations: [] };
    }
  }

  const adapter = new MockCustomAstAdapter();
  const suspiciousDiff = "diff --git a/src/app.js b/src/app.js\n--- a/src/app.js\n+++ b/src/app.js\n@@ -1,1 +1,1 @@\n+ const val = SUSPICIOUS_KEYWORD;\n";

  const violations = scanStructuralAntiEvasionViolations(suspiciousDiff, {
    astAdapter: adapter,
    targetFiles: ["src/app.js"]
  });

  assert.ok(violations.some(v => v.type === "semantic-evasion"));
});

test("Contract 8: ControlledRemediationSession blocks proposeFix on evasion attempts", () => {
  const session = new ControlledRemediationSession("FINDING-EVASION-001", ["src/auth.js"]);

  const evasionPatch = [
    "diff --git a/src/auth.js b/src/auth.js",
    "--- a/src/auth.js",
    "+++ b/src/auth.js",
    "@@ -10,2 +10,1 @@",
    "- if (!jwt.verify(token, secret)) throw new Error('Invalid token');",
    "+ // removed verification"
  ].join("\n");

  assert.throws(
    () => session.proposeFix({
      diff: evasionPatch,
      rationale: "Fake fix that strips JWT verification"
    }),
    (err) => err instanceof PatchJailSecurityError && err.message.includes("Anti-degradation check failed")
  );

  // Remains in OPEN state, prohibited from transitioning to FIX_PROPOSED
  assert.equal(session.status, REMEDIATION_STATES.OPEN);
});
