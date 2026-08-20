import test from "node:test";
import assert from "node:assert/strict";
import { redactSecrets, isPathSafe, evaluateGateDecision, formatSarifReport } from "../src/core/harness.mjs";

test("redactSecrets masks API keys and private keys", () => {
  const input = "Google API Key is AIzaSyD4_xxxxxxxxx and secret is bearer eyJhbGciOiJIUzI1NiJ9.test";
  const output = redactSecrets(input);
  assert.ok(!output.includes("AIzaSyD4"));
  assert.ok(output.includes("[REDACTED_SECRET]"));
});

test("isPathSafe blocks path traversal outside workspace root", () => {
  const root = "C:/Users/arcobaleno/Documents/Code/Triad-Flow";
  assert.equal(isPathSafe("src/app.ts", root), true);
  assert.equal(isPathSafe("../../../Windows/System32", root), false);
});

test("evaluateGateDecision blocks critical findings", () => {
  const gate = evaluateGateDecision([
    { severity: "critical", title: "Auth bypass" }
  ]);
  assert.equal(gate.decision, "block");
});

test("formatSarifReport generates valid OASIS SARIF 2.1.0 structure", () => {
  const sarif = formatSarifReport([
    { severity: "critical", title: "Auth bypass", file: "src/auth.js", line_start: 10 }
  ]);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].level, "error");
});
