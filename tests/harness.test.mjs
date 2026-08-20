import test from "node:test";
import assert from "node:assert/strict";
import { redactSecrets, isPathSafe, evaluateGateDecision, formatSarifReport } from "../src/core/harness.mjs";

test("redactSecrets masks Google, OpenAI Project, GitHub PAT, JWT and Private Keys", () => {
  const input = "Google: AIzaSyD4_123456789012345678901234567, OpenAI: sk-proj-1234567890123456789012345678, GitHub: ghp_123456789012345678901234567890123456, JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.test";
  const output = redactSecrets(input);
  assert.ok(!output.includes("AIzaSyD4"));
  assert.ok(!output.includes("sk-proj-12345"));
  assert.ok(!output.includes("ghp_12345"));
  assert.ok(!output.includes("eyJhbGciOiJIUzI1NiJ9"));
  assert.equal((output.match(/\[REDACTED_SECRET\]/g) || []).length, 4);
});

test("isPathSafe prevents sibling directory traversal (Prefix match attack)", () => {
  const root = "C:/Users/arcobaleno/Documents/Code/Triad-Flow";
  assert.equal(isPathSafe("src/app.ts", root), true);
  assert.equal(isPathSafe("../Triad-Flow-Attacker/secret.txt", root), false);
  assert.equal(isPathSafe("../../../Windows/System32", root), false);
});

test("evaluateGateDecision enforces Fail-Closed when Sentry Quorum fails", () => {
  const gate = evaluateGateDecision([], { sentryHealth: { quorumReached: false } });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Quorum Failure/i);
});

test("formatSarifReport sanitizes dangerous URI schemes and control characters", () => {
  const sarif = formatSarifReport([
    { severity: "critical", title: "Auth \u001b[31mBypass\u001b[0m", file: "javascript:alert(1)", line_start: -5 }
  ]);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "invalid-uri-scheme");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
});
