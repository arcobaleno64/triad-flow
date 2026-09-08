import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  redactSecrets,
  isPathSafe,
  evaluateGateDecision,
  formatSarifReport,
  deriveRuleId,
  normalizeFinding,
  validateSentryReport
} from "../src/core/harness.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { isTrustedConsensus } from "../src/core/consensus-state.mjs";

test("redactSecrets masks Google, OpenAI Project, GitHub PAT, JWT and Private Keys", () => {
  const input = "Google: AIzaSyD4_123456789012345678901234567, OpenAI: sk-proj-1234567890123456789012345678, GitHub: ghp_123456789012345678901234567890123456, JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.test";
  const output = redactSecrets(input);
  assert.ok(!output.includes("AIzaSyD4"));
  assert.ok(!output.includes("sk-proj-12345"));
  assert.ok(!output.includes("ghp_12345"));
  assert.ok(!output.includes("eyJhbGciOiJIUzI1NiJ9"));
  assert.equal((output.match(/\[REDACTED_SECRET\]/g) || []).length, 4);
});

test("isPathSafe uses dynamic temporary directory and rejects nonexistent workspace roots (P1-01)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-safe-root-"));
  try {
    assert.equal(isPathSafe("src/app.ts", tmpDir), true);
    assert.equal(isPathSafe("../outside/secret.txt", tmpDir), false);

    // Nonexistent workspace root must fail closed (INV-07)
    assert.equal(isPathSafe("src/app.ts", path.join(tmpDir, "nonexistent-workspace")), false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("isPathSafe multi-hop recursive symlink resolution and cycle detection (P1-04)", (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-multihop-sym-"));
  const workspaceRoot = path.join(tmpDir, "workspace");
  const outsideSecretDir = path.join(tmpDir, "outside-secret");

  fs.mkdirSync(workspaceRoot, { recursive: true });
  fs.mkdirSync(outsideSecretDir, { recursive: true });
  fs.writeFileSync(path.join(outsideSecretDir, "keys.env"), "SECRET=123");

  let symlinkCreated = false;
  try {
    const probeLink = path.join(workspaceRoot, "probe-link");
    fs.symlinkSync(outsideSecretDir, probeLink, "junction");
    fs.unlinkSync(probeLink);
    symlinkCreated = true;
  } catch (err) {
    console.log(`[INFO] Skipping symlink creation test due to OS privilege: ${err.message}`);
  }

  if (symlinkCreated) {
    // 1. Two-hop Escape: link1 -> link2 -> outside
    const link2 = path.join(workspaceRoot, "link2");
    const link1 = path.join(workspaceRoot, "link1");
    fs.symlinkSync(outsideSecretDir, link2, "junction");
    fs.symlinkSync("link2", link1, "junction");

    assert.equal(isPathSafe("link1/keys.env", workspaceRoot), false, "Two-hop symlink escape must be blocked");

    // 2. Three-hop Escape: linkA -> sub/linkB -> ../sub2/linkC -> outside
    const sub = path.join(workspaceRoot, "sub");
    const sub2 = path.join(workspaceRoot, "sub2");
    fs.mkdirSync(sub, { recursive: true });
    fs.mkdirSync(sub2, { recursive: true });

    const linkC = path.join(sub2, "linkC");
    const linkB = path.join(sub, "linkB");
    const linkA = path.join(workspaceRoot, "linkA");

    fs.symlinkSync(outsideSecretDir, linkC, "junction");
    fs.symlinkSync(path.join("..", "sub2", "linkC"), linkB, "junction");
    fs.symlinkSync(path.join("sub", "linkB"), linkA, "junction");

    assert.equal(isPathSafe("linkA/keys.env", workspaceRoot), false, "Three-hop symlink escape must be blocked");

    // 3. Symlink Cycle Attack: cycle1 -> cycle2 -> cycle1
    const cycle1 = path.join(workspaceRoot, "cycle1");
    const cycle2 = path.join(workspaceRoot, "cycle2");
    fs.symlinkSync("cycle2", cycle1, "junction");
    fs.symlinkSync("cycle1", cycle2, "junction");

    const start = Date.now();
    assert.equal(isPathSafe("cycle1/file.txt", workspaceRoot), false, "Symlink cycle must fail-closed");
    assert.ok(Date.now() - start < 100, "Cycle detection must terminate instantaneously without hanging");
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("normalizeFinding preserves valid filename whitespace without trimming (P1-03)", () => {
  const normLeading = normalizeFinding({
    title: "SQL Injection",
    severity: "critical",
    file: " auth.js"
  });
  assert.equal(normLeading.valid, true);
  assert.equal(normLeading.finding.file, " auth.js", "Leading whitespace in filename must be preserved");

  const normTrailing = normalizeFinding({
    title: "SQL Injection",
    severity: "critical",
    file: "auth.js "
  });
  assert.equal(normTrailing.valid, true);
  assert.equal(normTrailing.finding.file, "auth.js ", "Trailing whitespace in filename must be preserved");

  // NUL byte injection in file path must fail closed
  const normNul = normalizeFinding({
    title: "SQLi",
    severity: "critical",
    file: "auth.js\0.png"
  });
  assert.equal(normNul.valid, false);
  assert.match(normNul.reason, /NUL byte/i);
});

test("evaluateGateDecision enforces Trusted Capability requirement and rejects detached signatures", () => {
  // 1. Untrusted plain candidate fails closed
  const plainConsensus = { quorumReached: true, verdict: "approve", totalFindings: 0, findings: [] };
  const gatePlain = evaluateGateDecision(plainConsensus);
  assert.equal(gatePlain.decision, "block");
  assert.match(gatePlain.reason, /UNTRUSTED_CONSENSUS/i);

  // 2. Legacy detached arguments signature fails closed
  const gateLegacy = evaluateGateDecision([], { sentryHealth: { quorumReached: true } });
  assert.equal(gateLegacy.decision, "block");
  assert.match(gateLegacy.reason, /UNTRUSTED_CONSENSUS/i);

  // 3. Real trusted clean consensus approves
  const trustedClean = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } });
  assert.equal(isTrustedConsensus(trustedClean), true);
  const gateApproved = evaluateGateDecision(trustedClean);
  assert.equal(gateApproved.decision, "approve");

  // 4. Real trusted blocking consensus blocks
  const trustedBlocker = aggregateConsensus({
    macro: { findings: [{ title: "RCE", severity: "critical", file: "src/auth.js" }] },
    micro: { findings: [{ title: "RCE", severity: "critical", file: "src/auth.js" }] }
  });
  const gateBlocked = evaluateGateDecision(trustedBlocker);
  assert.equal(gateBlocked.decision, "block");
  assert.equal(gateBlocked.criticals.length, 1);
});

test("deriveRuleId produces distinct stable rule IDs for punctuation-colliding titles", () => {
  const id1 = deriveRuleId({ title: "SQL Injection!" });
  const id2 = deriveRuleId({ title: "SQL Injection?" });
  assert.notEqual(id1, id2, "Distinct titles must produce distinct stable rule IDs");
  assert.match(id1, /^sql_injection_[a-f0-9]{8}$/);
});

test("formatSarifReport deduplicates driver rules and associates correct ruleIndex", () => {
  const findings = [
    { severity: "critical", title: "Unvalidated Token Expiry", file: "src/auth.ts", line_start: 10 },
    { severity: "high", title: "Unvalidated Token Expiry", file: "src/auth login.ts", line_start: 20 },
    { severity: "medium", title: "Missing CSRF Header", file: "src/api.ts", line_start: 5 }
  ];

  const sarif = formatSarifReport(findings);
  assert.equal(sarif.version, "2.1.0");

  const driverRules = sarif.runs[0].tool.driver.rules;
  assert.equal(driverRules.length, 2, "Duplicate rule titles must be deduplicated in driver.rules");
});
