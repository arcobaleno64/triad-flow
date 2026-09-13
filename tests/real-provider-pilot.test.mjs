/**
 * Real Provider Controlled Pilot Test Suite (Milestone 2 / v2.1.0 Architecture)
 *
 * Validates 6 critical real-world paths with local AI CLI reviewers (Google agy, Anthropic claude):
 * - Path 1: Clean Pass (Benign change -> reviewed-clean, Gate APPROVE)
 * - Path 2: Vulnerability Catch & Gate Block (OWASP defects -> reviewed-with-findings, Gate BLOCK)
 * - Path 3: Timeout Kill & Fail-Closed (Subprocess forcefully terminated on timeout -> Gate BLOCK)
 * - Path 4: Auth Failure Graceful Degradation (Invalid credentials -> AUTH_FAILURE -> Gate BLOCK)
 * - Path 5: Coverage Incompleteness (Multi-file diff with omitted coverage -> Gate BLOCK)
 * - Path 6: Repo Immutability Guarantee (Repositories remain 100% untouched across all runs)
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createDisposableRepo, assertRepoImmutability } from "./fixtures/disposable-pilot-repo.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

function isRealPilotEnabled() {
  if (process.env.TRIAD_OFFLINE === "1") return false;
  if (process.env.TRIAD_REAL_PILOT === "1") return true;
  if (process.env.npm_lifecycle_event === "test:real-pilot") return true;
  // If running routine npm test, keep 100% offline regression
  if (process.env.npm_lifecycle_event === "test") return false;
  // If test file was explicitly targeted on the command line
  return process.argv.some(arg => typeof arg === "string" && arg.includes("real-provider-pilot"));
}

function isAgyAvailable() {
  if (!isRealPilotEnabled()) return false;
  try {
    const res = spawnSync("agy", ["--version"], { stdio: "ignore" });
    return res.status === 0;
  } catch {
    return false;
  }
}

function isClaudeAvailable() {
  if (!isRealPilotEnabled()) return false;
  try {
    const res = spawnSync("claude", ["--version"], { stdio: "ignore" });
    return res.status === 0;
  } catch {
    return false;
  }
}

test("Path 1 (Clean Pass): Real agy review on benign change approves cleanly", { timeout: 120000 }, async (t) => {
  if (!isAgyAvailable()) {
    t.skip("Real Google agy CLI reviewer not detected or offline routine test (enable via 'npm run test:real-pilot' or TRIAD_REAL_PILOT=1)");
    return;
  }

  const repo = createDisposableRepo("clean");
  try {
    assertRepoImmutability(repo.dir, repo.headSha);
    const start = Date.now();
    const adapter = new CliReviewAdapter({ command: "agy", cwd: repo.dir });
    const orchResult = await orchestrateReview(repo.changeSet, { macro: adapter }, {
      timeoutMs: 90000,
      plan: { mode: "single", reason: "clean-benign-math" }
    });
    const durationMs = Date.now() - start;
    console.log(`[Pilot Metric] Path 1 (Clean Pass): duration=${durationMs}ms, usage=`, orchResult.result?.usage ?? "n/a");

    assert.equal(orchResult.status, "reviewed-clean");
    assert.equal(orchResult.gate.decision, "approve");
    assert.equal(orchResult.result.findings.length, 0);
    assert.equal(orchResult.result.coverage.omittedFiles.length, 0);
    assertRepoImmutability(repo.dir, repo.headSha);
  } finally {
    repo.cleanup();
  }
});

test("Path 2 (Vulnerability Catch & Gate Block): Real agy catches OWASP defects and blocks Gate", { timeout: 120000 }, async (t) => {
  if (!isAgyAvailable()) {
    t.skip("Real Google agy CLI reviewer not detected or offline routine test (enable via 'npm run test:real-pilot' or TRIAD_REAL_PILOT=1)");
    return;
  }

  const repo = createDisposableRepo("vulnerable");
  try {
    assertRepoImmutability(repo.dir, repo.headSha);
    const start = Date.now();
    const adapter = new CliReviewAdapter({ command: "agy", cwd: repo.dir });
    const orchResult = await orchestrateReview(repo.changeSet, { macro: adapter }, {
      timeoutMs: 90000,
      plan: { mode: "single", reason: "vuln-owasp-pilot" }
    });
    const durationMs = Date.now() - start;
    console.log(`[Pilot Metric] Path 2 (Vulnerability Catch): duration=${durationMs}ms, findings=${orchResult.result?.findings?.length ?? 0}, usage=`, orchResult.result?.usage ?? "n/a");

    assert.equal(orchResult.status, "reviewed-with-findings");
    assert.equal(orchResult.gate.decision, "block");
    assert.ok(orchResult.result.findings.length > 0, "Expected provider to discover vulnerabilities");
    assertRepoImmutability(repo.dir, repo.headSha);
  } finally {
    repo.cleanup();
  }
});

test("Path 3 (Timeout Kill & Fail-Closed): Short deadline kills real child process and blocks Gate", { timeout: 30000 }, async (t) => {
  if (!isAgyAvailable()) {
    t.skip("Real Google agy CLI reviewer not detected or offline routine test (enable via 'npm run test:real-pilot' or TRIAD_REAL_PILOT=1)");
    return;
  }

  const repo = createDisposableRepo("clean");
  try {
    assertRepoImmutability(repo.dir, repo.headSha);
    const start = Date.now();
    const adapter = new CliReviewAdapter({ command: "agy", cwd: repo.dir });
    const orchResult = await orchestrateReview(repo.changeSet, { macro: adapter }, {
      timeoutMs: 200, // 200ms ultra-short timeout
      plan: { mode: "single", reason: "timeout-probe" }
    });
    const durationMs = Date.now() - start;
    console.log(`[Pilot Metric] Path 3 (Timeout Kill): duration=${durationMs}ms`);

    assert.equal(orchResult.status, "incomplete");
    assert.equal(orchResult.gate.decision, "block");
    assert.equal(orchResult.result.executionStatus, EXECUTION_STATUS.TIMEOUT);
    assertRepoImmutability(repo.dir, repo.headSha);
  } finally {
    repo.cleanup();
  }
});

test("Path 4 (Auth Failure Graceful Degradation): Invalid credentials identify AUTH_FAILURE and block Gate", { timeout: 30000 }, async () => {
  const repo = createDisposableRepo("clean");
  try {
    assertRepoImmutability(repo.dir, repo.headSha);
    let adapter;
    if (isClaudeAvailable()) {
      // Induce real CLI auth failure via invalid token
      adapter = new CliReviewAdapter({
        command: "claude",
        cwd: repo.dir,
        env: { ...process.env, ANTHROPIC_API_KEY: "invalid-key-for-test" }
      });
    } else {
      // Zero-dependency fallback auth failure fixture
      const mockSentry = path.resolve("tests", "fixtures", "mock-cli-sentry.mjs");
      adapter = new CliReviewAdapter({
        command: process.execPath,
        cwd: repo.dir,
        args: [mockSentry, "--auth-fail"]
      });
    }

    const start = Date.now();
    const orchResult = await orchestrateReview(repo.changeSet, { macro: adapter }, {
      timeoutMs: 15000,
      plan: { mode: "single", reason: "auth-failure-probe" }
    });
    const durationMs = Date.now() - start;
    console.log(`[Pilot Metric] Path 4 (Auth Failure): duration=${durationMs}ms`);

    assert.equal(orchResult.status, "incomplete");
    assert.equal(orchResult.gate.decision, "block");
    assert.equal(orchResult.result.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
    assert.match(orchResult.result.error, /auth/i);
    assertRepoImmutability(repo.dir, repo.headSha);
  } finally {
    repo.cleanup();
  }
});

test("Path 5 (Coverage Incompleteness): Multi-file changeset with omitted files triggers Gate BLOCK", async () => {
  const repo = createDisposableRepo("vulnerable"); // contains src/auth.js and src/db.js
  try {
    assertRepoImmutability(repo.dir, repo.headSha);
    // Reviewer only covers one of the two files
    const partialCoverageAdapter = new CliReviewAdapter({
      cwd: repo.dir,
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: {
            coveredFiles: ["src/auth.js"],
            omittedFiles: [{ path: "src/db.js", reason: "Truncated or omitted by reviewer" }]
          }
        })
      })
    });

    const orchResult = await orchestrateReview(repo.changeSet, { macro: partialCoverageAdapter }, {
      plan: { mode: "single", reason: "coverage-incompleteness-probe" }
    });

    assert.equal(orchResult.status, "incomplete");
    assert.equal(orchResult.gate.decision, "block");
    assert.match(orchResult.gate.reason, /coverage incomplete/i);
    assertRepoImmutability(repo.dir, repo.headSha);
  } finally {
    repo.cleanup();
  }
});

test("Path 6 (Repo Immutability Guarantee): Repository remains 100% clean and dirty states are rejected", async () => {
  const repo = createDisposableRepo("clean");
  try {
    assert.equal(assertRepoImmutability(repo.dir, repo.headSha), true);

    // Verify assertion catches unauthorized rogue files
    const rogueFile = path.join(repo.dir, "rogue-agent-leak.tmp");
    fs.writeFileSync(rogueFile, "unauthorized mutation\n", "utf8");

    assert.throws(
      () => assertRepoImmutability(repo.dir, repo.headSha),
      /Repo immutability violated: working tree contains uncommitted or dirty changes/
    );

    // Clean rogue file and verify immutability restored
    fs.unlinkSync(rogueFile);
    assert.equal(assertRepoImmutability(repo.dir, repo.headSha), true);

    // Verify assertion catches unauthorized HEAD commit drift
    assert.throws(
      () => assertRepoImmutability(repo.dir, "0000000000000000000000000000000000000000"),
      /HEAD commit drift detected/
    );
  } finally {
    repo.cleanup();
  }
});
