/**
 * Triad-Flow v2.0.2 Evidence Contract Scenarios Test Suite (SC-01 .. SC-10)
 *
 * Verifies all 10 Given-When-Then scenarios from the Evidence Contract Hardening Plan:
 * SC-01: Malformed Output Fail-Closed
 * SC-02: Omitted Coverage Fail-Closed
 * SC-03: Untracked File Digest Invariant
 * SC-04: Provider Family Heterogeneity
 * SC-05: Subprocess Exit Code Priority
 * SC-06: Finding Text Auth Non-Interference
 * SC-07: SARIF Successful on Finding Block
 * SC-08: Audit Report Persistence Guarantee
 * SC-09: ReadOnlySet ECMAScript Integrity
 * SC-10: Tool Version Unified Invariant
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";

import {
  EXECUTION_STATUS,
  validateProviderOutput
} from "../src/adapters/provider-contract.mjs";
import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { buildChangeSet } from "../src/core/git-collector.mjs";
import { aggregateConsensus, QuorumPolicies } from "../src/core/loop.mjs";
import { BLOCKING_SEVERITIES } from "../src/core/consensus-state.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { TOOL_VERSION } from "../src/core/review-run-report.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function makeChangeSet(files = [{ path: "src/calc.js", additions: 5, deletions: 1 }], hunks = "@@ -1,1 +1,2 @@\n+const x = 1;") {
  const contentDigest = crypto.createHash("sha256").update(hunks).digest("hex");
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/repo", hasHead: true, currentBranch: "main" },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: files.reduce((s, f) => s + (f.additions || 0), 0),
    totalDeletions: files.reduce((s, f) => s + (f.deletions || 0), 0),
    files,
    diffHunks: hunks
  };
}

// SC-01: Malformed Output Fail-Closed
test("SC-01: Malformed Output Fail-Closed -> rejects missing findings, Gate BLOCKs", async () => {
  // 1. Missing findings entirely
  const res1 = validateProviderOutput({ foo: "bar" });
  assert.equal(res1.ok, false);
  assert.equal(res1.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res1.error, /findings/i);

  // 2. Empty object
  const res2 = validateProviderOutput({});
  assert.equal(res2.ok, false);
  assert.equal(res2.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  // 3. Finding that fails normalizeFinding fails closed (does not silently drop)
  const res3 = validateProviderOutput({
    findings: [{ title: "Bad Finding", severity: "unsupported_severity", file: "src/a.js" }],
    coverage: { coveredFiles: ["src/a.js"], omittedFiles: [] }
  });
  assert.equal(res3.ok, false);
  assert.equal(res3.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  // Missing coverage object entirely
  const res4 = validateProviderOutput({ findings: [] });
  assert.equal(res4.ok, false);
  assert.equal(res4.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res4.error, /coverage/i);

  // Missing coveredFiles array
  const res5 = validateProviderOutput({ findings: [], coverage: { omittedFiles: [] } });
  assert.equal(res5.ok, false);
  assert.equal(res5.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res5.error, /coveredFiles/i);

  // Missing omittedFiles array
  const res6 = validateProviderOutput({ findings: [], coverage: { coveredFiles: [] } });
  assert.equal(res6.ok, false);
  assert.equal(res6.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res6.error, /omittedFiles/i);

  // 4. End-to-end orchestration with malformed provider output results in Gate BLOCK
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 1, deletions: 0 }]);
  const mockAdapter = {
    providerName: "mock-malformed",
    modelName: "mock-model",
    executeReview: async () => validateProviderOutput({ foo: "bar" })
  };

  const reviewResult = await orchestrateReview(changeSet, { macro: mockAdapter });

  assert.equal(reviewResult.gate.decision, "block");
  assert.equal(reviewResult.status, "incomplete");
});

// SC-02: Omitted Coverage Fail-Closed
test("SC-02: Omitted Coverage Fail-Closed -> omittedFiles triggers incomplete review & Gate BLOCK", async () => {
  const changeSet = makeChangeSet([
    { path: "src/a.js", additions: 10, deletions: 2 },
    { path: "src/b.js", additions: 5, deletions: 1 }
  ]);

  const mockAdapter = {
    providerName: "mock-omitted",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/b.js"],
        omittedFiles: [{ path: "src/a.js", reason: "context window budget exceeded" }]
      },
      providerIdentity: { provider: "mock-omitted", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Coverage Incomplete/i);
  assert.equal(result.result.coverage.omittedFiles.length, 1);
  assert.equal(result.result.coverage.omittedFiles[0].path, "src/a.js");
});

// SC-03: Untracked File Digest Invariant
test("SC-03: Untracked File Digest Invariant -> content change strictly changes contentDigest", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-sc03-"));
  try {
    spawnSync("git", ["init"], { cwd: tempDir });
    spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: tempDir });
    spawnSync("git", ["config", "user.name", "Test User"], { cwd: tempDir });

    // Initial commit so HEAD exists
    fs.writeFileSync(path.join(tempDir, "base.txt"), "base content\n", "utf8");
    spawnSync("git", ["add", "base.txt"], { cwd: tempDir });
    spawnSync("git", ["commit", "-m", "initial commit"], { cwd: tempDir });

    // Step 1: Add untracked new.txt with 'alpha'
    const newFile = path.join(tempDir, "new.txt");
    fs.writeFileSync(newFile, "alpha\n", "utf8");

    const cs1 = buildChangeSet(tempDir, { scopeMode: "working-tree" });
    assert.equal(cs1.ok, true);
    assert.match(cs1.diffHunks, /alpha/);
    assert.equal(cs1.files.some(f => f.path.includes("new.txt")), true);
    const digest1 = cs1.contentDigest;

    // Step 2: Modify untracked new.txt with 'bravo'
    fs.writeFileSync(newFile, "bravo\n", "utf8");

    const cs2 = buildChangeSet(tempDir, { scopeMode: "working-tree" });
    assert.equal(cs2.ok, true);
    assert.match(cs2.diffHunks, /bravo/);
    const digest2 = cs2.contentDigest;

    // Invariant: digests must be strictly different
    assert.notEqual(digest1, digest2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// SC-04: Provider Family Heterogeneity
test("SC-04: Provider Family Heterogeneity -> agy (Google) vs gemini (Google) blocked by STRICT_HETEROGENEOUS", async () => {
  // Test via loop.mjs aggregateConsensus
  const reportMacro = {
    reportId: "rep-macro-1",
    role: "macro",
    providerIdentity: { provider: "agy", family: "google", model: "gemini-pro", transport: "cli" },
    findings: []
  };

  const reportMicro = {
    reportId: "rep-micro-1",
    role: "micro",
    providerIdentity: { provider: "gemini", family: "google", model: "gemini-flash", transport: "cli" },
    findings: []
  };

  const consensus = aggregateConsensus(
    { macro: reportMacro, micro: reportMicro },
    { policy: QuorumPolicies.STRICT_HETEROGENEOUS }
  );

  assert.equal(consensus.quorumReached, false);
  assert.equal(consensus.verdict, "error");
  assert.match(consensus.consensusProof, /lack provider-family diversity/i);

  // Test via CLI runner
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/auth/token.ts", additions: 50, deletions: 10 }]); // routes to hierarchical

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=agy",
      "--micro-cmd=gemini"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: async ({ command }) => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/auth/token.ts"], omittedFiles: [] }
        })
      })
    }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /lack provider-family diversity/i);
});

// SC-05: Subprocess Exit Code Priority
test("SC-05: Subprocess Exit Code Priority -> non-zero exit code 7 with valid JSON stdout fails as ERROR", async () => {
  const adapter = new CliReviewAdapter({
    command: "test-cli",
    execFn: async () => ({
      code: 7,
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
      }),
      stderr: "Process failed unexpectedly with status 7"
    })
  });

  const changeSet = makeChangeSet();
  const result = await adapter.executeReview({
    runId: "sc05-run",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(result.error, /code 7/i);
});

// SC-06: Finding Text Auth Non-Interference
test("SC-06: Finding Text Auth Non-Interference -> 'Permission denied' in finding title does not trigger auth_failure", async () => {
  const adapter = new CliReviewAdapter({
    command: "test-cli",
    execFn: async () => ({
      code: 0,
      stdout: JSON.stringify({
        findings: [
          {
            title: "Permission denied message is not translated",
            severity: "medium",
            file: "src/calc.js",
            line_start: 10,
            line_end: 12,
            recommendation: "Use i18n translation string"
          }
        ],
        coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
      }),
      stderr: ""
    })
  });

  const changeSet = makeChangeSet();
  const result = await adapter.executeReview({
    runId: "sc06-run",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(result.ok, true);
  assert.equal(result.executionStatus, EXECUTION_STATUS.SUCCESS);
  assert.notEqual(result.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].title, "Permission denied message is not translated");
});

// SC-07: SARIF Successful on Finding Block
test("SC-07: SARIF Successful on Finding Block -> findings block Gate (exit 1) but executionSuccessful is true", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet();

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex",
      "--format=sarif"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: async () => ({
        code: 0,
        stdout: JSON.stringify({
          findings: [
            {
              title: "Hardcoded API Token",
              severity: "high",
              file: "src/calc.js",
              line_start: 1,
              line_end: 1,
              recommendation: "Use environment variable"
            }
          ],
          coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
        })
      })
    }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);

  const sarif = JSON.parse(stdout.buffer);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].message.text, "Use environment variable");
});

// SC-08: Audit Report Persistence Guarantee
test("SC-08: Audit Report Persistence Guarantee -> invalid --report path exits with SYSTEM_FAILURE (3)", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet();

  // Invalid path that cannot be written to
  const impossibleReportPath = path.join(os.platform() === "win32" ? "Z:\\invalid_nonexistent_drive_9999" : "/nonexistent_root_9999", "audit.json");

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex",
      `--report=${impossibleReportPath}`
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: async () => ({
        code: 0,
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
        })
      })
    }
  );

  assert.equal(exitCode, EXIT_CODES.SYSTEM_FAILURE);
  assert.match(stderr.buffer, /Failed to write audit run report/i);
});

// SC-09: ReadOnlySet ECMAScript Integrity
test("SC-09: ReadOnlySet ECMAScript Integrity -> forEach callback does not expose mutable internal set", () => {
  assert.equal(BLOCKING_SEVERITIES.has("low"), false);

  // Attempt to invoke .add() on the 3rd argument passed to forEach
  BLOCKING_SEVERITIES.forEach((value, key, setInstance) => {
    assert.throws(
      () => {
        setInstance.add("low");
      },
      /Cannot modify read-only severity policy set/
    );
  });

  // Verify internal set remains untouched
  assert.equal(BLOCKING_SEVERITIES.has("low"), false);
});

// SC-10: Tool Version Unified Invariant
test("SC-10: Tool Version Unified Invariant -> bump-version --check succeeds and all targets agree", () => {
  const checkOutput = execFileSync(process.execPath, ["scripts/bump-version.mjs", "--check"], {
    encoding: "utf8"
  });

  const pkg = JSON.parse(fs.readFileSync(path.resolve("package.json"), "utf8"));
  assert.match(checkOutput, new RegExp(`All 3 version targets agree on ${pkg.version}`));
  assert.equal(pkg.version, TOOL_VERSION);
});

// Adversarial Edge Case: Quorum failure with findings must remain status 'incomplete'
test("Adversarial: Quorum failure with findings preserves status 'incomplete'", async () => {
  const changeSet = makeChangeSet([
    { path: "src/auth/token.ts", additions: 100, deletions: 10 }
  ]);

  // Two adapters belonging to the same provider family (google)
  const macroAdapter = {
    providerName: "agy",
    modelName: "model-a",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.SUCCESS,
      findings: [{ title: "Critical Injection", severity: "critical", file: "src/auth/token.ts", line_start: 1, line_end: 2, recommendation: "Sanitize" }],
      coverage: { coveredFiles: ["src/auth/token.ts"], omittedFiles: [] },
      providerIdentity: { provider: "agy", family: "google", model: "model-a", transport: "mock" }
    })
  };

  const microAdapter = {
    providerName: "gemini",
    modelName: "model-b",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: { coveredFiles: ["src/auth/token.ts"], omittedFiles: [] },
      providerIdentity: { provider: "gemini", family: "google", model: "model-b", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: macroAdapter, micro: microAdapter });

  // Quorum failed due to same-family violation, status must be 'incomplete', NOT 'reviewed-with-findings'
  assert.equal(result.consensus.quorumReached, false);
  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
});

// Adversarial Edge Case: Orchestration error correctly maps to execution-error in CLI
test("Adversarial: Orchestration error maps to execution-error and exit code 3 in CLI", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const brokenChangeSet = {
    ok: false,
    error: { message: "Corrupted git state" }
  };

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => brokenChangeSet
    }
  );

  assert.equal(exitCode, EXIT_CODES.SYSTEM_FAILURE);
});

// Adversarial Edge Case: Untracked file synthesized hunk has clean line count without phantom trailing lines
test("Adversarial: Untracked file synthesized hunk matches additions count", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-hunk-"));
  try {
    spawnSync("git", ["init"], { cwd: tempDir });
    spawnSync("git", ["config", "user.email", "test@example.com"], { cwd: tempDir });
    spawnSync("git", ["config", "user.name", "Test User"], { cwd: tempDir });

    fs.writeFileSync(path.join(tempDir, "base.txt"), "base\n", "utf8");
    spawnSync("git", ["add", "base.txt"], { cwd: tempDir });
    spawnSync("git", ["commit", "-m", "init"], { cwd: tempDir });

    // Untracked file with trailing newline
    fs.writeFileSync(path.join(tempDir, "clean.txt"), "first line\nsecond line\n", "utf8");

    const cs = buildChangeSet(tempDir, { scopeMode: "working-tree" });
    assert.equal(cs.ok, true);

    const fileMeta = cs.files.find(f => f.path.includes("clean.txt"));
    assert.ok(fileMeta);
    assert.equal(fileMeta.additions, 2);

    // Hunk should declare 2 additions: @@ -0,0 +1,2 @@ and only two '+' lines
    assert.match(cs.diffHunks, /@@ -0,0 \+1,2 @@/);
    const addedLines = cs.diffHunks.split("\n").filter(l => l.startsWith("+") && !l.startsWith("+++"));
    assert.equal(addedLines.length, 2);
    assert.deepEqual(addedLines, ["+first line", "+second line"]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
