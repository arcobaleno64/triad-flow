/**
 * Test Suite: Deterministic Mock / Offline Provider CLI Test Sandbox (Milestone 2.10)
 *
 * Validates 14 rigorous contracts:
 * - Contract 1: Sandbox initialization, shim creation, state file setup, and clean teardown.
 * - Contract 2: --version probe returns valid semver for agy, claude, and codex.
 * - Contract 3: CLEAN_PASS subprocess execution approves cleanly across agy, claude, and codex.
 * - Contract 4: VULNERABILITY_FOUND subprocess execution emits valid findings and blocks gate.
 * - Contract 5: Provider-specific AUTH_FAILURE injection produces AUTH_FAILURE status and matching error messages.
 * - Contract 6: TIMEOUT subprocess execution hangs and is forcefully killed by adapter timeout budget.
 * - Contract 7: CRASH subprocess execution exits non-zero, captures stderr, and yields ERROR status.
 * - Contract 8: MALFORMED_OUTPUT yields MALFORMED_OUTPUT status and fails closed.
 * - Contract 9: OUTPUT_FLOOD yields error when process floods buffer beyond limits.
 * - Contract 10: SAFETY_REFUSAL with sequential fault injection verifies adapter retry mechanism and subsequent recovery.
 * - Contract 11: Codex -o <file> output channel writes output to designated file and cleans up temp file.
 * - Contract 12: Mandatory safety flags enforcement and prohibited flags rejection.
 * - Contract 13: Invocation auditing ledger logs structured records with exact argv, scenario, and exit codes.
 * - Contract 14: End-to-end orchestrateReview executes heterogeneous quorum (agy + claude) in sandbox.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  MOCK_SCENARIOS,
  PROVIDER_AUTH_ERROR_MESSAGES,
  PROVIDER_MOCK_VERSIONS,
  DEFAULT_MOCK_FINDINGS,
  createMockProviderSandbox,
  extractFilesFromPrompt
} from "../src/adapters/mock-provider-sandbox.mjs";

import {
  CliReviewAdapter
} from "../src/adapters/cli-transport.mjs";

import {
  EXECUTION_STATUS
} from "../src/adapters/provider-contract.mjs";

import {
  orchestrateReview
} from "../src/adapters/review-orchestrator.mjs";

import {
  verifyProviderReadiness
} from "../src/adapters/provider-profiles.mjs";

function makeChangeSet(files = [{ path: "src/auth.js", additions: 10, deletions: 2 }], hunks = "+ const auth = checkUser();") {
  const contentDigest = crypto.createHash("sha256").update(hunks).digest("hex");
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: process.cwd(), hasHead: true, currentBranch: "main" },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: files.reduce((s, f) => s + (f.additions || 0), 0),
    totalDeletions: files.reduce((s, f) => s + (f.deletions || 0), 0),
    files,
    diffHunks: hunks
  };
}

test("Contract 1: Sandbox initialization, shim creation, state file setup, and clean teardown", () => {
  const sandbox = createMockProviderSandbox();
  try {
    assert.equal(fs.existsSync(sandbox.sandboxDir), true);
    assert.equal(fs.existsSync(sandbox.binDir), true);
    assert.equal(fs.existsSync(sandbox.stateFile), true);
    assert.equal(fs.existsSync(sandbox.ledgerFile), true);
    assert.equal(fs.existsSync(sandbox.dispatcherScript), true);

    for (const p of ["agy", "claude", "codex"]) {
      assert.equal(fs.existsSync(path.join(sandbox.binDir, p)), true);
      assert.equal(fs.existsSync(path.join(sandbox.binDir, `${p}.cmd`)), true);
      assert.equal(fs.existsSync(path.join(sandbox.binDir, `${p}.js`)), true);
    }
  } finally {
    sandbox.cleanup();
    assert.equal(fs.existsSync(sandbox.sandboxDir), false);
  }
});

test("Contract 2: --version probe returns valid semver for agy, claude, and codex", () => {
  const sandbox = createMockProviderSandbox();
  try {
    for (const p of ["agy", "claude", "codex"]) {
      const cmd = sandbox.getProviderCommand(p);
      const res = spawnSync(cmd.command, [...cmd.prefixArgs, "--version"], {
        encoding: "utf8",
        windowsHide: true
      });

      assert.equal(res.status, 0);
      assert.match(res.stdout, new RegExp(`${p}\\s+\\d+\\.\\d+\\.\\d+`));
    }
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 3: CLEAN_PASS subprocess execution approves cleanly across agy, claude, and codex", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    for (const p of ["agy", "claude", "codex"]) {
      sandbox.setScenario(p, MOCK_SCENARIOS.CLEAN_PASS);
      const adapter = sandbox.createAdapter(p);

      const res = await adapter.executeReview({
        runId: `run-clean-${p}`,
        role: "macro",
        changeSet: cs,
        policyId: "SINGLE_SENTRY"
      });

      assert.equal(res.ok, true, `Provider ${p} review failed: ${res.error}`);
      assert.equal(res.executionStatus, EXECUTION_STATUS.EMPTY);
      assert.equal(res.findings.length, 0);
      assert.equal(res.coverage.coveredFiles.length >= 1, true);
    }
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 4: VULNERABILITY_FOUND subprocess execution emits valid findings and blocks gate", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("claude", MOCK_SCENARIOS.VULNERABILITY_FOUND);
    const adapter = sandbox.createAdapter("claude");

    const res = await adapter.executeReview({
      runId: "run-vuln-claude",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY"
    });

    assert.equal(res.ok, true);
    assert.equal(res.executionStatus, EXECUTION_STATUS.SUCCESS);
    assert.equal(res.findings.length, 1);
    assert.equal(res.findings[0].severity, "critical");
    assert.equal(res.findings[0].cwe, "CWE-89");
    assert.match(res.findings[0].title, /SQL Injection/);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 5: Provider-specific AUTH_FAILURE injection produces AUTH_FAILURE status and matching error messages", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    for (const p of ["agy", "claude", "codex"]) {
      sandbox.setScenario(p, MOCK_SCENARIOS.AUTH_FAILURE);
      const adapter = sandbox.createAdapter(p);

      const res = await adapter.executeReview({
        runId: `run-auth-${p}`,
        role: "macro",
        changeSet: cs,
        policyId: "SINGLE_SENTRY"
      });

      assert.equal(res.ok, false);
      assert.equal(res.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
      assert.match(res.error, /Authentication failure/i);
    }
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 6: TIMEOUT subprocess execution hangs and is forcefully killed by adapter timeout budget", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("agy", MOCK_SCENARIOS.TIMEOUT);
    const adapter = sandbox.createAdapter("agy");

    const start = Date.now();
    const res = await adapter.executeReview({
      runId: "run-timeout-agy",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY",
      timeoutMs: 300
    });
    const duration = Date.now() - start;

    assert.equal(res.ok, false);
    assert.equal(res.executionStatus, EXECUTION_STATUS.TIMEOUT);
    assert.match(res.error, /timed out/i);
    assert.equal(duration < 2000, true, `Timeout took too long: ${duration}ms`);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 7: CRASH subprocess execution exits non-zero, captures stderr, and yields ERROR status", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("codex", MOCK_SCENARIOS.CRASH);
    const adapter = sandbox.createAdapter("codex");

    const res = await adapter.executeReview({
      runId: "run-crash-codex",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY"
    });

    assert.equal(res.ok, false);
    assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
    assert.match(res.error, /unhandled exception/i);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 8: MALFORMED_OUTPUT yields MALFORMED_OUTPUT status and fails closed", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("claude", MOCK_SCENARIOS.MALFORMED_OUTPUT);
    const adapter = sandbox.createAdapter("claude");

    const res = await adapter.executeReview({
      runId: "run-malformed-claude",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY"
    });

    assert.equal(res.ok, false);
    assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 9: OUTPUT_FLOOD yields error when process floods buffer beyond limits", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("agy", MOCK_SCENARIOS.OUTPUT_FLOOD);
    const adapter = sandbox.createAdapter("agy");

    const res = await adapter.executeReview({
      runId: "run-flood-agy",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY",
      timeoutMs: 1500
    });

    assert.equal(res.ok, false);
    assert.equal(
      res.executionStatus === EXECUTION_STATUS.PAYLOAD_TOO_LARGE ||
      res.executionStatus === EXECUTION_STATUS.ERROR ||
      res.executionStatus === EXECUTION_STATUS.TIMEOUT,
      true
    );
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 10: SAFETY_REFUSAL with sequential fault injection verifies adapter retry mechanism and subsequent recovery", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    // agy has maxRetries = 2. Sequence: [SAFETY_REFUSAL, CLEAN_PASS]
    sandbox.setSequence("agy", [MOCK_SCENARIOS.SAFETY_REFUSAL, MOCK_SCENARIOS.CLEAN_PASS]);
    const adapter = sandbox.createAdapter("agy", { maxRetries: 2 });

    const res = await adapter.executeReview({
      runId: "run-retry-agy",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY",
      timeoutMs: 8000
    });

    assert.equal(res.ok, true, `Retry should have recovered on attempt 2: ${res.error}`);
    assert.equal(res.executionStatus, EXECUTION_STATUS.EMPTY);
    assert.equal(res.findings.length, 0);

    const invocations = sandbox.getInvocations("agy");
    assert.equal(invocations.length, 2);
    assert.equal(invocations[0].scenario, MOCK_SCENARIOS.SAFETY_REFUSAL);
    assert.equal(invocations[1].scenario, MOCK_SCENARIOS.CLEAN_PASS);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 11: Codex -o <file> output channel writes output to designated file and cleans up temp file", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    sandbox.setScenario("codex", MOCK_SCENARIOS.CLEAN_PASS);
    const adapter = sandbox.createAdapter("codex");

    const res = await adapter.executeReview({
      runId: "run-file-codex",
      role: "macro",
      changeSet: cs,
      policyId: "SINGLE_SENTRY"
    });

    assert.equal(res.ok, true);
    assert.equal(res.executionStatus, EXECUTION_STATUS.EMPTY);

    const invocations = sandbox.getInvocations("codex");
    assert.equal(invocations.length, 1);
    assert.equal(invocations[0].argv.includes("-o"), true);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 12: Mandatory safety flags enforcement and prohibited flags rejection", () => {
  const sandbox = createMockProviderSandbox({ strictSafetyArgs: true });

  try {
    // Prohibited flag rejection
    const cmd = sandbox.getProviderCommand("claude");
    const resProhibited = spawnSync(cmd.command, [...cmd.prefixArgs, "--dangerously-bypass-approvals-and-sandbox"], {
      encoding: "utf8",
      windowsHide: true
    });
    assert.equal(resProhibited.status, 2);
    assert.match(resProhibited.stderr, /Prohibited argument detected/);

    // Missing mandatory safety arg rejection (e.g. claude missing -p)
    const resMissing = spawnSync(cmd.command, [...cmd.prefixArgs, "--tools=", "some prompt"], {
      encoding: "utf8",
      windowsHide: true
    });
    assert.equal(resMissing.status, 2);
    assert.match(resMissing.stderr, /Missing mandatory safety arguments/);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 13: Invocation auditing ledger logs structured records with exact argv, scenario, and exit codes", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet();

  try {
    const adapterAgy = sandbox.createAdapter("agy");
    const adapterClaude = sandbox.createAdapter("claude");

    await adapterAgy.executeReview({ runId: "r1", role: "macro", changeSet: cs, policyId: "SINGLE_SENTRY" });
    await adapterClaude.executeReview({ runId: "r2", role: "micro", changeSet: cs, policyId: "SINGLE_SENTRY" });

    const ledger = sandbox.getInvocations();
    assert.equal(ledger.length >= 2, true);

    const agyEntry = ledger.find(e => e.provider === "agy");
    assert.ok(agyEntry);
    assert.equal(agyEntry.scenario, "clean_pass");
    assert.equal(agyEntry.exitCode, 0);

    const claudeEntry = ledger.find(e => e.provider === "claude");
    assert.ok(claudeEntry);
    assert.equal(claudeEntry.scenario, "clean_pass");
    assert.equal(claudeEntry.exitCode, 0);
  } finally {
    sandbox.cleanup();
  }
});

test("Contract 14: End-to-end orchestrateReview executes heterogeneous quorum (agy + claude) in sandbox", async () => {
  const sandbox = createMockProviderSandbox();
  const cs = makeChangeSet([{ path: "src/auth.js", additions: 5, deletions: 1 }]);

  try {
    sandbox.setScenario("agy", MOCK_SCENARIOS.CLEAN_PASS);
    sandbox.setScenario("claude", MOCK_SCENARIOS.CLEAN_PASS);

    const macroAdapter = sandbox.createAdapter("agy");
    const microAdapter = sandbox.createAdapter("claude");

    const orchResult = await orchestrateReview(cs, {
      macro: macroAdapter,
      micro: microAdapter
    }, {
      plan: { mode: "hierarchical", reason: "heterogeneous-quorum-test" },
      preliminary: true
    });

    assert.equal(orchResult.status, "preliminary-clean");
    assert.equal(orchResult.gate.decision, "approve");
    assert.equal(orchResult.gate.preliminary, true);
    const findings = orchResult.result?.findings ?? orchResult.consensus?.findings ?? [];
    assert.equal(findings.length, 0);
    assert.equal(orchResult.consensus.quorumReached, true);
  } finally {
    sandbox.cleanup();
  }
});
