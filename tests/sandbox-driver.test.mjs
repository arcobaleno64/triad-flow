/**
 * Test Suite: Pluggable Sandbox Driver Abstraction (M3 / v2.4)
 *
 * Validates ADR-024-02:
 * - Contract 1: WorktreeDriver probe, isolation, and capabilities receipt
 * - Contract 2: ContainerDriver probe failure and strict fail-closed (no silent downgrade)
 * - Contract 3: ContainerDriver probe success with custom/mock execution engine
 * - Contract 4: resolveSandboxDriver fail-closed on unavailable container runtime
 * - Contract 5: ControlledRemediationSession records truthful driver capabilities in receipt
 * - Contract 6: BatchRemediationSession records sandbox driver and capabilities in batch receipt
 * - Contract 7: CLI rejects invalid --sandbox flags with EXIT_CODES.USAGE_ERROR
 * - Contract 8: CLI rejects --sandbox=container on host without container daemon (fail-closed)
 * - Contract 9: Programmatic CLI executes with custom sandboxDriver recording capabilities
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  BaseSandboxDriver,
  WorktreeDriver,
  ContainerDriver,
  resolveSandboxDriver,
  SandboxUnavailableError,
  SilentDowngradeProhibitedError,
  SANDBOX_DRIVERS
} from "../src/core/sandbox-driver.mjs";

import {
  ControlledRemediationSession,
  REMEDIATION_STATES
} from "../src/core/controlled-remediation.mjs";

import {
  BatchRemediationSession,
  BATCH_VERDICTS
} from "../src/core/batch-remediation.mjs";

import { runCli, EXIT_CODES } from "../src/cli.mjs";

test("Contract 1: WorktreeDriver probe, isolation, and truthful capabilities receipt", (t) => {
  const driver = new WorktreeDriver();
  assert.equal(driver.name, "worktree");

  // Probe with host git
  const probe = driver.probe();
  assert.equal(probe.available, true);
  assert.match(probe.version, /git version/i);

  // Authoritative capabilities
  const caps = driver.capabilities();
  assert.equal(caps.driver, "worktree");
  assert.equal(caps.filesystemIsolation, "worktree");
  assert.equal(caps.networkEgressDenial, "unavailable");
  assert.equal(caps.writeBoundary, "jail-worktree-only");

  // Create temporary disposable repo to verify create()
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-driver-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("base");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

    const jail = driver.create(tmpDir);
    assert.ok(fs.existsSync(jail.jailPath));
    assert.equal(jail.driver, "worktree");
    assert.deepEqual(jail.capabilities, caps);

    jail.cleanup();
    assert.ok(!fs.existsSync(jail.jailPath));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 2: ContainerDriver probe failure and strict fail-closed (no silent downgrade)", () => {
  // Mock execFn that simulates missing binary
  const missingExecFn = () => {
    const err = new Error("spawn ENOENT");
    err.code = "ENOENT";
    throw err;
  };

  const driver = new ContainerDriver({
    containerRuntime: "non-existent-docker-binary",
    execFn: missingExecFn
  });

  const probe = driver.probe();
  assert.equal(probe.available, false);
  assert.match(probe.reason, /not installed or not in PATH/i);

  assert.throws(
    () => driver.create("."),
    (err) => {
      assert.ok(err instanceof SandboxUnavailableError);
      assert.match(err.message, /Cannot create container jail/);
      return true;
    }
  );
});

test("Contract 3: ContainerDriver probe success with custom/mock execution engine", () => {
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "Docker version 27.0.3, build 7d4eb36\n" };
    }
    if (args.includes("info")) {
      return { status: 0, stdout: "27.0.3\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: mockExecFn
  });

  const probe = driver.probe();
  assert.equal(probe.available, true);
  assert.equal(probe.runtime, "docker");

  const caps = driver.capabilities();
  assert.equal(caps.driver, "container");
  assert.equal(caps.filesystemIsolation, "container");
  assert.equal(caps.networkEgressDenial, "verified");
  assert.equal(caps.writeBoundary, "container-ephemeral-volume");
});

test("Contract 4: resolveSandboxDriver fail-closed on unavailable container runtime", () => {
  // Default resolution
  const defaultDriver = resolveSandboxDriver();
  assert.ok(defaultDriver instanceof WorktreeDriver);

  const worktreeDriver = resolveSandboxDriver("worktree");
  assert.ok(worktreeDriver instanceof WorktreeDriver);

  // Unsupported driver name
  assert.throws(
    () => resolveSandboxDriver("chroot-custom"),
    /Unsupported sandbox driver: 'chroot-custom'/
  );

  // Unavailable container driver throws SandboxUnavailableError with ADR-024-02 message
  const failingExecFn = () => {
    throw new Error("docker daemon not running");
  };

  assert.throws(
    () => resolveSandboxDriver("container", { execFn: failingExecFn }),
    (err) => {
      assert.ok(err instanceof SandboxUnavailableError);
      assert.match(err.message, /ADR-024-02/);
      assert.match(err.message, /Silent downgrade to worktree is prohibited/);
      return true;
    }
  );
});

function createMockVerificationRecord(findingId, options = {}) {
  const verdict = options.verdict || "SUPPORTED";
  return {
    schemaVersion: "1.0.0",
    verifiedAt: new Date().toISOString(),
    changeSetDigest: "sha256:" + "a".repeat(64),
    producer: {
      providerName: options.producerProvider || "agy",
      findingsCount: 1,
      findings: [{ id: findingId, findingId, title: "Test Finding", severity: "high", file: options.file || "lib.js" }]
    },
    verifier: {
      providerName: options.verifierProvider || "claude",
      modelName: "cli-default",
      actualModel: { value: "claude-3-5-sonnet", source: "reported" }
    },
    evaluations: [
      {
        findingId,
        verdict,
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Affirmatively verified by independent sentry."
      }
    ],
    verifierOmissions: [],
    disagreementLedger: [],
    summary: {
      totalEvaluated: 1,
      supportedCount: 1,
      partiallySupportedCount: 0,
      contestedCount: 0,
      insufficientEvidenceCount: 0,
      omissionsCount: 0
    }
  };
}

test("Contract 5: ControlledRemediationSession records truthful driver capabilities in receipt", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-remed-driver-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "lib.js"), 'function foo() { return "vulnerable"; }\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

    const session = new ControlledRemediationSession("FINDING-001", ["lib.js"]);
    const diff = [
      "diff --git a/lib.js b/lib.js",
      "--- a/lib.js",
      "+++ b/lib.js",
      "@@ -1 +1 @@",
      '-function foo() { return "vulnerable"; }',
      '+function foo() { return "secure"; }'
    ].join("\n");

    session.proposeFix({
      diff,
      rationale: "Fix vulnerability in foo()",
      synthesizer: { providerName: "codex", modelName: "cli-remediate" }
    });

    session.authorizePatch({
      authorizer: { identity: "sec-lead", type: "human" }
    });

    // Execute in worktree jail with default WorktreeDriver
    session.executeInJailWorktree(tmpDir, {
      testRunnerFn: () => ({ exitCode: 0, stdout: "all tests pass" })
    });

    session.recordClosureVerification({
      verifier: { providerName: "claude", modelName: "cli-default" },
      verificationRecord: createMockVerificationRecord("FINDING-001")
    });

    assert.equal(session.status, REMEDIATION_STATES.CLOSED);
    const receipt = session.toReceipt();

    assert.equal(receipt.jail.driver, "worktree");
    assert.deepEqual(receipt.jail.capabilities, {
      driver: "worktree",
      filesystemIsolation: "worktree",
      networkEgressDenial: "unavailable",
      writeBoundary: "jail-worktree-only"
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 6: BatchRemediationSession records sandbox driver and capabilities in batch receipt", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-driver-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "a.js"), 'const a = "old";\n');
    fs.writeFileSync(path.join(tmpDir, "b.js"), 'const b = "old";\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

    const findings = [
      {
        id: "F-001",
        targetFiles: ["a.js"],
        severity: "high",
        patch: [
          "diff --git a/a.js b/a.js",
          "--- a/a.js",
          "+++ b/a.js",
          "@@ -1 +1 @@",
          '-const a = "old";',
          '+const a = "new";'
        ].join("\n")
      }
    ];

    const batch = new BatchRemediationSession("BATCH-DRIVER-TEST", findings);
    const s1 = batch.getSession("F-001");
    s1.proposeFix({
      diff: findings[0].patch,
      rationale: "Fix a.js",
      synthesizer: { providerName: "codex", modelName: "cli-remediate" }
    });
    s1.authorizePatch({
      authorizer: { identity: "sec-lead", type: "human" }
    });

    batch.executeBatchInJailWorktree(tmpDir, {
      testRunnerFn: () => ({ exitCode: 0, stdout: "pass" })
    });

    s1.recordClosureVerification({
      verifier: { providerName: "claude", modelName: "cli-default" },
      verificationRecord: createMockVerificationRecord("F-001")
    });

    batch.finalize();
    const batchReceipt = batch.toBatchReceipt();

    assert.equal(batchReceipt.verdict, BATCH_VERDICTS.ALL_CLOSED);
    assert.equal(batchReceipt.sandbox.driver, "worktree");
    assert.deepEqual(batchReceipt.sandbox.capabilities, {
      driver: "worktree",
      filesystemIsolation: "worktree",
      networkEgressDenial: "unavailable",
      writeBoundary: "jail-worktree-only"
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 7: CLI rejects invalid --sandbox flags with EXIT_CODES.USAGE_ERROR", async () => {
  let stderr = "";
  const io = {
    stdout: { write: () => {} },
    stderr: { write: (msg) => { stderr += msg; } }
  };

  const code = await runCli(["remediate", "--sandbox"], io);
  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr, /Option '--sandbox' requires a <driver> argument/);

  stderr = "";
  const code2 = await runCli(["remediate", "--case=BENCH-REAL-001", "--sandbox=unsupported_jail"], io);
  assert.equal(code2, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr, /Unsupported sandbox driver: 'unsupported_jail'/);
});

test("Contract 8: CLI rejects --sandbox=container on host without container daemon (fail-closed)", async () => {
  let stderr = "";
  const io = {
    stdout: { write: () => {} },
    stderr: { write: (msg) => { stderr += msg; } }
  };

  // Mock execFn simulating that docker is not functional
  const failingExecFn = () => {
    return { status: 1, stderr: "docker daemon is not running\n" };
  };

  const code = await runCli(["remediate", "--case=BENCH-REAL-001", "--sandbox=container"], io, {
    sandboxExecFn: failingExecFn
  });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr, /Requested sandbox driver 'container' is unavailable on this host/);
  assert.match(stderr, /Silent downgrade to worktree is prohibited by ADR-024-02/);
});

test("Contract 9: Programmatic CLI executes with custom sandboxDriver recording capabilities", async () => {
  let stdout = "";
  let stderr = "";
  const io = {
    stdout: { write: (msg) => { stdout += msg; } },
    stderr: { write: (msg) => { stderr += msg; } }
  };

  const code = await runCli([
    "remediate",
    "--case=BENCH-REAL-001",
    "--authorizer=sec-approver",
    "--sandbox=worktree"
  ], io, {
    testRunnerFn: () => ({ exitCode: 0, stdout: "deterministic test suite passed" }),
    closureVerifierFn: (session) => createMockVerificationRecord(session.findingId)
  });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stdout, /Lifecycle Status:\s+CLOSED/);
  assert.match(stdout, /Sandbox Driver:\s+worktree \(fs: worktree, egress: unavailable\)/);
});
