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
  SandboxSecurityViolationError,
  SANDBOX_DRIVERS,
  DEFAULT_CONTAINER_IMAGE,
  ACTIVE_EGRESS_PROBE_SCRIPT
} from "../src/core/sandbox-driver.mjs";

import {
  ControlledRemediationSession,
  REMEDIATION_STATES,
  RemediationValidationError
} from "../src/core/controlled-remediation.mjs";

import {
  BatchRemediationSession,
  BATCH_VERDICTS,
  BatchValidationError
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
  assert.equal(caps.filesystemIsolation, "git-worktree");
  assert.equal(caps.networkEgressDenial, "unavailable");
  assert.equal(caps.processIsolation, "none");
  assert.equal(caps.hostFilesystemWriteRestriction, "unenforced");

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
      assert.match(err.message, /Requested sandbox driver 'container' is unavailable on this host/);
      assert.match(err.message, /Silent downgrade to worktree is prohibited by ADR-024-02/);
      return true;
    }
  );
});

test("Contract 3: ContainerDriver probe success with custom/mock execution engine and active egress probe", () => {
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "Docker version 27.0.3, build 7d4eb36\n" };
    }
    if (args.includes("info")) {
      return { status: 0, stdout: "27.0.3\n" };
    }
    if (args.includes("inspect")) {
      return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    }
    // Egress probe script: in --network=none, connection failure returns status 42 and sentinel
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH\n", stderr: "" };
    }
    // General in-container test command
    if (args.includes("node") && args.includes("-v")) {
      return { status: 0, stdout: "v20.15.0\n" };
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
  assert.equal(probe.imageDigest, "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-container-driver-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("container-base");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

    const jail = driver.create(tmpDir);
    assert.ok(fs.existsSync(jail.jailPath));
    assert.equal(jail.driver, "container");
    assert.equal(jail.capabilities.filesystemIsolation, "container");
    assert.equal(jail.capabilities.networkEgressDenial, "verified");
    assert.equal(jail.capabilities.processIsolation, "container");
    assert.equal(jail.capabilities.hostFilesystemWriteRestriction, "enforced-mount-ro");
    assert.equal(jail.capabilities.requestedControls.pullPolicy, "never");
    assert.equal(jail.capabilities.effectiveControls.networkMode, "none");
    assert.equal(jail.capabilities.verifiedControls.networkEgressDenied, true);
    assert.equal(jail.capabilities.environments.testExecutionEnvironment, "container");

    // In-container command execution
    const runRes = jail.runInContainer(["node", "-v"]);
    assert.equal(runRes.exitCode, 0);
    assert.equal(runRes.stdout.trim(), "v20.15.0");

    jail.cleanup();
    assert.ok(!fs.existsSync(jail.jailPath));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 4: resolveSandboxDriver resolves container driver when available, and fails closed when unavailable", () => {
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

  // When container daemon and image are available, resolveSandboxDriver returns ContainerDriver
  const passingExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    return { status: 0, stdout: "" };
  };

  const resolved = resolveSandboxDriver("container", { execFn: passingExecFn });
  assert.ok(resolved instanceof ContainerDriver);
  assert.equal(resolved.runtime, "docker");
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
      filesystemIsolation: "git-worktree",
      networkEgressDenial: "unavailable",
      processIsolation: "none",
      hostFilesystemWriteRestriction: "unenforced"
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
      filesystemIsolation: "git-worktree",
      networkEgressDenial: "unavailable",
      processIsolation: "none",
      hostFilesystemWriteRestriction: "unenforced"
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

  // Test empty --sandbox= flag
  stderr = "";
  const codeEmpty = await runCli(["remediate", "--case=BENCH-REAL-001", "--sandbox="], io);
  assert.equal(codeEmpty, EXIT_CODES.USAGE_ERROR);
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
  assert.match(stdout, /Sandbox Driver:\s+worktree \(fs: git-worktree, egress: unavailable\)/);
});

test("Contract 10: Local image missing under --pull=never policy fails closed immediately", () => {
  const missingImageExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) {
      return { status: 1, stderr: "Error: No such image: node:20-slim\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    image: "node:20-slim",
    execFn: missingImageExecFn
  });

  const probe = driver.probe();
  assert.equal(probe.available, false);
  assert.match(probe.reason, /--pull=never policy prohibits implicit pull/);

  assert.throws(
    () => driver.create("."),
    (err) => {
      assert.ok(err instanceof SandboxUnavailableError);
      assert.match(err.message, /--pull=never policy prohibits implicit pull/);
      return true;
    }
  );
});

test("Contract 11: Active egress probe detects unexpected outbound network access and throws SandboxSecurityViolationError", () => {
  const leakingExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    // Leaking egress: egress probe command returns 0 (connected!) instead of failing
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 0, stdout: "Connected to outbound host unexpectedly\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: leakingExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-egress-leak-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("base");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

    assert.throws(
      () => driver.create(tmpDir),
      (err) => {
        assert.ok(err instanceof SandboxSecurityViolationError);
        assert.match(err.message, /Active egress probe succeeded! Outbound network connection was established/);
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 12: BuildRunArgs validates strict isolation flags and strips host tokens/secrets", () => {
  const driver = new ContainerDriver({
    containerRuntime: "docker"
  });

  const origGitHubToken = process.env.GITHUB_TOKEN;
  const origOpenAiKey = process.env.OPENAI_API_KEY;
  const origAwsKey = process.env.AWS_SECRET_ACCESS_KEY;
  const origNodeEnv = process.env.NODE_ENV;

  try {
    process.env.GITHUB_TOKEN = "ghp_super_secret_token_123456";
    process.env.OPENAI_API_KEY = "sk-super_secret_openai_key_123456";
    process.env.AWS_SECRET_ACCESS_KEY = "super_secret_aws_key_123456";
    process.env.NODE_ENV = "test";

    const repoPath = "C:/fake/repo";
    const jailPath = "C:/fake/jail";
    const args = driver.buildRunArgs(repoPath, jailPath, ["npm", "test"]);

    // Isolation flags
    assert.ok(args.includes("--pull=never"), "Must include --pull=never");
    assert.ok(args.includes("--network=none"), "Must include --network=none");
    assert.ok(args.includes("--read-only"), "Must include --read-only rootfs");
    assert.ok(args.includes("--cap-drop=ALL"), "Must drop all capabilities");
    assert.ok(args.includes("--security-opt=no-new-privileges"), "Must enforce no-new-privileges");

    // Mount points
    assert.ok(args.some(a => a.endsWith(":/workspace:ro")), "Host repo must be mounted read-only (:ro)");
    assert.ok(args.some(a => a.endsWith(":/jail:rw")), "Jail worktree must be mounted read-write (:rw)");
    assert.ok(args.includes("/tmp:rw,noexec,nosuid,size=64m"), "Must mount volatile tmpfs");
    assert.ok(args.includes("-w") && args[args.indexOf("-w") + 1] === "/jail", "Working directory must be /jail");

    // Secrets MUST be stripped (never passed via -e)
    const flattenedArgs = args.join(" ");
    assert.ok(!flattenedArgs.includes("ghp_super_secret_token_123456"), "Must strip GITHUB_TOKEN");
    assert.ok(!flattenedArgs.includes("sk-super_secret_openai_key_123456"), "Must strip OPENAI_API_KEY");
    assert.ok(!flattenedArgs.includes("super_secret_aws_key_123456"), "Must strip AWS_SECRET_ACCESS_KEY");

    // Allowlisted environment variables MUST be passed
    assert.ok(args.includes("NODE_ENV=test"), "Allowlisted NODE_ENV must be present");
  } finally {
    if (origGitHubToken !== undefined) process.env.GITHUB_TOKEN = origGitHubToken; else delete process.env.GITHUB_TOKEN;
    if (origOpenAiKey !== undefined) process.env.OPENAI_API_KEY = origOpenAiKey; else delete process.env.OPENAI_API_KEY;
    if (origAwsKey !== undefined) process.env.AWS_SECRET_ACCESS_KEY = origAwsKey; else delete process.env.AWS_SECRET_ACCESS_KEY;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv; else delete process.env.NODE_ENV;
  }
});

test("Contract 13: Pinned image digest matching and rejection of mismatched digests", () => {
  const expectedDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
  const unexpectedDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

  let inspectDigestToReturn = unexpectedDigest;
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: inspectDigestToReturn + "\n" };
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    image: "node:20-slim",
    pinnedImageDigest: expectedDigest,
    execFn: mockExecFn
  });

  // Mismatch -> probe fails
  const mismatchProbe = driver.probe();
  assert.equal(mismatchProbe.available, false);
  assert.match(mismatchProbe.reason, /Image digest mismatch/);

  // Match -> probe succeeds
  inspectDigestToReturn = expectedDigest;
  const matchProbe = driver.probe();
  assert.equal(matchProbe.available, true);
  assert.equal(matchProbe.imageDigest, expectedDigest);
});

test("Contract 14: Active egress probe execution failure (status!=42 or missing sentinel) fails closed", () => {
  // Simulates runtime crash / missing node / syntax error inside container probe (exit 127)
  const crashedProbeExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      // Missing node or shell runtime crash: exits 127 without denial sentinel
      return { status: 127, stderr: "sh: node: not found\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: crashedProbeExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-probe-crash-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("test");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    assert.throws(
      () => driver.create(tmpDir),
      (err) => {
        assert.ok(err instanceof SandboxSecurityViolationError);
        assert.match(err.message, /Active egress probe execution failed \(status=127\) without authentic network denial sentinel/);
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 15: ContainerDriver rejects host function callback in ControlledRemediationSession (fails closed)", () => {
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH:NS_ISOLATED\n", stderr: "" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: mockExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-rem-cb-reject-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("old");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const session = new ControlledRemediationSession("F-CONTAINER-REJECT-CB", ["index.js"]);
    session.proposeFix({
      diff: "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-console.log(\"old\");\n+console.log(\"new\");\n",
      rationale: "Fix"
    });
    session.authorizePatch({ authorizer: { identity: "sec-lead", type: "human" } });

    assert.throws(
      () => session.executeInJailWorktree(tmpDir, {
        sandboxDriver: driver,
        testRunnerFn: () => ({ exitCode: 0 })
      }),
      (err) => {
        assert.ok(err instanceof RemediationValidationError);
        assert.match(err.message, /Container sandbox execution requires a typed command runner/);
        assert.match(err.message, /Arbitrary host callback functions are prohibited under container driver/);
        return true;
      }
    );
    assert.equal(session.status, REMEDIATION_STATES.PATCH_AUTHORIZED);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 16: ContainerDriver executes typed command runner in ControlledRemediationSession via jail.runInContainer", () => {
  const containerCommandsRan = [];
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH:NS_ISOLATED\n", stderr: "" };
    }
    if (args.includes("npm") && args.includes("test")) {
      containerCommandsRan.push(args);
      return { status: 0, stdout: "container deterministic tests passed\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: mockExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-rem-cmd-container-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("old");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const session = new ControlledRemediationSession("F-CONTAINER-CMD", ["index.js"]);
    session.proposeFix({
      diff: "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-console.log(\"old\");\n+console.log(\"new\");\n",
      rationale: "Fix",
      synthesizer: { providerName: "codex", modelName: "cli-remediate" }
    });
    session.authorizePatch({ authorizer: { identity: "sec-lead", type: "human" } });

    session.executeInJailWorktree(tmpDir, {
      sandboxDriver: driver,
      testRunnerFn: { command: "npm", args: ["test"] }
    });

    assert.equal(session.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
    assert.equal(containerCommandsRan.length, 1);
    assert.equal(session.deterministicChecks.runner, "container-runner");
    assert.equal(session.deterministicChecks.executionEnvironment, "container");
    assert.equal(session.deterministicChecks.exitCode, 0);

    session.recordClosureVerification({
      verifier: { providerName: "claude", modelName: "cli-default" },
      verificationRecord: createMockVerificationRecord("F-CONTAINER-CMD", { file: "index.js" })
    });

    assert.equal(session.status, REMEDIATION_STATES.CLOSED);
    const receipt = session.toReceipt();
    assert.equal(receipt.deterministicChecks.runner, "container-runner");
    assert.equal(receipt.deterministicChecks.executionEnvironment, "container");
    assert.equal(receipt.jail.capabilities.environments.testExecutionEnvironment, "container");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 17: ContainerDriver rejects host function callback in BatchRemediationSession (fails closed)", () => {
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH:NS_ISOLATED\n", stderr: "" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: mockExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-cb-reject-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "a.js"), 'console.log("a");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const batch = new BatchRemediationSession("BATCH-REJECT-CB", [
      { id: "F-001", targetFiles: ["a.js"] }
    ]);
    const s1 = batch.getSession("F-001");
    s1.proposeFix({
      diff: "diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-console.log(\"a\");\n+console.log(\"fixed\");\n",
      rationale: "Fix a"
    });
    s1.authorizePatch({ authorizer: { identity: "sec-lead", type: "human" } });

    assert.throws(
      () => batch.executeBatchInJailWorktree(tmpDir, {
        sandboxDriver: driver,
        testRunnerFn: () => ({ exitCode: 0 })
      }),
      (err) => {
        assert.ok(err instanceof BatchValidationError);
        assert.match(err.message, /Container sandbox execution requires a typed command runner/);
        assert.match(err.message, /Arbitrary host callback functions are prohibited under container driver/);
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 18: ContainerDriver executes typed command runner in BatchRemediationSession via jail.runInContainer", () => {
  const containerCommandsRan = [];
  const mockExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH:NS_ISOLATED\n", stderr: "" };
    }
    if (args.includes("npm") && args.includes("test")) {
      containerCommandsRan.push(args);
      return { status: 0, stdout: "batch container test passed\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: mockExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-cmd-container-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "a.js"), 'console.log("a");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const batch = new BatchRemediationSession("BATCH-CONTAINER-CMD", [
      { id: "F-001", targetFiles: ["a.js"] }
    ]);
    const s1 = batch.getSession("F-001");
    s1.proposeFix({
      diff: "diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-console.log(\"a\");\n+console.log(\"fixed\");\n",
      rationale: "Fix a",
      synthesizer: { providerName: "codex", modelName: "cli-remediate" }
    });
    s1.authorizePatch({ authorizer: { identity: "sec-lead", type: "human" } });

    batch.executeBatchInJailWorktree(tmpDir, {
      sandboxDriver: driver,
      testRunnerFn: { command: "npm", args: ["test"] }
    });

    assert.equal(containerCommandsRan.length, 1);
    assert.equal(s1.deterministicChecks.runner, "container-runner");
    assert.equal(s1.deterministicChecks.executionEnvironment, "container");
    assert.equal(s1.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);

    s1.recordClosureVerification({
      verifier: { providerName: "claude", modelName: "cli-default" },
      verificationRecord: createMockVerificationRecord("F-001", { file: "a.js" })
    });

    batch.finalize();
    const batchReceipt = batch.toBatchReceipt();
    assert.equal(batchReceipt.verdict, BATCH_VERDICTS.ALL_CLOSED);
    assert.equal(batchReceipt.receipts[0].deterministicChecks.runner, "container-runner");
    assert.equal(batchReceipt.receipts[0].deterministicChecks.executionEnvironment, "container");
    assert.equal(batchReceipt.sandbox.driver, "container");
    assert.equal(batchReceipt.sandbox.capabilities.environments.testExecutionEnvironment, "container");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 19: Container network namespace isolation breach (TF_NAMESPACE_LEAK) throws SandboxSecurityViolationError", () => {
  const leakExecFn = (cmd, args) => {
    if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.0.3\n" };
    if (args.includes("info")) return { status: 0, stdout: "27.0.3\n" };
    if (args.includes("inspect")) return { status: 0, stdout: "sha256:d8a2bc4e7a4b89e5c9f5653b47c0b05b38234857ef129994c50259e5a8c2efec\n" };
    if (args.includes("sh") && args.some(a => String(a).includes("192.0.2.1"))) {
      return { status: 1, stdout: "TF_NAMESPACE_LEAK:lo,eth0\n" };
    }
    return { status: 0, stdout: "" };
  };

  const driver = new ContainerDriver({
    containerRuntime: "docker",
    execFn: leakExecFn
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-ns-leak-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("test");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    assert.throws(
      () => driver.create(tmpDir),
      (err) => {
        assert.ok(err instanceof SandboxSecurityViolationError);
        assert.match(err.message, /Container network namespace isolation breach detected: non-loopback network interfaces present/);
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 20: WorktreeDriver supports typed command runner and records worktree-runner with host executionEnvironment", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-worktree-cmd-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("vulnerable");\n');
    fs.writeFileSync(path.join(tmpDir, "test.js"), 'process.exit(0);\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const session = new ControlledRemediationSession("F-WORKTREE-CMD", ["index.js"]);
    session.proposeFix({
      diff: "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-console.log(\"vulnerable\");\n+console.log(\"safe\");\n",
      rationale: "Fix"
    });
    session.authorizePatch({ authorizer: { identity: "sec-lead", type: "human" } });

    session.executeInJailWorktree(tmpDir, {
      testRunnerFn: { command: "node", args: ["test.js"] }
    });

    assert.equal(session.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
    assert.equal(session.deterministicChecks.runner, "worktree-runner");
    assert.equal(session.deterministicChecks.executionEnvironment, "host");
    assert.equal(session.deterministicChecks.exitCode, 0);

    const receipt = session.toReceipt();
    assert.equal(receipt.deterministicChecks.runner, "worktree-runner");
    assert.equal(receipt.deterministicChecks.executionEnvironment, "host");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

