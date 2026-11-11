/**
 * Test Suite: Hot-Reuse Container Sandbox Pool (M1 / v2.12)
 *
 * Validates Pillar 1 of Milestone v2.12 (RFC-028-01):
 * - Contract 1: Pool initialization and default configuration
 * - Contract 2: Probe failure and strict fail-closed when runtime is unavailable
 * - Contract 3: Multi-language warm daemon spawning with strict security isolation flags
 * - Contract 4: Hot-reuse command execution via exec (sub-150ms dispatch latency)
 * - Contract 5: Execution timeout handling in warm container
 * - Contract 6: Workspace hot-mounting and scrubbing on release (Scrub-on-Release)
 * - Contract 7: Pool capacity limits and acquire queue scheduling
 * - Contract 8: Acquire timeout when pool stays exhausted
 * - Contract 9: Active egress denial verification in warm daemon
 * - Contract 10: Daemon health checks, crash detection, and auto-replenishment
 * - Contract 11: Idle daemon reaping down to minWarm
 * - Contract 12: Zero Orphan Containers guarantee on pool drain and emergency exit
 * - Contract 13: PoolContainerDriver integration with BaseSandboxDriver contract
 * - Contract 14: Truthful capabilities reporting for audit receipts
 * - Contract 15: ControlledRemediationSession integration with PoolContainerDriver
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  ContainerSandboxPool,
  PoolContainerDriver,
  ContainerDaemon,
  POOL_CONTAINER_STATES,
  DEFAULT_RESOURCE_LIMITS,
  DEFAULT_POOL_OPTIONS,
  PoolError,
  PoolAcquireTimeoutError,
  PoolCapacityExceededError,
  PoolDisposedError,
  DaemonExecutionError,
  DaemonHealthCheckError
} from "../src/core/sandbox-pool.mjs";

import {
  SandboxUnavailableError,
  SandboxSecurityViolationError,
  BaseSandboxDriver
} from "../src/core/sandbox-driver.mjs";

import {
  ControlledRemediationSession,
  REMEDIATION_STATES
} from "../src/core/controlled-remediation.mjs";

import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE_CONTAINER_IMAGES
} from "../src/core/multi-language-remediation.mjs";

/**
 * Creates a configurable mock execution engine simulating Docker CLI.
 */
function createMockDocker(customHandlers = {}) {
  const executedCalls = [];
  const activeContainers = new Set();

  const mockExecFn = (cmd, args = [], opts = {}) => {
    const callRecord = { cmd, args: [...args], opts };
    executedCalls.push(callRecord);

    if (customHandlers.onCall) {
      const customRes = customHandlers.onCall(cmd, args, opts);
      if (customRes !== undefined) return customRes;
    }

    // Version
    if (args.includes("--version")) {
      return { status: 0, stdout: "Docker version 27.0.3, build 7d4eb36\n" };
    }

    // Daemon readiness info
    if (args.includes("info")) {
      return { status: 0, stdout: "27.0.3\n" };
    }

    // Run daemon
    if (args.includes("run") && args.includes("-d")) {
      const nameIdx = args.indexOf("--name");
      const cName = nameIdx !== -1 ? args[nameIdx + 1] : `container-${Date.now()}`;
      activeContainers.add(cName);
      return { status: 0, stdout: `${cName}\n` };
    }

    // Exec command
    if (args.includes("exec")) {
      if (customHandlers.onExec) {
        return customHandlers.onExec(args, opts);
      }
      // Egress probe script response
      if (args.some(a => String(a).includes("192.0.2.1"))) {
        return { status: 42, stdout: "TF_EGRESS_DENIED:ENETUNREACH\n", stderr: "" };
      }
      // Ping
      if (args.includes("echo") && args.includes("ping")) {
        return { status: 0, stdout: "ping\n" };
      }
      // General commands
      return { status: 0, stdout: "mock-exec-success\n", stderr: "" };
    }

    // Rm container
    if (args.includes("rm")) {
      for (const a of args) {
        activeContainers.delete(a);
      }
      return { status: 0, stdout: "" };
    }

    return { status: 0, stdout: "" };
  };

  return { mockExecFn, executedCalls, activeContainers };
}

test("Contract 1: Pool initialization and default configuration", () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  assert.equal(pool.runtime, "docker");
  assert.equal(pool.options.minWarm, 1);
  assert.equal(pool.options.maxCapacity, 8);
  assert.deepEqual(pool.options.resourceLimits, DEFAULT_RESOURCE_LIMITS);
  assert.equal(pool.options.defaultLanguage, SUPPORTED_LANGUAGES.JAVASCRIPT);

  const stats = pool.getStats();
  assert.equal(stats.totalDaemons, 0);
  assert.equal(stats.idleDaemons, 0);
  assert.equal(stats.busyDaemons, 0);
  assert.equal(stats.queueLength, 0);
});

test("Contract 2: Probe failure and strict fail-closed when runtime is unavailable", async () => {
  const missingExecFn = () => {
    const err = new Error("spawn ENOENT");
    err.code = "ENOENT";
    throw err;
  };

  const pool = new ContainerSandboxPool({
    execFn: missingExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const probe = pool.probe();
  assert.equal(probe.available, false);
  assert.match(probe.reason, /not installed or not in PATH/i);

  // Warmup must fail-closed
  await assert.rejects(
    async () => await pool.warmup(),
    (err) => {
      assert.ok(err instanceof SandboxUnavailableError);
      assert.match(err.message, /Cannot warmup ContainerSandboxPool/);
      return true;
    }
  );
});

test("Contract 3: Multi-language warm daemon spawning with strict security isolation flags", async () => {
  const { mockExecFn, executedCalls } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    minWarm: 1,
    maxCapacity: 5,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemons = await pool.warmup([
      SUPPORTED_LANGUAGES.JAVASCRIPT,
      SUPPORTED_LANGUAGES.PYTHON,
      SUPPORTED_LANGUAGES.RUST,
      SUPPORTED_LANGUAGES.GO,
      SUPPORTED_LANGUAGES.C
    ]);

    assert.equal(daemons.length, 5);
    assert.equal(pool.daemons.size, 5);

    // Verify language mapping
    const languages = daemons.map(d => d.language);
    assert.deepEqual(languages, ["javascript", "python", "rust", "go", "c"]);

    // Verify strict isolation flags on the spawned run commands
    const runCalls = executedCalls.filter(c => c.args.includes("run"));
    assert.equal(runCalls.length, 5);

    for (const call of runCalls) {
      assert.ok(call.args.includes("--pull=never"), "Must include --pull=never");
      assert.ok(call.args.includes("--network=none"), "Must include --network=none");
      assert.ok(call.args.includes("--read-only"), "Must include --read-only");
      assert.ok(call.args.includes("--memory=2g"), "Must enforce memory limit 2g");
      assert.ok(call.args.includes("--cpus=2.0"), "Must enforce CPU limit 2.0");
      assert.ok(call.args.includes("--user=1000:1000"), "Must degrade privileges to non-root 1000:1000");
      assert.ok(call.args.includes("--cap-drop=ALL"), "Must drop all Linux capabilities");
      assert.ok(call.args.includes("--security-opt=no-new-privileges"), "Must enforce no-new-privileges");
      assert.ok(call.args.includes("/tmp:rw,noexec,nosuid,size=64m"), "Must mount scratch tmpfs");
      assert.ok(call.args.includes("tail"), "Must run daemon command");
    }
  } finally {
    await pool.drain();
  }
});

test("Contract 4: Hot-reuse command execution via exec (sub-150ms dispatch latency)", async () => {
  const { mockExecFn, executedCalls } = createMockDocker({
    onExec: (args) => {
      if (args.includes("node") && args.includes("-v")) {
        return { status: 0, stdout: "v20.15.0\n", stderr: "" };
      }
      return { status: 0, stdout: "ok\n", stderr: "" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await pool.acquire({ language: SUPPORTED_LANGUAGES.JAVASCRIPT });
    assert.equal(daemon.status, POOL_CONTAINER_STATES.BUSY);

    const execResult = pool.execute(daemon, ["node", "-v"], { cwd: "src" });
    assert.equal(execResult.status, 0);
    assert.equal(execResult.stdout.trim(), "v20.15.0");
    assert.ok(execResult.durationMs < 150, `Dispatch latency must be sub-150ms (got ${execResult.durationMs}ms)`);

    // Verify exec arguments
    const execCall = executedCalls.find(c => c.args.includes("exec") && c.args.includes("node"));
    assert.ok(execCall, "Must execute via docker exec");
    assert.ok(execCall.args.includes("-w"), "Must forward working directory");
    assert.ok(execCall.args.includes("/jail/src"), "Must target /jail/src");
    assert.ok(execCall.args.includes(daemon.containerName), "Must target warm container daemon name");

    await pool.release(daemon);
    assert.equal(daemon.status, POOL_CONTAINER_STATES.IDLE);
  } finally {
    await pool.drain();
  }
});

test("Contract 5: Execution timeout handling in warm container", async () => {
  const { mockExecFn } = createMockDocker({
    onExec: () => {
      const err = new Error("Command timed out");
      err.code = "ETIMEDOUT";
      return { status: null, error: err, stdout: "", stderr: "" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await pool.acquire({ language: SUPPORTED_LANGUAGES.PYTHON });
    const res = pool.execute(daemon, ["python", "-c", "import time; time.sleep(10)"], { timeout: 200 });

    assert.equal(res.status, 124);
    assert.equal(res.timedOut, true);
    assert.match(res.stderr, /timed out/i);

    await pool.release(daemon);
  } finally {
    await pool.drain();
  }
});

test("Contract 6: Workspace hot-mounting and scrubbing on release (Scrub-on-Release)", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    scrubOnRelease: true,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await pool.acquire({ language: SUPPORTED_LANGUAGES.JAVASCRIPT });
    assert.ok(fs.existsSync(daemon.hostWorkspaceDir), "Host workspace dir must exist");

    // Simulate task producing files in host workspace
    const dirtyFile = path.join(daemon.hostWorkspaceDir, "trial-artifact.txt");
    const dirtySubDir = path.join(daemon.hostWorkspaceDir, "build");
    fs.mkdirSync(dirtySubDir, { recursive: true });
    fs.writeFileSync(dirtyFile, "dirty state from previous run");
    fs.writeFileSync(path.join(dirtySubDir, "out.bin"), "binary data");

    assert.ok(fs.existsSync(dirtyFile));
    assert.ok(fs.existsSync(dirtySubDir));

    // Release with scrubbing enabled
    await pool.release(daemon, { scrub: true });

    // Host workspace must be scrubbed clean
    assert.ok(fs.existsSync(daemon.hostWorkspaceDir), "Workspace dir itself remains");
    const remainingFiles = fs.readdirSync(daemon.hostWorkspaceDir);
    assert.deepEqual(remainingFiles, [], "Scrub-on-release must leave workspace empty without residual artifacts");
  } finally {
    await pool.drain();
  }
});

test("Contract 7: Pool capacity limits and acquire queue scheduling", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    minWarm: 1,
    maxCapacity: 2, // Strict capacity: max 2 daemons
    acquireTimeoutMs: 5000,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    // Acquire slot 1 and slot 2
    const slot1 = await pool.acquire({ taskId: "task-1" });
    const slot2 = await pool.acquire({ taskId: "task-2" });
    assert.equal(pool.daemons.size, 2);

    // Acquire slot 3: capacity reached, should be enqueued
    let slot3Resolved = false;
    const slot3Promise = pool.acquire({ taskId: "task-3" }).then(slot => {
      slot3Resolved = true;
      return slot;
    });

    const statsBefore = pool.getStats();
    assert.equal(statsBefore.queueLength, 1);
    assert.equal(slot3Resolved, false);

    // Release slot 1: should immediately dequeue and resolve slot 3
    await pool.release(slot1);

    const slot3 = await slot3Promise;
    assert.ok(slot3, "Slot 3 must resolve after release");
    assert.equal(slot3Resolved, true);
    assert.equal(slot3.id, slot1.id, "Slot 3 should reuse the released container slot");
    assert.equal(pool.getStats().queueLength, 0);

    await pool.release(slot2);
    await pool.release(slot3);
  } finally {
    await pool.drain();
  }
});

test("Contract 8: Acquire timeout when pool stays exhausted", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 1,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const slot1 = await pool.acquire({ taskId: "blocking-task" });

    // Request with short timeout while pool is exhausted
    await assert.rejects(
      async () => await pool.acquire({ taskId: "will-timeout", timeoutMs: 100 }),
      (err) => {
        assert.ok(err instanceof PoolAcquireTimeoutError);
        assert.match(err.message, /Pool acquire timed out/);
        return true;
      }
    );

    await pool.release(slot1);
  } finally {
    await pool.drain();
  }
});

test("Contract 9: Active egress denial verification in warm daemon", async () => {
  // 1. Success case: returns 42 and sentinel
  const { mockExecFn: successMock } = createMockDocker();
  const poolSuccess = new ContainerSandboxPool({
    execFn: successMock,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await poolSuccess.acquire({ language: SUPPORTED_LANGUAGES.JAVASCRIPT });
    const egressRes = poolSuccess.verifyEgress(daemon);
    assert.equal(egressRes.verified, true);
    assert.equal(egressRes.exitCode, 42);
    await poolSuccess.release(daemon);
  } finally {
    await poolSuccess.drain();
  }

  // 2. Breach case: outbound connection unexpectedly succeeded (exit 0)
  const { mockExecFn: breachMock } = createMockDocker({
    onExec: (args) => {
      if (args.some(a => String(a).includes("192.0.2.1"))) {
        return { status: 0, stdout: "Connected successfully!\n" };
      }
      return { status: 0, stdout: "" };
    }
  });

  const poolBreach = new ContainerSandboxPool({
    execFn: breachMock,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await poolBreach.acquire({ language: SUPPORTED_LANGUAGES.JAVASCRIPT });
    assert.throws(
      () => poolBreach.verifyEgress(daemon),
      (err) => {
        assert.ok(err instanceof SandboxSecurityViolationError);
        assert.match(err.message, /Active egress probe succeeded/);
        return true;
      }
    );
    await poolBreach.release(daemon);
  } finally {
    await poolBreach.drain();
  }
});

test("Contract 10: Daemon health checks, crash detection, and auto-replenishment", async () => {
  let pingFails = false;
  const { mockExecFn } = createMockDocker({
    onExec: (args) => {
      if (args.includes("echo") && args.includes("ping")) {
        return pingFails ? { status: 1, stdout: "", stderr: "Connection reset by peer\n" } : { status: 0, stdout: "ping\n" };
      }
      return { status: 0, stdout: "" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    minWarm: 2,
    maxCapacity: 4,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    await pool.warmup();
    assert.equal(pool.daemons.size, 2);

    const daemon = await pool.acquire();

    // Simulate daemon crashing while acquired
    pingFails = true;

    // Release should detect crash, evict corrupted daemon, and trigger replenishment
    await pool.release(daemon);

    assert.equal(daemon.status, POOL_CONTAINER_STATES.DRAINED);
    assert.ok(pool.stats.totalEvictions >= 1);
  } finally {
    await pool.drain();
  }
});

test("Contract 11: Idle daemon reaping down to minWarm", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    minWarm: 1,
    maxCapacity: 5,
    idleTimeoutMs: 50, // 50ms idle expiration
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    // Spawn 3 daemons
    const d1 = await pool.acquire({ language: "javascript" });
    const d2 = await pool.acquire({ language: "python" });
    const d3 = await pool.acquire({ language: "go" });
    assert.equal(pool.daemons.size, 3);

    // Release all 3
    await pool.release(d1);
    await pool.release(d2);
    await pool.release(d3);

    // Manually artificially age the daemons' lastUsedAt
    const oldTime = Date.now() - 1000;
    for (const d of pool.daemons.values()) {
      d.lastUsedAt = oldTime;
    }

    // Trigger reaper
    pool.reapIdle();

    // Should reap idle containers down to minWarm (1 daemon retained)
    assert.equal(pool.daemons.size, 1);
  } finally {
    await pool.drain();
  }
});

test("Contract 12: Zero Orphan Containers guarantee on pool drain and emergency exit", async () => {
  const { mockExecFn, executedCalls, activeContainers } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    minWarm: 2,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const daemons = await pool.warmup();
  const daemonNames = daemons.map(d => d.containerName);
  assert.equal(activeContainers.size, 2);

  // Drain pool
  await pool.drain();

  // All active containers must have been destroyed with `rm -f`
  const rmCalls = executedCalls.filter(c => c.args.includes("rm") && c.args.includes("-f"));
  for (const name of daemonNames) {
    const wasRemoved = rmCalls.some(c => c.args.includes(name));
    assert.ok(wasRemoved, `Container ${name} must be removed on drain`);
  }
  assert.equal(pool.daemons.size, 0);
  assert.equal(pool.isDisposed, true);
});

test("Contract 13: PoolContainerDriver integration with BaseSandboxDriver contract", async () => {
  const { mockExecFn } = createMockDocker({
    onExec: (args) => {
      if (args.includes("node") && args.includes("-v")) {
        return { status: 0, stdout: "v20.15.0\n" };
      }
      return { status: 0, stdout: "" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const driver = new PoolContainerDriver({}, pool);
  assert.equal(driver.name, "container-pool");

  const probe = driver.probe();
  assert.equal(probe.available, true);
  assert.equal(probe.runtime, "docker");

  // Create temporary disposable repository
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-pool-driver-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Pool Test"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "pool@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "index.js"), 'console.log("driver test");\n');
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    const jail = await driver.create(tmpDir, { language: "javascript" });

    assert.ok(fs.existsSync(jail.jailPath));
    assert.equal(jail.driver, "container-pool");
    assert.equal(typeof jail.runInContainer, "function");

    // Execute in warm container
    const execRes = jail.runInContainer(["node", "-v"]);
    assert.equal(execRes.status, 0);
    assert.equal(execRes.stdout.trim(), "v20.15.0");

    // Cleanup: scrubs workspace and releases daemon
    await jail.cleanup();
    assert.equal(jail.daemon.status, POOL_CONTAINER_STATES.IDLE);
  } finally {
    await pool.drain();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 14: Truthful capabilities reporting for audit receipts", () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const caps = pool.capabilities();
  assert.equal(caps.driver, "container-pool");
  assert.equal(caps.mode, "hot-reuse");
  assert.equal(caps.filesystemIsolation, "container-hot-mount");
  assert.equal(caps.networkEgressDenial, "verified");
  assert.equal(caps.processIsolation, "warm-daemon-exec");
  assert.equal(caps.workspaceScrubbing, "enforced");
  assert.equal(caps.zeroOrphanGuaranteed, true);
  assert.equal(caps.sub150msDispatch, true);
  assert.deepEqual(caps.resourceLimits, DEFAULT_RESOURCE_LIMITS);
});

test("Contract 15: ControlledRemediationSession integration with PoolContainerDriver", () => {
  const { mockExecFn } = createMockDocker({
    onExec: (args) => {
      // Return 0 for test command execution
      return { status: 0, stdout: "TAP version 13\nok 1 - test\n1..1\n# tests 1\n# pass 1\n" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const driver = new PoolContainerDriver({}, pool);

  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-pool-session-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Pool Test"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "pool@triadflow.dev"], { cwd: tmpRepo, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpRepo, "target.js"), 'const x = 1;\n');
    execFileSync("git", ["add", "."], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpRepo, stdio: "ignore" });

    const session = new ControlledRemediationSession("FINDING-POOL-001", ["target.js"]);

    const diff = `--- a/target.js\n+++ b/target.js\n@@ -1,1 +1,1 @@\n-const x = 1;\n+const x = 2;\n`;

    session.proposeFix({ diff, rationale: "Update x value" });
    session.authorizePatch({ authorizer: { identity: "test-lead", type: "human" } });

    const jailRes = session.executeInJailWorktree(tmpRepo, {
      sandboxDriver: driver,
      testRunner: { command: "node", args: ["--test"] }
    });

    assert.equal(session.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
    assert.equal(jailRes.checkResult.exitCode, 0);
    assert.equal(jailRes.checkResult.passedCount, 1);
    assert.equal(jailRes.checkResult.failedCount, 0);
    assert.equal(jailRes.checkResult.runner, "container-runner");
    assert.equal(jailRes.checkResult.executionEnvironment, "container");

    const receipt = session.toReceipt();
    assert.ok(receipt);
    assert.equal(receipt.jail.driver, "container-pool");
    assert.equal(receipt.jail.capabilities.mode, "hot-reuse");
  } finally {
    pool.drain();
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});
