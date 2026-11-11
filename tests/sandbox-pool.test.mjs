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
  ContainerOrphanReconciler,
  reconcileOrphanContainers,
  POOL_CONTAINER_LABELS,
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
  BaseSandboxDriver,
  resolveSandboxDriver,
  SANDBOX_DRIVERS
} from "../src/core/sandbox-driver.mjs";

import {
  ControlledRemediationSession,
  REMEDIATION_STATES
} from "../src/core/controlled-remediation.mjs";

import {
  BatchRemediationSession
} from "../src/core/batch-remediation.mjs";

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
      assert.ok(call.args.some(a => String(a).includes("triad-flow-pool=true")), "Must include label triad-flow-pool=true");
      assert.ok(call.args.some(a => String(a).includes("triad-flow-pool-id=")), "Must include label triad-flow-pool-id");
      assert.ok(call.args.some(a => String(a).includes("triad-flow-created-at=")), "Must include label triad-flow-created-at");
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

test("Contract 16: Background Container Reconciler scans and reclaims expired orphan containers by label & TTL", () => {
  const removedContainers = [];
  const now = Date.now();
  const expiredTime = now - 3700000; // 1 hour + 100s ago (TTL expired)
  const freshTime = now - 10000; // 10s ago (fresh)

  const mockPsOutput = [
    `c101\ttf-pool-old-js-1\ttriad-flow-pool=true,triad-flow-pool-id=oldpool,triad-flow-created-at=${expiredTime},triad-flow-ttl-ms=1800000\tUp 1 hour\t1 hour ago`,
    `c102\ttf-pool-active-py-2\ttriad-flow-pool=true,triad-flow-pool-id=activepool,triad-flow-created-at=${freshTime},triad-flow-ttl-ms=1800000\tUp 10 seconds\t10 seconds ago`,
    `c103\ttf-pool-dead-go-3\ttriad-flow-pool=true,triad-flow-pool-id=otherpool,triad-flow-created-at=${freshTime},triad-flow-ttl-ms=1800000\tExited (137) 5 seconds ago\t5 seconds ago`
  ].join("\n");

  const mockExecFn = (cmd, args = []) => {
    if (args.includes("ps")) {
      return { status: 0, stdout: mockPsOutput, stderr: "" };
    }
    if (args.includes("rm")) {
      const target = args[args.length - 1];
      removedContainers.push(target);
      return { status: 0, stdout: `${target}\n`, stderr: "" };
    }
    return { status: 0, stdout: "" };
  };

  const reconciler = new ContainerOrphanReconciler({
    runtime: "docker",
    execFn: mockExecFn,
    poolId: "activepool"
  });

  const res = reconciler.reconcile();
  assert.equal(res.scanned, 3);
  // c101 (expired TTL) and c103 (exited/dead) must be reclaimed; c102 (fresh & up) must be preserved
  assert.equal(res.reclaimed, 2);
  assert.ok(removedContainers.includes("tf-pool-old-js-1") || removedContainers.includes("c101"));
  assert.ok(removedContainers.includes("tf-pool-dead-go-3") || removedContainers.includes("c103"));
  assert.ok(!removedContainers.includes("tf-pool-active-py-2"));
  assert.ok(!removedContainers.includes("c102"));
});

test("Contract 17: Background Container Reconciler cleans orphaned host workspace directories in os.tmpdir()", () => {
  const tmpDir = os.tmpdir();
  const orphanWsDir = path.join(tmpDir, `tf-pool-ws-orphan-${Date.now()}-slot1`);
  fs.mkdirSync(orphanWsDir, { recursive: true });
  fs.writeFileSync(path.join(orphanWsDir, "garbage.txt"), "leftover from crashed process");
  assert.ok(fs.existsSync(orphanWsDir));

  // Set mtime to 2 hours ago to guarantee TTL expiration
  const twoHoursAgo = new Date(Date.now() - 7200000);
  fs.utimesSync(orphanWsDir, twoHoursAgo, twoHoursAgo);

  const mockExecFn = (cmd, args = []) => {
    if (args.includes("ps")) return { status: 0, stdout: "", stderr: "" };
    return { status: 0, stdout: "" };
  };

  const reconciler = new ContainerOrphanReconciler({
    runtime: "docker",
    execFn: mockExecFn,
    ttlMs: 3600000
  });

  const res = reconciler.reconcile({ sweepWorkspaces: true });
  assert.ok(!fs.existsSync(orphanWsDir), "Orphaned workspace directory must be swept and deleted");
  assert.ok(res.reclaimedWorkspaces.some(w => orphanWsDir.includes(w)));
});

test("Contract 18: forceReleaseByTaskId immediately cleans and releases/scrubs container slot or queued task", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 1,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const daemon = await pool.acquire({ taskId: "task-stuck-123" });
    assert.equal(daemon.currentTaskId, "task-stuck-123");
    assert.equal(daemon.status, POOL_CONTAINER_STATES.BUSY);

    // Write file in workspace to verify scrub
    fs.writeFileSync(path.join(daemon.hostWorkspaceDir, "file.txt"), "hello");

    const released = pool.forceReleaseByTaskId("task-stuck-123", { scrub: true });
    assert.equal(released, true);
    assert.equal(daemon.status, POOL_CONTAINER_STATES.IDLE);
    assert.equal(daemon.currentTaskId, null);
    assert.deepEqual(fs.readdirSync(daemon.hostWorkspaceDir), []);

    // Non-existent task returns false
    assert.equal(pool.forceReleaseByTaskId("no-such-task"), false);
  } finally {
    await pool.drain();
  }
});

test("Contract 19: acquire with AbortSignal aborts gracefully without slot leakage", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 1,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const d1 = await pool.acquire({ taskId: "d1" });

    // Try acquiring d2 with an AbortSignal that aborts after 50ms
    const controller = new AbortController();
    setTimeout(() => controller.abort(new Error("Circuit breaker tripped")), 50);

    await assert.rejects(
      async () => await pool.acquire({ taskId: "d2", signal: controller.signal, timeoutMs: 5000 }),
      /aborted/i
    );

    // Queue must be empty after abort
    assert.equal(pool.getStats().queueLength, 0);

    // Release d1
    await pool.release(d1);
    assert.equal(pool.getStats().busyDaemons, 0);
  } finally {
    await pool.drain();
  }
});

test("Contract 20: executeAsync streams output and respects execution timeout", async () => {
  const pool = new ContainerSandboxPool({
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const mockDaemon = new ContainerDaemon({
    id: "async-slot-1",
    containerName: "tf-mock-async-daemon",
    status: POOL_CONTAINER_STATES.IDLE
  });
  pool.daemons.set(mockDaemon.id, mockDaemon);

  // Use custom execAsyncFn to simulate async execution
  const res = await pool.executeAsync(mockDaemon, ["echo", "hello"], {
    execAsyncFn: async (daemon, args) => {
      return {
        status: 0,
        exitCode: 0,
        stdout: "async-hello\n",
        stderr: "",
        timedOut: false,
        durationMs: 4,
        containerName: daemon.containerName
      };
    }
  });

  assert.equal(res.exitCode, 0);
  assert.equal(res.stdout.trim(), "async-hello");
  assert.equal(res.timedOut, false);
});

test("Contract 21: Machine verification of vulnerability causal features (forbidden, required, exitCode)", () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-causal-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Causal Test"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "causal@triadflow.dev"], { cwd: tmpRepo, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpRepo, "service.js"), 'const port = 8080;\n');
    execFileSync("git", ["add", "."], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpRepo, stdio: "ignore" });

    const session = new ControlledRemediationSession("FINDING-CAUSAL-01", ["service.js"]);
    session.proposeFix({
      diff: "--- a/service.js\n+++ b/service.js\n@@ -1,1 +1,1 @@\n-const port = 8080;\n+const port = 8081;\n",
      rationale: "Change port"
    });
    session.authorizePatch({ authorizer: { identity: "security-auditor", type: "human" } });

    // 1. Runner where forbidden pattern appears (vulnerability symptom reproduces)
    const failingRunner = {
      command: "node",
      args: ["-e", "console.error('CRITICAL_VULNERABILITY_LEAK: token_123')"],
      causalFeatures: {
        forbiddenPatterns: ["CRITICAL_VULNERABILITY_LEAK"],
        expectedExitCode: 0
      }
    };

    const jailResFail = session.executeInJailWorktree(tmpRepo, {
      testRunner: failingRunner
    });

    assert.equal(jailResFail.checkResult.regressionDetected, true, "Regression must be flagged when forbidden causal pattern is detected");
    assert.equal(jailResFail.checkResult.causalVerification.verified, false);
    assert.deepEqual(jailResFail.checkResult.causalVerification.matchedForbidden, ["CRITICAL_VULNERABILITY_LEAK"]);
    assert.equal(session.status, REMEDIATION_STATES.REJECTED_FIX);

    // 2. Successful runner meeting affirmative causal proof
    const successSession = new ControlledRemediationSession("FINDING-CAUSAL-02", ["service.js"]);
    successSession.proposeFix({
      diff: "--- a/service.js\n+++ b/service.js\n@@ -1,1 +1,1 @@\n-const port = 8080;\n+const port = 8081;\n",
      rationale: "Change port"
    });
    successSession.authorizePatch({ authorizer: { identity: "security-auditor", type: "human" } });

    const passingRunner = {
      command: "node",
      args: ["-e", "console.log('TF_REMEDIATION_PROOF_AFFIRMED: safe')"],
      causalFeatures: {
        requiredPatterns: ["TF_REMEDIATION_PROOF_AFFIRMED"],
        expectedExitCode: 0
      }
    };

    const jailResPass = successSession.executeInJailWorktree(tmpRepo, {
      testRunner: passingRunner
    });

    assert.equal(jailResPass.checkResult.regressionDetected, false);
    assert.equal(jailResPass.checkResult.causalVerification.verified, true);
    assert.equal(successSession.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test("Contract 22: resolveSandboxDriver seamlessly resolves pool and container-pool", () => {
  const { mockExecFn } = createMockDocker();

  // Test 'container-pool'
  const driver1 = resolveSandboxDriver("container-pool", {
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });
  assert.equal(driver1.name, "container-pool");
  assert.equal(driver1.driverType, "container-pool");

  // Test alias 'pool'
  const driver2 = resolveSandboxDriver("pool", {
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });
  assert.equal(driver2.name, "container-pool");

  // Verify capabilities include hot-reuse and zeroOrphanGuaranteed
  const caps = driver1.capabilities();
  assert.equal(caps.mode, "hot-reuse");
  assert.equal(caps.zeroOrphanGuaranteed, true);
});

test("Contract 23: Batch remediation with PoolContainerDriver verifies multi-task hot reuse and scrub-on-release", () => {
  const { mockExecFn } = createMockDocker({
    onExec: (args) => {
      return { status: 0, stdout: "ok\n" };
    }
  });

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  const driver = new PoolContainerDriver({}, pool);

  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-batch-pool-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Batch Pool Test"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "batch@triadflow.dev"], { cwd: tmpRepo, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpRepo, "fileA.js"), 'const a = 1;\n');
    fs.writeFileSync(path.join(tmpRepo, "fileB.js"), 'const b = 1;\n');
    execFileSync("git", ["add", "."], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpRepo, stdio: "ignore" });

    const batch = new BatchRemediationSession("BATCH-POOL-001", [
      { id: "FINDING-A", targetFiles: ["fileA.js"], severity: "high" },
      { id: "FINDING-B", targetFiles: ["fileB.js"], severity: "medium" }
    ]);

    const sessA = batch.getSession("FINDING-A");
    sessA.proposeFix({ diff: "--- a/fileA.js\n+++ b/fileA.js\n@@ -1,1 +1,1 @@\n-const a = 1;\n+const a = 2;\n", rationale: "Fix A" });
    sessA.authorizePatch({ authorizer: { identity: "lead", type: "human" } });

    const sessB = batch.getSession("FINDING-B");
    sessB.proposeFix({ diff: "--- a/fileB.js\n+++ b/fileB.js\n@@ -1,1 +1,1 @@\n-const b = 1;\n+const b = 2;\n", rationale: "Fix B" });
    sessB.authorizePatch({ authorizer: { identity: "lead", type: "human" } });

    const batchResult = batch.executeBatchInJailWorktree(tmpRepo, {
      sandboxDriver: driver,
      testRunner: { command: "node", args: ["--version"] }
    });

    assert.equal(batchResult.executionResults.length, 2);
    assert.ok(batchResult.executionResults.every(r => r.testsPassed));
    assert.ok(batchResult.executionResults.every(r => r.applied));

    const receipt = batch.toBatchReceipt();
    assert.ok(receipt);
    assert.equal(receipt.sandbox.driver, "container-pool");
    assert.equal(receipt.sandbox.capabilities.mode, "hot-reuse");
    assert.equal(receipt.sandbox.capabilities.zeroOrphanGuaranteed, true);
  } finally {
    pool.drain();
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test("Contract 24: Reconciler reclaims dead/exited containers in active pool, handles Podman map labels, and cleans leading slashes", () => {
  const reclaimedContainers = [];
  const mockExec = (cmd, args) => {
    if (args.includes("ps")) {
      return {
        status: 0,
        stdout: [
          // Podman style map[...] labels with leading slash in name and dead status
          `c-dead-1\t/tf-active-dead-container\tmap[triad-flow-pool:true triad-flow-pool-id:pool-999 triad-flow-slot-id:s1]\tExited (137) 2 minutes ago\t2026-11-11T12:00:00Z`,
          // Docker style labels with leading slash in name
          `c-orphan-2\t/tf-old-orphan\ttriad-flow-pool=true,triad-flow-pool-id=other-pool,triad-flow-created-at=${Date.now() - 5000000},triad-flow-ttl-ms=1000\tUp 1 hour\t`
        ].join("\n")
      };
    }
    if (args.includes("rm")) {
      reclaimedContainers.push(args[args.length - 1]);
      return { status: 0, stdout: "" };
    }
    return { status: 0, stdout: "" };
  };

  const activeDaemon = new ContainerDaemon({
    id: "s1",
    containerName: "tf-active-dead-container",
    status: POOL_CONTAINER_STATES.IDLE
  });
  const daemons = new Map([["s1", activeDaemon]]);

  const reconciler = new ContainerOrphanReconciler({
    execFn: mockExec,
    poolId: "pool-999",
    ttlMs: 60000
  });

  const res = reconciler.reconcile({ activeDaemons: daemons, sweepWorkspaces: false });

  assert.equal(res.scanned, 2);
  assert.equal(res.reclaimed, 2);
  // Must clean leading slashes when passing to docker rm
  assert.ok(reclaimedContainers.includes("tf-active-dead-container"));
  assert.ok(reclaimedContainers.includes("tf-old-orphan"));
  // Active daemon must be marked as crashed
  assert.equal(activeDaemon.status, POOL_CONTAINER_STATES.CRASHED);
});

test("Contract 25: Queued acquire strictly respects runtime language compatibility on daemon release", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 1,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    // Acquire the only slot with javascript
    const dJs = await pool.acquire({ language: SUPPORTED_LANGUAGES.JAVASCRIPT });
    assert.equal(dJs.language, SUPPORTED_LANGUAGES.JAVASCRIPT);

    // Queue an acquire for PYTHON while pool is at capacity (maxCapacity = 1)
    let pythonResolved = false;
    let pythonDaemon = null;
    const pythonPromise = pool.acquire({ language: SUPPORTED_LANGUAGES.PYTHON, timeoutMs: 500 }).then(d => {
      pythonResolved = true;
      pythonDaemon = d;
      return d;
    });

    // Release the JavaScript daemon. It must NOT be given to the Python request!
    await pool.release(dJs);

    // Python request should NOT be resolved with JavaScript daemon
    assert.equal(pythonResolved, false, "JavaScript daemon must not be handed to a Python acquire request");
    assert.equal(dJs.status, POOL_CONTAINER_STATES.IDLE);

    // Now drain and clean up
    await assert.rejects(async () => await pythonPromise, /timed out/i);
  } finally {
    await pool.drain();
  }
});

test("Contract 26: PoolContainerDriver fails closed on image switching, cleans up on acquire error, and supports runInContainerAsync", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 1,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });
  const driver = new PoolContainerDriver({}, pool);
  assert.equal(driver.runtime, "docker");

  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "tf-driver-cleanup-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Driver Test"], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "driver@triadflow.dev"], { cwd: tmpRepo, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpRepo, "index.js"), 'console.log("ok");\n');
    execFileSync("git", ["add", "."], { cwd: tmpRepo, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpRepo, stdio: "ignore" });

    // 1. Successful creation and runInContainerAsync
    const jail = driver.create(tmpRepo);
    assert.ok(typeof jail.runInContainerAsync === "function");

    // Switching image on warm daemon must fail closed
    assert.throws(
      () => jail.runInContainer(["echo", "hi"], { image: "different-image:latest" }),
      /Cannot switch container image/
    );

    jail.cleanup();

    // 2. Fail-closed on acquire failure: fill capacity then attempt another create
    const d1 = await pool.acquire();
    assert.throws(
      () => driver.create(tmpRepo),
      /capacity exhausted/i
    );
    await pool.release(d1);
  } finally {
    await pool.drain();
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test("Contract 27: forceReleaseByTaskId sweeps multiple matching slots and queued requests", async () => {
  const { mockExecFn } = createMockDocker();
  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    maxCapacity: 2,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  try {
    const d1 = await pool.acquire({ taskId: "batch-task-shared" });
    const d2 = await pool.acquire({ taskId: "batch-task-shared" });

    assert.equal(d1.currentTaskId, "batch-task-shared");
    assert.equal(d2.currentTaskId, "batch-task-shared");

    const released = pool.forceReleaseByTaskId("batch-task-shared");
    assert.equal(released, true);
    assert.equal(d1.status, POOL_CONTAINER_STATES.IDLE);
    assert.equal(d2.status, POOL_CONTAINER_STATES.IDLE);
    assert.equal(d1.currentTaskId, null);
    assert.equal(d2.currentTaskId, null);
  } finally {
    await pool.drain();
  }
});

