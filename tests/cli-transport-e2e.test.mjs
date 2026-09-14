/**
 * Triad-Flow End-to-End Real CLI Transport Test Suite (PR-04 / PR-05)
 *
 * Validates real OS process execution via child_process.spawn across 8 core scenarios:
 * - E2E-01: Single sentry clean review (Tier 2 small diff) -> Exit 0, Gate APPROVE.
 * - E2E-02: Heterogeneous quorum consensus (Tier 1 high-risk diff) -> Exit 1, Gate BLOCK with finding.
 * - E2E-03: Model instruction injection neutralization -> Arbitrary commands stripped, host safe.
 * - E2E-04: Process timeout and forceful kill -> Timeout status, process killed, Gate BLOCK.
 * - E2E-05: Process crash and non-zero exit code -> Captures stderr, Gate BLOCK.
 * - E2E-06: Memory flood defense (maxOutputBytes exceeded) -> Child killed, Gate BLOCK.
 * - E2E-07: Auth failure pattern detection -> AUTH_FAILURE detected, Gate BLOCK.
 * - E2E-08: Invocation via bin/triad-flow.mjs directly -> Real outer CLI invocation with spawned sentry child process.
 *
 * Enforces 0 external runtime dependencies and Windows CVE-2024-27980 safe binary execution.
 */

import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const FIXTURE_SCRIPT = path.resolve(__dirname, "fixtures", "mock-cli-sentry.mjs");
const BIN_SCRIPT = path.resolve(ROOT_DIR, "bin", "triad-flow.mjs");

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function makeChangeSet(files = [{ path: "src/calc.js", additions: 5, deletions: 1 }], hunks = "+ const a = 1;") {
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

/**
 * Creates an executable binary alias for process.execPath with symlink -> hard link -> copy fallback.
 * Ensures INV-04 / PR-05 heterogeneity requirements and bypasses Windows EINVAL for batch files.
 */
function createExecutableAlias(tempDir, aliasName, overrides = {}) {
  const isWindows = process.platform === "win32";
  const ext = isWindows ? ".exe" : "";
  const targetPath = path.join(tempDir, `${aliasName}${ext}`);

  if (fs.existsSync(targetPath)) return targetPath;

  const symlink = overrides.symlinkSync || fs.symlinkSync;
  const link = overrides.linkSync || fs.linkSync;
  const copy = overrides.copyFileSync || fs.copyFileSync;

  try {
    symlink(process.execPath, targetPath, isWindows ? "file" : undefined);
  } catch {
    try {
      link(process.execPath, targetPath);
    } catch {
      copy(process.execPath, targetPath);
      if (!isWindows) {
        fs.chmodSync(targetPath, 0o755);
      }
    }
  }

  return targetPath;
}

async function cleanupDir(dirPath, maxRetries = 5, delayMs = 100) {
  if (!dirPath || !fs.existsSync(dirPath)) return;
  for (let i = 0; i < maxRetries; i++) {
    try {
      fs.rmSync(dirPath, { recursive: true, force: true });
      return;
    } catch {
      if (i === maxRetries - 1) break;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

let tempDir;
let macroBin;
let microBin;

before(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-flow-e2e-transport-"));
  macroBin = createExecutableAlias(tempDir, "mock-agy-sentry");
  microBin = createExecutableAlias(tempDir, "mock-claude-sentry");

  // Verify fallback tiers of executable alias helper
  const fbHardlink = createExecutableAlias(tempDir, "mock-fb-hardlink", {
    symlinkSync: () => { throw new Error("EPERM: simulated symlink failure"); }
  });
  assert.equal(fs.existsSync(fbHardlink), true);
  const hlCheck = spawnSync(fbHardlink, ["-v"], { encoding: "utf8" });
  assert.equal(hlCheck.status, 0);

  const fbCopy = createExecutableAlias(tempDir, "mock-fb-copy", {
    symlinkSync: () => { throw new Error("EPERM: simulated symlink failure"); },
    linkSync: () => { throw new Error("EXDEV: simulated cross-device link failure"); }
  });
  assert.equal(fs.existsSync(fbCopy), true);
  const copyCheck = spawnSync(fbCopy, ["-v"], { encoding: "utf8" });
  assert.equal(copyCheck.status, 0);
});

after(async () => {
  await new Promise(r => setTimeout(r, 100));
  await cleanupDir(tempDir);
});

test("E2E-01: Single sentry clean review (Tier 2 small diff) -> Exit 0, Gate APPROVE", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--clean`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet }
  );

  assert.equal(exitCode, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Scale Routing: Mode = SINGLE/i);
  assert.match(stderr.buffer, /Consensus Verdict: APPROVE/i);
  assert.match(stderr.buffer, /Gate Decision: APPROVE/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "reviewed-clean");
  assert.equal(report.gate.decision, "approve");
  assert.equal(report.findings.total, 0);
  assert.equal(report.findings.blocking, 0);

  // 2. Verify via direct CliReviewAdapter
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--clean"]
  });
  const directRes = await adapter.executeReview({
    runId: "e2e-clean-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });
  assert.equal(directRes.ok, true);
  assert.equal(directRes.executionStatus, EXECUTION_STATUS.EMPTY);
  assert.deepEqual(directRes.findings, []);
});

test("E2E-02: Heterogeneous quorum consensus (Tier 1 high-risk diff) -> Exit 1, Gate BLOCK with finding", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  // Tier 1 critical path triggers hierarchical swarm dispatch
  const changeSet = makeChangeSet([{ path: "src/auth/jwt.ts", additions: 10, deletions: 2 }]);

  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--clean`,
      `--micro-cmd=${microBin}`,
      `--micro-args=${FIXTURE_SCRIPT},--finding`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Scale Routing: Mode = HIERARCHICAL/i);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Found 1 critical\/high severity findings/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "reviewed-with-findings");
  assert.equal(report.gate.decision, "block");
  assert.equal(report.findings.total, 1);
  assert.equal(report.findings.blocking, 1);
  assert.match(report.findings.findingKeys[0], /src\/auth\/jwt\.ts/);
  assert.match(report.findings.findingKeys[0], /Unverified Signature/);

  // 2. Direct transport verification with finding
  const adapter = new CliReviewAdapter({
    command: microBin,
    args: [FIXTURE_SCRIPT, "--finding"]
  });
  const directRes = await adapter.executeReview({
    runId: "e2e-finding-direct",
    role: "micro",
    changeSet,
    policyId: "STRICT_HETEROGENEOUS"
  });
  assert.equal(directRes.ok, true);
  assert.equal(directRes.executionStatus, EXECUTION_STATUS.SUCCESS);
  assert.equal(directRes.findings.length, 1);
  assert.equal(directRes.findings[0].title, "Unverified Signature");
});

test("E2E-03: Model instruction injection neutralization -> Arbitrary commands stripped, host safe", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli full execution
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--injection`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet }
  );

  assert.equal(exitCode, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Gate Decision: APPROVE/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "reviewed-clean");
  assert.equal(report.gate.decision, "approve");
  // Hostile command keys must be stripped by Default-Deny
  assert.equal("command" in report, false);
  assert.equal("shell" in report, false);
  assert.equal("execute" in report, false);
  assert.equal("command" in report.consensus, false);
  assert.equal("execute" in report.consensus, false);

  // 2. Verify directly on CliReviewAdapter layer
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--injection"]
  });

  const adapterRes = await adapter.executeReview({
    runId: "e2e-injection-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(adapterRes.ok, true);
  assert.equal("command" in adapterRes, false);
  assert.equal("shell" in adapterRes, false);
  assert.equal("execute" in adapterRes, false);
});

test("E2E-04: Process timeout and forceful kill -> Timeout status, process killed, Gate BLOCK", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli with low timeout
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--hang`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet, timeoutMs: 400 }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Quorum Failure/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "incomplete");
  assert.equal(report.gate.decision, "block");
  assert.equal(report.providers[0].executionStatus, EXECUTION_STATUS.TIMEOUT);

  // 2. Direct transport execution check
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--hang"]
  });

  const res = await adapter.executeReview({
    runId: "e2e-timeout-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY",
    timeoutMs: 300
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.TIMEOUT);
});

test("E2E-05: Process crash and non-zero exit code -> Captures stderr, Gate BLOCK", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--crash`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Quorum Failure/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "incomplete");
  assert.equal(report.gate.decision, "block");
  assert.equal(report.providers[0].executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(report.consensus.consensusProof, /Quorum Failure/i);

  // 2. Direct adapter execution check captures non-zero code & stderr
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--crash"]
  });

  const res = await adapter.executeReview({
    runId: "e2e-crash-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /137/);
  assert.match(res.error, /Fatal crash: unexpected termination/);
});

test("E2E-06: Memory flood defense (maxOutputBytes exceeded) -> Child killed, Gate BLOCK", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli with output limit
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--flood`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet, limits: { maxOutputBytes: 10 * 1024 } }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "incomplete");
  assert.equal(report.gate.decision, "block");
  assert.equal(report.providers[0].executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE);
  assert.match(report.consensus.consensusProof, /Quorum Failure/i);

  // 2. Direct adapter execution check
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--flood"]
  });

  const res = await adapter.executeReview({
    runId: "e2e-flood-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY",
    limits: { maxOutputBytes: 10 * 1024 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE);
  assert.match(res.error, /payload_too_large/);
});

test("E2E-07: Auth failure pattern detection -> AUTH_FAILURE detected, Gate BLOCK", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const changeSet = makeChangeSet([{ path: "src/calc.js", additions: 5, deletions: 1 }]);

  // 1. Verify via runCli
  const exitCode = await runCli(
    [
      "review",
      `--macro-cmd=${macroBin}`,
      `--macro-args=${FIXTURE_SCRIPT},--auth-fail`,
      "--format=json"
    ],
    { stdout, stderr },
    { getChangeSet: () => changeSet }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "incomplete");
  assert.equal(report.gate.decision, "block");
  assert.equal(report.providers[0].executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
  assert.match(report.consensus.consensusProof, /Quorum Failure/i);

  // 2. Direct adapter execution check
  const adapter = new CliReviewAdapter({
    command: macroBin,
    args: [FIXTURE_SCRIPT, "--auth-fail"]
  });

  const res = await adapter.executeReview({
    runId: "e2e-auth-direct",
    role: "macro",
    changeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
  assert.match(res.error, /Authentication failure detected/i);
  assert.match(res.error, /You are not logged into Antigravity/i);
});

test("E2E-08: Invocation via bin/triad-flow.mjs directly -> Real outer CLI invocation with spawned sentry child process", async () => {
  const repoDir = path.join(tempDir, "e2e-08-repo");
  fs.mkdirSync(repoDir, { recursive: true });

  spawnSync("git", ["init"], { cwd: repoDir });
  spawnSync("git", ["config", "user.name", "E2E Tester"], { cwd: repoDir });
  spawnSync("git", ["config", "user.email", "e2e@triad-flow.org"], { cwd: repoDir });

  fs.mkdirSync(path.join(repoDir, "src", "auth"), { recursive: true });
  fs.writeFileSync(path.join(repoDir, "src", "auth", "token.js"), "export const token = 'initial';\n", "utf8");
  spawnSync("git", ["add", "."], { cwd: repoDir });
  spawnSync("git", ["commit", "-m", "initial commit"], { cwd: repoDir });

  fs.writeFileSync(path.join(repoDir, "src", "auth", "token.js"), "export const token = 'updated';\n", "utf8");
  spawnSync("git", ["add", "."], { cwd: repoDir });

  const reportFile = path.join(repoDir, "audit-run.json");

  const res = spawnSync(process.execPath, [
    BIN_SCRIPT,
    "review",
    "--staged",
    `--macro-cmd=${macroBin}`,
    `--macro-args=${FIXTURE_SCRIPT},--clean`,
    `--micro-cmd=${microBin}`,
    `--micro-args=${FIXTURE_SCRIPT},--clean`,
    `--report=${reportFile}`,
    "--format=json"
  ], {
    cwd: repoDir,
    encoding: "utf-8",
    timeout: 15000
  });

  assert.equal(res.status, 0, `CLI exited with ${res.status}: ${res.stderr}`);
  assert.equal(fs.existsSync(reportFile), true);

  const stdoutReport = JSON.parse(res.stdout);
  assert.equal(stdoutReport.schemaVersion, "1.0.0");
  assert.equal(stdoutReport.status, "reviewed-clean");
  assert.equal(stdoutReport.gate.decision, "approve");
  assert.equal(stdoutReport.policy.id, "STRICT_HETEROGENEOUS");

  const fileReport = JSON.parse(fs.readFileSync(reportFile, "utf8"));
  assert.equal(fileReport.schemaVersion, "1.0.0");
  assert.equal(fileReport.status, "reviewed-clean");
  assert.equal(fileReport.gate.decision, "approve");
  assert.equal(fileReport.routing.mode, "hierarchical");
});
