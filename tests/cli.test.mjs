import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const isWin = process.platform === "win32";
const npmCmd = isWin ? "npm.cmd" : "npm";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

test("runCli 'doctor' succeeds with EXIT_CODES.SUCCESS and accurate capabilities", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["doctor"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Doctor/i);
  assert.match(stderr.buffer, /Deterministic Safety Core: Loaded/i);
});

test("runCli 'demo' runs simulated cycle with EXIT_CODES.SUCCESS", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["demo"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /\[DEMO \/ SIMULATION MODE\]/i);
});

test("runCli 'review' outside git repository returns EXIT_CODES.SYSTEM_FAILURE (Exit Code 3) (P0-02)", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockFailedGitState = {
    ok: false,
    error: { code: "NOT_A_GIT_REPO", message: "fatal: not a git repository" }
  };

  const code = await runCli(["review"], { stdout, stderr }, { getGitState: () => mockFailedGitState });
  assert.equal(code, EXIT_CODES.SYSTEM_FAILURE);
  assert.match(stderr.buffer, /\[FATAL SYSTEM FAILURE\]/i);
});

test("runCli 'review' on clean repo returns EXIT_CODES.SUCCESS with No-op", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockCleanGitState = { ok: true, files: [] };

  const code = await runCli(["review"], { stdout, stderr }, { getGitState: () => mockCleanGitState });
  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /\[No Changes\].*No files to review/i);
});

test("runCli 'review' with changes and unconfigured sentries fails closed with EXIT_CODES.GATE_BLOCKED", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockChangedGitState = {
    ok: true,
    files: [{ path: "src/auth/jwt.ts", additions: 10, deletions: 2 }]
  };

  const code = await runCli(["review"], { stdout, stderr }, { getGitState: () => mockChangedGitState });
  assert.equal(code, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Consensus Verdict: ERROR/i);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
});

test("runCli 'factory' fails closed safely with EXIT_CODES.GATE_BLOCKED when unconfigured", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["factory"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Unconfigured Factory Adapters/i);
});

test("runCli unknown command returns EXIT_CODES.USAGE_ERROR (Exit Code 2)", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["unknown-command"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Usage: triad-flow/i);
});

test("Repository npm scripts execute real CLI entrypoint and produce output (P0-01, EVID-03)", () => {
  // 1. npm run doctor
  const docRes = spawnSync(npmCmd, ["run", "doctor"], {
    cwd: ROOT_DIR,
    encoding: "utf-8",
    shell: isWin
  });
  assert.equal(docRes.status, 0);
  assert.match(docRes.stderr + docRes.stdout, /Triad-Flow.*Doctor|Deterministic Safety Core/i);

  // 2. npm run demo
  const demoRes = spawnSync(npmCmd, ["run", "demo"], {
    cwd: ROOT_DIR,
    encoding: "utf-8",
    shell: isWin
  });
  assert.equal(demoRes.status, 0);
  assert.match(demoRes.stderr + demoRes.stdout, /\[DEMO \/ SIMULATION MODE\]/i);

  // 3. npm run factory (unconfigured fails closed)
  const factoryRes = spawnSync(npmCmd, ["run", "factory"], {
    cwd: ROOT_DIR,
    encoding: "utf-8",
    shell: isWin
  });
  assert.equal(factoryRes.status, 1);
  assert.match(factoryRes.stderr + factoryRes.stdout, /Unconfigured Factory Adapters/i);
});

test("runCli rejects unsupported options like --invalid-flag with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["review", "--invalid-flag"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Unsupported option/i);
});

test("runCli rejects --head without --base with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["review", "--head=HEAD"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /requires '--base <ref>'/i);
});

test("runCli review rejects unresolvable --base with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["review", "--base=nonexistent_ref_99999"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /invalid or cannot be resolved/i);
});

test("runCli review emits SARIF with failed invocations when blocked", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockChangedGitState = {
    ok: true,
    files: [{ path: "src/auth/jwt.ts", additions: 10, deletions: 2 }]
  };

  const code = await runCli(["review", "--format=sarif"], { stdout, stderr }, { getGitState: () => mockChangedGitState });
  assert.equal(code, EXIT_CODES.GATE_BLOCKED);
  const sarif = JSON.parse(stdout.buffer);
  assert.equal(sarif.runs[0].results.length, 0);
  assert.ok(sarif.runs[0].invocations);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
});

test("runCli rejects --base followed by unknown flag like --bogus with EXIT_CODES.USAGE_ERROR without invoking git", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  let getGitCalled = false;
  const code = await runCli(["review", "--base", "--bogus"], { stdout, stderr }, {
    getGitState: () => {
      getGitCalled = true;
      return { ok: true, files: [] };
    }
  });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.equal(getGitCalled, false);
  assert.match(stderr.buffer, /Unsupported option\(s\): --bogus/i);
});

test("runCli rejects bare --base without ref argument with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["review", "--base"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Option '--base' requires a <ref> argument/i);
});

test("runCli rejects --report followed by unknown flag with EXIT_CODES.USAGE_ERROR without creating file", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["review", "--report", "--bogus"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Unsupported option\(s\): --bogus/i);
});
