/**
 * Review Adapter Wiring Verification Test Suite (V1-V7)
 *
 * Verifies end-to-end wiring of --macro-cmd, --micro-cmd, --macro-args, and --micro-args
 * into review orchestration, scale routing, fail-closed heterogeneity checks,
 * and error handling without spawning external processes.
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function makeChangeSet(files = [{ path: "src/sample.js", additions: 10, deletions: 2 }], hunks = "+ const a = 1;") {
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

// V1: 未帶任何新旗標 -> 行為與現況完全相同：INCOMPLETE、閘門 blocked（回歸保護）
test("V1: 未帶任何新旗標時維持 INCOMPLETE 與 blocked 回歸保護", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const exitCode = await runCli(["review"], { stdout, stderr }, {
    getChangeSet: () => changeSet
  });

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Consensus Verdict: ERROR/i);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Quorum Failure/i);
});

// V2: 帶 macro 與 micro 兩個不同指令，小改動 (plan.mode === 'single') -> 走單哨兵路徑，實際叫起其中一支 CLI
test("V2: 帶 macro 與 micro 不同指令於小改動時走單哨兵路徑且支援自訂 args", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const execCalls = [];
  const mockExec = async ({ command, args, prompt, input }) => {
    execCalls.push({ command, args, role: input.role });
    return {
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
      })
    };
  };

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex",
      "--macro-args=--print,-p"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: mockExec
    }
  );

  assert.equal(exitCode, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Scale Routing: Mode = SINGLE/i);
  assert.match(stderr.buffer, /Gate Decision: APPROVE/i);

  // Exactly one sentry called in single mode
  assert.equal(execCalls.length, 1);
  assert.equal(execCalls[0].command, "claude");
  assert.equal(execCalls[0].role, "macro");
  // Custom args passed correctly
  assert.equal(execCalls[0].args[0], "--print");
  assert.equal(execCalls[0].args[1], "-p");

  // Space-separated argument test
  const stdout2 = new MockStream();
  const stderr2 = new MockStream();
  const execCalls2 = [];
  const mockExec2 = async ({ command, args, prompt, input }) => {
    execCalls2.push({ command, args, role: input.role });
    return {
      stdout: JSON.stringify({ findings: [] })
    };
  };

  const exitCode2 = await runCli(
    [
      "review",
      "--macro-cmd", "claude",
      "--micro-cmd", "codex",
      "--micro-args", "--json,--quiet"
    ],
    { stdout: stdout2, stderr: stderr2 },
    {
      getChangeSet: () => changeSet,
      execFn: mockExec2
    }
  );

  assert.equal(exitCode2, EXIT_CODES.SUCCESS);
  assert.equal(execCalls2.length, 1);
});

// V3: 帶 macro 與 micro 兩個不同指令，大改動/高風險 (plan.mode === 'hierarchical') -> 兩支 CLI 併發執行
test("V3: 帶 macro 與 micro 不同指令於高風險改動時兩支 CLI 併發執行並依 STRICT_HETEROGENEOUS 判定", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  // Tier 1 Auth file routes to hierarchical mode
  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.ts", additions: 45, deletions: 10 }
  ]);

  const execCalls = [];
  const mockExec = async ({ command, args, input }) => {
    execCalls.push({ command, role: input.role });
    return {
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/auth/jwt.ts"], omittedFiles: [] }
      })
    };
  };

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex",
      "--format=json"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: mockExec
    }
  );

  assert.equal(exitCode, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Scale Routing: Mode = HIERARCHICAL/i);
  assert.match(stderr.buffer, /Gate Decision: APPROVE/i);

  // Both sentries must have executed
  assert.equal(execCalls.length, 2);
  const commandsCalled = execCalls.map(c => c.command).sort();
  assert.deepEqual(commandsCalled, ["claude", "codex"]);

  // Report JSON verification
  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "reviewed-clean");
  assert.equal(report.policy.id, "STRICT_HETEROGENEOUS");
  assert.equal(report.providers.length, 2);

  // Subcase: Heterogeneous quorum blocks when one sentry finds a critical flaw
  const stdout3 = new MockStream();
  const stderr3 = new MockStream();
  const mockExecWithFinding = async ({ command, input }) => {
    if (input.role === "micro") {
      return {
        stdout: JSON.stringify({
          findings: [
            {
              title: "Broken Signature Check",
              severity: "critical",
              file: "src/auth/jwt.ts",
              line_start: 30,
              line_end: 30
            }
          ]
        })
      };
    }
    return { stdout: JSON.stringify({ findings: [] }) };
  };

  const exitCode3 = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--micro-cmd=codex"
    ],
    { stdout: stdout3, stderr: stderr3 },
    {
      getChangeSet: () => changeSet,
      execFn: mockExecWithFinding
    }
  );

  assert.equal(exitCode3, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr3.buffer, /Gate Decision: BLOCK/i);
});

// V4: 只帶 macro 一個指令，高風險改動 -> 仍為 incomplete + blocked (fail-closed 不得被繞過)
test("V4: 高風險改動僅帶 macro 單一指令時 fail-closed 保持 incomplete 與 blocked", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.ts", additions: 35, deletions: 8 }
  ]);

  const execCalls = [];
  const mockExec = async ({ command, input }) => {
    execCalls.push({ command, role: input.role });
    return {
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/auth/jwt.ts"], omittedFiles: [] }
      })
    };
  };

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=claude",
      "--format=json"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: mockExec
    }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Scale Routing: Mode = HIERARCHICAL/i);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Consensus Verdict: ERROR/i);

  // Active macro ran, but missing micro caused quorum failure
  assert.equal(execCalls.length, 1);
  assert.equal(execCalls[0].command, "claude");
  assert.equal(execCalls[0].role, "macro");

  const report = JSON.parse(stdout.buffer);
  assert.equal(report.status, "incomplete");
  assert.equal(report.gate.decision, "block");
  assert.match(report.gate.reason, /Quorum Failure/i);
  assert.equal(report.providers.length, 1);
  assert.equal(report.providers[0].role, "macro");
});

// V5: macro 與 micro 帶相同指令 -> 以 USAGE ERROR 拒絕，不執行審查
test("V5: macro 與 micro 帶相同指令以 USAGE ERROR 拒絕且不執行審查", async () => {
  let changeSetCalled = false;
  const getChangeSet = () => {
    changeSetCalled = true;
    return makeChangeSet();
  };

  // Format 1: --key=value
  const stdout1 = new MockStream();
  const stderr1 = new MockStream();
  const code1 = await runCli(
    ["review", "--macro-cmd=claude", "--micro-cmd=claude"],
    { stdout: stdout1, stderr: stderr1 },
    { getChangeSet }
  );
  assert.equal(code1, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr1.buffer, /Heterogeneity violation/i);
  assert.match(stderr1.buffer, /--macro-cmd.*--micro-cmd.*cannot be identical/i);
  assert.equal(changeSetCalled, false);

  // Format 2: --key value (space separated)
  const stdout2 = new MockStream();
  const stderr2 = new MockStream();
  const code2 = await runCli(
    ["review", "--macro-cmd", "agy", "--micro-cmd", "agy"],
    { stdout: stdout2, stderr: stderr2 },
    { getChangeSet }
  );
  assert.equal(code2, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr2.buffer, /Heterogeneity violation/i);
  assert.equal(changeSetCalled, false);

  // Format 3: Case-insensitive check
  const stdout3 = new MockStream();
  const stderr3 = new MockStream();
  const code3 = await runCli(
    ["review", "--macro-cmd=Claude", "--micro-cmd=claude"],
    { stdout: stdout3, stderr: stderr3 },
    { getChangeSet }
  );
  assert.equal(code3, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr3.buffer, /Heterogeneity violation/i);
  assert.equal(changeSetCalled, false);
});

// V6: 帶一個拼錯或不存在的旗標 -> 既有的 unknown-flag 拒絕行為照常生效
test("V6: 拼錯或未支援的旗標照常以 USAGE ERROR 拒絕", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const code = await runCli(
    ["review", "--macro-cmdd=claude"],
    { stdout, stderr }
  );

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Unsupported option\(s\): --macro-cmdd=claude/i);
});

// V7: 指定的 CLI 不存在於 PATH (或 spawn 拋錯) -> adapter 回 error，法定人數失敗，blocked
test("V7: adapter 執行錯誤/CLI 不存在於 PATH 時法定人數失敗且 blocked", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const mockExec = async () => {
    throw new Error("spawn nonexistent-cli ENOENT");
  };

  const exitCode = await runCli(
    [
      "review",
      "--macro-cmd=nonexistent-cli",
      "--micro-cmd=codex"
    ],
    { stdout, stderr },
    {
      getChangeSet: () => changeSet,
      execFn: mockExec
    }
  );

  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr.buffer, /Gate Decision: BLOCK/i);
  assert.match(stderr.buffer, /Consensus Verdict: ERROR/i);
});
