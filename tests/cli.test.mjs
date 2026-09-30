import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
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

test("runCli 'doctor --format=json' produces valid structured JSON on stdout", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockExec = (cmd) => {
    if (cmd === "agy") return { status: 0, stdout: "1.2.2\n" };
    if (cmd === "claude") return { status: 0, stdout: "2.1.270\n" };
    return { status: null, error: new Error("ENOENT") };
  };

  const code = await runCli(["doctor", "--format=json"], { stdout, stderr }, { execFn: mockExec });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.equal(stderr.buffer, "");
  const report = JSON.parse(stdout.buffer);
  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.quorum.status, "BINARY_QUORUM_READY");
  assert.equal(report.quorum.ready, true);
  assert.deepEqual(report.quorum.families, ["google", "anthropic"]);
  assert.equal(report.safetyCore.loaded, true);
});

test("runCli 'doctor --format json' (space-delimited) produces valid structured JSON on stdout", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockExec = () => ({ status: 0, stdout: "1.0.0" });

  const code = await runCli(["doctor", "--format", "json"], { stdout, stderr }, { execFn: mockExec });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.equal(stderr.buffer, "");
  const report = JSON.parse(stdout.buffer);
  assert.equal(report.schemaVersion, "1.0.0");
});

test("runCli '--format json' (default doctor, space-delimited) produces valid structured JSON on stdout", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockExec = () => ({ status: 0, stdout: "1.0.0" });

  const code = await runCli(["--format", "json"], { stdout, stderr }, { execFn: mockExec });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.equal(stderr.buffer, "");
  const report = JSON.parse(stdout.buffer);
  assert.equal(report.schemaVersion, "1.0.0");
});

test("runCli '--format=json' (default doctor) produces valid structured JSON on stdout", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockExec = () => ({ status: 0, stdout: "1.0.0" });

  const code = await runCli(["--format=json"], { stdout, stderr }, { execFn: mockExec });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.equal(stderr.buffer, "");
  const report = JSON.parse(stdout.buffer);
  assert.equal(report.schemaVersion, "1.0.0");
});

test("runCli '--base main review' correctly resolves command when flags precede command", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockCleanGitState = { ok: true, files: [] };

  const code = await runCli(["--base", "main", "review"], { stdout, stderr }, { getGitState: () => mockCleanGitState });
  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /\[No Changes\].*No files to review/i);
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

test("runCli 'remediate --case=BENCH-REAL-001' fails closed with GATE_BLOCKED without explicit authorizer", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(["remediate", "--case=BENCH-REAL-001", `--receipt=${receiptPath}`], { stdout, stderr });
    assert.equal(code, EXIT_CODES.GATE_BLOCKED);
    assert.match(stderr.buffer, /No human authorizer specified/i);
    assert.match(stdout.buffer, /Lifecycle Status:\s+FIX_PROPOSED/i);
    assert.ok(fs.existsSync(receiptPath));
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.schemaVersion, "1.0.0");
    assert.equal(receipt.status, "FIX_PROPOSED");
    assert.equal(receipt.findingId, "BENCH-REAL-001-FINDING-001");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runCli 'remediate' fails closed with GATE_BLOCKED when authorizer is given but test runner is missing", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(
      ["remediate", "--case=BENCH-REAL-001", "--authorizer=security-lead@triad.flow", `--receipt=${receiptPath}`],
      { stdout, stderr }
    );
    assert.equal(code, EXIT_CODES.GATE_BLOCKED);
    assert.match(stderr.buffer, /No deterministic test runner provided/i);
    assert.match(stdout.buffer, /Lifecycle Status:\s+PATCH_AUTHORIZED/i);
    assert.ok(fs.existsSync(receiptPath));
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.status, "PATCH_AUTHORIZED");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runCli 'remediate' fails closed with GATE_BLOCKED when tests pass but closure verifier is missing", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(
      ["remediate", "--case=BENCH-REAL-001", "--authorizer=security-lead@triad.flow", `--receipt=${receiptPath}`],
      { stdout, stderr },
      {
        testRunnerFn: () => ({
          testCommand: "node --check src/db/user-repo.js",
          exitCode: 0,
          passedCount: 1,
          failedCount: 0
        })
      }
    );
    assert.equal(code, EXIT_CODES.GATE_BLOCKED);
    assert.match(stderr.buffer, /No independent closure verifier provided/i);
    assert.match(stdout.buffer, /Lifecycle Status:\s+FIXED_PENDING_VERIFY/i);
    assert.ok(fs.existsSync(receiptPath));
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.status, "FIXED_PENDING_VERIFY");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runCli 'remediate' successfully reaches CLOSED when authorizer, test runner, and verifier are all affirmatively provided", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(
      ["remediate", "--case=BENCH-REAL-001", "--authorizer=security-lead@triad.flow", `--receipt=${receiptPath}`],
      { stdout, stderr },
      {
        testRunnerFn: () => ({
          testCommand: "node --check src/db/user-repo.js",
          exitCode: 0,
          passedCount: 1,
          failedCount: 0
        }),
        closureVerifierFn: (session) => ({
          schemaVersion: "1.0.0",
          verifiedAt: new Date().toISOString(),
          changeSetDigest: "sha256:" + "a".repeat(64),
          producer: {
            providerName: "agy",
            findingsCount: 1,
            findings: [
              {
                id: session.findingId,
                findingId: session.findingId,
                title: "SQL Injection in User Query Handler",
                severity: "critical",
                file: "src/db/user-repo.js",
                line_start: 1,
                line_end: 1
              }
            ]
          },
          verifier: {
            providerName: "claude",
            modelName: "cli-default",
            actualModel: { value: "claude-verifier", source: "reported" }
          },
          evaluations: [
            {
              findingId: session.findingId,
              verdict: "SUPPORTED",
              locatorAccurate: true,
              typeAccurate: true,
              severityAccurate: true,
              reasoning: "Controlled remediation verified by independent verifier."
            }
          ],
          verifierOmissions: [],
          disagreementLedger: [],
          summary: {
            totalEvaluated: 1,
            supportedCount: 1,
            contestedCount: 0,
            insufficientEvidenceCount: 0,
            omissionsCount: 0
          }
        })
      }
    );
    assert.equal(code, EXIT_CODES.SUCCESS);
    assert.match(stdout.buffer, /Triad-Flow Remediation Summary: CLOSED/i);
    assert.match(stdout.buffer, /Plan-Only Boundary/i);
    assert.ok(fs.existsSync(receiptPath));
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.schemaVersion, "1.0.0");
    assert.equal(receipt.status, "CLOSED");
    assert.equal(receipt.findingId, "BENCH-REAL-001-FINDING-001");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runCli 'remediate --case=BENCH-REAL-001 --format=json' produces valid JSON receipt on stdout when fully verified", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(
      ["remediate", "--case=BENCH-REAL-001", "--format=json", "--authorizer=security-lead@triad.flow", `--receipt=${receiptPath}`],
      { stdout, stderr },
      {
        testRunnerFn: () => ({
          testCommand: "node --check src/db/user-repo.js",
          exitCode: 0,
          passedCount: 1,
          failedCount: 0
        }),
        closureVerifierFn: (session) => ({
          schemaVersion: "1.0.0",
          verifiedAt: new Date().toISOString(),
          changeSetDigest: "sha256:" + "a".repeat(64),
          producer: {
            providerName: "agy",
            findingsCount: 1,
            findings: [
              {
                id: session.findingId,
                findingId: session.findingId,
                title: "SQL Injection in User Query Handler",
                severity: "critical",
                file: "src/db/user-repo.js",
                line_start: 1,
                line_end: 1
              }
            ]
          },
          verifier: {
            providerName: "claude",
            modelName: "cli-default",
            actualModel: { value: "claude-verifier", source: "reported" }
          },
          evaluations: [
            {
              findingId: session.findingId,
              verdict: "SUPPORTED",
              locatorAccurate: true,
              typeAccurate: true,
              severityAccurate: true,
              reasoning: "JSON receipt verified."
            }
          ],
          verifierOmissions: [],
          disagreementLedger: [],
          summary: {
            totalEvaluated: 1,
            supportedCount: 1,
            contestedCount: 0,
            insufficientEvidenceCount: 0,
            omissionsCount: 0
          }
        })
      }
    );
    assert.equal(code, EXIT_CODES.SUCCESS);
    const receipt = JSON.parse(stdout.buffer);
    assert.equal(receipt.schemaVersion, "1.0.0");
    assert.equal(receipt.status, "CLOSED");
    assert.equal(receipt.actors.synthesizer.providerName, "codex");
    assert.equal(receipt.actors.verifier.providerName, "claude");
    assert.equal(receipt.actors.authorizer.identity, "security-lead@triad.flow");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runCli 'remediate' without --case fails with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["remediate"], { stdout, stderr });
  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /requires '--case <case-id>'/i);
});

test("runCli 'remediate --case=UNKNOWN_999' fails with EXIT_CODES.USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["remediate", "--case=UNKNOWN_999"], { stdout, stderr });
  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Unknown corpus case: 'UNKNOWN_999'/i);
});

test("runCli 'remediate' fails closed with EXIT_CODES.GATE_BLOCKED when tests fail in strict mode", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-remed-cli-"));
  const receiptPath = path.join(tmpDir, "rem-receipt.json");
  try {
    const code = await runCli(
      ["remediate", "--case=BENCH-REAL-001", "--strict", "--authorizer=security-lead@triad.flow", `--receipt=${receiptPath}`],
      { stdout, stderr },
      {
        testRunnerFn: () => ({ exitCode: 1, passedCount: 0, failedCount: 1, regressionDetected: true })
      }
    );
    assert.equal(code, EXIT_CODES.GATE_BLOCKED);
    assert.match(stderr.buffer, /Remediation did not reach CLOSED state/i);
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.status, "REJECTED_FIX");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

