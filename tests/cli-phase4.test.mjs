import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { runCli, EXIT_CODES, formatHelp } from "../src/cli.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

test("CLI Phase 4 Help: formats swarm, poc, and pool usage messages", () => {
  const swarmHelp = formatHelp("swarm");
  assert.match(swarmHelp, /triad-flow swarm/);
  assert.match(swarmHelp, /--diff/);
  assert.match(swarmHelp, /--acceptance-runbook/);

  const pocHelp = formatHelp("poc");
  assert.match(pocHelp, /triad-flow poc/);
  assert.match(pocHelp, /--cwe/);
  assert.match(pocHelp, /--acceptance-runbook/);

  const poolHelp = formatHelp("pool");
  assert.match(poolHelp, /triad-flow pool/);
  assert.match(poolHelp, /reconcile/);
});

test("CLI Phase 4: 'triad-flow pool status' exits 0 with daemon counts", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["pool", "status"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stdout.buffer, /Container Sandbox Pool Status/);
  assert.match(stdout.buffer, /Active Daemons/);
});

test("CLI Phase 4: 'triad-flow pool reconcile' runs clean scan and exits 0", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const mockExec = () => ({ status: 0, stdout: "" });
  const code = await runCli(["pool", "reconcile"], { stdout, stderr }, { execFn: mockExec });

  assert.equal(code, EXIT_CODES.SUCCESS);
  assert.match(stdout.buffer, /HEALTHY_INVARIANT_PRESERVED/);
});

test("CLI Phase 4: 'triad-flow poc' verifies differential PoC and generates acceptance runbook", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-poc-cli-"));
  const runbookPath = path.join(tmpDir, "acceptance-runbook.md");
  const reportPath = path.join(tmpDir, "poc-receipt.json");

  try {
    const stdout = new MockStream();
    const stderr = new MockStream();
    const code = await runCli(
      [
        "poc",
        "--cwe=CWE-89",
        `--report=${reportPath}`,
        `--acceptance-runbook=${runbookPath}`
      ],
      { stdout, stderr },
      { cwd: tmpDir }
    );

    assert.equal(code, EXIT_CODES.SUCCESS);
    assert.match(stdout.buffer, /VERIFIED \(REMEDIATED\)/);
    assert.match(stdout.buffer, /CWE-89/);

    assert.ok(fs.existsSync(reportPath));
    const reportData = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    assert.equal(reportData.verified, true);
    assert.equal(reportData.cwe, "CWE-89");

    assert.ok(fs.existsSync(runbookPath));
    const runbookContent = fs.readFileSync(runbookPath, "utf8");
    assert.match(runbookContent, /驗收交付指引手冊/);
    assert.match(runbookContent, /CWE-89/);
    assert.match(runbookContent, /缺陷成功重現/);
    assert.match(runbookContent, /缺陷成功消除/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Phase 4: 'triad-flow swarm' dispatches review with Ed25519 signatures and outputs json", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(
    [
      "swarm",
      "--workers=worker-agy,worker-claude",
      "--format=json"
    ],
    { stdout, stderr }
  );

  assert.equal(code, EXIT_CODES.SUCCESS);
  const result = JSON.parse(stdout.buffer);
  assert.equal(result.ok, true);
  assert.equal(result.verdict, "approve");
  assert.ok(result.receiptChain.length > 0);
  assert.ok(result.rootReceiptHash.startsWith("sha256:"));
});

test("CLI Phase 4: 'triad-flow swarm' with invalid diff path exits USAGE_ERROR", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const code = await runCli(["swarm", "--diff=non_existent_diff.patch"], { stdout, stderr });

  assert.equal(code, EXIT_CODES.USAGE_ERROR);
  assert.match(stderr.buffer, /Diff file not found/);
});
