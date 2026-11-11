import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { executePostRemediationHook } from "../scripts/post-remediation-hook.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

test("Post-Remediation Hook Contract: Rule ① Non-blocking stdin returns promptly without hanging", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-hook-test-"));
  const runbookPath = path.join(tmpDir, "acceptance-delivery.md");

  try {
    const stdout = new MockStream();
    const stderr = new MockStream();

    const startTime = performance.now();
    const code = await executePostRemediationHook(
      [`--runbook=${runbookPath}`, "--cwe=CWE-89"],
      {
        cwd: tmpDir,
        stdout,
        stderr,
        stdinTimeoutMs: 100 // ensure short non-blocking timeout
      }
    );
    const duration = performance.now() - startTime;

    assert.equal(code, 0);
    assert.ok(duration < 2000, `Hook must return without hanging, took ${duration}ms`);
    assert.ok(fs.existsSync(runbookPath));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Post-Remediation Hook Contract: Rule ② Strict LF output (Zero CRLF pollution)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-hook-test-"));
  const runbookPath = path.join(tmpDir, "acceptance-delivery.md");

  try {
    const stdout = new MockStream();
    const stderr = new MockStream();

    const code = await executePostRemediationHook(
      [`--runbook=${runbookPath}`, "--format=json"],
      {
        cwd: tmpDir,
        stdout,
        stderr,
        stdinData: ""
      }
    );

    assert.equal(code, 0);
    assert.ok(fs.existsSync(runbookPath));

    // Verify written runbook contains NO CRLF (\r\n)
    const content = fs.readFileSync(runbookPath, "utf8");
    assert.equal(content.includes("\r\n"), false, "Runbook content must not contain CRLF");
    assert.equal(content.includes("\r"), false, "Runbook content must not contain CR");

    // Verify stdout contains NO CRLF
    assert.equal(stdout.buffer.includes("\r\n"), false, "Stdout must not contain CRLF");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Post-Remediation Hook: Generates runbook from piped JSON remediation receipt", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-hook-test-"));
  const runbookPath = path.join(tmpDir, "acceptance-delivery.md");

  const sampleReceipt = {
    schemaVersion: "1.0.0",
    findingId: "FINDING-CWE-89-001",
    status: "FIXED_PENDING_VERIFY",
    patch: {
      targetFiles: ["src/db/query.js"],
      additions: 12,
      deletions: 2
    },
    deterministicChecks: {
      executed: true,
      exitCode: 0,
      pocVerification: {
        verified: true,
        cwe: "CWE-89",
        prePatchExecution: { flawReproduced: true },
        postPatchExecution: { flawRemediated: true },
        receiptDigest: "sha256:112233445566778899aabbccddeeff00"
      }
    }
  };

  try {
    const stdout = new MockStream();
    const stderr = new MockStream();

    const code = await executePostRemediationHook(
      [`--runbook=${runbookPath}`, "--format=json"],
      {
        cwd: tmpDir,
        stdout,
        stderr,
        stdinData: JSON.stringify(sampleReceipt)
      }
    );

    assert.equal(code, 0);
    assert.ok(fs.existsSync(runbookPath));

    const runbookContent = fs.readFileSync(runbookPath, "utf8");
    assert.match(runbookContent, /FINDING-CWE-89-001/);
    assert.match(runbookContent, /src\/db\/query\.js/);
    assert.match(runbookContent, /PoC 缺陷重現 \(Pre-Patch\)/);
    assert.match(runbookContent, /缺陷成功消除 \(轉綠\)/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Post-Remediation Hook: Strict mode blocks gate on unresolved defect", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-hook-test-"));
  const runbookPath = path.join(tmpDir, "acceptance-delivery.md");

  const failingReceipt = {
    findingId: "FINDING-BROKEN",
    status: "REJECTED_FIX",
    deterministicChecks: {
      executed: true,
      exitCode: 1, // test failed
      pocVerification: {
        prePatchExecution: { flawReproduced: true },
        postPatchExecution: { flawRemediated: false } // failed remediation
      }
    }
  };

  try {
    const stdout = new MockStream();
    const stderr = new MockStream();

    const code = await executePostRemediationHook(
      [`--runbook=${runbookPath}`, "--strict"],
      {
        cwd: tmpDir,
        stdout,
        stderr,
        stdinData: JSON.stringify(failingReceipt)
      }
    );

    assert.equal(code, 1);
    assert.match(stderr.buffer, /Gate blocked/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
