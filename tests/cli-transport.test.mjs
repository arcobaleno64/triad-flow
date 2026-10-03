import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import {
  CliReviewAdapter,
  OfflineReviewAdapter,
  extractJsonFromText,
  buildReviewPrompt,
  readBoundedFile
} from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS, validateProviderOutput } from "../src/adapters/provider-contract.mjs";
import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

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

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

test("extractJsonFromText extracts JSON directly, from fences, or from surrounding text", () => {
  assert.deepEqual(extractJsonFromText('{"findings":[]}'), { findings: [] });
  assert.deepEqual(extractJsonFromText('Here is output:\n```json\n{"findings":[{"title":"issue"}]}\n```\nDone.'), { findings: [{ title: "issue" }] });
  assert.deepEqual(extractJsonFromText('Preamble {"findings":[{"title":"direct"}]} epilogue'), { findings: [{ title: "direct" }] });
  assert.equal(extractJsonFromText("garbage without json"), null);

  // Robustness: trailing comma tolerance
  assert.deepEqual(extractJsonFromText('{"findings":[{"title":"issue",}],}'), { findings: [{ title: "issue" }] });

  // Robustness: string literals containing trailing comma patterns must NOT be mutated
  const literalWithCommas = '{"findings":[{"title":"code snippet: { a: 1, } and [2, ]"}]}';
  assert.deepEqual(extractJsonFromText(literalWithCommas), { findings: [{ title: "code snippet: { a: 1, } and [2, ]" }] });

  // Robustness: preamble with braces and postamble with braces
  const complexText = `
  I analyzed the code. Note that options like { safe: true } were considered.
  Here is the formal review:
  {
    "findings": [
      {
        "title": "Complex finding",
        "severity": "high"
      }
    ],
    "coverage": { "coveredFiles": ["index.js"], "omittedFiles": [] }
  }
  End of review. Context snippet: function() { return 1; }
  `;
  const complexParsed = extractJsonFromText(complexText);
  assert.ok(complexParsed);
  assert.equal(complexParsed.findings[0].title, "Complex finding");

  // Robustness: coverage before findings with inner braces
  const coverageFirstText = `
  Here is review:
  {
    "coverage": {
      "nested": { "inner": true },
      "coveredFiles": ["index.js"]
    },
    "findings": [
      { "title": "Coverage first", "severity": "high" }
    ]
  }
  `;
  const covFirstParsed = extractJsonFromText(coverageFirstText);
  assert.ok(covFirstParsed);
  assert.equal(covFirstParsed.findings[0].title, "Coverage first");
});

test("buildReviewPrompt includes ChangeSet metadata, file list, and diff", () => {
  const cs = makeChangeSet();
  const prompt = buildReviewPrompt(cs, "macro");

  assert.match(prompt, /Scope: working-tree/);
  assert.match(prompt, /src\/sample\.js/);
  assert.match(prompt, /\+ const a = 1;/);
});

test("CliReviewAdapter (Acceptance 1: 成功 Success)", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    stdout: JSON.stringify({
      findings: [
        {
          title: "Hardcoded secret in sample",
          severity: "high",
          file: "src/sample.js",
          line_start: 1,
          line_end: 1,
          recommendation: "Use environment variables"
        }
      ],
      coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
    })
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-success-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, true);
  assert.equal(res.executionStatus, EXECUTION_STATUS.SUCCESS);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].title, "Hardcoded secret in sample");
  assert.equal(res.findings[0].severity, "high");
  assert.equal(res.findings[0].file, "src/sample.js");
});

test("CliReviewAdapter (Acceptance 2: 空結果 Empty Results)", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    stdout: JSON.stringify({
      findings: [],
      coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
    })
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-empty-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, true);
  assert.equal(res.executionStatus, EXECUTION_STATUS.EMPTY);
  assert.equal(res.findings.length, 0);
});

test("CliReviewAdapter (Acceptance 3: 認證失敗 Auth Failure)", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    stdout: "",
    stderr: "Error: You are not logged into Antigravity. Please run agy auth login."
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-auth-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
  assert.match(res.error, /Authentication failure/i);
});

test("CliReviewAdapter (Acceptance 4: 超時 Timeout)", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    executionStatus: EXECUTION_STATUS.TIMEOUT,
    error: "Process timed out"
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-timeout-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    timeoutMs: 100
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.TIMEOUT);
});

test("CliReviewAdapter (Acceptance 5: 取消 Cancelled via AbortSignal)", async () => {
  const cs = makeChangeSet();
  const controller = new AbortController();
  controller.abort(); // pre-aborted

  const adapter = new CliReviewAdapter({
    execFn: async () => {
      assert.fail("Should not execute when signal is aborted");
    }
  });

  const res = await adapter.executeReview({
    runId: "run-abort-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    signal: controller.signal
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.CANCELLED);
});

test("CliReviewAdapter (Acceptance 6: 格式錯誤 Malformed Output)", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    stdout: "Sorry, as an AI language model I cannot parse this. {broken json here..."
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-malformed-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
});

test("CliReviewAdapter: detects provider refusal/content filter and classifies as ERROR", async () => {
  const cs = makeChangeSet();
  const mockExec = async () => ({
    code: 0,
    stdout: "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding..."
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-refusal-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /Provider safety\/content filter refusal detected/);
});

test("CliReviewAdapter (Acceptance 7: 過大回應 Output Flood Execution Error)", async () => {
  const cs = makeChangeSet();
  const hugeOutput = "A".repeat(1024 * 1024); // 1 MB string
  const mockExec = async () => ({
    stdout: hugeOutput
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-huge-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    limits: { maxOutputBytes: 1000 } // Low limit
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /maxOutputBytes/i);
});

test("CliReviewAdapter (Acceptance 7b: Stderr Output Flood Execution Error)", async () => {
  const cs = makeChangeSet();
  const hugeStderr = "E".repeat(1024 * 1024); // 1 MB string
  const mockExec = async () => ({
    stdout: "{}",
    stderr: hugeStderr
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-huge-stderr-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    limits: { maxOutputBytes: 1000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /maxOutputBytes/i);
});

test("CliReviewAdapter (Acceptance 7c: Preclassified status with stdout flood classified as ERROR)", async () => {
  const cs = makeChangeSet();
  const floodOutput = "X".repeat(600 * 1024);
  const mockExec = async () => ({
    executionStatus: "payload_too_large",
    stdout: floodOutput
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-flood-preclass-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    limits: { maxOutputBytes: 1000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /maxOutputBytes/i);
});

test("CliReviewAdapter (Acceptance 7d: fileOutput flood classified as ERROR)", async () => {
  const cs = makeChangeSet();
  const floodFile = "F".repeat(600 * 1024);
  const mockExec = async () => ({
    fileOutput: floodFile,
    stdout: "{}"
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-flood-file-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    limits: { maxOutputBytes: 1000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /maxOutputBytes/i);
});

test("CliReviewAdapter (Acceptance 7e: stat/read race with bounded read classified as ERROR)", async () => {
  const cs = makeChangeSet();
  const tmpFile = path.join(os.tmpdir(), `tf-race-test-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, "X".repeat(2092), "utf8");

  const origStatSync = fs.statSync;
  fs.statSync = (p, opts) => {
    if (p === tmpFile) {
      return { size: 1 };
    }
    return origStatSync(p, opts);
  };

  try {
    const adapter = new CliReviewAdapter({
      execFn: async () => ({
        code: 0,
        stdout: "{}"
      })
    });

    const res = adapter._processResult(
      { code: 0, stdout: "{}" },
      { changeSet: cs, providerName: "mock" },
      { maxOutputBytes: 1000, maxInputBytes: 100000 },
      tmpFile
    );

    assert.equal(res.ok, false);
    assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
    assert.match(res.error, /maxOutputBytes/i);
  } finally {
    fs.statSync = origStatSync;
    try { fs.unlinkSync(tmpFile); } catch {}
  }
});

test("CliReviewAdapter (Acceptance 8: 部分覆蓋 Partial Coverage & Omitted Files)", async () => {
  const cs = makeChangeSet([
    { path: "src/sample.js", additions: 5, deletions: 1 },
    { path: "src/large-binary.dat", additions: 100, deletions: 0 }
  ]);

  const mockExec = async () => ({
    stdout: JSON.stringify({
      findings: [],
      coverage: {
        coveredFiles: ["src/sample.js"],
        omittedFiles: [{ path: "src/large-binary.dat", code: "OMIT_BINARY", reason: "Binary file skipped by reviewer" }]
      }
    })
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-partial-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, true);
  assert.deepEqual(res.coverage.coveredFiles, ["src/sample.js"]);
  assert.equal(res.coverage.omittedFiles.length, 1);
  assert.equal(res.coverage.omittedFiles[0].path, "src/large-binary.dat");
  assert.match(res.coverage.omittedFiles[0].reason, /binary file skipped/i);
});

test("CliReviewAdapter (Acceptance 9: 不改檔 Read-Only Invariant)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-readonly-test-"));
  const filePath = path.join(tmpDir, "untouched.txt");
  fs.writeFileSync(filePath, "original content\n", "utf8");
  const originalStat = fs.statSync(filePath);

  const cs = makeChangeSet([{ path: "untouched.txt", additions: 1, deletions: 0 }]);
  const mockExec = async () => ({
    stdout: JSON.stringify({ findings: [] })
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  await adapter.executeReview({
    runId: "run-readonly-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  const afterStat = fs.statSync(filePath);
  assert.equal(fs.readFileSync(filePath, "utf8"), "original content\n");
  assert.equal(afterStat.mtimeMs, originalStat.mtimeMs);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("CliReviewAdapter (Acceptance 10: 不跑模型提供的任意命令 No Command Execution)", async () => {
  const cs = makeChangeSet();
  // Hostile model output with arbitrary shell commands injected
  const mockExec = async () => ({
    stdout: JSON.stringify({
      findings: [
        {
          title: "Sample finding",
          severity: "low",
          file: "src/sample.js",
          line_start: 1,
          line_end: 1,
          recommendation: "Safe fix"
        }
      ],
      coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] },
      command: "rm -rf /",
      shell: "calc.exe",
      execute: "curl https://malicious.site"
    })
  });

  const adapter = new CliReviewAdapter({ execFn: mockExec });
  const res = await adapter.executeReview({
    runId: "run-no-cmd-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, true);
  // Host never executes nor retains arbitrary commands
  assert.equal(res.command, undefined);
  assert.equal(res.shell, undefined);
  assert.equal(res.execute, undefined);
});

test("OfflineReviewAdapter (Acceptance 11: Offline Replay Tagged Accurately)", async () => {
  const cs = makeChangeSet();
  const fixture = {
    findings: [
      {
        title: "Replayed finding",
        severity: "medium",
        file: "src/sample.js",
        line_start: 1,
        line_end: 1
      }
    ]
  };

  const adapter = new OfflineReviewAdapter({ fixture, providerName: "offline-goldens" });
  const res = await adapter.executeReview({
    runId: "run-offline-01",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.ok, true);
  assert.equal(res.providerIdentity.transport, "offline");
  assert.equal(res.providerIdentity.provider, "offline-goldens");
  assert.equal(res.findings.length, 1);
});

test("Review Orchestrator (Acceptance 12: 高風險需要雙 reviewer 而只有一個時，保持 incomplete/blocked)", async () => {
  // Tier 1 Critical file (Auth/JWT) requires hierarchical swarm mode
  const criticalChangeSet = makeChangeSet([
    { path: "src/auth/jwt.ts", additions: 20, deletions: 5 }
  ]);

  // Provide ONLY macro adapter (no micro adapter)
  const macroAdapter = new OfflineReviewAdapter({
    fixture: { findings: [] },
    providerName: "macro-sentry"
  });

  const orchResult = await orchestrateReview(criticalChangeSet, { macro: macroAdapter });

  assert.equal(orchResult.plan.mode, "hierarchical");
  assert.equal(orchResult.status, "incomplete");
  assert.equal(orchResult.consensus.verdict, "error");
  assert.equal(orchResult.consensus.quorumReached, false);
  assert.equal(orchResult.gate.decision, "block");
  assert.match(orchResult.gate.reason, /Quorum Failure/i);
});

test("Review Orchestrator (Acceptance 13: Low-risk diff with single reviewer approves cleanly)", async () => {
  // Small Tier 2 file within threshold routes to single-agent mode
  const smallChangeSet = makeChangeSet([
    { path: "src/utils/calc.ts", additions: 5, deletions: 1 }
  ]);

  const macroAdapter = new OfflineReviewAdapter({
    fixture: { findings: [] },
    providerName: "macro-sentry"
  });

  const orchResult = await orchestrateReview(smallChangeSet, { macro: macroAdapter });

  assert.equal(orchResult.plan.mode, "single");
  assert.equal(orchResult.status, "reviewed-clean");
  assert.equal(orchResult.consensus.verdict, "approve");
  assert.equal(orchResult.gate.decision, "approve");
});

test("runCli review integrates reviewAdapters with real CLI execution and exit codes", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const mockChangeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const cleanAdapter = new OfflineReviewAdapter({
    fixture: { findings: [] },
    providerName: "cli-macro"
  });

  // 1. Clean review passes with EXIT_CODES.SUCCESS (0)
  const exitCodeClean = await runCli(["review"], { stdout, stderr }, {
    getChangeSet: () => mockChangeSet,
    reviewAdapters: { macro: cleanAdapter }
  });

  assert.equal(exitCodeClean, EXIT_CODES.SUCCESS);
  assert.match(stderr.buffer, /Gate Decision: APPROVE/i);

  // 2. Review with blocking finding fails with EXIT_CODES.GATE_BLOCKED (1)
  const stdout2 = new MockStream();
  const stderr2 = new MockStream();

  const blockingAdapter = new OfflineReviewAdapter({
    fixture: {
      findings: [
        {
          title: "SQL Injection Flaw",
          severity: "critical",
          file: "src/calc.js",
          line_start: 1,
          line_end: 1
        }
      ]
    },
    providerName: "cli-macro"
  });

  const exitCodeBlock = await runCli(["review"], { stdout: stdout2, stderr: stderr2 }, {
    getChangeSet: () => mockChangeSet,
    reviewAdapters: { macro: blockingAdapter }
  });

  assert.equal(exitCodeBlock, EXIT_CODES.GATE_BLOCKED);
  assert.match(stderr2.buffer, /Gate Decision: BLOCK/i);
});

test("validateProviderOutput enforces 4096-byte UTF-8 cap and redacts secrets in error", () => {
  const multiByteStr = "測".repeat(2000); // 2000 CJK chars * 3 bytes = 6000 bytes > 4096
  const out = validateProviderOutput({
    executionStatus: EXECUTION_STATUS.ERROR,
    rawOutput: multiByteStr,
    error: "Failed with token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
  });

  assert.equal(out.ok, false);
  assert.ok(out.rawOutput.endsWith(" ... [TRUNCATED]"));
  const rawPrefix = out.rawOutput.slice(0, -(" ... [TRUNCATED]".length));
  assert.ok(Buffer.byteLength(rawPrefix, "utf8") <= 4096);
  assert.ok(!out.error.includes("ghp_"));
  assert.ok(out.error.includes("[REDACTED_SECRET]"));
});

test("CliReviewAdapter enforces timeoutMs budget across retries without sleeping past deadline", async () => {
  let execAttempts = 0;
  const adapter = new CliReviewAdapter({
    command: "fake-provider",
    args: [],
    providerName: "fake-provider",
    modelName: "fake-model",
    family: "google", // maxRetries = 2
    execFn: async () => {
      execAttempts++;
      return {
        code: 0,
        stdout: "This request was blocked by Gemini's filters."
      };
    }
  });

  const t0 = Date.now();
  const res = await adapter.executeReview({
    runId: "retry-deadline-test",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    timeoutMs: 50, // Much smaller than 1000ms retry backoff
    changeSet: makeChangeSet([{ path: "src/a.js", additions: 1, deletions: 0 }])
  });
  const elapsed = Date.now() - t0;

  assert.ok(elapsed < 800, `Execution should finish quickly without 1000ms sleep (took ${elapsed}ms)`);
  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.TIMEOUT);
  assert.match(res.error, /timeout budget/i);
});

test("readBoundedFile enforces maxBytes strictly without unbounded fallback", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-read-bounded-"));
  try {
    const validFile = path.join(tmpDir, "valid.txt");
    fs.writeFileSync(validFile, "hello world", "utf8");
    const content = readBoundedFile(validFile, 100);
    assert.equal(content, "hello world");

    // File exceeding limit triggers error via stat
    const largeFile = path.join(tmpDir, "large.txt");
    fs.writeFileSync(largeFile, "A".repeat(200), "utf8");
    assert.throws(() => {
      readBoundedFile(largeFile, 100);
    }, /exceeded maxOutputBytes/);

    // Exact boundary: 100 bytes allowed
    const exactFile = path.join(tmpDir, "exact.txt");
    fs.writeFileSync(exactFile, "B".repeat(100), "utf8");
    const exactContent = readBoundedFile(exactFile, 100);
    assert.equal(exactContent.length, 100);

    // 101 bytes with maxBytes 100 triggers error
    const boundaryExceededFile = path.join(tmpDir, "exceeded.txt");
    fs.writeFileSync(boundaryExceededFile, "C".repeat(101), "utf8");
    assert.throws(() => {
      readBoundedFile(boundaryExceededFile, 100);
    }, /exceeded maxOutputBytes/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
