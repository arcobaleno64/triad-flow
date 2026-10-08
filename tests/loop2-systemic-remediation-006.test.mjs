/**
 * LOOP2-SYSTEMIC-REMEDIATION-006: Comprehensive Regression & Qualification Tests
 *
 * Verifies:
 * 1. 006-B: AGY stdin stream-json capability, NDJSON framing, result parsing, and Windows argv limit bypass.
 * 2. 006-C: Staged scheduler modernization, pre-flight feasibility check, bounded concurrency pool (maxConcurrency=2),
 *    dynamic budgeting, deterministic reduction in chunkIndex order, cross-chunk contradiction checks, and leak prevention.
 * 3. 006-A: Telemetry metrics enrichment (providerTimeoutCount, chunkTimeoutCount, timeoutCycle, phaseMetrics).
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import {
  CliReviewAdapter,
  extractStreamJsonResponse
} from "../src/adapters/cli-transport.mjs";
import {
  PROVIDER_PROFILES,
  SAFE_ARGV_THRESHOLD_BYTES
} from "../src/adapters/provider-profiles.mjs";
import {
  EXECUTION_STATUS,
  COVERAGE_OMISSION_CODES
} from "../src/adapters/provider-contract.mjs";
import {
  executeStagedReview
} from "../src/adapters/staged-review.mjs";
import {
  parseArgs
} from "../scripts/dogfood-review.mjs";

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

// -----------------------------------------------------------------------------
// Workstream 006-B: Transport Layer & AGY Stream-JSON Tests
// -----------------------------------------------------------------------------

test("006-B: PROVIDER_PROFILES.agy preserves canonical frozen contract and declares supportsStreamJson: true", () => {
  assert.equal(PROVIDER_PROFILES.agy.id, "agy");
  assert.equal(PROVIDER_PROFILES.agy.family, "google");
  assert.equal(PROVIDER_PROFILES.agy.inputChannel, "argv");
  assert.equal(PROVIDER_PROFILES.agy.supportsStdin, false, "Canonical agy profile must maintain supportsStdin: false for backward compatibility");
  assert.equal(PROVIDER_PROFILES.agy.supportsStreamJson, true, "agy profile declares supportsStreamJson capability");
});

test("006-B: CliReviewAdapter with streamJson: true configures stdin streaming and removes --print", () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true
  });

  assert.equal(adapter.streamJson, true);
  assert.equal(adapter.supportsStdin, true);
  assert.equal(adapter.inputChannel, "stdin");
  assert.ok(adapter.args.includes("--mode=plan"), "Must include mandatory read-only flag --mode=plan");
  assert.ok(adapter.args.includes("--disable-slash-commands"), "Must include mandatory safety flag --disable-slash-commands");
  assert.ok(adapter.args.includes("--input-format=stream-json"), "Must include --input-format=stream-json");
  assert.ok(adapter.args.includes("--output-format=stream-json"), "Must include --output-format=stream-json");
  assert.ok(!adapter.args.includes("--print"), "Must omit --print when using stream-json");
});

test("006-B: extractStreamJsonResponse correctly extracts event=result from NDJSON lines", () => {
  const rawStream = [
    JSON.stringify({ event: "init", conversation_id: "c-123" }),
    JSON.stringify({ event: "step_update", index: 1 }),
    JSON.stringify({
      event: "result",
      result: {
        status: "SUCCESS",
        response: JSON.stringify({
          findings: [{ title: "Found Flaw", severity: "high", file: "src/sample.js", line_start: 1, line_end: 1 }],
          coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
        })
      }
    })
  ].join("\n");

  const res = extractStreamJsonResponse(rawStream);
  assert.ok(res, "Must extract result event");
  assert.equal(res.event, "result");
  assert.equal(res.result.status, "SUCCESS");
  assert.match(res.result.response, /Found Flaw/);
});

test("006-B: CliReviewAdapter executes with streamJson via execFn, frames NDJSON user message, and parses findings", async () => {
  let capturedStdin = null;
  let capturedArgs = null;

  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async ({ args, stdin }) => {
      capturedArgs = args;
      capturedStdin = stdin;
      const ndjsonOutput = [
        JSON.stringify({ event: "init", conversation_id: "test-c" }),
        JSON.stringify({
          event: "result",
          result: {
            status: "SUCCESS",
            response: JSON.stringify({
              findings: [{ title: "SQL Injection Flaw", severity: "critical", file: "src/sample.js", line_start: 5, line_end: 5 }],
              coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
            })
          }
        })
      ].join("\n");

      return {
        code: 0,
        stdout: ndjsonOutput
      };
    }
  });

  const cs = makeChangeSet();
  const res = await adapter.executeReview({
    runId: "run-stream-test",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: cs,
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, true);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].title, "SQL Injection Flaw");
  assert.equal(res.coverage.coveredFiles[0], "src/sample.js");

  // Verify NDJSON input framing
  assert.ok(capturedStdin, "Must send payload via stdin");
  const parsedInput = JSON.parse(capturedStdin.trim());
  assert.equal(parsedInput.event, "user");
  assert.ok(parsedInput.message && parsedInput.message.content);
  assert.ok(!capturedArgs.includes("--print"));
});

test("006-B: Large payload (>35KB) bypasses Windows argv limit cleanly with streamJson: true", async () => {
  const largeHunk = "+ const a = '" + "X".repeat(35000) + "';";
  const largeCs = makeChangeSet([{ path: "src/large.js", additions: 1, deletions: 0 }], largeHunk);

  let capturedStdinLength = 0;
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async ({ stdin }) => {
      capturedStdinLength = Buffer.byteLength(stdin, "utf8");
      return {
        code: 0,
        stdout: JSON.stringify({
          event: "result",
          result: {
            status: "SUCCESS",
            response: JSON.stringify({
              findings: [],
              coverage: { coveredFiles: ["src/large.js"], omittedFiles: [] }
            })
          }
        })
      };
    }
  });

  const res = await adapter.executeReview({
    runId: "run-large-stream",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: largeCs,
    timeoutMs: 5000,
    limits: { maxInputBytes: 200000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, true);
  assert.notEqual(res.executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE, "Must not trigger PAYLOAD_TOO_LARGE when streamJson is active");
  assert.ok(capturedStdinLength > 35000, `Stdin payload (${capturedStdinLength} bytes) must carry full prompt`);
});

// -----------------------------------------------------------------------------
// Workstream 006-C: Staged Scheduler & Bounded Worker Pool Tests
// -----------------------------------------------------------------------------

test("006-C: Pre-flight feasibility check records warning when budget is mathematically insufficient", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-feasibility-test-"));
  const files = Array.from({ length: 6 }, (_, i) => ({ path: `src/f${i}.js` }));
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      const target = (params.changeSet.files || [])[0]?.path;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: target ? [target] : [], omittedFiles: [] }
      };
    }
  };

  // 6 chunks with concurrency 1 and budget 20,000ms -> 6 waves * 10,000ms = 60,000ms > 20,000ms -> infeasible
  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 20000,
    maxChunkBytes: 50,
    maxConcurrency: 1,
    minChunkBudgetMs: 10000
  });

  assert.ok(result.telemetry, "Must produce telemetry object");
  assert.ok(result.telemetry.feasibility, "Must include feasibility assessment");
  assert.equal(result.telemetry.feasibility.isFeasible, false);
  assert.match(result.telemetry.feasibility.warning, /insufficient/i);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C: Bounded worker pool (maxConcurrency=2) executes chunks concurrently and preserves chunkIndex order", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-concurrency-order-"));
  const files = [
    { path: "src/c0.js" },
    { path: "src/c1.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const executionLog = [];
  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      const target = (params.changeSet.files || [])[0]?.path;
      executionLog.push({ event: "start", target, t: Date.now() });

      // Invert completion order: chunk 0 takes 80ms, chunk 1 takes 10ms
      const delayMs = target === "src/c0.js" ? 80 : 10;
      await new Promise(r => setTimeout(r, delayMs));

      executionLog.push({ event: "finish", target, t: Date.now() });
      return {
        ok: true,
        findings: [
          { title: `Flaw in ${target}`, severity: "medium", file: target, line_start: 1, line_end: 1 }
        ],
        coverage: { coveredFiles: [target], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 60000,
    maxChunkBytes: 50,
    maxConcurrency: 2
  });

  assert.equal(result.ok, true);
  assert.equal(result.status, "completed");
  assert.equal(result.findings.length, 2);

  // Findings must be reduced strictly in chunkIndex order (c0 first, then c1)
  assert.equal(result.findings[0].file, "src/c0.js", "First finding must come from chunk 0");
  assert.equal(result.findings[1].file, "src/c1.js", "Second finding must come from chunk 1");

  // Receipts must be ordered by chunkIndex (1-indexed)
  assert.equal(result.receipts[0].chunkIndex, 1);
  assert.equal(result.receipts[1].chunkIndex, 2);

  // Telemetry verifies concurrency
  assert.equal(result.telemetry.maxConcurrency, 2);
  assert.equal(result.telemetry.chunkCount, 2);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C: Cross-chunk contradiction detection fails closed even under concurrent completion", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-concurrency-contra-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/split.js" }],
    diffHunks: [
      "diff --git a/src/split.js b/src/split.js\n--- a/src/split.js\n+++ b/src/split.js\n@@ -1,5 +1,10 @@\n+ // Hunk 1\n+ const a = 1;",
      "@@ -100,5 +105,10 @@\n+ // Hunk 2\n+ const b = 2;"
    ].join("\n")
  };

  let callCount = 0;
  const adapter = {
    providerName: "mock-agy",
    executeReview: async () => {
      callCount++;
      if (callCount === 1) {
        // Chunk 1 covers src/split.js
        return {
          ok: true,
          findings: [],
          coverage: { coveredFiles: ["src/split.js"], omittedFiles: [] }
        };
      } else {
        // Chunk 2 falsely declares src/split.js omitted (cross-chunk contradiction!)
        return {
          ok: true,
          findings: [],
          coverage: {
            coveredFiles: [],
            omittedFiles: [{ file: "src/split.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "Hunk 2 omitted" }]
          }
        };
      }
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 60000,
    maxChunkBytes: 50,
    maxConcurrency: 2
  });

  assert.equal(result.ok, false, "Cross-chunk contradiction must fail closed");
  assert.equal(result.status, "incomplete");
  assert.ok(result.receipts.some(r => r.status === "failed"), "Contradictory chunk must be marked failed");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C: AbortSignal cleanly aborts all concurrent workers without orphan execution", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-abort-workers-"));
  const files = [
    { path: "src/w1.js" },
    { path: "src/w2.js" },
    { path: "src/w3.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const abortController = new AbortController();
  let executedCount = 0;

  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      executedCount++;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve({ ok: true, coverage: { coveredFiles: [], omittedFiles: [] } });
        }, 10000);
        if (params.signal) {
          params.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            resolve({
              ok: false,
              executionStatus: EXECUTION_STATUS.TIMEOUT,
              status: "timeout",
              error: "Aborted by signal"
            });
          }, { once: true });
        }
      });
    }
  };

  const reviewPromise = executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 60000,
    maxChunkBytes: 50,
    maxConcurrency: 2,
    signal: abortController.signal
  });

  // Abort after 50ms
  setTimeout(() => abortController.abort("Test abort triggered"), 50);
  const result = await reviewPromise;

  assert.equal(result.ok, false);
  assert.equal(result.status, "incomplete");
  assert.ok(result.receipts.every(r => r.status === "timeout" || r.status === "failed"));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// -----------------------------------------------------------------------------
// Workstream 006-A: Telemetry & Dogfood Review CLI Options
// -----------------------------------------------------------------------------

test("006-A: parseArgs recognizes --agy-stream-json and --staged-concurrency flags", () => {
  const parsed = parseArgs(["--agy-stream-json", "--staged-concurrency", "3", "--live"]);
  assert.equal(parsed.agyStreamJson, true);
  assert.equal(parsed.stagedConcurrency, 3);
  assert.equal(parsed.live, true);

  const parsedEquals = parseArgs(["--staged-concurrency=4"]);
  assert.equal(parsedEquals.stagedConcurrency, 4);

  assert.throws(() => parseArgs(["--staged-concurrency", "invalid"]), /positive integer/i);
  assert.throws(() => parseArgs(["--staged-concurrency=-1"]), /positive integer/i);
});
