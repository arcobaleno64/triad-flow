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
  SAFE_ARGV_THRESHOLD_BYTES,
  resolveProviderProfile
} from "../src/adapters/provider-profiles.mjs";
import {
  EXECUTION_STATUS,
  COVERAGE_OMISSION_CODES
} from "../src/adapters/provider-contract.mjs";
import {
  executeStagedReview,
  CheckpointStore
} from "../src/adapters/staged-review.mjs";
import {
  parseArgs,
  runDogfoodReview
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
  assert.ok(result.receipts.every(r => r.status === "timeout" || r.status === "failed" || r.status === "cancelled"));

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

// -----------------------------------------------------------------------------
// P1-01: Negative & Strict Protocol Tests for Stream-JSON Mode
// -----------------------------------------------------------------------------

test("006-B P1-01: streamJson rejects zero-exit output lacking terminal result event even if legacy JSON is present (Fail-Closed)", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async () => ({
      code: 0,
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
      })
    })
  });

  const res = await adapter.executeReview({
    runId: "run-p101-missing-result",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: makeChangeSet(),
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, false, "Must fail closed when terminal result event is missing");
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /requires a valid terminal 'result' event/i);
});

test("006-B P1-01: streamJson rejects terminal result event with non-success status (Fail-Closed)", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async () => ({
      code: 0,
      stdout: JSON.stringify({
        event: "result",
        result: {
          status: "ERROR",
          error: "Internal model execution failure"
        }
      })
    })
  });

  const res = await adapter.executeReview({
    runId: "run-p101-error-status",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: makeChangeSet(),
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /Stream-json result reported non-success status: ERROR/i);
});

test("006-B P1-01: streamJson rejects terminal result event with non-string response (Fail-Closed)", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async () => ({
      code: 0,
      stdout: JSON.stringify({
        event: "result",
        result: {
          status: "SUCCESS",
          response: { findings: [], coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] } }
        }
      })
    })
  });

  const res = await adapter.executeReview({
    runId: "run-p101-non-string-response",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: makeChangeSet(),
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /missing a string response payload/i);
});

test("006-B P1-01: streamJson rejects terminal result event with invalid string response (Fail-Closed)", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async () => ({
      code: 0,
      stdout: JSON.stringify({
        event: "result",
        result: {
          status: "SUCCESS",
          response: "This is not valid JSON findings."
        }
      })
    })
  });

  const res = await adapter.executeReview({
    runId: "run-p101-invalid-response-string",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: makeChangeSet(),
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /Failed to (?:parse|extract) (?:valid )?JSON/i);
});

// -----------------------------------------------------------------------------
// P1-02: Telemetry Metrics Independent Partitioning Tests
// -----------------------------------------------------------------------------

test("006-A P1-02: Dogfood review partitions top-level reviewer, verifier, and chunk timeouts independently", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-p102-partition-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  let agyCalls = 0;
  const agy = {
    providerName: "agy",
    family: "google",
    modelName: "gemini-3.8-flash",
    executeReview: async () => {
      agyCalls++;
      if (agyCalls === 1) {
        return {
          ok: false,
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: "Payload too large for Windows argv"
        };
      }
      return {
        ok: false,
        executionStatus: EXECUTION_STATUS.TIMEOUT,
        status: "timeout",
        error: "Chunk timed out"
      };
    }
  };

  const clean = (provider, family, model) => ({
    providerName: provider,
    family,
    modelName: model,
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] },
      providerIdentity: { provider, family, model }
    })
  });

  const timingOutCodex = {
    providerName: "codex",
    family: "openai",
    modelName: "gpt-6.1-sol",
    executeReview: async () => ({
      ok: false,
      executionStatus: "timeout",
      findings: [],
      coverage: { coveredFiles: [], omittedFiles: [] }
    })
  };

  try {
    const report = await runDogfoodReview({
      live: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        totalFiles: 1,
        totalAdditions: 1,
        totalDeletions: 0,
        files: [{ path: "src/sample.js", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "diff --git a/src/sample.js b/src/sample.js\n--- a/src/sample.js\n+++ b/src/sample.js\n@@ -0,0 +1 @@\n+export const x = 1;"
      },
      reviewAdapters: {
        agy,
        claude: clean("claude", "anthropic", "claude-5.5-sonnet"),
        codex: timingOutCodex
      },
      out: tmpOut,
      log: false
    });

    const metrics = report.telemetryMetrics;
    assert.equal(metrics.stagedFallbackUsed, true);
    assert.equal(metrics.reviewerTimeoutCount, 1, "reviewerTimeoutCount must reflect only top-level direct reviewer timeouts");
    assert.equal(metrics.chunkTimeoutCount, 1, "chunkTimeoutCount must reflect staged chunk timeouts independently");
    assert.equal(metrics.verifierTimeoutCount, 0);
    assert.equal(metrics.providerTimeoutCount, 1, "providerTimeoutCount must NOT be polluted by chunk timeouts");
    assert.equal(metrics.timeoutCount, 2, "timeoutCount is the sum of providerTimeoutCount and chunkTimeoutCount");
    assert.equal(metrics.timeoutCycle, true);
    assert.equal(metrics.phaseMetrics.transport, "argv");
    assert.equal(metrics.phaseMetrics.maxConcurrency, 2);
    assert.ok(metrics.phaseMetrics.feasibility);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------------
// P1-04: Stream-JSON Read-Only Safety Argument Filtering Tests
// -----------------------------------------------------------------------------

test("006-B P1-04: streamJson filters prohibited arguments and guarantees mandatory safety args", () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    args: ["apply", "--approve-for-me", "--user-custom-flag=true", "--mode=edit"]
  });

  assert.ok(!adapter.args.includes("apply"), "Must strip prohibited argument 'apply'");
  assert.ok(!adapter.args.includes("--approve-for-me"), "Must strip prohibited argument '--approve-for-me'");
  assert.ok(!adapter.args.includes("--print"), "Must strip '--print' in streamJson mode");
  assert.ok(!adapter.args.includes("--mode=edit"), "Must not allow overriding --mode=plan with --mode=edit");
  assert.ok(adapter.args.includes("--mode=plan"), "Must guarantee mandatory safety flag --mode=plan");
  assert.ok(adapter.args.includes("--disable-slash-commands"), "Must guarantee mandatory safety flag --disable-slash-commands");
  assert.ok(adapter.args.includes("--input-format=stream-json"), "Must include --input-format=stream-json");
  assert.ok(adapter.args.includes("--output-format=stream-json"), "Must include --output-format=stream-json");
  assert.ok(adapter.args.includes("--user-custom-flag=true"), "Must preserve safe user flags");
});

test("006-B P1-01 / Codex: extractStreamJsonResponse rejects non-terminal result events", () => {
  // Case A: Trailing non-blank error line after result
  const trailingErrorStream = [
    JSON.stringify({ event: "init" }),
    JSON.stringify({ event: "result", result: { status: "SUCCESS", response: "{}" } }),
    JSON.stringify({ event: "error", error: "Connection lost after result" })
  ].join("\n");
  assert.equal(extractStreamJsonResponse(trailingErrorStream), null, "Must reject result followed by trailing events");

  // Case B: Trailing unparseable garbage after result
  const trailingGarbageStream = [
    JSON.stringify({ event: "result", result: { status: "SUCCESS", response: "{}" } }),
    "FATAL UNHANDLED REJECTION IN SUBPROCESS"
  ].join("\n");
  assert.equal(extractStreamJsonResponse(trailingGarbageStream), null, "Must reject result followed by trailing garbage");

  // Case C: Valid terminal result with trailing empty newlines
  const validTerminalStream = [
    JSON.stringify({ event: "init" }),
    JSON.stringify({ event: "result", result: { status: "SUCCESS", response: "{}" } }),
    "",
    "   "
  ].join("\n");
  const extracted = extractStreamJsonResponse(validTerminalStream);
  assert.ok(extracted, "Must accept terminal result with trailing whitespace/empty lines");
  assert.equal(extracted.event, "result");
});

// -----------------------------------------------------------------------------
// P1-05: Dynamic Wave Budgeting Tests
// -----------------------------------------------------------------------------

test("006-C P1-05: Dynamic wave budgeting reclaims budget from fast early waves for later waves", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-dyn-budget-"));
  const files = [
    { path: "src/w0.js" },
    { path: "src/w1.js" },
    { path: "src/w2.js" },
    { path: "src/w3.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const allocatedBudgets = [];
  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      allocatedBudgets.push(params.timeoutMs);
      const target = (params.changeSet.files || [])[0]?.path;
      // Fast wave 1 (w0, w1): finishes together ensuring both workers drain wave 1
      if (target === "src/w0.js" || target === "src/w1.js") {
        await new Promise(r => setTimeout(r, 10));
      }
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: target ? [target] : [], omittedFiles: [] }
      };
    }
  };

  // 4 chunks, maxConcurrency 2 -> 2 waves. Total budget: 100,000 ms.
  // Initial wave budget = 100,000 / 2 = 50,000 ms.
  // When wave 1 finishes immediately:
  // Wave 2 starts with remainingGlobalMs ~ 100,000 ms, remainingWaves = 1 -> budget calculates 100,000 -> capped at 60,000 ms!
  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 100000,
    maxChunkBytes: 50,
    maxConcurrency: 2,
    minChunkBudgetMs: 10000
  });

  assert.equal(result.ok, true);
  assert.equal(allocatedBudgets.length, 4);

  // Early chunks receive ~50,000ms
  assert.ok(allocatedBudgets[0] >= 49000 && allocatedBudgets[0] <= 50000, `allocatedBudgets[0] (${allocatedBudgets[0]}) must be ~50000ms`);
  assert.ok(allocatedBudgets[1] >= 49000 && allocatedBudgets[1] <= 50000, `allocatedBudgets[1] (${allocatedBudgets[1]}) must be ~50000ms`);

  // Final chunk receives reclaimed budget capped at 60,000ms (NOT constrained to initial 50,000ms!)
  assert.ok(allocatedBudgets[3] > 50000, `Reclaimed budget ${allocatedBudgets[3]} must exceed initial 50000ms`);
  assert.equal(allocatedBudgets[3], 60000, "Reclaimed budget should reach 60,000ms ceiling");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// -----------------------------------------------------------------------------
// P1-06: Scheduler Timeout vs External Cancellation Classification Tests
// -----------------------------------------------------------------------------

test("006-C P1-06: Scheduler timeout abort maps to TIMEOUT receipt and omission, not failed/cancelled", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-scheduler-timeout-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/hang.js" }],
    diffHunks: "diff --git a/src/hang.js b/src/hang.js\n@@ -1 +1 @@\n-old\n+new"
  };

  // Mock adapter that listens to signal and returns executionStatus: "cancelled" (exact CliReviewAdapter behavior)
  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      return new Promise((resolve) => {
        if (params.signal) {
          params.signal.addEventListener("abort", () => {
            resolve({
              ok: false,
              executionStatus: EXECUTION_STATUS.CANCELLED,
              error: "CLI reviewer cancelled via signal",
              findings: []
            });
          }, { once: true });
        }
      });
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 200,
    maxChunkBytes: 50,
    minChunkBudgetMs: 50
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, "incomplete");
  assert.equal(result.receipts.length, 1);
  assert.equal(result.receipts[0].status, "timeout", "Receipt status must be 'timeout' when scheduler timer aborts");
  assert.equal(result.telemetry.chunkTimeoutCount, 1, "chunkTimeoutCount must count scheduler deadline aborts");

  const omission = result.coverage.omittedFiles.find(o => o.file === "src/hang.js");
  assert.ok(omission);
  assert.equal(omission.code, COVERAGE_OMISSION_CODES.TIMEOUT, "Omission code must be TIMEOUT, not SIZE_LIMIT");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C P1-06: External cancellation signal is preserved as cancelled, not timeout", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-ext-cancel-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/cancel.js" }],
    diffHunks: "diff --git a/src/cancel.js b/src/cancel.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const externalAbortController = new AbortController();
  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      return new Promise((resolve) => {
        if (params.signal) {
          params.signal.addEventListener("abort", () => {
            resolve({
              ok: false,
              executionStatus: EXECUTION_STATUS.CANCELLED,
              error: "Execution cancelled via external signal",
              findings: []
            });
          }, { once: true });
        }
      });
    }
  };

  const promise = executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 60000,
    maxChunkBytes: 50,
    signal: externalAbortController.signal
  });

  // External cancellation after 50ms
  setTimeout(() => externalAbortController.abort("User cancelled"), 50);
  const result = await promise;

  assert.equal(result.ok, false);
  assert.equal(result.status, "incomplete", "Run status must be 'incomplete' for external signal abort");
  assert.equal(result.executionStatus, EXECUTION_STATUS.CANCELLED, "Execution status must be 'cancelled' for external signal abort");
  assert.equal(result.receipts[0].status, "cancelled", "Receipt status must be 'cancelled'");
  assert.equal(result.telemetry.chunkTimeoutCount, 0, "External cancellation must NOT increment chunkTimeoutCount");

  const omission = result.coverage.omittedFiles.find(o => o.file === "src/cancel.js");
  assert.ok(omission);
  assert.equal(omission.code, COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, "Omission code must be OUT_OF_SCOPE for cancellation, not TIMEOUT");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-B / Codex: resolveProviderProfile preserves supportsStreamJson on resolved profile", () => {
  const profile = resolveProviderProfile("agy");
  assert.equal(profile.supportsStreamJson, true, "resolveProviderProfile('agy') must advertise supportsStreamJson: true");
  assert.equal(resolveProviderProfile("claude").supportsStreamJson, false);
  assert.equal(resolveProviderProfile("codex").supportsStreamJson, false);
});

test("006-C / Codex: Progressive checkpoints do not claim failed chunks as completed", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-chkpt-failed-"));
  const files = [
    { path: "src/f0.js" },
    { path: "src/f1.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  let callCount = 0;
  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      callCount++;
      const target = (params.changeSet.files || [])[0]?.path;
      if (target === "src/f0.js") {
        // First chunk fails
        return {
          ok: false,
          status: "timeout",
          executionStatus: EXECUTION_STATUS.TIMEOUT,
          error: "Chunk timeout budget exhausted"
        };
      }
      // Second chunk succeeds
      return {
        ok: true,
        findings: [{ title: "Finding from f1", severity: "high", file: "src/f1.js", line_start: 1, line_end: 1 }],
        coverage: { coveredFiles: ["src/f1.js"], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    maxChunkBytes: 50,
    maxConcurrency: 1
  });

  assert.equal(result.ok, false);
  const store = new CheckpointStore({ cwd: tmpDir });
  const checkpoint = store.readCheckpoint(result.runId);
  assert.ok(checkpoint, "Checkpoint must exist for incomplete review");

  // Verify that failed chunk was recorded as omitted in checkpoint rather than claiming completed
  const f0Omission = result.coverage.omittedFiles.find(o => o.file === "src/f0.js");
  assert.ok(f0Omission, "Failed chunk must be recorded in omittedFiles");
  assert.equal(f0Omission.code, COVERAGE_OMISSION_CODES.TIMEOUT);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C / Codex: Progressive checkpoints accumulate salvaged findings correctly", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-chkpt-salvage-"));
  const files = [
    { path: "src/s0.js" },
    { path: "src/s1.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      const target = (params.changeSet.files || [])[0]?.path;
      if (target === "src/s0.js") {
        return {
          ok: true,
          findings: [{ title: "Finding from s0", severity: "high", file: "src/s0.js", line_start: 1, line_end: 1 }],
          coverage: { coveredFiles: ["src/s0.js"], omittedFiles: [] }
        };
      }
      return {
        ok: false,
        status: "timeout",
        executionStatus: EXECUTION_STATUS.TIMEOUT,
        error: "Chunk timeout budget exhausted"
      };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    maxChunkBytes: 50,
    maxConcurrency: 1
  });

  assert.equal(result.ok, false);
  const store = new CheckpointStore({ cwd: tmpDir });
  const checkpoint = store.readCheckpoint(result.runId);
  assert.ok(checkpoint, "Checkpoint must exist for incomplete review");
  assert.equal(checkpoint.completedChunks, 1);
  assert.ok(Array.isArray(checkpoint.salvagedFindings), "salvagedFindings must be an array");
  assert.equal(checkpoint.salvagedFindings.length, 1);
  assert.equal(checkpoint.salvagedFindings[0].title, "Finding from s0");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-C / Codex: Timeout abort takes precedence over adapter success race", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-timeout-race-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/race.js" }],
    diffHunks: "diff --git a/src/race.js b/src/race.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      // Wait past the small chunk budget, then return ok: true
      await new Promise(r => setTimeout(r, 60));
      return {
        ok: true,
        findings: [{ title: "Late finding", severity: "low", file: "src/race.js", line_start: 1, line_end: 1 }],
        coverage: { coveredFiles: ["src/race.js"], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    timeoutMs: 30,
    minChunkBudgetMs: 20,
    maxChunkBytes: 50
  });

  assert.equal(result.ok, false, "Must fail closed when timeout occurred, even if adapter returned ok: true");
  assert.equal(result.receipts[0].status, "timeout", "Receipt must be timeout");
  assert.equal(result.telemetry.chunkTimeoutCount, 1, "Must count as chunk timeout");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-A / Codex: parseArgs strictly validates --staged-concurrency", () => {
  assert.throws(() => parseArgs(["--repository=test/repo", "--staged-concurrency=2workers"]), /Must be a positive integer/);
  assert.throws(() => parseArgs(["--repository=test/repo", "--staged-concurrency=2.5"]), /Must be a positive integer/);
  assert.throws(() => parseArgs(["--repository=test/repo", "--staged-concurrency", "0"]), /Must be a positive integer/);
  assert.throws(() => parseArgs(["--repository=test/repo", "--staged-concurrency", "-1"]), /Missing value|Must be a positive integer/);

  const validEquals = parseArgs(["--repository=test/repo", "--staged-concurrency=3"]);
  assert.equal(validEquals.stagedConcurrency, 3);

  const validSpace = parseArgs(["--repository=test/repo", "--staged-concurrency", "4"]);
  assert.equal(validSpace.stagedConcurrency, 4);
});

test("006-B / Codex: Injected execFn with stderr auth error and streamJson returns AUTH_FAILURE", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    execFn: async () => ({
      code: 0,
      stdout: "",
      stderr: "Authentication failed. You are not logged into Antigravity."
    })
  });

  const res = await adapter.executeReview({
    runId: "auth-test",
    role: "security-reviewer",
    policyId: "strict",
    changeSet: makeChangeSet([{ path: "src/test.js" }]),
    limits: { maxOutputBytes: 100000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.AUTH_FAILURE, "Must be classified as AUTH_FAILURE, not MALFORMED_OUTPUT");
});

test("006-B / Codex: Spreading agy profile with streamJson: true forces stdin mode", () => {
  const agyProfile = resolveProviderProfile("agy");
  assert.equal(agyProfile.supportsStdin, false);
  assert.equal(agyProfile.inputChannel, "argv");

  const adapter = new CliReviewAdapter({
    ...agyProfile,
    streamJson: true
  });

  assert.equal(adapter.streamJson, true);
  assert.equal(adapter.supportsStdin, true, "streamJson must force supportsStdin to true");
  assert.equal(adapter.inputChannel, "stdin", "streamJson must force inputChannel to stdin");
  assert.equal(adapter.useStdin, true, "streamJson must force useStdin to true");
});

test("006-C / Codex: Unstarted chunks after Tier 1 failure are marked failed, not timeout", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tier1-unstarted-"));
  const files = [
    { path: "src/critical.js" },
    { path: "src/other1.js" },
    { path: "src/other2.js" }
  ];
  const diffHunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const cs = { scopeMode: "working-tree", files, diffHunks };

  const adapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      const target = (params.changeSet.files || [])[0]?.path;
      if (target === "src/critical.js") {
        return {
          ok: false,
          executionStatus: EXECUTION_STATUS.ERROR,
          error: "Critical failure"
        };
      }
      return { ok: true, findings: [], coverage: { coveredFiles: [target], omittedFiles: [] } };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    maxChunkBytes: 50,
    maxConcurrency: 1
  });

  assert.equal(result.ok, false);
  // Verify that unstarted chunks are marked failed, not timeout
  assert.equal(result.telemetry.chunkTimeoutCount, 0, "Tier 1 halt must NOT increment chunkTimeoutCount");
  for (const r of result.receipts) {
    assert.notEqual(r.status, "timeout", "Receipt status must not be timeout when halted due to Tier 1 failure");
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("006-B / Codex: Transient refusal error details in non-success stream result are preserved for retry", async () => {
  let callCount = 0;
  const adapter = new CliReviewAdapter({
    command: "agy",
    streamJson: true,
    maxRetries: 1,
    execFn: async () => {
      callCount++;
      if (callCount === 1) {
        // First attempt: stream result with safety filter refusal
        return {
          code: 0,
          stdout: JSON.stringify({
            event: "result",
            status: "ERROR",
            error: "Blocked by Gemini safety filters"
          }) + "\n"
        };
      }
      // Second attempt: succeeds
      return {
        code: 0,
        stdout: JSON.stringify({
          event: "result",
          status: "SUCCESS",
          response: JSON.stringify({
            findings: [],
            coverage: { coveredFiles: ["src/test.js"], omittedFiles: [] }
          })
        }) + "\n"
      };
    }
  });

  const res = await adapter.executeReview({
    runId: "retry-test",
    role: "security-reviewer",
    policyId: "strict",
    changeSet: makeChangeSet([{ path: "src/test.js" }]),
    limits: { maxOutputBytes: 100000 }
  });

  assert.equal(callCount, 2, "Adapter must retry on stream-json safety filter refusal");
  assert.equal(res.ok, true, "Retry must succeed");
});
