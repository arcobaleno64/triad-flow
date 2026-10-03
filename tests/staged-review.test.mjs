import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  COVERAGE_OMISSION_CODES,
  evaluateCoverageContract,
  CheckpointStore,
  executeStagedReview
} from "../src/adapters/staged-review.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";

test("evaluateCoverageContract validates complete coverage and enforces Tier 1 fail-closed", () => {
  const cs = {
    files: [
      { path: "src/auth/token.js" }, // Tier 1 Critical
      { path: "src/normal.js" }      // Tier 2
    ]
  };

  // Case 1: All covered
  const res1 = evaluateCoverageContract(cs, ["src/auth/token.js", "src/normal.js"], []);
  assert.equal(res1.isComplete, true);
  assert.equal(res1.coveredPercentage, 100);

  // Case 2: Tier 1 file omitted due to size limit -> Violates Fail-Closed
  const res2 = evaluateCoverageContract(cs, ["src/normal.js"], [
    { file: "src/auth/token.js", code: COVERAGE_OMISSION_CODES.SIZE_LIMIT, reason: "Too big" }
  ]);
  assert.equal(res2.isComplete, false, "Tier 1 file cannot be omitted under size limit");
  assert.ok(res2.violations.some(v => v.includes("Tier 1 (Critical)")));

  // Case 3: Tier 2 file omitted due to generated code -> Allowed
  const res3 = evaluateCoverageContract(cs, ["src/auth/token.js"], [
    { file: "src/normal.js", code: COVERAGE_OMISSION_CODES.GENERATED, reason: "Minified bundle" }
  ]);
  assert.equal(res3.isComplete, true);
});

test("CheckpointStore saves, reads, and clears atomic review checkpoints", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-checkpoint-test-"));
  const store = new CheckpointStore({ cwd: tmpDir });
  const runId = "test-run-123";

  // Initially empty
  assert.equal(store.readCheckpoint(runId), null);

  // Save checkpoint
  store.saveCheckpoint(runId, {
    stage: "stage-2-deep-review",
    findings: [{ title: "Partial finding" }],
    completedChunks: 1
  });

  const readBack = store.readCheckpoint(runId);
  assert.ok(readBack);
  assert.equal(readBack.runId, runId);
  assert.equal(readBack.completedChunks, 1);
  assert.equal(readBack.findings[0].title, "Partial finding");

  // Clear checkpoint
  store.clearCheckpoint(runId);
  assert.equal(store.readCheckpoint(runId), null);

  // Clean up tmp dir
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview partitions chunks and executes adapter with checkpoints", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-test-"));

  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/module1.js" },
      { path: "src/module2.js" }
    ],
    diffHunks: [
      "diff --git a/src/module1.js b/src/module1.js",
      "@@ -1,2 +1,3 @@",
      "+ function evalUser(input) { return eval(input); }",
      "diff --git a/src/module2.js b/src/module2.js",
      "@@ -10 +10,2 @@",
      "+ const x = 1;"
    ].join("\n")
  };

  const mockAdapter = {
    providerName: "mock-sentry",
    executeReview: async ({ changeSet }) => {
      const targetPaths = (changeSet.files || []).map(f => f.path);
      if (changeSet.diffHunks.includes("evalUser")) {
        return {
          ok: true,
          findings: [
            {
              title: "Code Injection via eval",
              severity: "critical",
              file: "src/module1.js",
              line_start: 1,
              cwe: "CWE-94",
              evidenceSnippet: "eval(input)"
            }
          ],
          coverage: {
            coveredFiles: targetPaths,
            omittedFiles: []
          }
        };
      }
      return {
        ok: true,
        findings: [],
        coverage: {
          coveredFiles: targetPaths,
          omittedFiles: []
        }
      };
    }
  };

  const result = await executeStagedReview(cs, mockAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 50 // force into multi-chunk
  });

  assert.equal(result.status, "completed");
  assert.equal(result.ok, true);
  assert.equal(result.executionStatus, "success");
  assert.equal(result.providerIdentity?.provider, "mock-sentry");
  assert.ok(result.findings.length >= 1);
  assert.equal(result.findings[0].severity, "critical");
  assert.equal(result.findings[0].cwe, "cwe-94");
  assert.ok(result.receipts.length >= 2);

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview on chunk failure fails closed with ok=false and incomplete status", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-fail-test-"));

  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/auth/token.js" }, // Tier 1 Critical
      { path: "src/other.js" }
    ],
    diffHunks: [
      "diff --git a/src/auth/token.js b/src/auth/token.js",
      "@@ -1,1 +1,2 @@",
      "+ criticalTokenChange();",
      "diff --git a/src/other.js b/src/other.js",
      "@@ -1,1 +1,2 @@",
      "+ otherChange();"
    ].join("\n")
  };

  const failingAdapter = {
    providerName: "failing-sentry",
    executeReview: async ({ changeSet }) => {
      if (changeSet.diffHunks.includes("criticalTokenChange")) {
        return {
          ok: false,
          status: "timeout",
          error: "Process timed out"
        };
      }
      return { ok: true, findings: [{ title: "Non-critical finding", severity: "low" }] };
    }
  };

  const result = await executeStagedReview(cs, failingAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 50
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.ok, false, "Incomplete staged execution must fail closed (ok=false)");
  assert.equal(result.executionStatus, "incomplete");
  assert.ok(result.error);
  assert.equal(result.providerIdentity?.provider, "failing-sentry");

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview rejects empty provider coverage with omission and fails closed", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-empty-cov-"));

  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/auth/token.js" }],
    diffHunks: "diff --git a/src/auth/token.js b/src/auth/token.js\n--- a/src/auth/token.js\n+++ b/src/auth/token.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const emptyCoverageAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: [], omittedFiles: [{ path: "src/auth/token.js", code: COVERAGE_OMISSION_CODES.SIZE_LIMIT, reason: "size limit" }] }
    })
  };

  const result = await executeStagedReview(cs, emptyCoverageAdapter, {
    cwd: tmpDir
  });

  assert.equal(result.ok, false, "Empty provider coverage must NOT be promoted to full coverage");
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.coveredFiles.length, 0);
  assert.equal(result.coverage.isComplete, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview marks run incomplete if any chunk receipt timed out", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-timeout-receipt-"));

  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/normal.js" }],
    diffHunks: "diff --git a/src/normal.js b/src/normal.js\n--- a/src/normal.js\n+++ b/src/normal.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const timeoutAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: false,
      status: "timeout",
      error: "Provider timed out"
    })
  };

  const result = await executeStagedReview(cs, timeoutAdapter, {
    cwd: tmpDir
  });

  assert.equal(result.ok, false, "Timeout chunk must cause staged review to fail closed (ok=false)");
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.status, "incomplete");
  assert.ok(result.receipts.some(r => r.status === "timeout"));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview ignores provider coverage claims outside chunk targetFiles", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-overclaim-"));

  const cs = {
    scopeMode: "revision-range",
    files: [
      { path: "src/chunk1.js" },
      { path: "src/chunk2.js" }
    ],
    diffHunks: [
      "diff --git a/src/chunk1.js b/src/chunk1.js\n--- a/src/chunk1.js\n+++ b/src/chunk1.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/chunk2.js b/src/chunk2.js\n--- a/src/chunk2.js\n+++ b/src/chunk2.js\n@@ -1 +1 @@\n-old\n+new"
    ].join("\n")
  };

  const overclaimAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: {
        coveredFiles: ["src/chunk1.js", "src/chunk2.js", "unrelated/secret.env"],
        omittedFiles: [{ path: "unrelated/other.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "ignored" }]
      }
    })
  };

  const result = await executeStagedReview(cs, overclaimAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 50
  });

  assert.equal(result.ok, true);
  assert.ok(!result.coverage.coveredFiles.includes("unrelated/secret.env"));
  assert.ok(!result.coverage.omittedFiles.some(o => o.file?.includes("unrelated/other.js")));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview fails closed when chunkResult has no coverage object (Finding 2)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-nocov-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/api.js" }],
    diffHunks: "diff --git a/src/api.js b/src/api.js\n--- a/src/api.js\n+++ b/src/api.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const noCoverageAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: true,
      findings: []
    })
  };

  const result = await executeStagedReview(cs, noCoverageAdapter, { cwd: tmpDir });
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.coveredFiles.length, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview safely handles null or non-object omissions (Finding 3)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-null-omit-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/api.js" }],
    diffHunks: "diff --git a/src/api.js b/src/api.js\n--- a/src/api.js\n+++ b/src/api.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const malformedOmitAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: {
        coveredFiles: ["src/api.js"],
        omittedFiles: [null, undefined, "not-an-object"]
      }
    })
  };

  const result = await executeStagedReview(cs, malformedOmitAdapter, { cwd: tmpDir });
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.isComplete, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("executeStagedReview enforces per-chunk coverage: later chunk returning empty coverage fails closed (Finding 7)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-hunk-conceal-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/large.js" }],
    diffHunks: [
      "diff --git a/src/large.js b/src/large.js\n--- a/src/large.js\n+++ b/src/large.js\n@@ -1,5 +1,10 @@\n+ // Hunk 1\n+ const a = 1;",
      "@@ -100,5 +105,10 @@\n+ // Hunk 2\n+ const b = 2;"
    ].join("\n")
  };

  let callCount = 0;
  const partialCoverageAdapter = {
    providerName: "mock-agy",
    executeReview: async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: true,
          findings: [],
          coverage: { coveredFiles: ["src/large.js"], omittedFiles: [] }
        };
      }
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: [], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, partialCoverageAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 100
  });

  assert.equal(result.ok, false, "Must not conceal unreviewed chunk of the same file");
  assert.equal(result.executionStatus, "incomplete");
  assert.ok(result.receipts.some(r => r.status === "failed" || r.status === "incomplete"));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-1 Test A: evaluateCoverageContract rejects file present in both coveredFiles and omittedFiles", () => {
  const cs = {
    files: [
      { path: "src/normal.js" }
    ]
  };
  const res = evaluateCoverageContract(cs, ["src/normal.js"], [
    { file: "src/normal.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "Declared omitted" }
  ]);
  assert.equal(res.isComplete, false);
  assert.ok(res.violations.some(v => v.includes("contradictory coverage declaration") && v.includes("src/normal.js")));
});

test("Regression P1-1 Test B: executeStagedReview rejects same chunk returning file in covered and omitted", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-intra-contra-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/normal.js" }],
    diffHunks: "diff --git a/src/normal.js b/src/normal.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const contradictoryAdapter = {
    providerName: "mock-agy",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: {
        coveredFiles: ["src/normal.js"],
        omittedFiles: [{ file: "src/normal.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "Scope exclusion" }]
      }
    })
  };

  const result = await executeStagedReview(cs, contradictoryAdapter, { cwd: tmpDir });
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.isComplete, false);
  assert.ok(result.violations.some(v => v.includes("contradictory coverage declaration")));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-1 Test C: executeStagedReview rejects split file covered in chunk 1 but omitted in chunk 2", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-cross-contra-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/split.js" }],
    diffHunks: [
      "diff --git a/src/split.js b/src/split.js\n--- a/src/split.js\n+++ b/src/split.js\n@@ -1,5 +1,10 @@\n+ // Hunk 1\n+ const a = 1;",
      "@@ -100,5 +105,10 @@\n+ // Hunk 2\n+ const b = 2;"
    ].join("\n")
  };

  let callCount = 0;
  const splitContradictoryAdapter = {
    providerName: "mock-claude",
    executeReview: async () => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: true,
          findings: [],
          coverage: { coveredFiles: ["src/split.js"], omittedFiles: [] }
        };
      }
      return {
        ok: true,
        findings: [],
        coverage: {
          coveredFiles: [],
          omittedFiles: [{ file: "src/split.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "Hunk 2 omitted" }]
        }
      };
    }
  };

  const result = await executeStagedReview(cs, splitContradictoryAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 100
  });

  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.isComplete, false);
  assert.ok(result.violations.some(v => v.includes("contradictory coverage declaration")));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-2 Test D: Multi-chunk timeout allocation (T_total=120000, N=4 -> <=30000ms)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-timeout-d-"));
  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/f1.js" },
      { path: "src/f2.js" },
      { path: "src/f3.js" },
      { path: "src/f4.js" }
    ],
    diffHunks: [
      "diff --git a/src/f1.js b/src/f1.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/f2.js b/src/f2.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/f3.js b/src/f3.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/f4.js b/src/f4.js\n@@ -1 +1 @@\n-old\n+new"
    ].join("\n")
  };

  const recordedTimeouts = [];
  const recordingAdapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      recordedTimeouts.push(params.timeoutMs);
      const target = (params.changeSet.files || [])[0]?.path;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: target ? [target] : [], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, recordingAdapter, {
    cwd: tmpDir,
    timeoutMs: 120000,
    maxChunkBytes: 50
  });

  assert.equal(recordedTimeouts.length, 4);
  for (const t of recordedTimeouts) {
    assert.ok(t <= 30000, `per-chunk timeout ${t} should be <= 30000ms`);
  }
  assert.equal(result.ok, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-2 Test E: 60s ceiling (T_total=600000, N=2 -> per-chunk timeout <= 60000ms)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-timeout-e-"));
  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/f1.js" },
      { path: "src/f2.js" }
    ],
    diffHunks: [
      "diff --git a/src/f1.js b/src/f1.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/f2.js b/src/f2.js\n@@ -1 +1 @@\n-old\n+new"
    ].join("\n")
  };

  const recordedTimeouts = [];
  const recordingAdapter = {
    providerName: "mock-agy",
    executeReview: async (params) => {
      recordedTimeouts.push(params.timeoutMs);
      const target = (params.changeSet.files || [])[0]?.path;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: target ? [target] : [], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, recordingAdapter, {
    cwd: tmpDir,
    timeoutMs: 600000,
    maxChunkBytes: 50
  });

  assert.equal(recordedTimeouts.length, 2);
  for (const t of recordedTimeouts) {
    assert.equal(t, 60000, `per-chunk timeout ${t} must not exceed 60000ms ceiling`);
  }
  assert.equal(result.ok, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-2 Test F: Global budget exhaustion marks later chunks uninvoked and omitted with TIMEOUT", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-timeout-f-"));
  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/f1.js" },
      { path: "src/f2.js" }
    ],
    diffHunks: [
      "diff --git a/src/f1.js b/src/f1.js\n@@ -1 +1 @@\n-old\n+new",
      "diff --git a/src/f2.js b/src/f2.js\n@@ -1 +1 @@\n-old\n+new"
    ].join("\n")
  };

  let callCount = 0;
  const slowAdapter = {
    providerName: "mock-agy",
    executeReview: async () => {
      callCount++;
      // Simulate chunk 0 taking 150ms when totalBudget is 100ms
      await new Promise(r => setTimeout(r, 150));
      return {
        ok: true,
        findings: [{ title: "Finding from chunk 1", severity: "high", file: "src/f1.js", line_start: 1, line_end: 1 }],
        coverage: { coveredFiles: ["src/f1.js"], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, slowAdapter, {
    cwd: tmpDir,
    timeoutMs: 100, // Small budget exhausted by chunk 0
    maxChunkBytes: 50
  });

  assert.equal(callCount, 1, "Chunk 2 must not be invoked after budget exhausted");
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  const f2Omission = result.coverage.omittedFiles.find(o => o.file === "src/f2.js");
  assert.ok(f2Omission, "src/f2.js must be in omittedFiles");
  assert.equal(f2Omission.code, COVERAGE_OMISSION_CODES.TIMEOUT);
  assert.equal(result.findings.length, 1, "Findings from chunk 0 must be salvaged");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression P1-2 Test G: Retry/deadline interaction prevents retry from exceeding timeout budget", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-timeout-g-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/retry.js" }],
    diffHunks: "diff --git a/src/retry.js b/src/retry.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const retryAdapter = {
    providerName: "mock-gemini",
    executeReview: async (params) => {
      // Simulate timeout when retry backoff (1000ms) would exceed remaining budget
      if (params.timeoutMs < 500) {
        return {
          ok: false,
          executionStatus: "timeout",
          status: "timeout",
          error: "Timeout budget exhausted during retry backoff"
        };
      }
      return { ok: true, coverage: { coveredFiles: ["src/retry.js"], omittedFiles: [] } };
    }
  };

  const startTime = Date.now();
  const result = await executeStagedReview(cs, retryAdapter, {
    cwd: tmpDir,
    timeoutMs: 200 // Less than backoff sleep
  });
  const elapsed = Date.now() - startTime;

  assert.ok(elapsed < 2000, `Execution elapsed (${elapsed}ms) must not escape global budget`);
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  const omission = result.coverage.omittedFiles.find(o => o.file === "src/retry.js");
  assert.ok(omission);
  assert.equal(omission.code, COVERAGE_OMISSION_CODES.TIMEOUT);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression 4: Mixed Tier-2 coverage with authorized omission satisfies coverage contract", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-mixed-t2-"));
  const cs = {
    scopeMode: "working-tree",
    files: [
      { path: "src/normal1.js" }, // Tier 2
      { path: "src/normal2.js" }  // Tier 2
    ],
    diffHunks: [
      "diff --git a/src/normal1.js b/src/normal1.js\n--- a/src/normal1.js\n+++ b/src/normal1.js\n@@ -1,2 +1,3 @@\n+ const a = 1;",
      "diff --git a/src/normal2.js b/src/normal2.js\n--- a/src/normal2.js\n+++ b/src/normal2.js\n@@ -1,2 +1,3 @@\n+ const b = 2;"
    ].join("\n")
  };

  const mixedAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: {
        coveredFiles: ["src/normal1.js"],
        omittedFiles: [
          { path: "src/normal2.js", code: COVERAGE_OMISSION_CODES.GENERATED, reason: "Compiled bundle" }
        ]
      }
    })
  };

  const result = await executeStagedReview(cs, mixedAdapter, { cwd: tmpDir });
  assert.equal(result.ok, true);
  assert.equal(result.executionStatus, "success");
  assert.equal(result.coverage.isComplete, true);
  assert.equal(result.coverage.coveredPercentage, 50);
  assert.equal(result.coverage.omittedFiles.length, 1);
  assert.equal(result.coverage.omittedFiles[0].code, COVERAGE_OMISSION_CODES.GENERATED);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression 5: Tier-1 source omission fails closed for every omission code", () => {
  const cs = {
    files: [
      { path: "src/auth/token.js" }, // Tier 1 Critical
      { path: "src/normal.js" }      // Tier 2
    ]
  };

  // Test every single code in COVERAGE_OMISSION_CODES for Tier 1 file
  for (const [codeKey, codeVal] of Object.entries(COVERAGE_OMISSION_CODES)) {
    const res = evaluateCoverageContract(cs, ["src/normal.js"], [
      { file: "src/auth/token.js", code: codeVal, reason: `Reason for ${codeKey}` }
    ]);
    assert.equal(res.isComplete, false, `Tier 1 file omission under ${codeKey} (${codeVal}) must fail closed`);
    assert.ok(
      res.violations.some(v => v.includes("Tier 1 (Critical)") && v.includes("src/auth/token.js")),
      `Violation must mention Tier 1 (Critical) for code ${codeVal}`
    );
  }
});

test("Regression 6: Tier-2 source omission requires explicit authorized code + non-empty reason", () => {
  const cs = {
    files: [{ path: "src/normal.js" }] // Tier 2
  };

  // Missing code -> fails closed
  const resMissingCode = evaluateCoverageContract(cs, [], [
    { file: "src/normal.js", reason: "Valid reason without code" }
  ]);
  assert.equal(resMissingCode.isComplete, false);
  assert.ok(resMissingCode.violations.some(v => v.includes("missing or unauthorized code")));

  // Unknown/unauthorized code -> fails closed
  const resUnknownCode = evaluateCoverageContract(cs, [], [
    { file: "src/normal.js", code: "OMIT_UNKNOWN_CUSTOM", reason: "Valid reason with invalid code" }
  ]);
  assert.equal(resUnknownCode.isComplete, false);
  assert.ok(resUnknownCode.violations.some(v => v.includes("missing or unauthorized code")));

  // Empty reason -> fails closed
  const resEmptyReason = evaluateCoverageContract(cs, [], [
    { file: "src/normal.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "   " }
  ]);
  assert.equal(resEmptyReason.isComplete, false);
  assert.ok(resEmptyReason.violations.some(v => v.includes("missing or empty reason")));

  // Explicit authorized code + non-empty reason -> satisfies accounting
  const resValid = evaluateCoverageContract(cs, [], [
    { file: "src/normal.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "Scope exclusion confirmed" }
  ]);
  assert.equal(resValid.isComplete, true);
  assert.equal(resValid.violations.length, 0);
  assert.equal(resValid.coveredPercentage, 0);
});

test("Regression 7: Normalized CLI provider path preserves valid code and rejects missing code from staged evidence", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-cli-path-"));
  const cs = {
    schemaVersion: "1.0.0",
    contentDigest: "a".repeat(64),
    scopeMode: "working-tree",
    files: [
      { path: "src/worker.js" }, // Tier 2
      { path: "src/vendor.js" }  // Tier 2
    ],
    diffHunks: [
      "diff --git a/src/worker.js b/src/worker.js\n--- a/src/worker.js\n+++ b/src/worker.js\n@@ -1,2 +1,3 @@\n+ const w = 1;",
      "diff --git a/src/vendor.js b/src/vendor.js\n--- a/src/vendor.js\n+++ b/src/vendor.js\n@@ -1,2 +1,3 @@\n+ const v = 2;"
    ].join("\n")
  };

  // Part A: Valid code survives complete path (CliReviewAdapter -> validateProviderOutput -> executeStagedReview)
  const validExec = async () => ({
    stdout: JSON.stringify({
      findings: [],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: [
          { path: "src/vendor.js", code: COVERAGE_OMISSION_CODES.GENERATED, reason: "Vendor bundle" }
        ]
      }
    })
  });
  const validAdapter = new CliReviewAdapter({ execFn: validExec, providerName: "cli-macro" });
  const validResult = await executeStagedReview(cs, validAdapter, { cwd: tmpDir });

  assert.equal(validResult.ok, true, "Valid code must produce ok=true across complete pipeline");
  assert.equal(validResult.executionStatus, "success");
  assert.equal(validResult.coverage.isComplete, true);
  const vendorOmission = validResult.coverage.omittedFiles.find(o => o.file.includes("vendor.js"));
  assert.ok(vendorOmission, "vendor.js omission must exist");
  assert.equal(vendorOmission.code, COVERAGE_OMISSION_CODES.GENERATED, "Authorized code must survive complete pipeline");
  assert.equal(vendorOmission.reason, "Vendor bundle");

  // Part B: Missing code in CLI output cannot become successful staged evidence
  const missingCodeExec = async () => ({
    stdout: JSON.stringify({
      findings: [],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: [
          { path: "src/vendor.js", reason: "Vendor bundle without code" }
        ]
      }
    })
  });
  const missingCodeAdapter = new CliReviewAdapter({ execFn: missingCodeExec, providerName: "cli-macro" });
  const missingCodeResult = await executeStagedReview(cs, missingCodeAdapter, { cwd: tmpDir });

  assert.equal(missingCodeResult.ok, false, "Missing code must fail closed across complete pipeline");
  assert.notEqual(missingCodeResult.executionStatus, "success");
  assert.equal(missingCodeResult.coverage.isComplete, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression 8: evaluateCoverageContract never throws on stateful throwing getter omission (R1 hardening)", () => {
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/worker.js" }]
  };

  let reads = 0;
  const omission = {
    path: "src/worker.js",
    reason: "Valid reason",
    get code() {
      if (++reads === 1) return null;
      throw new Error("diagnostic getter threw");
    }
  };

  let res;
  assert.doesNotThrow(() => {
    res = evaluateCoverageContract(cs, [], [omission]);
  });

  assert.equal(res.isComplete, false);
  assert.ok(res.violations.some(v => v.includes("missing or unauthorized code")));
});

test("Regression 9: evaluateCoverageContract never throws on revoked Proxy omissions or lists (R1 hardening)", () => {
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/worker.js" }]
  };

  const makeRevoked = () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  };

  let res1;
  assert.doesNotThrow(() => {
    res1 = evaluateCoverageContract(cs, [], [makeRevoked()]);
  });
  assert.equal(res1.isComplete, false);

  let res2;
  assert.doesNotThrow(() => {
    res2 = evaluateCoverageContract(cs, makeRevoked(), makeRevoked());
  });
  assert.equal(res2.isComplete, false);
});

test("Regression 10: executeStagedReview never throws on stateful throwing getter omission in chunk result (P2 hardening)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-staged-getter-"));
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/worker.js", riskTier: 2, additions: 200, deletions: 10 }],
    diffHunks: "diff --git a/src/worker.js b/src/worker.js\n@@ -1 +1 @@\n-old\n+new"
  };

  let reads = 0;
  const hostileOmission = {
    path: "src/worker.js",
    reason: "Valid reason",
    get code() {
      if (++reads === 1) return "OMIT_GENERATED";
      throw new Error("stateful getter threw on second access");
    }
  };

  const hostileAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: {
        coveredFiles: [],
        omittedFiles: [hostileOmission]
      }
    })
  };

  let stagedResult;
  await assert.doesNotReject(async () => {
    stagedResult = await executeStagedReview(cs, hostileAdapter, { cwd: tmpDir });
  });

  assert.ok(stagedResult);
  assert.equal(stagedResult.ok, true);
  assert.equal(stagedResult.coverage.isComplete, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression 11: evaluateCoverageContract and executeStagedReview reject revoked omission list or [revokedProxy] even when coverage is complete", async () => {
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/worker.js", additions: 10, deletions: 0 }],
    diffHunks: "diff --git a/src/worker.js b/src/worker.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const makeRevoked = () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  };

  // 1. Direct evaluateCoverageContract with covered worker.js and revoked omission-list Proxy
  const res1 = evaluateCoverageContract(cs, ["src/worker.js"], makeRevoked());
  assert.equal(res1.isComplete, false);
  assert.ok(res1.violations.length > 0);

  // 2. Direct evaluateCoverageContract with covered worker.js and [revokedProxy]
  const res2 = evaluateCoverageContract(cs, ["src/worker.js"], [makeRevoked()]);
  assert.equal(res2.isComplete, false);
  assert.ok(res2.violations.length > 0);

  // 3. executeStagedReview with covered worker.js and revoked omission-list Proxy
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-staged-revoked-"));
  const revokedListAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: makeRevoked()
      }
    })
  };

  const stagedResult1 = await executeStagedReview(cs, revokedListAdapter, { cwd: tmpDir });
  assert.equal(stagedResult1.ok, false);
  assert.equal(stagedResult1.executionStatus, "incomplete");
  assert.equal(stagedResult1.coverage.isComplete, false);

  // 4. executeStagedReview with covered worker.js and [revokedProxy]
  const revokedItemAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: [makeRevoked()]
      }
    })
  };

  const stagedResult2 = await executeStagedReview(cs, revokedItemAdapter, { cwd: tmpDir });
  assert.equal(stagedResult2.ok, false);
  assert.equal(stagedResult2.executionStatus, "incomplete");
  assert.equal(stagedResult2.coverage.isComplete, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Regression 12: executeStagedReview and evaluateCoverageContract handle throw null and revoked findings without unhandled rejection", async () => {
  const cs = {
    scopeMode: "working-tree",
    files: [{ path: "src/worker.js", additions: 10, deletions: 0 }],
    diffHunks: "diff --git a/src/worker.js b/src/worker.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const makeRevoked = () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  };

  // 1. evaluateCoverageContract on changeSet throwing null
  const hostileCs = new Proxy({}, {
    get(target, prop) {
      if (prop === "files") throw null;
      return target[prop];
    }
  });
  let res;
  assert.doesNotThrow(() => {
    res = evaluateCoverageContract(hostileCs, ["src/worker.js"], []);
  });
  assert.equal(res.isComplete, false);

  // 2. executeStagedReview with revoked findings
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-staged-findings-"));
  const revokedFindingsAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: makeRevoked(),
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };

  let res2;
  await assert.doesNotReject(async () => {
    res2 = await executeStagedReview(cs, revokedFindingsAdapter, { cwd: tmpDir });
  });
  assert.equal(res2.ok, false);
  assert.equal(res2.executionStatus, "incomplete");
  assert.equal(res2.coverage.isComplete, false);

  // 3. executeStagedReview with [revokedProxy] as finding item
  const revokedItemFindingsAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [makeRevoked()],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };

  let res3;
  await assert.doesNotReject(async () => {
    res3 = await executeStagedReview(cs, revokedItemFindingsAdapter, { cwd: tmpDir });
  });
  assert.equal(res3.ok, false);
  assert.equal(res3.executionStatus, "incomplete");
  assert.equal(res3.coverage.isComplete, false);

  // 4. executeStagedReview with throwing toJSON finding item
  const throwingJsonFindingsAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [{
        title: "Trap",
        severity: "high",
        toJSON() {
          throw null;
        }
      }],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };

  let res4;
  await assert.doesNotReject(async () => {
    res4 = await executeStagedReview(cs, throwingJsonFindingsAdapter, { cwd: tmpDir });
  });
  assert.equal(res4.ok, false);
  assert.equal(res4.executionStatus, "incomplete");
  assert.equal(res4.coverage.isComplete, false);

  // 5. executeStagedReview with fractional array length findings
  const fractionalFindingsAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: new Proxy([{ title: "X", severity: "high", file: "src/worker.js" }], {
        get: (t, k) => k === "length" ? 0.5 : t[k]
      }),
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };

  let res5;
  await assert.doesNotReject(async () => {
    res5 = await executeStagedReview(cs, fractionalFindingsAdapter, { cwd: tmpDir });
  });
  assert.equal(res5.ok, false);
  assert.equal(res5.executionStatus, "incomplete");
  assert.equal(res5.coverage.isComplete, false);

  // 6. executeStagedReview with adapter throwing null
  const throwNullAdapter = {
    providerName: "mock-provider",
    executeReview: async () => {
      throw null;
    }
  };
  let throwNullRes;
  await assert.doesNotReject(async () => {
    throwNullRes = await executeStagedReview(cs, throwNullAdapter, { cwd: tmpDir });
  });
  assert.equal(throwNullRes.ok, false);
  assert.equal(throwNullRes.executionStatus, "incomplete");

  // 7. executeStagedReview with { title: {} } finding
  const hostileTitleAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [{ title: {}, severity: "high", file: "src/worker.js" }],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };
  let res7;
  await assert.doesNotReject(async () => {
    res7 = await executeStagedReview(cs, hostileTitleAdapter, { cwd: tmpDir });
  });
  assert.equal(res7.ok, false);
  assert.equal(res7.executionStatus, "incomplete");
  assert.equal(res7.coverage.isComplete, false);

  // 8. executeStagedReview with { severity: { toString: null } } finding
  const hostileSeverityAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [{ title: "SQLi", severity: { toString: null }, file: "src/worker.js" }],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };
  let res8;
  await assert.doesNotReject(async () => {
    res8 = await executeStagedReview(cs, hostileSeverityAdapter, { cwd: tmpDir });
  });
  assert.equal(res8.ok, false);
  assert.equal(res8.executionStatus, "incomplete");
  assert.equal(res8.coverage.isComplete, false);

  // 9. executeStagedReview with { sources: {} } finding
  const hostileSourcesAdapter = {
    providerName: "mock-provider",
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [{ title: "SQLi", severity: "high", file: "src/worker.js", sources: {} }],
      coverage: {
        coveredFiles: ["src/worker.js"],
        omittedFiles: []
      }
    })
  };
  let res9;
  await assert.doesNotReject(async () => {
    res9 = await executeStagedReview(cs, hostileSourcesAdapter, { cwd: tmpDir });
  });
  assert.equal(res9.ok, false);
  assert.equal(res9.executionStatus, "incomplete");
  assert.equal(res9.coverage.isComplete, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});



test("Finding B: earlier non-critical failure followed by success remains incomplete in final evidence", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-b-fail-then-success-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/first.js" }, { path: "src/second.js" }],
    diffHunks: [
      "diff --git a/src/first.js b/src/first.js\n--- a/src/first.js\n+++ b/src/first.js\n@@ -1 +1 @@\n-old1\n+new1",
      "diff --git a/src/second.js b/src/second.js\n--- a/src/second.js\n+++ b/src/second.js\n@@ -1 +1 @@\n-old2\n+new2"
    ].join("\n")
  };

  let callCount = 0;
  const adapter = {
    providerName: "mock-b",
    executeReview: async ({ changeSet }) => {
      callCount++;
      const target = changeSet.files[0].path;
      if (target === "src/first.js") {
        return { ok: false, executionStatus: "error", status: "error", error: "first chunk failed" };
      }
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: ["src/second.js"], omittedFiles: [] }
      };
    }
  };

  const result = await executeStagedReview(cs, adapter, {
    cwd: tmpDir,
    maxChunkBytes: 80
  });

  assert.equal(callCount, 2, "Non-critical failure may continue to later chunks");
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.equal(result.coverage.isComplete, false);
  assert.ok(result.receipts.some(r => r.status === "failed" && r.chunkIndex === 1));
  assert.ok(result.receipts.some(r => r.status === "completed" && r.chunkIndex === 2));
  assert.ok(result.coverage.omittedFiles.some(o => o.file === "src/first.js"));

  const store = new CheckpointStore({ cwd: tmpDir });
  const checkpoint = store.readCheckpoint(result.runId);
  assert.ok(checkpoint, "Incomplete run keeps its latest checkpoint");
  assert.equal(checkpoint.completedChunks, 2, "Current checkpoint records the later successful index, not true cumulative success count");
  assert.equal(checkpoint.omittedFiles, undefined, "Current successful checkpoint overwrites prior persisted omission history");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Finding C: malformed findings array is atomic and cannot salvage a valid prefix", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-staged-c-atomic-"));
  const cs = {
    scopeMode: "revision-range",
    files: [{ path: "src/atomic.js" }],
    diffHunks: "diff --git a/src/atomic.js b/src/atomic.js\n--- a/src/atomic.js\n+++ b/src/atomic.js\n@@ -1 +1 @@\n-old\n+new"
  };

  const adapter = {
    providerName: "mock-c",
    executeReview: async () => ({
      ok: true,
      findings: [
        { title: "valid prefix must not survive", severity: "high", file: "src/atomic.js", line_start: 1, line_end: 1 },
        null
      ],
      coverage: { coveredFiles: ["src/atomic.js"], omittedFiles: [] }
    })
  };

  const result = await executeStagedReview(cs, adapter, { cwd: tmpDir });
  assert.equal(result.ok, false);
  assert.equal(result.executionStatus, "incomplete");
  assert.deepEqual(result.findings, [], "Rejected provider output must contribute zero findings");

  const store = new CheckpointStore({ cwd: tmpDir });
  const checkpoint = store.readCheckpoint(result.runId);
  assert.ok(checkpoint);
  assert.deepEqual(checkpoint.salvagedFindings, [], "Malformed array must not persist a valid prefix into salvage state");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
