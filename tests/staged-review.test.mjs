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
          ]
        };
      }
      return { ok: true, findings: [] };
    }
  };

  const result = await executeStagedReview(cs, mockAdapter, {
    cwd: tmpDir,
    maxChunkBytes: 50 // force into multi-chunk
  });

  assert.equal(result.status, "completed");
  assert.ok(result.findings.length >= 1);
  assert.equal(result.findings[0].severity, "critical");
  assert.equal(result.findings[0].cwe, "cwe-94");
  assert.ok(result.receipts.length >= 2);

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});
