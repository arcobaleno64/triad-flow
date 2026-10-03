/**
 * Contract & Smoke Tests for Track D1 Shadow Dogfood Review
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  parseArgs,
  runDogfoodReview,
  classifyDogfoodFileRisk,
  filterChangeSetExclusions,
  getCurrentCommitSha,
  getCurrentBranch
} from "../scripts/dogfood-review.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

test("Dogfood Contract 1: parseArgs correctly parses flags", () => {
  const def = parseArgs([]);
  assert.equal(def.live, false);
  assert.equal(def.mock, true);
  assert.equal(def.base, "main");
  assert.equal(def.head, "HEAD");
  assert.equal(def.out, "dogfood-run.json");

  const live = parseArgs(["--live", "--base", "origin/main", "--out", "custom.json"]);
  assert.equal(live.live, true);
  assert.equal(live.mock, false);
  assert.equal(live.base, "origin/main");
  assert.equal(live.out, "custom.json");
});

test("Dogfood Contract 2: runDogfoodReview in mock mode executes and generates dogfood-run.json", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-dogfood-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  try {
    const report = await runDogfoodReview({
      mock: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 10,
        totalDeletions: 2,
        files: [{ path: "src/index.js", additions: 10, deletions: 2, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.schemaVersion, "1.0.0");
    assert.equal(report.track, "Track D1: SHADOW_DOGFOOD");
    assert.equal(report.authority, "NONE (ADVISORY_ONLY)");
    assert.ok(fs.existsSync(tmpOut));

    const onDisk = JSON.parse(fs.readFileSync(tmpOut, "utf8"));
    assert.equal(onDisk.authority, "NONE (ADVISORY_ONLY)");
    assert.ok(onDisk.providerTelemetry.agy);
    assert.ok(onDisk.providerTelemetry.claude);
    assert.ok(onDisk.providerTelemetry.codex);
    assert.equal(onDisk.advisoryGate.effectiveMergeAuthority, "NONE");
    assert.equal(onDisk.advisoryGate.mergeBlockedInProduction, false);
    assert.equal(typeof onDisk.advisoryGate.simulatedGateBlock, "boolean");
    assert.ok(typeof onDisk.telemetryMetrics.totalDurationMs === "number");
    assert.ok(typeof onDisk.telemetryMetrics.reviewerPhaseDurationMs === "number");
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Dogfood Contract 3: CLI Subprocess --help displays usage and exits 0", () => {
  const res = spawnSync("node", ["scripts/dogfood-review.mjs", "--help"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("Shadow Dogfood Review"));
  assert.ok(res.stdout.includes("--live"));
  assert.ok(res.stdout.includes("--mock"));
});

test("Dogfood Contract 4: parseArgs rejects unknown CLI arguments and invalid timeouts", () => {
  assert.throws(() => parseArgs(["--livee"]), /Unknown argument: '--livee'/);
  assert.throws(() => parseArgs(["--timeout", "abc"]), /Invalid --timeout value: 'abc'/);
  assert.throws(() => parseArgs(["--timeout=-10"]), /Invalid --timeout value: '-10'/);
  assert.throws(() => parseArgs(["--base"]), /Missing value for --base/);
});

test("Dogfood Contract 5: classifyDogfoodFileRisk classifies security paths as Tier 1", () => {
  assert.equal(classifyDogfoodFileRisk(".github/workflows/ci.yml"), 1);
  assert.equal(classifyDogfoodFileRisk("src/core/harness.mjs"), 1);
  assert.equal(classifyDogfoodFileRisk("src/adapters/provider-contract.mjs"), 1);
  assert.equal(classifyDogfoodFileRisk("scripts/bump-version.mjs"), 1);
  assert.equal(classifyDogfoodFileRisk("docs/README.md"), 2);
  assert.equal(classifyDogfoodFileRisk("src/utils/formatter.js"), 2);
});

test("Dogfood Contract 6: filterChangeSetExclusions handles renames symmetrically between files and diff (Finding 3)", () => {
  // Case A: src/old.mjs renamed into excluded file dogfood-run.json
  const renameDiff = [
    "diff --git a/src/old.mjs b/dogfood-run.json",
    "similarity index 90%",
    "rename from src/old.mjs",
    "rename to dogfood-run.json",
    "--- a/src/old.mjs",
    "+++ b/dogfood-run.json",
    "@@ -1,2 +1,2 @@",
    "- old content",
    "+ new content"
  ].join("\n");

  const csRename = {
    files: [
      { path: "dogfood-run.json", oldPath: "src/old.mjs", additions: 1, deletions: 1 },
      { path: "src/normal.js", additions: 5, deletions: 0 }
    ],
    diffHunks: renameDiff + "\n" + [
      "diff --git a/src/normal.js b/src/normal.js",
      "--- a/src/normal.js",
      "+++ b/src/normal.js",
      "@@ -1 +1 @@",
      "+ console.log(1);"
    ].join("\n")
  };

  const filtered = filterChangeSetExclusions(csRename, ["dogfood-run.json"]);
  // Source src/old.mjs was not excluded, so both diff chunk and file entry must be retained!
  assert.ok(filtered.diffHunks.includes("diff --git a/src/old.mjs b/dogfood-run.json"));
  assert.equal(filtered.files.length, 2, "Retained rename must preserve file entry in files");
  assert.equal(filtered.totalAdditions, 6);
  assert.equal(filtered.totalDeletions, 1);

  // Case B: Both source and destination in exclusion list
  const filteredBoth = filterChangeSetExclusions(csRename, ["dogfood-run.json", "src/old.mjs"]);
  assert.ok(!filteredBoth.diffHunks.includes("diff --git a/src/old.mjs b/dogfood-run.json"));
  assert.equal(filteredBoth.files.length, 1);
  assert.equal(filteredBoth.files[0].path, "src/normal.js");
  assert.equal(filteredBoth.totalAdditions, 5);
  assert.equal(filteredBoth.totalDeletions, 0);
});

test("Dogfood Contract 7: Output flood does NOT invoke executeStagedReview and reports error in telemetry (R3)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-dogfood-flood-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  // Simulate an output flood exceeding maxOutputBytes (512KB)
  const floodOutput = "X".repeat(600 * 1024);
  let agyInvocations = 0;
  const agyFloodAdapter = new CliReviewAdapter({
    execFn: async () => {
      agyInvocations++;
      return { stdout: floodOutput };
    }
  });

  const cleanAdapter = new CliReviewAdapter({
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
      })
    })
  });

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 10,
        totalDeletions: 2,
        files: [{ path: "src/index.js", additions: 10, deletions: 2, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      reviewAdapters: {
        agy: agyFloodAdapter,
        claude: cleanAdapter,
        codex: cleanAdapter
      },
      out: tmpOut,
      log: false
    });

    // Output flood must NOT trigger staged fallback (which would have called agy multiple times for chunks)
    assert.equal(agyInvocations, 1, "agy must be invoked exactly once without staged review retry");

    // Failure remains visible in provider telemetry as error
    assert.equal(report.providerTelemetry.agy.executionStatus, EXECUTION_STATUS.ERROR);
    assert.equal(report.providerTelemetry.agy.findingsCount, 0);

    // Advisory gate should register simulated block due to incomplete/errored review
    assert.equal(report.advisoryGate.simulatedGateBlock, true);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

