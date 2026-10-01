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
  getCurrentCommitSha,
  getCurrentBranch
} from "../scripts/dogfood-review.mjs";

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
