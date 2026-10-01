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
      base: "main",
      head: "HEAD",
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
