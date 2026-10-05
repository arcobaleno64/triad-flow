/**
 * Contract & Smoke Tests for Track D1 Shadow Dogfood Review
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import {
  parseArgs,
  runDogfoodReview,
  classifyDogfoodFileRisk,
  filterChangeSetExclusions,
  getCurrentCommitSha,
  getCurrentBranch,
  normalizeTelemetryIdentity,
  buildProviderTelemetry,
  instrumentVerifierAdapter
} from "../scripts/dogfood-review.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";
import { CliVerifierAdapter } from "../src/core/independent-verifier.mjs";

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

    assert.equal(report.schemaVersion, "1.1.0");
    assert.equal(report.executionMode, "mock");
    assert.equal(report.repository.name, "arcobaleno64/triad-flow");
    assert.match(report.runStartedAt, /^\d{4}-\d{2}-\d{2}T.*Z$/);
    assert.ok(report.runId.startsWith("dogfood-"));
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
    command: "agy",
    providerName: "agy",
    family: "google",
    modelName: "gemini-3.8-flash",
    execFn: async () => {
      agyInvocations++;
      return { stdout: floodOutput };
    }
  });

  const cleanClaudeAdapter = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    family: "anthropic",
    modelName: "claude-5.5-sonnet",
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
      })
    })
  });

  const cleanCodexAdapter = new CliReviewAdapter({
    command: "codex",
    providerName: "codex",
    family: "openai",
    modelName: "gpt-6.1-sol",
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
        claude: cleanClaudeAdapter,
        codex: cleanCodexAdapter
      },
      out: tmpOut,
      log: false
    });

    // Output flood must NOT trigger staged fallback (which would have called agy multiple times for chunks)
    assert.equal(agyInvocations, 1, "agy must be invoked exactly once without staged review retry");

    // Failure remains visible in provider telemetry as error
    assert.equal(report.providerTelemetry.agy.executionStatus, EXECUTION_STATUS.ERROR);
    assert.equal(report.providerTelemetry.agy.findingsCount, 0);

    // Execution completeness is false due to reviewer error
    assert.equal(report.telemetryMetrics.executionComplete, false);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Dogfood Contract 7b: Preclassified flood status does NOT invoke executeStagedReview and classifies as error (R3 hardening)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-dogfood-flood-preclass-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const floodOutput = "X".repeat(600 * 1024);
  let agyInvocations = 0;
  const agyPreclassifiedFloodAdapter = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    family: "google",
    modelName: "gemini-3.8-flash",
    execFn: async () => {
      agyInvocations++;
      return { executionStatus: "payload_too_large", stdout: floodOutput };
    }
  });

  const cleanClaudeAdapter = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    family: "anthropic",
    modelName: "claude-5.5-sonnet",
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
      })
    })
  });

  const cleanCodexAdapter = new CliReviewAdapter({
    command: "codex",
    providerName: "codex",
    family: "openai",
    modelName: "gpt-6.1-sol",
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
        agy: agyPreclassifiedFloodAdapter,
        claude: cleanClaudeAdapter,
        codex: cleanCodexAdapter
      },
      out: tmpOut,
      log: false
    });

    assert.equal(agyInvocations, 1, "agy must be invoked exactly once without staged review retry");
    assert.equal(report.providerTelemetry.agy.executionStatus, EXECUTION_STATUS.ERROR);
    assert.equal(report.telemetryMetrics.executionComplete, false);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Dogfood Contract 8: Injected reviewAdapters with consensus findings initializes default verifier (P2 hardening)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-dogfood-verifier-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const findingPayload = JSON.stringify({
    findings: [
      {
        title: "SQL Injection in User Lookup",
        severity: "critical",
        file: "src/index.js",
        line_start: 1,
        line_end: 1,
        recommendation: "Use parameterized queries",
        evidenceSnippet: "const a = 1;"
      }
    ],
    coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
  });

  const makeFindingAdapter = (name, cmd, fam, model) => new CliReviewAdapter({
    command: cmd,
    providerName: name,
    family: fam,
    modelName: model,
    execFn: async () => ({ stdout: findingPayload })
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
        agy: makeFindingAdapter("agy", "agy", "google", "gemini-3.8-flash"),
        claude: makeFindingAdapter("claude", "claude", "anthropic", "claude-5.5-sonnet"),
        codex: makeFindingAdapter("codex", "codex", "openai", "gpt-6.1-sol")
      },
      out: tmpOut,
      log: false
    });

    assert.ok(report);
    assert.equal(report.consensus.totalFindings, 1);
    assert.equal(report.advisoryGate.simulatedGateBlock, true);
    assert.ok(report.verificationRecord !== null, "Verification record must be populated");
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

// ==============================================================================
// RB-1: Derive providerTelemetry identity from actual execution result
// ==============================================================================

test("RB1-A: Default identities in mock/live result reflect canonical values", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb1-a-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  try {
    const report = await runDogfoodReview({
      mock: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 5,
        totalDeletions: 1,
        files: [{ path: "src/index.js", additions: 5, deletions: 1, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.providerTelemetry.agy.provider, "agy");
    assert.equal(report.providerTelemetry.agy.family, "google");
    assert.equal(report.providerTelemetry.agy.model, "gemini-3.8-flash");

    assert.equal(report.providerTelemetry.claude.provider, "claude");
    assert.equal(report.providerTelemetry.claude.family, "anthropic");
    assert.equal(report.providerTelemetry.claude.model, "claude-5.5-sonnet");

    assert.equal(report.providerTelemetry.codex.provider, "codex");
    assert.equal(report.providerTelemetry.codex.family, "openai");
    assert.equal(report.providerTelemetry.codex.model, "gpt-6.1-sol");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB1-B: Injected reviewer identities reflect exact values regardless of slot", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb1-b-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const makeCustomAdapter = (provider, family, model) => ({
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] },
      providerIdentity: { provider, family, model }
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
        totalAdditions: 5,
        totalDeletions: 1,
        files: [{ path: "src/index.js", additions: 5, deletions: 1, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      reviewAdapters: {
        agy: makeCustomAdapter("custom-reviewer-x", "custom-family-x", "custom-model-x"),
        claude: makeCustomAdapter("custom-reviewer-y", "custom-family-y", "custom-model-y"),
        codex: makeCustomAdapter("custom-reviewer-z", "custom-family-z", "custom-model-z")
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.providerTelemetry.agy.provider, "custom-reviewer-x");
    assert.equal(report.providerTelemetry.agy.family, "custom-family-x");
    assert.equal(report.providerTelemetry.agy.model, "custom-model-x");

    assert.equal(report.providerTelemetry.claude.provider, "custom-reviewer-y");
    assert.equal(report.providerTelemetry.claude.family, "custom-family-y");
    assert.equal(report.providerTelemetry.claude.model, "custom-model-y");

    assert.equal(report.providerTelemetry.codex.provider, "custom-reviewer-z");
    assert.equal(report.providerTelemetry.codex.family, "custom-family-z");
    assert.equal(report.providerTelemetry.codex.model, "custom-model-z");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB1-C: Missing providerIdentity does not throw and defaults fields to 'unknown' without canonical false attribution", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb1-c-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const bareAdapter = {
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
    })
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 5,
        totalDeletions: 1,
        files: [{ path: "src/index.js", additions: 5, deletions: 1, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      reviewAdapters: {
        agy: bareAdapter,
        claude: bareAdapter,
        codex: bareAdapter
      },
      out: tmpOut,
      log: false
    });

    for (const slot of ["agy", "claude", "codex"]) {
      assert.equal(report.providerTelemetry[slot].provider, "unknown");
      assert.equal(report.providerTelemetry[slot].family, "unknown");
      assert.equal(report.providerTelemetry[slot].model, "unknown");
      // Explicitly assert NO canonical false attribution
      assert.notEqual(report.providerTelemetry[slot].provider, slot);
      assert.notEqual(report.providerTelemetry[slot].family, "google");
      assert.notEqual(report.providerTelemetry[slot].family, "anthropic");
      assert.notEqual(report.providerTelemetry[slot].family, "openai");
      assert.notEqual(report.providerTelemetry[slot].model, "gemini-3.8-flash");
      assert.notEqual(report.providerTelemetry[slot].model, "claude-5.5-sonnet");
      assert.notEqual(report.providerTelemetry[slot].model, "gpt-6.1-sol");
    }
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB1-D: Invalid or partial providerIdentity defaults missing/non-string fields to 'unknown'", () => {
  // Test unit helper directly and through review execution
  assert.deepEqual(normalizeTelemetryIdentity(null), { provider: "unknown", family: "unknown", model: "unknown" });
  assert.deepEqual(normalizeTelemetryIdentity({}), { provider: "unknown", family: "unknown", model: "unknown" });
  assert.deepEqual(normalizeTelemetryIdentity({ providerIdentity: null }), { provider: "unknown", family: "unknown", model: "unknown" });
  assert.deepEqual(normalizeTelemetryIdentity({ providerIdentity: { provider: "valid-prov" } }), { provider: "valid-prov", family: "unknown", model: "unknown" });
  assert.deepEqual(normalizeTelemetryIdentity({ providerIdentity: { provider: 123, family: null, model: "" } }), { provider: "unknown", family: "unknown", model: "unknown" });
  assert.deepEqual(normalizeTelemetryIdentity({ providerIdentity: { provider: "  test  ", family: " fam ", model: " mod " } }), { provider: "test", family: "fam", model: "mod" });
});

test("RB1-E: Injected model does not falsely appear as canonical names because of slot", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb1-e-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  // Swap provider/models across slots to verify slot name does not dictate telemetry identity
  const swappedAdapters = {
    agy: {
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] },
        providerIdentity: { provider: "codex", family: "openai", model: "gpt-6.1-sol" }
      })
    },
    claude: {
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] },
        providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
      })
    },
    codex: {
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] },
        providerIdentity: { provider: "claude", family: "anthropic", model: "claude-5.5-sonnet" }
      })
    }
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 5,
        totalDeletions: 1,
        files: [{ path: "src/index.js", additions: 5, deletions: 1, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      reviewAdapters: swappedAdapters,
      out: tmpOut,
      log: false
    });

    // Slot agy must show codex/openai/gpt-6.1-sol, NOT agy/google/gemini-3.8-flash
    assert.equal(report.providerTelemetry.agy.provider, "codex");
    assert.equal(report.providerTelemetry.agy.family, "openai");
    assert.equal(report.providerTelemetry.agy.model, "gpt-6.1-sol");

    // Slot claude must show agy/google/gemini-3.8-flash, NOT claude/anthropic/claude-5.5-sonnet
    assert.equal(report.providerTelemetry.claude.provider, "agy");
    assert.equal(report.providerTelemetry.claude.family, "google");
    assert.equal(report.providerTelemetry.claude.model, "gemini-3.8-flash");

    // Slot codex must show claude/anthropic/claude-5.5-sonnet, NOT codex/openai/gpt-6.1-sol
    assert.equal(report.providerTelemetry.codex.provider, "claude");
    assert.equal(report.providerTelemetry.codex.family, "anthropic");
    assert.equal(report.providerTelemetry.codex.model, "claude-5.5-sonnet");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

// ==============================================================================
// RB-2: Failed attempted verification makes execution incomplete
// ==============================================================================

const mockChangeSetWithFindings = {
  ok: true,
  schemaVersion: "1.0.0",
  repository: "test",
  totalFiles: 1,
  totalAdditions: 10,
  totalDeletions: 2,
  files: [{ path: "src/index.js", additions: 10, deletions: 2, riskTier: 2 }],
  diffHunks: "+ const a = 1;"
};

const makeFindingReviewAdapters = () => {
  const makeAdapter = (name, cmd, fam, model) => new CliReviewAdapter({
    command: cmd,
    providerName: name,
    family: fam,
    modelName: model,
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [
          {
            title: "Command Injection in ExecHandler",
            severity: "critical",
            file: "src/index.js",
            line_start: 1,
            line_end: 1,
            recommendation: "Sanitize arguments",
            evidenceSnippet: "const a = 1;"
          }
        ],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
      })
    })
  });
  return {
    agy: makeAdapter("agy", "agy", "google", "gemini-3.8-flash"),
    claude: makeAdapter("claude", "claude", "anthropic", "claude-5.5-sonnet"),
    codex: makeAdapter("codex", "codex", "openai", "gpt-6.1-sol")
  };
};

test("Observation verifier timeout instrumentation materializes command-only verifier adapters", () => {
  let timeoutSignals = 0;
  const instrumented = instrumentVerifierAdapter(
    { command: "claude", providerName: "claude", modelName: "claude-5.5-sonnet" },
    () => { timeoutSignals++; }
  );
  assert.equal(typeof instrumented.executeVerification, "function");
  assert.equal(instrumented.providerName, "claude");
  assert.equal(timeoutSignals, 0);
});

test("Observation verifier timeout includes exceptions swallowed by CliVerifierAdapter execFn", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-verifier-exec-timeout-"));
  try {
    for (const timedOut of [true, false]) {
      const execFn = async () => {
        const err = new Error(timedOut ? "Injected verifier timed out" : "Injected command not found");
        err.name = timedOut ? "TimeoutError" : "Error";
        throw err;
      };
      const verifierAdapter = new CliVerifierAdapter({ command: "claude", execFn });
      const report = await runDogfoodReview({
        live: true,
        changeSet: mockChangeSetWithFindings,
        reviewAdapters: makeFindingReviewAdapters(),
        verifierAdapter,
        out: path.join(tmpDir, `run-${timedOut}.json`),
        log: false
      });
      assert.equal(report.verificationRecord.ok, false);
      assert.equal(report.telemetryMetrics.executionComplete, false);
      assert.equal(report.telemetryMetrics.reviewerTimeoutCount, 0);
      assert.equal(report.telemetryMetrics.verifierTimeoutCount, timedOut ? 1 : 0);
      assert.equal(report.telemetryMetrics.timeoutCount, timedOut ? 1 : 0);
      assert.equal(verifierAdapter.execFn, execFn, "Instrumentation must not mutate the caller's adapter");
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Observation source run IDs remain unique when reviews begin in the same millisecond", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-run-id-"));
  const originalNow = Date.now;
  const providerRunIds = [];
  const clean = (provider, family) => ({
    executeReview: async ({ runId }) => {
      providerRunIds.push(runId);
      return {
        ok: true, executionStatus: "success", findings: [],
        coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] },
        providerIdentity: { provider, family, model: "test" }
      };
    }
  });
  try {
    Date.now = () => 1791160000000;
    const reports = await Promise.all([0, 1].map(i => runDogfoodReview({
      live: true,
      changeSet: mockChangeSetWithFindings,
      reviewAdapters: { agy: clean("agy", "google"), claude: clean("claude", "anthropic"), codex: clean("codex", "openai") },
      out: path.join(tmpDir, `run-${i}.json`),
      log: false
    })));
    assert.notEqual(reports[0].runId, reports[1].runId);
    assert.equal(new Set(providerRunIds).size, 6);
    for (const report of reports) assert.ok(providerRunIds.some(id => id.startsWith(`${report.runId}-`)));
  } finally {
    Date.now = originalNow;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Observation repository identity supports upstream-only and explicit remote-less CLI runs", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-remote-identity-"));
  const git = (...args) => execFileSync("git", args, { cwd: tmpDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const script = path.resolve("scripts/dogfood-review.mjs");
  const out = path.join(tmpDir, "run.json");
  const run = (...args) => spawnSync(process.execPath, [script, "--mock", "--base", "HEAD", "--out", out, ...args], {
    cwd: tmpDir, encoding: "utf8"
  });
  try {
    git("init", "--initial-branch=main");
    git("config", "user.email", "triad-flow-test@example.invalid");
    git("config", "user.name", "Triad Flow Test");
    fs.writeFileSync(path.join(tmpDir, "one.txt"), "one\n");
    git("add", "one.txt");
    git("commit", "-m", "first");
    git("remote", "add", "upstream", "https://github.com/Example/Reviewed.git");
    const upstream = run();
    assert.equal(upstream.status, 0, upstream.stderr);
    assert.equal(JSON.parse(fs.readFileSync(out, "utf8")).repository.name, "example/reviewed");
    const mismatch = run("--repository", "other/repository");
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /repository.*does not match/i);
    git("remote", "remove", "upstream");
    assert.notEqual(run().status, 0, "Remote-less run needs an explicit canonical repository identity");
    const explicit = run("--repository=Example/Reviewed");
    assert.equal(explicit.status, 0, explicit.stderr);
    assert.equal(JSON.parse(fs.readFileSync(out, "utf8")).repository.name, "example/reviewed");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("RB2-A: Successful verifier allows executionComplete === true", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb2-a-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const successfulVerifierAdapter = {
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    executeVerification: async () => ({
      ok: true,
      evaluations: [
        {
          findingId: "finding-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Vulnerability verified against diff.",
          dissent: ""
        }
      ],
      verifierOmissions: []
    })
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: mockChangeSetWithFindings,
      reviewAdapters: makeFindingReviewAdapters(),
      verifierAdapter: successfulVerifierAdapter,
      out: tmpOut,
      log: false
    });

    assert.ok(report.verificationRecord !== null, "Verification record must be present");
    assert.equal(report.verificationRecord.ok, true);
    assert.equal(report.consensus.quorumReached, true);
    assert.equal(report.telemetryMetrics.executionComplete, true);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB2-B: Verifier timeout results in verificationRecord.ok === false and executionComplete === false", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb2-b-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const timeoutVerifierAdapter = {
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    executeVerification: async () => {
      const err = new Error("Independent verifier execution timed out after 30000ms");
      err.name = "TimeoutError";
      throw err;
    }
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: mockChangeSetWithFindings,
      reviewAdapters: makeFindingReviewAdapters(),
      verifierAdapter: timeoutVerifierAdapter,
      out: tmpOut,
      log: false
    });

    assert.ok(report.verificationRecord !== null, "Verification record must be preserved");
    assert.equal(report.verificationRecord.ok, false);
    assert.equal(report.consensus.quorumReached, true);
    assert.equal(report.telemetryMetrics.executionComplete, false);
    assert.equal(report.telemetryMetrics.reviewerTimeoutCount, 0);
    assert.equal(report.telemetryMetrics.verifierTimeoutCount, 1);
    assert.equal(report.telemetryMetrics.timeoutCount, 1);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB2-C: Malformed verifier response results in verificationRecord.ok === false and executionComplete === false", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb2-c-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const malformedVerifierAdapter = {
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    executeVerification: async () => ({
      stdout: "INVALID NON-JSON OUTPUT <<<<>>>>"
    })
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: mockChangeSetWithFindings,
      reviewAdapters: makeFindingReviewAdapters(),
      verifierAdapter: malformedVerifierAdapter,
      out: tmpOut,
      log: false
    });

    assert.ok(report.verificationRecord !== null, "Verification record must be preserved");
    assert.equal(report.verificationRecord.ok, false);
    assert.equal(report.consensus.quorumReached, true);
    assert.equal(report.telemetryMetrics.executionComplete, false);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB2-D: Verifier execution error results in verificationRecord.ok === false and executionComplete === false", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb2-d-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const errorVerifierAdapter = {
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    executeVerification: async () => {
      throw new Error("CLI process failed with exit code 127: command not found");
    }
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: mockChangeSetWithFindings,
      reviewAdapters: makeFindingReviewAdapters(),
      verifierAdapter: errorVerifierAdapter,
      out: tmpOut,
      log: false
    });

    assert.ok(report.verificationRecord !== null, "Verification record must be preserved");
    assert.equal(report.verificationRecord.ok, false);
    assert.equal(report.consensus.quorumReached, true);
    assert.equal(report.telemetryMetrics.executionComplete, false);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("RB2-E: Zero consensus findings means verificationRecord === null and preserves previous executionComplete semantics", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-rb2-e-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const cleanReviewAdapters = {
    agy: new CliReviewAdapter({
      command: "agy",
      providerName: "agy",
      family: "google",
      modelName: "gemini-3.8-flash",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    }),
    claude: new CliReviewAdapter({
      command: "claude",
      providerName: "claude",
      family: "anthropic",
      modelName: "claude-5.5-sonnet",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    }),
    codex: new CliReviewAdapter({
      command: "codex",
      providerName: "codex",
      family: "openai",
      modelName: "gpt-6.1-sol",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    })
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: "test",
        totalFiles: 1,
        totalAdditions: 2,
        totalDeletions: 1,
        files: [{ path: "src/index.js", additions: 2, deletions: 1, riskTier: 2 }],
        diffHunks: "+ const a = 1;"
      },
      reviewAdapters: cleanReviewAdapters,
      out: tmpOut,
      log: false
    });

    assert.equal(report.consensus.totalFindings, 0);
    assert.equal(report.verificationRecord, null, "No verification attempted when findings === 0");
    assert.equal(report.consensus.quorumReached, true);
    assert.equal(report.telemetryMetrics.executionComplete, true, "Clean review with quorum must complete successfully");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});



test("Observation producer authority: runStartedAt precedes every reviewer invocation", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-producer-authority-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");
  let firstInvocationAt = Number.POSITIVE_INFINITY;

  const makeAdapter = (provider, family, model) => ({
    executeReview: async () => {
      firstInvocationAt = Math.min(firstInvocationAt, Date.now());
      return {
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["scripts/example.mjs"], omittedFiles: [] },
        providerIdentity: { provider, family, model }
      };
    }
  });

  try {
    const report = await runDogfoodReview({
      live: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        totalFiles: 1,
        totalAdditions: 1,
        totalDeletions: 0,
        files: [{ path: "scripts/example.mjs", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "diff --git a/scripts/example.mjs b/scripts/example.mjs\n--- a/scripts/example.mjs\n+++ b/scripts/example.mjs\n@@ -0,0 +1 @@\n+export const x = 1;"
      },
      reviewAdapters: {
        agy: makeAdapter("agy", "google", "gemini-3.8-flash"),
        claude: makeAdapter("claude", "anthropic", "claude-5.5-sonnet"),
        codex: makeAdapter("codex", "openai", "gpt-6.1-sol")
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.executionMode, "live");
    assert.match(report.runStartedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.ok(Date.parse(report.runStartedAt) <= firstInvocationAt);
    assert.ok(report.runId.startsWith("dogfood-"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Observation producer authority: genuine staged fallback is preserved explicitly", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-staged-signal-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");
  let agyCalls = 0;

  const agy = {
    executeReview: async ({ changeSet }) => {
      agyCalls++;
      if (agyCalls === 1) {
        return {
          ok: false,
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: "input prompt too large",
          providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
        };
      }
      return {
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: (changeSet.files || []).map(f => f.path), omittedFiles: [] },
        providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
      };
    }
  };
  const clean = (provider, family, model) => ({
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["scripts/example.mjs"], omittedFiles: [] },
      providerIdentity: { provider, family, model }
    })
  });

  try {
    const report = await runDogfoodReview({
      live: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        totalFiles: 1,
        totalAdditions: 1,
        totalDeletions: 0,
        files: [{ path: "scripts/example.mjs", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "diff --git a/scripts/example.mjs b/scripts/example.mjs\n--- a/scripts/example.mjs\n+++ b/scripts/example.mjs\n@@ -0,0 +1 @@\n+export const x = 1;"
      },
      reviewAdapters: {
        agy,
        claude: clean("claude", "anthropic", "claude-5.5-sonnet"),
        codex: clean("codex", "openai", "gpt-6.1-sol")
      },
      out: tmpOut,
      log: false
    });

    assert.ok(agyCalls >= 2);
    assert.equal(report.telemetryMetrics.stagedFallbackUsed, true);
    assert.equal(report.providerTelemetry.agy.stagedFallbackUsed, true);
    assert.ok(Number.isInteger(report.telemetryMetrics.chunkCount));
    assert.ok(report.telemetryMetrics.chunkCount >= 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});


test("Observation producer authority: report commit matches the actually reviewed --head ref", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-reviewed-head-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");
  const originalCwd = process.cwd();

  const git = (...args) => execFileSync("git", args, {
    cwd: tmpDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();

  const clean = (provider, family, model) => ({
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["scripts/example.mjs"], omittedFiles: [] },
      providerIdentity: { provider, family, model }
    })
  });

  try {
    git("init");
    git("config", "user.email", "triad-flow-test@example.invalid");
    git("config", "user.name", "Triad Flow Test");
    git("remote", "add", "origin", "https://github.com/Example/Reviewed.git");
    fs.writeFileSync(path.join(tmpDir, "one.txt"), "one\n", "utf8");
    git("add", "one.txt");
    git("commit", "-m", "first");
    const reviewedSha = git("rev-parse", "HEAD").toLowerCase();
    git("branch", "reviewed-topic");

    fs.writeFileSync(path.join(tmpDir, "two.txt"), "two\n", "utf8");
    git("add", "two.txt");
    git("commit", "-m", "second");
    const checkoutSha = git("rev-parse", "HEAD").toLowerCase();
    assert.notEqual(reviewedSha, checkoutSha);

    process.chdir(tmpDir);
    const report = await runDogfoodReview({
      live: true,
      head: reviewedSha,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        repository: { headSha: reviewedSha },
        totalFiles: 1,
        totalAdditions: 1,
        totalDeletions: 0,
        files: [{ path: "scripts/example.mjs", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "diff --git a/scripts/example.mjs b/scripts/example.mjs\n--- a/scripts/example.mjs\n+++ b/scripts/example.mjs\n@@ -0,0 +1 @@\n+export const x = 1;"
      },
      reviewAdapters: {
        agy: clean("agy", "google", "gemini-3.8-flash"),
        claude: clean("claude", "anthropic", "claude-5.5-sonnet"),
        codex: clean("codex", "openai", "gpt-6.1-sol")
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.repository.name, "example/reviewed");
    assert.equal(report.repository.commitSha, reviewedSha);
    assert.equal(report.repository.head, reviewedSha);
    assert.equal(report.repository.branch, null, "An immutable reviewed SHA does not imply the checkout branch");
    assert.notEqual(report.repository.commitSha, checkoutSha);

    const fromRef = await runDogfoodReview({ mock: true, base: reviewedSha, head: "reviewed-topic", out: tmpOut, log: false });
    assert.equal(fromRef.repository.branch, "reviewed-topic");
    assert.equal(fromRef.repository.head, "reviewed-topic");
    assert.equal(fromRef.repository.commitSha, reviewedSha);

    git("checkout", "--detach", checkoutSha);
    const detached = await runDogfoodReview({ mock: true, base: reviewedSha, out: tmpOut, log: false });
    assert.equal(detached.repository.branch, null);
    assert.equal(detached.repository.head, "HEAD");
    assert.equal(detached.repository.commitSha, checkoutSha);
  } finally {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Observation producer authority: staged chunk timeout contributes to reviewer and total timeout counts", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-staged-timeout-"));
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
          error: "input prompt too large",
          providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
        };
      }
      return {
        ok: false,
        executionStatus: EXECUTION_STATUS.TIMEOUT,
        status: "timeout",
        error: "staged chunk timed out",
        findings: [],
        providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash" }
      };
    }
  };

  const clean = (provider, family, model) => ({
    executeReview: async () => ({
      ok: true,
      executionStatus: "success",
      findings: [],
      coverage: { coveredFiles: ["scripts/example.mjs"], omittedFiles: [] },
      providerIdentity: { provider, family, model }
    })
  });

  try {
    const report = await runDogfoodReview({
      live: true,
      changeSet: {
        ok: true,
        schemaVersion: "1.0.0",
        totalFiles: 1,
        totalAdditions: 1,
        totalDeletions: 0,
        files: [{ path: "scripts/example.mjs", additions: 1, deletions: 0, riskTier: 2 }],
        diffHunks: "diff --git a/scripts/example.mjs b/scripts/example.mjs\n--- a/scripts/example.mjs\n+++ b/scripts/example.mjs\n@@ -0,0 +1 @@\n+export const x = 1;"
      },
      reviewAdapters: {
        agy,
        claude: clean("claude", "anthropic", "claude-5.5-sonnet"),
        codex: clean("codex", "openai", "gpt-6.1-sol")
      },
      out: tmpOut,
      log: false
    });

    assert.equal(report.telemetryMetrics.stagedFallbackUsed, true);
    assert.equal(report.telemetryMetrics.reviewerTimeoutCount, 1);
    assert.equal(report.telemetryMetrics.verifierTimeoutCount, 0);
    assert.equal(report.telemetryMetrics.timeoutCount, 1);
    assert.equal(report.telemetryMetrics.executionComplete, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
