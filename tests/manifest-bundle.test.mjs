/**
 * Test Suite: Baseline Artifact Manifest Bundle & Verifier (Phase 3 RC)
 *
 * Implements verification of Contract 5 from TF-SPEC-RECEIPT-v1.0.0:
 * - Bundle generation from real/mock benchmark outputs
 * - Embedded provenance in summary.md (Run ID, Commit SHA, Corpus Digest, Receipt Digest, Results Digest)
 * - Tamper detection (mutating any byte in results/receipt/summary triggers failure)
 * - CLI generator and verifier script integration and exit code invariants
 * - scripts/run-real-benchmark.mjs --manifest integration
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  formatSummaryMarkdown,
  generateManifestBundle,
  verifyManifestBundle,
  DEFAULT_ARTIFACT_NAMES
} from "../src/core/manifest-bundle.mjs";
import {
  buildArtifactManifest,
  validateArtifactManifest,
  computeReceiptDigest,
  UnsupportedReceiptSchemaError,
  ReceiptValidationError
} from "../src/core/audit-receipt.mjs";
import { createCorpusIdentity, computeDigest } from "../src/core/canonical-digest.mjs";
import { TF_RBC_V0_CASES } from "./fixtures/real-corpus-fixtures.mjs";

const execFileAsync = promisify(execFile);

function createTestFixtures() {
  const identity = createCorpusIdentity(TF_RBC_V0_CASES.slice(0, 3));
  const resultsData = {
    framework: "Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)",
    mode: "single",
    executionMode: "mock",
    workspaceMode: "virtual",
    timestamp: "2026-09-29T10:00:00.000Z",
    runId: "run-test-fixture-1234",
    metrics: {
      totalCases: 3,
      vulnerableCasesCount: 2,
      cleanCasesCount: 1,
      totalGoldens: 2,
      caughtGoldens: 2,
      totalReportedFindings: 2,
      truePositives: 2,
      falsePositives: 0,
      falseBlocks: 0,
      recall: 1.0,
      precision: 1.0,
      falseBlockRate: 0.0,
      latency: {
        p50Ms: 120,
        p95Ms: 250,
        avgMs: 140
      },
      tokens: {
        available: true,
        totalTokens: 4200
      }
    }
  };

  const receiptData = {
    schemaVersion: "1.0.0",
    identity,
    run: {
      runId: "run-test-fixture-1234",
      startedAt: "2026-09-29T10:00:00.000Z",
      finishedAt: "2026-09-29T10:01:00.000Z",
      environment: {
        platform: "linux",
        arch: "x64",
        nodeVersion: "v22.0.0"
      }
    },
    systemProvenance: {
      commitSha: "a1b2c3d4e5f67890123456789abcdef012345678",
      branch: "main",
      triadFlowVersion: "2.2.0"
    },
    providerProvenance: {
      macro: {
        actualModel: { value: "gemini-3.8-flash", source: "cli" },
        binaryDetected: true,
        command: "agy",
        mandatoryArgsVerified: true,
        profileMatched: "agy-canonical",
        reviewProfileReady: true,
        version: "1.1.0"
      }
    },
    results: {
      mode: "single",
      recall: 1.0,
      precision: 1.0,
      falseBlockRate: 0.0
    }
  };

  resultsData.receipt = receiptData;
  return { identity, resultsData, receiptData };
}

test("Manifest Bundle Generator: generates all 4 artifacts with correct metadata and embedded digests", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bundle-test-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();

    const bundle = generateManifestBundle({
      targetDir: tmpDir,
      resultsData,
      receiptData
    });

    // Verify all 4 files exist on disk
    const expectedFiles = [
      "benchmark-results.json",
      "audit-receipt.json",
      "summary.md",
      "artifact-manifest.json"
    ];
    for (const f of expectedFiles) {
      assert.ok(fs.existsSync(path.join(tmpDir, f)), `File '${f}' must exist`);
    }

    // Verify manifest contents and schema
    assert.equal(bundle.manifest.schemaVersion, "1.0.0");
    assert.deepEqual(Object.keys(bundle.manifest.artifacts), [
      "audit-receipt.json",
      "benchmark-results.json",
      "summary.md"
    ]);

    // Verify metadata
    assert.equal(bundle.manifest.metadata.runId, "run-test-fixture-1234");
    assert.equal(bundle.manifest.metadata.commitSha, "a1b2c3d4e5f67890123456789abcdef012345678");
    assert.equal(bundle.manifest.metadata.corpusDigest, receiptData.identity.corpusDigest);
    assert.match(bundle.manifest.metadata.receiptDigest, /^sha256:[a-f0-9]{64}$/);
    assert.match(bundle.manifest.metadata.resultsDigest, /^sha256:[a-f0-9]{64}$/);

    // Verify summary.md embeds the required 5 provenance fields
    const summaryContent = fs.readFileSync(path.join(tmpDir, "summary.md"), "utf8");
    assert.ok(summaryContent.includes("run-test-fixture-1234"), "summary.md must embed Run ID");
    assert.ok(summaryContent.includes("a1b2c3d4e5f67890123456789abcdef012345678"), "summary.md must embed Commit SHA");
    assert.ok(summaryContent.includes(receiptData.identity.corpusDigest), "summary.md must embed Corpus Digest");
    assert.ok(summaryContent.includes(bundle.manifest.metadata.receiptDigest), "summary.md must embed Receipt Digest");
    assert.ok(summaryContent.includes(bundle.manifest.metadata.resultsDigest), "summary.md must embed Results Digest");

    // Verification on pristine bundle succeeds
    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, true);
    assert.equal(verification.errors.length, 0);
    assert.equal(verification.verifiedArtifacts.length, 3);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Bundle Generator: generates from pre-existing files on disk", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bundle-disk-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();

    fs.writeFileSync(path.join(tmpDir, "benchmark-results.json"), JSON.stringify(resultsData, null, 2) + "\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "audit-receipt.json"), JSON.stringify(receiptData, null, 2) + "\n", "utf8");

    const bundle = generateManifestBundle({ targetDir: tmpDir });
    assert.ok(fs.existsSync(bundle.summaryPath));
    assert.ok(fs.existsSync(bundle.manifestPath));

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, true);
    assert.equal(verification.errors.length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Tamper Detection: mutating any byte in benchmark-results.json triggers failure", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-tamper-results-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    // Mutate 1 character in benchmark-results.json
    const resultsFile = path.join(tmpDir, "benchmark-results.json");
    const original = fs.readFileSync(resultsFile, "utf8");
    // Change recall from 1.0 to 0.9
    const tampered = original.replace('"recall": 1', '"recall": 0.9');
    assert.notEqual(original, tampered);
    fs.writeFileSync(resultsFile, tampered, "utf8");

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("benchmark-results.json") && e.includes("Digest mismatch")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Tamper Detection: mutating any byte in audit-receipt.json triggers failure", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-tamper-receipt-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    // Mutate 1 character in audit-receipt.json
    const receiptFile = path.join(tmpDir, "audit-receipt.json");
    const original = fs.readFileSync(receiptFile, "utf8");
    const tampered = original.replace('"triadFlowVersion": "2.2.0"', '"triadFlowVersion": "2.2.1"');
    assert.notEqual(original, tampered);
    fs.writeFileSync(receiptFile, tampered, "utf8");

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("audit-receipt.json") && e.includes("Digest mismatch")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Tamper Detection: mutating any byte in summary.md triggers failure", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-tamper-summary-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    // Mutate 1 character in summary.md
    const summaryFile = path.join(tmpDir, "summary.md");
    const original = fs.readFileSync(summaryFile, "utf8");
    const tampered = original + "\n<!-- unauthorized comment -->\n";
    fs.writeFileSync(summaryFile, tampered, "utf8");

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("summary.md") && e.includes("Digest mismatch")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Tamper Detection: deleting an artifact file triggers failure", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-tamper-delete-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    // Delete summary.md
    fs.unlinkSync(path.join(tmpDir, "summary.md"));

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("summary.md") && e.includes("missing on disk")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Tamper Detection: altering manifest digest or schemaVersion triggers failure", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-tamper-manifest-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    const manifestFile = path.join(tmpDir, "artifact-manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));

    // Case 1: Fake digest in manifest
    manifest.artifacts["summary.md"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    let verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("Digest mismatch for artifact 'summary.md'")));

    // Case 2: Incompatible schemaVersion 2.0.0
    manifest.schemaVersion = "2.0.0";
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("Unsupported artifact manifest schema version")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Script Integration: scripts/generate-manifest-bundle.mjs & scripts/verify-artifact-manifest.mjs", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-cli-bundle-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();

    // Write input files
    fs.writeFileSync(path.join(tmpDir, "benchmark-results.json"), JSON.stringify(resultsData, null, 2) + "\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "audit-receipt.json"), JSON.stringify(receiptData, null, 2) + "\n", "utf8");

    // 1. Run generator script
    const genScript = path.resolve("scripts/generate-manifest-bundle.mjs");
    const genRes = await execFileAsync(process.execPath, [genScript, tmpDir]);
    assert.equal(genRes.stderr, "");
    assert.ok(genRes.stdout.includes("Successfully generated artifact manifest bundle"));

    // Verify artifacts exist
    assert.ok(fs.existsSync(path.join(tmpDir, "summary.md")));
    assert.ok(fs.existsSync(path.join(tmpDir, "artifact-manifest.json")));

    // 2. Run verifier script on pristine bundle
    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    const verRes = await execFileAsync(process.execPath, [verScript, tmpDir]);
    assert.equal(verRes.stderr, "");
    assert.ok(verRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));

    // 3. Mutate summary.md and verify script fails non-zero
    fs.appendFileSync(path.join(tmpDir, "summary.md"), "\n# Tampered Line\n", "utf8");

    await assert.rejects(
      async () => {
        await execFileAsync(process.execPath, [verScript, tmpDir]);
      },
      (err) => {
        assert.equal(err.code, 1);
        assert.ok(err.stderr.includes("Manifest Bundle Verification FAILED"));
        assert.ok(err.stderr.includes("summary.md"));
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Script Integration: scripts/run-real-benchmark.mjs --manifest generates verifiable bundle", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-run-bench-manifest-"));
  try {
    const benchScript = path.resolve("scripts/run-real-benchmark.mjs");
    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    const reportPath = path.join(tmpDir, "benchmark-results.json");

    // Run benchmark runner with --limit=2 and --manifest
    const benchRes = await execFileAsync(process.execPath, [
      benchScript,
      "--limit=2",
      `--report=${reportPath}`,
      "--manifest"
    ]);

    assert.ok(benchRes.stdout.includes("Baseline artifact manifest bundle generated"));

    // Check all 4 files are generated in tmpDir
    assert.ok(fs.existsSync(path.join(tmpDir, "benchmark-results.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "audit-receipt.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "summary.md")));
    assert.ok(fs.existsSync(path.join(tmpDir, "artifact-manifest.json")));

    // Verify using CLI verifier script
    const verRes = await execFileAsync(process.execPath, [verScript, tmpDir]);
    assert.ok(verRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));
    assert.ok(verRes.stdout.includes("Verified Artifacts (3)"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Subcommand Integration: bin/triad-flow.mjs benchmark --manifest generates verifiable bundle", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bin-bench-manifest-"));
  try {
    const binScript = path.resolve("bin/triad-flow.mjs");
    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    const reportPath = path.join(tmpDir, "benchmark-results.json");

    // Run triad-flow benchmark with --limit=2 and --manifest
    await execFileAsync(process.execPath, [
      binScript,
      "benchmark",
      "--limit=2",
      `--report=${reportPath}`,
      "--manifest"
    ]);

    // Check all 4 files exist
    assert.ok(fs.existsSync(path.join(tmpDir, "benchmark-results.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "audit-receipt.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "summary.md")));
    assert.ok(fs.existsSync(path.join(tmpDir, "artifact-manifest.json")));

    // Verify using CLI verifier script
    const verRes = await execFileAsync(process.execPath, [verScript, tmpDir]);
    assert.ok(verRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Protected Live Workflow Contract: .github/workflows/benchmark-live.yml adheres to live security rules", () => {
  const workflowPath = path.resolve(".github/workflows/benchmark-live.yml");
  assert.ok(fs.existsSync(workflowPath), "Workflow file .github/workflows/benchmark-live.yml must exist");

  const workflowContent = fs.readFileSync(workflowPath, "utf8");

  // Invariant 1: Trigger must strictly be manual workflow_dispatch only
  assert.ok(workflowContent.includes("workflow_dispatch:"), "Workflow must trigger on workflow_dispatch");
  assert.ok(!workflowContent.includes("schedule:"), "Workflow MUST NOT trigger on schedule (manual workflow_dispatch only)");

  // Invariant 2: Strictly MUST NOT trigger on pull_request or normal push
  assert.ok(!workflowContent.includes("pull_request:"), "Workflow MUST NOT trigger on pull_request");
  assert.ok(!workflowContent.includes("push:"), "Workflow MUST NOT trigger on push");

  // Invariant 3: Generates all 4 artifacts and uploads manifest bundle
  assert.ok(workflowContent.includes("actions/checkout"), "Workflow must checkout repository");
  assert.ok(workflowContent.includes("actions/setup-node"), "Workflow must setup Node.js");
  assert.ok(workflowContent.includes("Install dependencies"), "Workflow must have Install dependencies step");
  assert.ok(workflowContent.includes("npm install"), "Workflow must run npm install");
  assert.ok(workflowContent.includes("--manifest"), "Workflow must run benchmark with --manifest");
  assert.ok(workflowContent.includes("verify-artifact-manifest.mjs"), "Workflow must verify manifest bundle");
  assert.ok(workflowContent.includes("upload-artifact"), "Workflow must upload artifacts");
  assert.ok(workflowContent.includes("artifact-manifest.json"), "Artifact list must include artifact-manifest.json");
  assert.ok(workflowContent.includes("benchmark-results.json"), "Artifact list must include benchmark-results.json");
  assert.ok(workflowContent.includes("audit-receipt.json"), "Artifact list must include audit-receipt.json");
  assert.ok(workflowContent.includes("summary.md"), "Artifact list must include summary.md");
});

test("Manifest Edge Cases: missing inputs throw descriptive errors", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-edge-missing-"));
  try {
    // Missing results file
    assert.throws(
      () => generateManifestBundle({ targetDir: tmpDir }),
      /Cannot generate manifest bundle: results file not found/
    );

    // Results file exists but no receipt
    const resultsOnlyPath = path.join(tmpDir, "benchmark-results.json");
    fs.writeFileSync(resultsOnlyPath, JSON.stringify({ mode: "single" }), "utf8");
    assert.throws(
      () => generateManifestBundle({ targetDir: tmpDir }),
      /Cannot generate manifest bundle: receipt file not found/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Edge Cases: verifyManifestBundle detects malformed JSON and missing files", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-edge-malformed-"));
  try {
    // Manifest file does not exist
    const nonExistent = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(nonExistent.valid, false);
    assert.ok(nonExistent.errors.some(e => e.includes("not found")));

    // Manifest is malformed JSON
    const manifestFile = path.join(tmpDir, "artifact-manifest.json");
    fs.writeFileSync(manifestFile, "{ bad json", "utf8");
    const malformed = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(malformed.valid, false);
    assert.ok(malformed.errors.some(e => e.includes("Failed to parse manifest JSON")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Edge Cases: verifyManifestBundle detects summary.md missing provenance tokens", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-edge-summary-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    // Rewrite summary.md without the Run ID
    const summaryFile = path.join(tmpDir, "summary.md");
    fs.writeFileSync(summaryFile, "# Stripped Summary\nNo run id here\n", "utf8");

    // Also update manifest artifact hash for summary.md so hash matches but provenance check fails
    const manifestFile = path.join(tmpDir, "artifact-manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
    manifest.artifacts["summary.md"] = computeDigest(fs.readFileSync(summaryFile));
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("summary.md does not embed required Run ID")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Edge Cases: metadata digest cross-check mismatch detection", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-edge-meta-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    const manifestFile = path.join(tmpDir, "artifact-manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));

    // Case 1: metadata.resultsDigest mismatch
    manifest.metadata.resultsDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    let verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("Metadata resultsDigest")));

    // Case 2: metadata.receiptDigest mismatch
    manifest.metadata.resultsDigest = manifest.artifacts["benchmark-results.json"];
    manifest.metadata.receiptDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("Metadata receiptDigest mismatch")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Script Edge Cases: help flags and invalid arguments exit with proper codes", async () => {
  const genScript = path.resolve("scripts/generate-manifest-bundle.mjs");
  const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");

  // Help flag exits 0
  const genHelp = await execFileAsync(process.execPath, [genScript, "--help"]);
  assert.ok(genHelp.stdout.includes("Options:"));

  const verHelp = await execFileAsync(process.execPath, [verScript, "--help"]);
  assert.ok(verHelp.stdout.includes("Usage:"));

  // Verifier on non-existent directory exits 1
  await assert.rejects(
    async () => {
      await execFileAsync(process.execPath, [verScript, "non-existent-dir-123456"]);
    },
    (err) => {
      assert.equal(err.code, 1);
      assert.ok(err.stderr.includes("Artifact manifest file not found") || err.stderr.includes("Manifest Bundle Verification FAILED"));
      return true;
    }
  );
});

test("CLI Verifier: handles positional custom manifest path alongside --dir option", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-cli-custom-pos-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    const bundle = generateManifestBundle({
      targetDir: tmpDir,
      resultsData,
      receiptData,
      manifestPath: path.join(tmpDir, "custom-manifest.json")
    });

    assert.ok(fs.existsSync(bundle.manifestPath));

    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    // Pass custom manifest as positional and --dir pointing to tmpDir
    const verRes = await execFileAsync(process.execPath, [verScript, bundle.manifestPath, `--dir=${tmpDir}`]);
    assert.ok(verRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Security: verifyManifestBundle rejects artifact filenames with path traversal", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-traversal-test-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    generateManifestBundle({ targetDir: tmpDir, resultsData, receiptData });

    const manifestFile = path.join(tmpDir, "artifact-manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
    manifest.artifacts["../../sensitive.txt"] = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), "utf8");

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, false);
    assert.ok(verification.errors.some(e => e.includes("Prohibited path traversal")));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Bundle Generator: respects caller custom metadata override", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-custom-meta-"));
  try {
    const { resultsData, receiptData } = createTestFixtures();
    const bundle = generateManifestBundle({
      targetDir: tmpDir,
      resultsData,
      receiptData,
      metadata: {
        runId: "custom-run-override-999",
        customTag: "rc-validation"
      }
    });

    assert.equal(bundle.manifest.metadata.runId, "custom-run-override-999");
    assert.equal(bundle.manifest.metadata.customTag, "rc-validation");

    const summaryContent = fs.readFileSync(bundle.summaryPath, "utf8");
    assert.ok(summaryContent.includes("custom-run-override-999"));

    const verification = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verification.valid, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Environment: TRIAD_LIVE_BENCHMARK activates live benchmark mode in scripts/run-real-benchmark.mjs", async () => {
  const benchScript = path.resolve("scripts/run-real-benchmark.mjs");
  // Combining --virtual with live mode is prohibited and fails with exit 1
  await assert.rejects(
    async () => {
      await execFileAsync(process.execPath, [benchScript, "--virtual"], {
        env: { ...process.env, TRIAD_LIVE_BENCHMARK: "1" }
      });
    },
    (err) => {
      assert.equal(err.code, 1);
      assert.ok(err.stderr.includes("Live evaluation requires physical repository workspace"));
      return true;
    }
  );
});

test("Exports: manifest-bundle.mjs exports buildArtifactManifest and validateArtifactManifest", () => {
  assert.equal(typeof buildArtifactManifest, "function");
  assert.equal(typeof validateArtifactManifest, "function");
});

test("Evidence Bundle: verifyManifestBundle verifies multi-file release bundles when bundleId is set", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-test-evidence-bundle-"));
  try {
    const file1 = path.join(tmpDir, "corpus-identity.json");
    const file2 = path.join(tmpDir, "release-identity.json");
    fs.writeFileSync(file1, "{\"corpus\":\"test\"}\n", "utf8");
    fs.writeFileSync(file2, "{\"release\":\"test\"}\n", "utf8");

    const digest1 = computeDigest(fs.readFileSync(file1));
    const digest2 = computeDigest(fs.readFileSync(file2));

    const manifest = buildArtifactManifest({
      artifacts: {
        "corpus-identity.json": digest1,
        "release-identity.json": digest2
      },
      metadata: {
        bundleId: "TF-EVIDENCE-TEST",
        commitSha: "abcdef1234567890abcdef1234567890abcdef12"
      }
    });

    const manifestPath = path.join(tmpDir, "artifact-manifest.json");
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");

    // 1. Programmatic verification
    const res = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(res.valid, true);
    assert.equal(res.verifiedArtifacts.length, 2);

    // 2. CLI script verification with --bundle flag
    const scriptPath = path.resolve("scripts/verify-artifact-manifest.mjs");
    const { stdout } = await execFileAsync(process.execPath, [scriptPath, "--bundle", tmpDir]);
    assert.ok(stdout.includes("Manifest Bundle Verification SUCCEEDED"));
    assert.ok(stdout.includes("corpus-identity.json"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});


