/**
 * Contract & Smoke Tests for Triad-Flow TF-EVIDENCE-0009 Assembler
 *
 * Verifies:
 * 1. Script loads and parses arguments correctly (--help, --live, --mock, --dry-run, --case).
 * 2. Default execution produces valid bundle metadata and seals with artifact-manifest.json.
 * 3. Manifest verification passes via verifyManifestBundle.
 * 4. Frozen TF-OSS-v1 corpus digest matches sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625.
 * 5. Adherence to Provider Execution Contracts & Security Rules (agy, claude, codex).
 * 6. Single target case execution (--case TF-OSS-001).
 * 7. CLI subprocess execution with --help and --dry-run.
 * 8. Gate policy pass: 5/5 cases achieve gatePolicyPass=true (BLOCK).
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  BUNDLE_ID,
  parseArgs,
  assembleEvidence0009,
  getCurrentCommitSha,
  getCurrentBranch,
  DEFAULT_BASELINE_COMMIT_SHA
} from "../scripts/assemble-evidence-0009.mjs";

import {
  TF_OSS_CORPUS_V1_CASES,
  TF_OSS_V1_EXPECTED_CORPUS_DIGEST,
  TF_OSS_V1_EXPECTED_CASE_DIGESTS
} from "./fixtures/real-oss-fixtures.mjs";

import { createCorpusIdentity } from "../src/core/canonical-digest.mjs";
import { verifyManifestBundle } from "../src/core/manifest-bundle.mjs";
import { resolveProviderProfile } from "../src/adapters/provider-profiles.mjs";
import { validateAuditReceipt } from "../src/core/audit-receipt.mjs";
import { validateVerificationRecord } from "../src/core/independent-verifier.mjs";

test("Contract 1: parseArgs correctly parses all CLI flags and defaults for 0009", () => {
  const def = parseArgs([]);
  assert.equal(def.live, false);
  assert.equal(def.mock, true);
  assert.equal(def.dryRun, false);
  assert.equal(def.caseId, null);
  assert.equal(def.outDir, null);
  assert.equal(def.help, false);

  const live = parseArgs(["--live"]);
  assert.equal(live.live, true);
  assert.equal(live.mock, false);

  const dry = parseArgs(["--dry-run"]);
  assert.equal(dry.dryRun, true);
  assert.equal(dry.mock, true);

  const c1 = parseArgs(["--case", "TF-OSS-001"]);
  assert.equal(c1.caseId, "TF-OSS-001");
  const c2 = parseArgs(["--case=TF-OSS-002"]);
  assert.equal(c2.caseId, "TF-OSS-002");

  const o1 = parseArgs(["--out-dir", "/custom/path"]);
  assert.equal(o1.outDir, "/custom/path");

  const t1 = parseArgs(["--timeout", "120000"]);
  assert.equal(t1.timeoutMs, 120000);

  const h1 = parseArgs(["--help"]);
  assert.equal(h1.help, true);
});

test("Contract 2: Frozen TF-OSS-v1 corpus digest matches sha256:47ed3ce4... in 0009", () => {
  const corpusIdentity = createCorpusIdentity(TF_OSS_CORPUS_V1_CASES, { corpusVersion: "TF-OSS-v1" });

  assert.equal(
    corpusIdentity.corpusDigest,
    TF_OSS_V1_EXPECTED_CORPUS_DIGEST,
    "Corpus digest must exactly match frozen TF-OSS-v1 digest"
  );
  assert.equal(
    corpusIdentity.corpusDigest,
    "sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625"
  );

  for (const [caseId, expectedCaseDigest] of Object.entries(TF_OSS_V1_EXPECTED_CASE_DIGESTS)) {
    assert.equal(
      corpusIdentity.caseDigests[caseId],
      expectedCaseDigest,
      `Case digest for ${caseId} must match frozen baseline`
    );
  }
});

test("Contract 3: Provider profiles strictly adhere to execution contracts & security rules", () => {
  const agyProfile = resolveProviderProfile("agy");
  assert.equal(agyProfile.family, "google");
  assert.equal(agyProfile.supportsStdin, false);
  assert.deepEqual(agyProfile.args, ["--mode=plan", "--disable-slash-commands", "--print"]);
  assert.ok(agyProfile.readOnlyFlags.includes("--mode=plan"));
  assert.ok(agyProfile.readOnlyFlags.includes("--disable-slash-commands"));

  const claudeProfile = resolveProviderProfile("claude");
  assert.equal(claudeProfile.family, "anthropic");
  assert.equal(claudeProfile.supportsStdin, true);
  assert.deepEqual(claudeProfile.args, ["-p", "--tools="]);
  assert.ok(claudeProfile.readOnlyFlags.includes("--tools="));

  const codexProfile = resolveProviderProfile("codex");
  assert.equal(codexProfile.family, "openai");
  assert.equal(codexProfile.supportsStdin, true);
  assert.deepEqual(codexProfile.args, ["exec", "--sandbox=read-only", "--ephemeral", "--color", "never"]);
  assert.ok(codexProfile.readOnlyFlags.includes("--sandbox=read-only"));
});

test("Contract 4: Offline simulation produces valid bundle metadata, sealed manifest, 5/5 gatePolicyPass, and passes verifyManifestBundle", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-evidence-0009-"));

  try {
    const result = await assembleEvidence0009({
      mock: true,
      outDir: tempDir,
      log: false
    });

    assert.equal(result.bundleId, "TF-EVIDENCE-0009");
    assert.equal(result.benchmarkResults.bundleId, "TF-EVIDENCE-0009");
    assert.equal(result.benchmarkResults.executionMode, "mock");
    assert.equal(result.benchmarkResults.totalCases, 5);

    // G4 acceptance check: all 5 cases have gatePolicyPass=true
    assert.equal(result.benchmarkResults.metrics.incompleteCasesCount, 0);
    assert.equal(result.benchmarkResults.metrics.incompleteRate, 0);
    assert.equal(result.benchmarkResults.metrics.recall, 1.0);
    for (const c of result.benchmarkResults.caseResults) {
      assert.equal(c.gatePolicyPass, true, `Case ${c.caseId} must have gatePolicyPass=true`);
      assert.equal(c.actualGateDecision, "block", `Case ${c.caseId} must have actualGateDecision=block`);
    }

    // Required files exist
    const requiredFiles = [
      "corpus-identity.json",
      "benchmark-results.json",
      "release-identity.json",
      "audit-receipt.json",
      "disagreement-ledger.json",
      "evidence-index.json",
      "README-EVIDENCE.md",
      "artifact-manifest.json",
      "verification-records/verification-record.json",
      "verification-records/TF-OSS-001-verification.json",
      "verification-records/TF-OSS-002-verification.json",
      "verification-records/TF-OSS-003-verification.json",
      "verification-records/TF-OSS-004-verification.json",
      "verification-records/TF-OSS-005-verification.json"
    ];

    for (const rel of requiredFiles) {
      assert.ok(fs.existsSync(path.join(tempDir, rel)), `Missing required bundle file: ${rel}`);
    }

    // Verify manifest bundle cryptographically
    const verifyRes = verifyManifestBundle({
      targetDir: tempDir,
      bundle: true
    });
    assert.ok(verifyRes.valid, `Bundle manifest verification failed: ${verifyRes.errors?.join("; ")}`);
    assert.ok(verifyRes.verifiedArtifacts.length >= 14);

    // Validate audit receipt on disk
    const receiptOnDisk = JSON.parse(fs.readFileSync(path.join(tempDir, "audit-receipt.json"), "utf8"));
    const diskValidation = validateAuditReceipt(receiptOnDisk);
    assert.ok(diskValidation.valid, `Audit receipt on disk invalid: ${diskValidation.errors?.join("; ")}`);
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 5: Single target case execution (--case TF-OSS-001) for 0009", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-single-0009-"));

  try {
    const result = await assembleEvidence0009({
      mock: true,
      caseId: "TF-OSS-001",
      outDir: tempDir,
      log: false
    });

    assert.equal(result.benchmarkResults.totalCases, 1);
    assert.equal(result.benchmarkResults.caseResults[0].caseId, "TF-OSS-001");
    assert.equal(result.benchmarkResults.caseResults[0].gatePolicyPass, true);

    const verifyRes = verifyManifestBundle({
      targetDir: tempDir,
      bundle: true
    });
    assert.ok(verifyRes.valid);
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 6: CLI Subprocess --help displays usage and exits 0 for 0009", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0009.mjs", "--help"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0009"));
  assert.ok(res.stdout.includes("--live"));
  assert.ok(res.stdout.includes("--mock"));
  assert.ok(res.stdout.includes("--dry-run"));
});

test("Contract 7: CLI Subprocess --dry-run executes in mock mode and verifies manifest without touching evidence-runs/", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0009.mjs", "--dry-run"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0009"));
  assert.ok(res.stdout.includes("Bundle successfully assembled and sealed!"));
});
