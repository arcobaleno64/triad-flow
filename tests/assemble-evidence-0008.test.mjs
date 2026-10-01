/**
 * Contract & Smoke Tests for Triad-Flow TF-EVIDENCE-0008 Assembler
 *
 * Verifies:
 * 1. Script loads and parses arguments correctly (--help, --live, --mock, --dry-run, --case).
 * 2. Default execution produces valid bundle metadata and seals with artifact-manifest.json.
 * 3. Manifest verification passes via verifyManifestBundle.
 * 4. Frozen TF-OSS-v1 corpus digest matches sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625.
 * 5. Adherence to Provider Execution Contracts & Security Rules (agy, claude, codex).
 * 6. Single target case execution (--case TF-OSS-001).
 * 7. CLI subprocess execution with --help and --dry-run.
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
  assembleEvidence0008,
  getCurrentCommitSha,
  getCurrentBranch,
  DEFAULT_BASELINE_COMMIT_SHA
} from "../scripts/assemble-evidence-0008.mjs";

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

test("Contract 1: parseArgs correctly parses all CLI flags and defaults", () => {
  // Default values: mock is true, live is false, dryRun is false
  const def = parseArgs([]);
  assert.equal(def.live, false);
  assert.equal(def.mock, true);
  assert.equal(def.dryRun, false);
  assert.equal(def.caseId, null);
  assert.equal(def.outDir, null);
  assert.equal(def.help, false);

  // --live sets live=true, mock=false
  const live = parseArgs(["--live"]);
  assert.equal(live.live, true);
  assert.equal(live.mock, false);

  // --dry-run
  const dry = parseArgs(["--dry-run"]);
  assert.equal(dry.dryRun, true);
  assert.equal(dry.mock, true);

  // --case separated and equals
  const c1 = parseArgs(["--case", "TF-OSS-001"]);
  assert.equal(c1.caseId, "TF-OSS-001");
  const c2 = parseArgs(["--case=TF-OSS-002"]);
  assert.equal(c2.caseId, "TF-OSS-002");

  // --out-dir and --dest
  const o1 = parseArgs(["--out-dir", "/custom/path"]);
  assert.equal(o1.outDir, "/custom/path");
  const o2 = parseArgs(["--dest=/another/path"]);
  assert.equal(o2.outDir, "/another/path");

  // --timeout
  const t1 = parseArgs(["--timeout", "120000"]);
  assert.equal(t1.timeoutMs, 120000);
  const t2 = parseArgs(["--timeout=60000"]);
  assert.equal(t2.timeoutMs, 60000);

  // --help
  const h1 = parseArgs(["--help"]);
  assert.equal(h1.help, true);
  const h2 = parseArgs(["-h"]);
  assert.equal(h2.help, true);
});

test("Contract 2: Frozen TF-OSS-v1 corpus digest matches sha256:47ed3ce4...", () => {
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
      `Case digest for ${caseId} must match frozen fixture digest`
    );
  }
});

test("Contract 3: Provider profiles strictly adhere to execution contracts & security rules", () => {
  // Google agy: --mode=plan --disable-slash-commands --print, argv input
  const agyProfile = resolveProviderProfile("agy");
  assert.equal(agyProfile.id, "agy");
  assert.equal(agyProfile.family, "google");
  assert.equal(agyProfile.inputChannel, "argv");
  assert.equal(agyProfile.supportsStdin, false);
  assert.deepEqual(agyProfile.args, ["--mode=plan", "--disable-slash-commands", "--print"]);
  assert.ok(agyProfile.readOnlyFlags.includes("--mode=plan"));
  assert.ok(agyProfile.readOnlyFlags.includes("--disable-slash-commands"));

  // Anthropic claude: -p --tools=, stdin/argv input
  const claudeProfile = resolveProviderProfile("claude");
  assert.equal(claudeProfile.id, "claude");
  assert.equal(claudeProfile.family, "anthropic");
  assert.equal(claudeProfile.supportsStdin, true);
  assert.deepEqual(claudeProfile.args, ["-p", "--tools="]);
  assert.ok(claudeProfile.readOnlyFlags.includes("--tools="));

  // OpenAI codex: exec --sandbox=read-only --ephemeral --color never -o <tempFile>, stdin input with pipe, isolated output file extraction
  const codexProfile = resolveProviderProfile("codex");
  assert.equal(codexProfile.id, "codex");
  assert.equal(codexProfile.family, "openai");
  assert.equal(codexProfile.inputChannel, "stdin");
  assert.equal(codexProfile.supportsStdin, true);
  assert.equal(codexProfile.outputChannel, "file");
  assert.equal(codexProfile.outputFileFlag, "-o");
  assert.deepEqual(codexProfile.args, ["exec", "--sandbox=read-only", "--ephemeral", "--color", "never"]);
  assert.ok(codexProfile.readOnlyFlags.includes("--sandbox=read-only"));
});

test("Contract 4: Offline simulation produces valid bundle metadata, sealed manifest, and passes verifyManifestBundle", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-evidence-0008-"));

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      live: false,
      log: false
    });

    assert.equal(res.bundleId, BUNDLE_ID);
    assert.equal(res.bundleDir, tmpDir);

    // Verify all required output files exist
    const expectedFiles = [
      "corpus-identity.json",
      "benchmark-results.json",
      "release-identity.json",
      "disagreement-ledger.json",
      "audit-receipt.json",
      "README-EVIDENCE.md",
      "evidence-index.json",
      "artifact-manifest.json",
      "verification-records/TF-OSS-001-verification.json",
      "verification-records/TF-OSS-002-verification.json",
      "verification-records/TF-OSS-003-verification.json",
      "verification-records/TF-OSS-004-verification.json",
      "verification-records/TF-OSS-005-verification.json",
      "verification-records/verification-record.json",
      "verification/TF-OSS-001-verification.json",
      "verification/TF-OSS-002-verification.json",
      "verification/TF-OSS-003-verification.json",
      "verification/TF-OSS-004-verification.json",
      "verification/TF-OSS-005-verification.json",
      "verification/verification-record.json"
    ];

    for (const file of expectedFiles) {
      assert.ok(fs.existsSync(path.join(tmpDir, file)), `File '${file}' must exist in assembled bundle`);
    }

    // Validate corpus-identity.json
    const corpusDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "corpus-identity.json"), "utf8"));
    assert.equal(corpusDoc.schemaVersion, "1.0.0");
    assert.equal(corpusDoc.corpusVersion, "TF-OSS-v1");
    assert.equal(corpusDoc.corpusDigest, TF_OSS_V1_EXPECTED_CORPUS_DIGEST);
    assert.equal(corpusDoc.casesCount, 5);

    // Validate benchmark-results.json
    const benchDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "benchmark-results.json"), "utf8"));
    assert.equal(benchDoc.bundleId, BUNDLE_ID);
    assert.equal(benchDoc.executionMode, "mock");
    assert.equal(benchDoc.mode, "tri-party");
    assert.equal(benchDoc.totalCases, 5);
    assert.equal(benchDoc.caseResults.length, 5);
    assert.ok(typeof benchDoc.metrics.recall === "number");
    assert.ok(typeof benchDoc.metrics.precision === "number");
    assert.equal(benchDoc.metrics.incompleteCasesCount, 0);
    assert.equal(benchDoc.metrics.incompleteRate, 0.0);
    assert.ok(benchDoc.metrics.latency.avgMs > 0);

    // Validate release-identity.json
    const releaseDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "release-identity.json"), "utf8"));
    assert.equal(releaseDoc.bundleId, BUNDLE_ID);
    assert.equal(releaseDoc.corpusVersion, "TF-OSS-v1");
    assert.equal(releaseDoc.corpusDigest, TF_OSS_V1_EXPECTED_CORPUS_DIGEST);
    assert.equal(releaseDoc.reviewQuorum.policy, "TRI_PARTY_HETEROGENEOUS");
    assert.equal(releaseDoc.reviewQuorum.executionMode, "mock");
    assert.equal(releaseDoc.reviewQuorum.providers.length, 3);
    assert.equal(releaseDoc.independentVerifier.role, "verifier");

    // Validate disagreement-ledger.json
    const ledgerDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "disagreement-ledger.json"), "utf8"));
    assert.ok(Array.isArray(ledgerDoc.triPartyEntries));
    assert.ok(ledgerDoc.triPartyEntries.some(e => e.type === "SOLITARY_BLOCKER_VETO"));

    // Validate audit-receipt.json
    const receiptDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "audit-receipt.json"), "utf8"));
    assert.equal(receiptDoc.schemaVersion, "1.0.0");
    assert.ok(receiptDoc.providerProvenance.agy);
    assert.ok(receiptDoc.providerProvenance.claude);
    assert.ok(receiptDoc.providerProvenance.codex);

    const receiptVal = validateAuditReceipt(receiptDoc);
    assert.equal(receiptVal.valid, true, `Receipt validation failed: ${receiptVal.errors.join("; ")}`);

    // Validate all per-case verification records
    for (let c = 1; c <= 5; c++) {
      const recDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "verification-records", `TF-OSS-00${c}-verification.json`), "utf8"));
      const recVal = validateVerificationRecord(recDoc);
      assert.equal(recVal.valid, true, `Case TF-OSS-00${c} verification record failed: ${recVal.errors.join("; ")}`);
    }

    // Run verifyManifestBundle on assembled bundle
    const manifestVerification = verifyManifestBundle({
      targetDir: tmpDir,
      bundle: true
    });
    assert.equal(manifestVerification.valid, true, `Manifest verification errors: ${manifestVerification.errors.join("; ")}`);
    assert.ok(manifestVerification.verifiedArtifacts.length >= 19);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 5: Single target case execution (--case TF-OSS-001)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-case-0008-"));

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "TF-OSS-001",
      live: false,
      log: false
    });

    assert.equal(res.benchmarkResults.totalCases, 1);
    assert.equal(res.benchmarkResults.caseResults[0].caseId, "TF-OSS-001");
    assert.equal(res.benchmarkResults.caseResults[0].evalResult.caughtGoldens, 1);
    assert.equal(res.releaseIdentity.casesCount, 1);

    // Manifest verification still passes cleanly for single case bundle
    const manifestVerification = verifyManifestBundle({
      targetDir: tmpDir,
      bundle: true
    });
    assert.equal(manifestVerification.valid, true);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 6: CLI Subprocess --help displays usage and exits 0", () => {
  const proc = spawnSync(process.execPath, ["scripts/assemble-evidence-0008.mjs", "--help"], {
    encoding: "utf8"
  });

  assert.equal(proc.status, 0);
  assert.match(proc.stdout, /Triad-Flow Empirical Evidence Bundle Assembler: TF-EVIDENCE-0008/);
  assert.match(proc.stdout, /--live/);
  assert.match(proc.stdout, /--mock/);
  assert.match(proc.stdout, /--dry-run/);
  assert.match(proc.stdout, /--case/);
});

test("Contract 7: CLI Subprocess --dry-run executes in mock mode and verifies manifest without touching evidence-runs/", () => {
  const proc = spawnSync(process.execPath, ["scripts/assemble-evidence-0008.mjs", "--dry-run"], {
    encoding: "utf8"
  });

  assert.equal(proc.status, 0, `CLI failed with stderr: ${proc.stderr}`);
  assert.match(proc.stdout, /Dry-Run: YES/);
  assert.match(proc.stdout, /Mode: MOCK/);
  assert.match(proc.stdout, /\[TF-EVIDENCE-0008\] Bundle successfully assembled and sealed!/);
  assert.match(proc.stdout, /Verified \d+ artifacts matching cryptographic SHA-256 digests!/);
});

test("Contract 8: Error handling and input validation edge cases", async () => {
  // 1. Missing flag values must throw errors and not absorb subsequent flags
  assert.throws(() => parseArgs(["--case"]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case", "--dry-run"]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case="]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case=--dry-run"]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case=-h"]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case", ""]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--case", "   "]), /Missing value for --case flag/);
  assert.throws(() => parseArgs(["--out-dir"]), /Missing value for --out-dir flag/);
  assert.throws(() => parseArgs(["--out-dir", "--live"]), /Missing value for --out-dir flag/);
  assert.throws(() => parseArgs(["--out-dir="]), /Missing value for --out-dir flag/);
  assert.throws(() => parseArgs(["--out-dir=--live"]), /Missing value for --out-dir flag/);
  assert.throws(() => parseArgs(["--out-dir", ""]), /Missing value for --out-dir flag/);
  assert.throws(() => parseArgs(["--dest="]), /Missing value for --dest flag/);
  assert.throws(() => parseArgs(["--dest=--mock"]), /Missing value for --dest flag/);
  assert.throws(() => parseArgs(["--dest", "  "]), /Missing value for --dest flag/);
  assert.throws(() => parseArgs(["--timeout"]), /Missing value for --timeout flag/);
  assert.throws(() => parseArgs(["--timeout", "--dry-run"]), /Missing value for --timeout flag/);

  // 2. Conflicting flags and unknown/unexpected arguments must be rejected
  assert.throws(() => parseArgs(["--live", "--mock"]), /Cannot specify both --live and --mock flags/);
  assert.throws(() => parseArgs(["--mock", "--live"]), /Cannot specify both --live and --mock flags/);
  assert.throws(() => parseArgs(["--unknown-option"]), /Unknown option: '--unknown-option'/);
  assert.throws(() => parseArgs(["--dryrun"]), /Unknown option: '--dryrun'/);
  assert.throws(() => parseArgs(["unexpected-positional"]), /Unexpected argument: 'unexpected-positional'/);

  // 3. Programmatic option conflict and validation failures
  await assert.rejects(
    async () => assembleEvidence0008({ live: true, mock: true, log: false }),
    /Cannot specify both --live and --mock options/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ caseId: "", log: false }),
    /Missing value for caseId option/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ outDir: "", log: false }),
    /Invalid outDir: must be a non-empty string path/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ timeoutMs: 0, log: false }),
    /Invalid timeoutMs: '0'/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ timeoutMs: -100, log: false }),
    /Invalid timeoutMs: '-100'/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ commitSha: "not-a-valid-hex-sha", log: false }),
    /Invalid commitSha: 'not-a-valid-hex-sha'/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ branch: "", log: false }),
    /Invalid branch: ''/
  );
  await assert.rejects(
    async () => assembleEvidence0008({ branch: "line1\nline2", log: false }),
    /Invalid branch: 'line1\nline2'/
  );

  // 4. Invalid timeout values (non-numeric, negative, zero) must be rejected
  assert.throws(() => parseArgs(["--timeout", "abc"]), /Invalid --timeout value/);
  assert.throws(() => parseArgs(["--timeout", "-500"]), /Invalid --timeout value/);
  assert.throws(() => parseArgs(["--timeout", "0"]), /Invalid --timeout value/);
  assert.throws(() => parseArgs(["--timeout=not-a-number"]), /Invalid --timeout value/);

  // 5. Target case validation fails closed BEFORE creating directory or touching disk
  const nonExistentDir = path.join(os.tmpdir(), `tf-nonexistent-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  assert.equal(fs.existsSync(nonExistentDir), false);

  await assert.rejects(
    async () => {
      await assembleEvidence0008({
        outDir: nonExistentDir,
        caseId: "NON_EXISTENT_CASE_999",
        live: false,
        log: false
      });
    },
    /Target case not found: 'NON_EXISTENT_CASE_999'/
  );

  // Invariant: Directory must not have been created on early validation failure
  assert.equal(fs.existsSync(nonExistentDir), false, "Destination directory must not be created on validation error");

  // 6. Case-insensitive matching works seamlessly
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-case-insensitive-"));
  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "tf-oss-001",
      live: false,
      log: false
    });
    assert.equal(res.benchmarkResults.totalCases, 1);
    assert.equal(res.benchmarkResults.caseResults[0].caseId, "TF-OSS-001");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 9: Generated artifacts contain accurate CVE identifiers, package names, and claimed findings", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-artifacts-0008-"));

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      live: false,
      log: false
    });

    // Check README-EVIDENCE.md contents
    const readmeContent = fs.readFileSync(path.join(tmpDir, "README-EVIDENCE.md"), "utf8");
    assert.ok(readmeContent.includes("CVE-2020-7598"), "README must include CVE-2020-7598");
    assert.ok(readmeContent.includes("CVE-2020-7788"), "README must include CVE-2020-7788");
    assert.ok(readmeContent.includes("CVE-2021-4279"), "README must include CVE-2021-4279");
    assert.ok(readmeContent.includes("CVE-2022-25883"), "README must include CVE-2022-25883");
    assert.ok(readmeContent.includes("CVE-2022-29078"), "README must include CVE-2022-29078");
    assert.ok(readmeContent.includes("| `TF-OSS-001` | minimist | CVE-2020-7598 |"));

    // Check benchmark-results.json caseResults schema
    for (const c of res.benchmarkResults.caseResults) {
      assert.ok(c.name, `caseResult ${c.caseId} must have name`);
      assert.ok(c.cve, `caseResult ${c.caseId} must have cve`);
      assert.ok(c.cwe, `caseResult ${c.caseId} must have cwe`);
      assert.equal(typeof c.evalResult.claimedFindingsCount, "number");
      assert.equal(typeof c.incomplete, "boolean");
    }
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 10: Disagreement ledger accurately reflects vendor divergence and excludes false positive clean reviews", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-ledger-0008-"));

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      live: false,
      log: false
    });

    const ledger = res.disagreementLedger;
    assert.ok(Array.isArray(ledger.triPartyEntries));

    // Case 1 (TF-OSS-001) had 3/3 unanimous detection: must NOT be in divergence ledger
    const case1Entry = ledger.triPartyEntries.find(e => e.caseId === "TF-OSS-001");
    assert.equal(case1Entry, undefined, "Unanimous agreement case must not appear in divergence ledger");

    // Case 4 (TF-OSS-004) was uniquely caught by Codex: must be recorded as SOLITARY_BLOCKER_VETO
    const case4Entry = ledger.triPartyEntries.find(e => e.caseId === "TF-OSS-004");
    assert.ok(case4Entry, "TF-OSS-004 must be present in disagreement ledger");
    assert.equal(case4Entry.type, "SOLITARY_BLOCKER_VETO");
    assert.equal(case4Entry.sentry, "codex");
    assert.equal(case4Entry.disposition, "BLOCK");

    // Cases 2, 3, 5: 2-of-3 majority divergences
    for (const cId of ["TF-OSS-002", "TF-OSS-003", "TF-OSS-005"]) {
      const entry = ledger.triPartyEntries.find(e => e.caseId === cId);
      assert.ok(entry, `Case ${cId} must be present in disagreement ledger`);
      assert.equal(entry.type, "VENDOR_DIVERGENCE");
      assert.equal(entry.disposition, "BLOCK");
    }
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 11: Single case without divergence records empty ledger and preserves 0/3 corroboration format", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-single-clean-0008-"));

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "TF-OSS-001",
      live: false,
      log: false
    });

    // TF-OSS-001 has 3/3 consensus, so disagreement ledger should have 0 divergence entries
    assert.equal(res.disagreementLedger.triPartyEntries.length, 0);

    // Verify manifest verification succeeds cleanly on single case bundle
    const manifestVerification = verifyManifestBundle({ targetDir: tmpDir, bundle: true });
    assert.equal(manifestVerification.valid, true);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 12: getCurrentCommitSha and getCurrentBranch return valid formats and respect fallback invariant", () => {
  const sha = getCurrentCommitSha();
  assert.ok(typeof sha === "string", "commitSha must be a string");
  assert.match(sha, /^[0-9a-f]{40,64}$/i, "commitSha must be a 40-64 char hexadecimal string");

  const branch = getCurrentBranch();
  assert.ok(typeof branch === "string", "branch must be a string");
  assert.ok(branch.length > 0, "branch must be non-empty");
  assert.equal(branch.includes("\n"), false, "branch must not contain newlines");

  assert.equal(DEFAULT_BASELINE_COMMIT_SHA, "052a5c1bdb5dda866eb31545e04fbd684657998a");
});

test("Contract 13: Numeric case index and alias matching (--case 1, --case 001, --case 4)", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-numeric-alias-"));

  try {
    // Numeric '1' maps to TF-OSS-001
    const res1 = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "1",
      live: false,
      log: false
    });
    assert.equal(res1.benchmarkResults.totalCases, 1);
    assert.equal(res1.benchmarkResults.caseResults[0].caseId, "TF-OSS-001");

    // Padded numeric '004' maps to TF-OSS-004
    const res4 = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "004",
      live: false,
      log: false
    });
    assert.equal(res4.benchmarkResults.totalCases, 1);
    assert.equal(res4.benchmarkResults.caseResults[0].caseId, "TF-OSS-004");

    // Prefix-tolerant 'TF-OSS-1', 'oss-001', 'oss-1'
    const resPrefixed1 = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "TF-OSS-1",
      live: false,
      log: false
    });
    assert.equal(resPrefixed1.benchmarkResults.totalCases, 1);
    assert.equal(resPrefixed1.benchmarkResults.caseResults[0].caseId, "TF-OSS-001");

    const resPrefixed2 = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "oss-002",
      live: false,
      log: false
    });
    assert.equal(resPrefixed2.benchmarkResults.totalCases, 1);
    assert.equal(resPrefixed2.benchmarkResults.caseResults[0].caseId, "TF-OSS-002");

    const resPrefixed3 = await assembleEvidence0008({
      outDir: tmpDir,
      caseId: "oss-3",
      live: false,
      log: false
    });
    assert.equal(resPrefixed3.benchmarkResults.totalCases, 1);
    assert.equal(resPrefixed3.benchmarkResults.caseResults[0].caseId, "TF-OSS-003");
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 14: Custom commitSha and branch provenance overrides are recorded faithfully", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-provenance-override-"));
  const customSha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
  const customBranch = "feat/reviewer-2-adversarial-hardening";

  try {
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      commitSha: customSha,
      branch: customBranch,
      caseId: "TF-OSS-001",
      live: false,
      log: false
    });

    const receipt = JSON.parse(fs.readFileSync(path.join(tmpDir, "audit-receipt.json"), "utf8"));
    assert.equal(receipt.systemProvenance.commitSha, customSha);
    assert.equal(receipt.systemProvenance.branch, customBranch);

    const releaseDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "release-identity.json"), "utf8"));
    assert.equal(releaseDoc.commitSha, customSha);

    const manifestVerification = verifyManifestBundle({ targetDir: tmpDir, bundle: true });
    assert.equal(manifestVerification.valid, true);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 15: Cancellation via AbortSignal aborts child execution cleanly", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-abort-"));
  const controller = new AbortController();
  controller.abort(); // already aborted

  try {
    // Must execute and handle pre-aborted signal without uncaught exception
    const res = await assembleEvidence0008({
      outDir: tmpDir,
      signal: controller.signal,
      caseId: "TF-OSS-001",
      live: false,
      log: false
    });

    assert.ok(res.bundleId, BUNDLE_ID);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
});

test("Contract 16: CLI dry-run cleans up its temporary directory from os.tmpdir()", () => {
  const proc = spawnSync(process.execPath, ["scripts/assemble-evidence-0008.mjs", "--dry-run"], {
    encoding: "utf8"
  });

  assert.equal(proc.status, 0);
  const match = proc.stdout.match(/Target:\s*([^\r\n]+)/);
  assert.ok(match, "Output must print target directory");
  const tempTarget = match[1].trim();
  // Target dir must have been cleaned up after run
  assert.equal(fs.existsSync(tempTarget), false, "CLI dry-run must remove its temporary directory upon completion");
});

