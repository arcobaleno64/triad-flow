/**
 * Contract & Smoke Tests for Triad-Flow TF-EVIDENCE-0011 Assembler
 *
 * Verifies:
 * 1. Script loads and parses arguments correctly (--help, --live, --mock, --dry-run, --case).
 * 2. Default execution produces valid bundle metadata and seals with artifact-manifest.json.
 * 3. Manifest verification passes via verifyManifestBundle.
 * 4. Frozen TF-OSS-v2 corpus digest matches sha256:87d0720fbca96d4e8d2070260d25631eecb9ae84b60b77a0729fc23dd1975117.
 * 5. Adherence to Provider Execution Contracts & Security Rules (agy, claude, codex).
 * 6. Single target case execution (--case TF-OSS-201 and --case redis).
 * 7. CLI subprocess execution with --help and --dry-run.
 * 8. Gate policy pass: 10/10 cases achieve gatePolicyPass=true (BLOCK).
 * 9. Truthful README generation on pass, detection miss, partial run, and incomplete run.
 * 10. Independent verifier failure resilience and fail-closed handling.
 * 11. Cryptographic integrity of the committed bundle in evidence-runs/TF-EVIDENCE-0011.
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
  assembleEvidence0011,
  getCurrentCommitSha,
  getCurrentBranch,
  DEFAULT_BASELINE_COMMIT_SHA,
  DEFAULT_BUNDLE_DIR
} from "../scripts/assemble-evidence-0011.mjs";

import {
  TF_OSS_CORPUS_V2_CASES,
  TF_OSS_V2_EXPECTED_CORPUS_DIGEST,
  TF_OSS_V2_EXPECTED_CASE_DIGESTS
} from "./fixtures/real-oss-v2-fixtures.mjs";

import { createCorpusIdentity } from "../src/core/canonical-digest.mjs";
import { verifyManifestBundle } from "../src/core/manifest-bundle.mjs";
import { resolveProviderProfile } from "../src/adapters/provider-profiles.mjs";
import { validateAuditReceipt } from "../src/core/audit-receipt.mjs";
import { validateVerificationRecord } from "../src/core/independent-verifier.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";

test("Contract 1: parseArgs correctly parses all CLI flags and defaults for 0011", () => {
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

  const c1 = parseArgs(["--case", "TF-OSS-201"]);
  assert.equal(c1.caseId, "TF-OSS-201");
  const c2 = parseArgs(["--case=TF-OSS-202"]);
  assert.equal(c2.caseId, "TF-OSS-202");
  const c3 = parseArgs(["--case=redis"]);
  assert.equal(c3.caseId, "redis");

  const o1 = parseArgs(["--out-dir", "/custom/path"]);
  assert.equal(o1.outDir, "/custom/path");
  const o2 = parseArgs(["--dest", "/custom/dest"]);
  assert.equal(o2.outDir, "/custom/dest");

  const t1 = parseArgs(["--timeout", "120000"]);
  assert.equal(t1.timeoutMs, 120000);
  const t2 = parseArgs(["--timeout=60000"]);
  assert.equal(t2.timeoutMs, 60000);

  const h1 = parseArgs(["--help"]);
  assert.equal(h1.help, true);
  const h2 = parseArgs(["-h"]);
  assert.equal(h2.help, true);

  // Conflicting flags
  assert.throws(() => parseArgs(["--live", "--mock"]), /Cannot specify both/);

  // Invalid timeout
  assert.throws(() => parseArgs(["--timeout", "abc"]), /Invalid --timeout value/);
  assert.throws(() => parseArgs(["--timeout", "-5"]), /Invalid --timeout value/);

  // Unknown flag
  assert.throws(() => parseArgs(["--unknown"]), /Unknown option/);
});

test("Contract 2: Frozen TF-OSS-v2 corpus digest matches pinned digest and all 10 case digests in 0011", () => {
  const corpusIdentity = createCorpusIdentity(TF_OSS_CORPUS_V2_CASES, { corpusVersion: "TF-OSS-v2" });

  assert.equal(
    corpusIdentity.corpusDigest,
    TF_OSS_V2_EXPECTED_CORPUS_DIGEST,
    "Corpus digest must exactly match frozen TF-OSS-v2 digest"
  );
  assert.equal(
    corpusIdentity.corpusDigest,
    "sha256:87d0720fbca96d4e8d2070260d25631eecb9ae84b60b77a0729fc23dd1975117"
  );

  assert.equal(Object.keys(corpusIdentity.caseDigests).length, 10);
  for (const [caseId, expectedCaseDigest] of Object.entries(TF_OSS_V2_EXPECTED_CASE_DIGESTS)) {
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

test("Contract 4: Offline simulation produces valid bundle metadata, sealed manifest, 10/10 gatePolicyPass, and passes verifyManifestBundle", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-evidence-0011-"));

  try {
    const result = await assembleEvidence0011({
      mock: true,
      outDir: tempDir,
      log: false
    });

    assert.equal(result.bundleId, "TF-EVIDENCE-0011");
    assert.equal(result.benchmarkResults.bundleId, "TF-EVIDENCE-0011");
    assert.equal(result.benchmarkResults.executionMode, "mock");
    assert.equal(result.benchmarkResults.totalCases, 10);

    // Acceptance check: all 10 cases have gatePolicyPass=true
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
      "verification/verification-record.json"
    ];

    for (let i = 201; i <= 210; i++) {
      requiredFiles.push(`verification-records/TF-OSS-${i}-verification.json`);
      requiredFiles.push(`verification/TF-OSS-${i}-verification.json`);
    }

    for (const rel of requiredFiles) {
      assert.ok(fs.existsSync(path.join(tempDir, rel)), `Missing required bundle file: ${rel}`);
    }

    // Verify manifest bundle cryptographically
    const verifyRes = verifyManifestBundle({
      targetDir: tempDir,
      bundle: true
    });
    assert.ok(verifyRes.valid, `Bundle manifest verification failed: ${verifyRes.errors?.join("; ")}`);
    assert.equal(verifyRes.verifiedArtifacts.length, 29);

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

test("Contract 5: Single target case execution (--case TF-OSS-201 and --case redis) for 0011", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-single-0011-"));

  try {
    const result1 = await assembleEvidence0011({
      mock: true,
      caseId: "TF-OSS-201",
      outDir: tempDir,
      log: false
    });

    assert.equal(result1.benchmarkResults.totalCases, 1);
    assert.equal(result1.benchmarkResults.caseResults[0].caseId, "TF-OSS-201");
    assert.equal(result1.benchmarkResults.caseResults[0].gatePolicyPass, true);

    const verifyRes1 = verifyManifestBundle({
      targetDir: tempDir,
      bundle: true
    });
    assert.ok(verifyRes1.valid);

    // By name "redis"
    const result2 = await assembleEvidence0011({
      mock: true,
      caseId: "redis",
      outDir: tempDir,
      log: false
    });

    assert.equal(result2.benchmarkResults.totalCases, 1);
    assert.equal(result2.benchmarkResults.caseResults[0].caseId, "TF-OSS-201");
    assert.equal(result2.benchmarkResults.caseResults[0].name, "redis");
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 6: CLI Subprocess --help displays usage and exits 0 for 0011", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0011.mjs", "--help"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0011"));
  assert.ok(res.stdout.includes("--live"));
  assert.ok(res.stdout.includes("--mock"));
  assert.ok(res.stdout.includes("--dry-run"));
});

test("Contract 7: CLI Subprocess --dry-run executes in mock mode and verifies manifest without touching evidence-runs/", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0011.mjs", "--dry-run"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0011"));
  assert.ok(res.stdout.includes("Bundle successfully assembled and sealed!"));
});

test("Contract 8: Truthful README generation under 10/10 pass (TARGET MET, all defended, zero debt)", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-10-10-"));

  try {
    await assembleEvidence0011({
      mock: true,
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    // Must report TARGET MET, not TARGET MISSED
    assert.ok(readmeContent.includes("**TARGET MET**"), "Must report TARGET MET when 10/10 pass");
    assert.ok(!readmeContent.includes("**TARGET MISSED**"), "Must NOT report TARGET MISSED when 10/10 pass");

    // Must list all 10 defended cases
    assert.ok(
      readmeContent.includes("cases TF-OSS-201, TF-OSS-202, TF-OSS-203, TF-OSS-204, TF-OSS-205, TF-OSS-206, TF-OSS-207, TF-OSS-208, TF-OSS-209, TF-OSS-210 defended"),
      "Must list all 10 defended cases"
    );

    // Debt section must state None
    assert.ok(
      readmeContent.includes("None. All 10 evaluated case(s) satisfied expected detection and gate decisions."),
      "Must report zero debt when 10/10 pass"
    );

    // Corpus immutability must report PASS
    assert.ok(
      readmeContent.includes(`| **Corpus Immutability** | ${TF_OSS_V2_EXPECTED_CORPUS_DIGEST} | Verified byte-for-byte unchanged | **PASS** |`)
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 9: Truthful README generation under detection miss (TARGET MISSED, only defended cases listed, debt recorded)", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-9-10-"));

  // Mock adapters where TF-OSS-208 returns empty findings (simulating detection miss)
  function create9of10Adapters() {
    function findCaseForInput(input) {
      const filePaths = (input.changeSet?.files || []).map(f => f.path.replace(/\\/g, "/"));
      for (const c of TF_OSS_CORPUS_V2_CASES) {
        for (const target of c.targetFiles || []) {
          if (filePaths.includes(target.replace(/\\/g, "/"))) return c;
        }
      }
      return null;
    }

    function createExecFn(role) {
      return async ({ input }) => {
        const c = findCaseForInput(input);
        const coveredFiles = (input.changeSet?.files || []).map(f => f.path);
        let findings = [];
        if (c && c.goldenFindings && c.id !== "TF-OSS-208") {
          const g = c.goldenFindings[0];
          findings.push({
            title: `Detected ${g.type} in ${c.name}`,
            severity: "high",
            file: g.file,
            line_start: g.line,
            line_end: g.line,
            cwe: g.cwe,
            type: g.type,
            recommendation: g.rationale
          });
        }
        return {
          stdout: JSON.stringify({
            findings,
            coverage: { coveredFiles, omittedFiles: [] },
            usage: { promptTokens: 400, completionTokens: 50, totalTokens: 450 }
          })
        };
      };
    }

    return {
      agy: new CliReviewAdapter({ command: "agy", providerName: "agy", modelName: "gemini-3.8-flash", actualModel: { value: "gemini-3.8-flash", source: "reported" }, execFn: createExecFn("agy") }),
      claude: new CliReviewAdapter({ command: "claude", providerName: "claude", modelName: "claude-5.5-sonnet", actualModel: { value: "claude-5.5-sonnet", source: "reported" }, execFn: createExecFn("claude") }),
      codex: new CliReviewAdapter({ command: "codex", providerName: "codex", modelName: "gpt-6.1-sol", actualModel: { value: "gpt-6.1-sol", source: "reported" }, execFn: createExecFn("codex") })
    };
  }

  try {
    await assembleEvidence0011({
      mock: true,
      reviewAdapters: create9of10Adapters(),
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    // Must report TARGET MISSED
    assert.ok(readmeContent.includes("**TARGET MISSED**"), "Must report TARGET MISSED when 9/10 pass");
    assert.ok(!readmeContent.includes("**TARGET MET**"), "Must NOT report TARGET MET when 9/10 pass");

    // TF-OSS-208 must NOT be listed in defended cases
    assert.ok(!readmeContent.includes("TF-OSS-208 defended"), "Must NOT list TF-OSS-208 as defended");

    // Debt section must record TF-OSS-208
    assert.ok(readmeContent.includes("- **TF-OSS-208"), "Must record TF-OSS-208 in debt");
    assert.ok(readmeContent.includes("Expected Gate: `BLOCK` | Actual Gate: `APPROVE`"), "Must record gate discrepancy");
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 10: Truthful README generation on partial run (--case TF-OSS-201) never describes unexecuted cases", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-partial-"));

  try {
    await assembleEvidence0011({
      mock: true,
      caseId: "TF-OSS-201",
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    assert.ok(readmeContent.includes("cases TF-OSS-201 defended"), "Must list TF-OSS-201 defended");
    for (let i = 202; i <= 210; i++) {
      assert.ok(!readmeContent.includes(`TF-OSS-${i}`), `Must NOT mention unexecuted case TF-OSS-${i}`);
    }
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 11: Truthful README generation on incomplete execution marks failure as G4-BLOCKING", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-incomplete-blocking-"));

  function createIncompleteAdapters() {
    function createExecFn(role) {
      return async ({ input }) => {
        const filePaths = (input.changeSet?.files || []).map(f => f.path.replace(/\\/g, "/"));
        const isCase10 = filePaths.some(p => p.includes("commit-graph.c"));
        if (isCase10) {
          return {
            ok: false,
            executionStatus: "timeout",
            error: { code: "TIMEOUT", message: "Provider timeout" }
          };
        }
        return {
          stdout: JSON.stringify({
            findings: [{
              title: "Detected vulnerability",
              severity: "high",
              file: filePaths[0] || "test.c",
              line_start: 1,
              line_end: 1,
              cwe: "CWE-125",
              type: "out-of-bounds-read",
              recommendation: "Fix"
            }],
            coverage: { coveredFiles: filePaths, omittedFiles: [] },
            usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 }
          })
        };
      };
    }
    return {
      agy: new CliReviewAdapter({ command: "agy", providerName: "agy", modelName: "gemini-3.8-flash", actualModel: { value: "gemini-3.8-flash", source: "reported" }, execFn: createExecFn("agy") }),
      claude: new CliReviewAdapter({ command: "claude", providerName: "claude", modelName: "claude-5.5-sonnet", actualModel: { value: "claude-5.5-sonnet", source: "reported" }, execFn: createExecFn("claude") }),
      codex: new CliReviewAdapter({ command: "codex", providerName: "codex", modelName: "gpt-6.1-sol", actualModel: { value: "gpt-6.1-sol", source: "reported" }, execFn: createExecFn("codex") })
    };
  }

  try {
    await assembleEvidence0011({
      mock: true,
      reviewAdapters: createIncompleteAdapters(),
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    const oss10Idx = readmeContent.indexOf("- **TF-OSS-210");
    assert.ok(oss10Idx !== -1, "TF-OSS-210 debt entry must exist");
    const oss10Block = readmeContent.slice(oss10Idx);

    assert.ok(
      oss10Block.includes("G4-BLOCKING"),
      "Incomplete run must be explicitly labeled G4-BLOCKING"
    );
    assert.ok(
      !oss10Block.includes("Non-blocking for G4"),
      "Incomplete case must NOT be labeled Non-blocking for G4"
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 12: Independent verifier failure marks all cases incomplete and fails acceptance gate", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-verif-fail-11-"));

  const failingVerifierAdapter = {
    providerName: "claude",
    executeVerification: async () => ({
      ok: false,
      error: "Verifier connection timed out",
      evaluations: []
    })
  };

  try {
    await assembleEvidence0011({
      mock: true,
      verifierAdapter: failingVerifierAdapter,
      outDir: tempDir,
      log: false
    });

    const results = JSON.parse(fs.readFileSync(path.join(tempDir, "benchmark-results.json"), "utf8"));
    const readme = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    assert.equal(results.metrics.incompleteCasesCount, 10, "All 10 cases must be incomplete when verifier fails");
    assert.equal(results.metrics.incompleteRate, 1.0);

    for (const c of results.caseResults) {
      assert.equal(c.incomplete, true, `Case ${c.caseId} must be incomplete`);
      assert.equal(c.status, "incomplete", `Case ${c.caseId} status must be incomplete`);
      assert.equal(c.verifierFailed, true, `Case ${c.caseId} verifierFailed must be true`);
      assert.equal(c.passed, false, `Case ${c.caseId} passed must be false`);
    }

    assert.ok(
      readme.includes("| **Incomplete Runs** | 0/10 cases (zero incomplete runs) | **100.0%** (10/10) | **FAIL** |"),
      "Must fail Incomplete Runs gate when verifier fails"
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 13: Committed offline evidence bundle in evidence-runs/TF-EVIDENCE-0011 is authoritative and valid", () => {
  assert.ok(fs.existsSync(DEFAULT_BUNDLE_DIR), `Bundle dir ${DEFAULT_BUNDLE_DIR} must exist on disk`);

  // 1. Verify manifest
  const verifyRes = verifyManifestBundle({
    targetDir: DEFAULT_BUNDLE_DIR,
    bundle: true
  });
  assert.ok(verifyRes.valid, `Bundle manifest validation failed: ${verifyRes.errors?.join("; ")}`);
  assert.equal(verifyRes.verifiedArtifacts.length, 29);

  // 2. Validate audit receipt
  const receiptPath = path.join(DEFAULT_BUNDLE_DIR, "audit-receipt.json");
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const receiptValidation = validateAuditReceipt(receipt);
  assert.ok(receiptValidation.valid, `Audit receipt invalid: ${receiptValidation.errors?.join("; ")}`);

  // 3. Verify corpus identity
  const corpusPath = path.join(DEFAULT_BUNDLE_DIR, "corpus-identity.json");
  const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
  assert.equal(corpus.corpusDigest, TF_OSS_V2_EXPECTED_CORPUS_DIGEST);
  assert.equal(corpus.casesCount, 10);

  // 4. Verify benchmark results
  const resultsPath = path.join(DEFAULT_BUNDLE_DIR, "benchmark-results.json");
  const results = JSON.parse(fs.readFileSync(resultsPath, "utf8"));
  assert.equal(results.bundleId, "TF-EVIDENCE-0011");
  assert.equal(results.totalCases, 10);
  assert.equal(results.metrics.recall, 1.0);
  assert.equal(results.metrics.incompleteCasesCount, 0);

  // 5. Verify disagreement ledger
  const ledgerPath = path.join(DEFAULT_BUNDLE_DIR, "disagreement-ledger.json");
  const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
  assert.ok(Array.isArray(ledger.triPartyEntries));
  assert.ok(ledger.triPartyEntries.length > 0);
  const solitary = ledger.triPartyEntries.find(e => e.type === "SOLITARY_BLOCKER_VETO");
  assert.ok(solitary, "Must have recorded SOLITARY_BLOCKER_VETO for TF-OSS-204");
  assert.equal(solitary.caseId, "TF-OSS-204");
});
