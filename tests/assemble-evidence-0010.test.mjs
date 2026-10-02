/**
 * Contract & Smoke Tests for Triad-Flow TF-EVIDENCE-0010 Assembler
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
  assembleEvidence0010,
  getCurrentCommitSha,
  getCurrentBranch,
  DEFAULT_BASELINE_COMMIT_SHA
} from "../scripts/assemble-evidence-0010.mjs";

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
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { filterChangeSetExclusions } from "../scripts/dogfood-review.mjs";

test("Contract 1: parseArgs correctly parses all CLI flags and defaults for 0010", () => {
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

test("Contract 2: Frozen TF-OSS-v1 corpus digest matches sha256:47ed3ce4... in 0010", () => {
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
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-evidence-0010-"));

  try {
    const result = await assembleEvidence0010({
      mock: true,
      outDir: tempDir,
      log: false
    });

    assert.equal(result.bundleId, "TF-EVIDENCE-0010");
    assert.equal(result.benchmarkResults.bundleId, "TF-EVIDENCE-0010");
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

test("Contract 5: Single target case execution (--case TF-OSS-001) for 0010", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-single-0010-"));

  try {
    const result = await assembleEvidence0010({
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

test("Contract 6: CLI Subprocess --help displays usage and exits 0 for 0010", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0010.mjs", "--help"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0010"));
  assert.ok(res.stdout.includes("--live"));
  assert.ok(res.stdout.includes("--mock"));
  assert.ok(res.stdout.includes("--dry-run"));
});

test("Contract 7: CLI Subprocess --dry-run executes in mock mode and verifies manifest without touching evidence-runs/", () => {
  const res = spawnSync("node", ["scripts/assemble-evidence-0010.mjs", "--dry-run"], {
    encoding: "utf8"
  });

  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes("TF-EVIDENCE-0010"));
  assert.ok(res.stdout.includes("Bundle successfully assembled and sealed!"));
});

test("Contract 8: Truthful README generation under 5/5 pass (TARGET MET, all defended, zero debt)", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-5-5-"));

  try {
    await assembleEvidence0010({
      mock: true,
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    // Must report TARGET MET, not TARGET MISSED
    assert.ok(readmeContent.includes("**TARGET MET**"), "Must report TARGET MET when 5/5 pass");
    assert.ok(!readmeContent.includes("**TARGET MISSED**"), "Must NOT report TARGET MISSED when 5/5 pass");

    // Must list all 5 defended cases
    assert.ok(
      readmeContent.includes("cases TF-OSS-001, TF-OSS-002, TF-OSS-003, TF-OSS-004, TF-OSS-005 defended"),
      "Must list all 5 defended cases"
    );

    // Debt section must state None, not falsely claim TF-OSS-005 missed
    assert.ok(
      readmeContent.includes("None. All 5 evaluated case(s) satisfied expected detection and gate decisions."),
      "Must report zero debt when 5/5 pass"
    );
    assert.ok(
      !readmeContent.includes("- **TF-OSS-005"),
      "Must NOT falsely report TF-OSS-005 in debt when 5/5 pass"
    );

    // Corpus immutability must report PASS
    assert.ok(
      readmeContent.includes("| **Corpus Immutability** | sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625 | Verified byte-for-byte unchanged | **PASS** |")
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 9: Truthful README generation under 4/5 pass (TARGET MISSED, only 001..004 defended, debt recorded)", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-4-5-"));

  // Mock adapters where TF-OSS-005 returns empty findings (simulating detection miss)
  function create4of5Adapters() {
    function findCaseForInput(input) {
      const filePaths = (input.changeSet?.files || []).map(f => f.path.replace(/\\/g, "/"));
      for (const c of TF_OSS_CORPUS_V1_CASES) {
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
        if (c && c.goldenFindings && c.id !== "TF-OSS-005") {
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
    await assembleEvidence0010({
      mock: true,
      reviewAdapters: create4of5Adapters(),
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    // Must report TARGET MISSED
    assert.ok(readmeContent.includes("**TARGET MISSED**"), "Must report TARGET MISSED when 4/5 pass");
    assert.ok(!readmeContent.includes("**TARGET MET**"), "Must NOT report TARGET MET when 4/5 pass");

    // Defended cases must only list cases 001..004
    assert.ok(
      readmeContent.includes("cases TF-OSS-001, TF-OSS-002, TF-OSS-003, TF-OSS-004 defended"),
      "Must list only cases 001..004 as defended"
    );
    assert.ok(
      !readmeContent.includes("TF-OSS-005 defended"),
      "Must NOT list TF-OSS-005 as defended"
    );

    // Debt section must specifically identify TF-OSS-005
    assert.ok(
      readmeContent.includes("- **TF-OSS-005 (ejs CVE-2022-29078 / CWE-94)**:"),
      "Must record TF-OSS-005 in Known Empirical Debt"
    );
    assert.ok(
      readmeContent.includes("Expected Gate: `BLOCK` | Actual Gate: `APPROVE`"),
      "Must describe expected vs actual gate for TF-OSS-005"
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 10: Truthful README generation on partial run (--case TF-OSS-001) never describes unexecuted cases", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-truth-partial-"));

  try {
    await assembleEvidence0010({
      mock: true,
      caseId: "TF-OSS-001",
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    assert.ok(readmeContent.includes("cases TF-OSS-001 defended"), "Must list TF-OSS-001 defended");
    assert.ok(!readmeContent.includes("TF-OSS-002"), "Must NOT mention unexecuted case TF-OSS-002");
    assert.ok(!readmeContent.includes("TF-OSS-003"), "Must NOT mention unexecuted case TF-OSS-003");
    assert.ok(!readmeContent.includes("TF-OSS-004"), "Must NOT mention unexecuted case TF-OSS-004");
    assert.ok(!readmeContent.includes("TF-OSS-005"), "Must NOT mention unexecuted case TF-OSS-005");
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
        const isCase5 = filePaths.some(p => p.includes("ejs"));
        if (isCase5) {
          return {
            ok: false,
            executionStatus: "timeout",
            error: { code: "TIMEOUT", message: "Provider timeout" }
          };
        }
        return {
          stdout: JSON.stringify({
            findings: [{
              title: "Detected prototype pollution",
              severity: "high",
              file: filePaths[0] || "test.js",
              line_start: 1,
              line_end: 1,
              cwe: "CWE-1321",
              type: "prototype-pollution",
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
    await assembleEvidence0010({
      mock: true,
      reviewAdapters: createIncompleteAdapters(),
      outDir: tempDir,
      log: false
    });

    const readmeContent = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    const oss5Idx = readmeContent.indexOf("- **TF-OSS-005");
    assert.ok(oss5Idx !== -1, "TF-OSS-005 debt entry must exist");
    const oss5Block = readmeContent.slice(oss5Idx);

    // Incomplete case MUST be labeled G4-BLOCKING, never Non-blocking for G4
    assert.ok(
      oss5Block.includes("G4-BLOCKING"),
      "Incomplete run must be explicitly labeled G4-BLOCKING"
    );
    assert.ok(
      !oss5Block.includes("Non-blocking for G4"),
      "Incomplete case must NOT be labeled Non-blocking for G4"
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 12: filterChangeSetExclusions strips exact outPath and dogfood-run.json, decodes octal escapes, preserves source renames, and tracks excludedFiles", () => {
  const mockCs = {
    files: [
      { path: "src/core/harness.mjs", additions: 5, deletions: 2 },
      { path: "dogfood-run.json", additions: 100, deletions: 50 },
      { path: "nested/dogfood-run.json", additions: 20, deletions: 10 },
      { path: "src/recovered.mjs", additions: 15, deletions: 1 },
      { path: "custom output.json", additions: 30, deletions: 5 },
      { path: "測.json", additions: 10, deletions: 5 }
    ],
    diffHunks: [
      "diff --git a/src/core/harness.mjs b/src/core/harness.mjs",
      "index 123..456 100644",
      "--- a/src/core/harness.mjs",
      "+++ b/src/core/harness.mjs",
      "@@ -1,1 +1,2 @@",
      "+harness edit",
      "diff --git a/dogfood-run.json b/dogfood-run.json",
      "index 789..abc 100644",
      "--- a/dogfood-run.json",
      "+++ b/dogfood-run.json",
      "@@ -1,1 +1,2 @@",
      "+telemetry edit",
      'diff --git "a/custom output.json" "b/custom output.json"',
      "index 111..222 100644",
      '--- "a/custom output.json"',
      '+++ "b/custom output.json"',
      "@@ -1,1 +1,2 @@",
      "+quoted telemetry edit",
      'diff --git "a/\\346\\270\\254.json" "b/\\346\\270\\254.json"',
      "index 333..444 100644",
      '--- "a/\\346\\270\\254.json"',
      '+++ "b/\\346\\270\\254.json"',
      "@@ -1,1 +1,2 @@",
      "+octal escaped telemetry edit",
      "diff --git a/dogfood-run.json b/src/recovered.mjs",
      "similarity index 90%",
      "rename from dogfood-run.json",
      "rename to src/recovered.mjs",
      "@@ -1,1 +1,2 @@",
      "+rename into source retained",
      "diff --git a/src/old.mjs b/dogfood-run.json",
      "similarity index 90%",
      "rename from src/old.mjs",
      "rename to dogfood-run.json",
      "@@ -1,1 +1,2 @@",
      "+rename from source into telemetry retained",
      "diff --git a/old-telemetry.json b/dogfood-run.json",
      "similarity index 90%",
      "rename from old-telemetry.json",
      "rename to dogfood-run.json",
      "@@ -1,1 +1,2 @@",
      "+rename between two telemetry dropped"
    ].join("\n"),
    contentDigest: "sha256:olddigest",
    totalAdditions: 180,
    totalDeletions: 73
  };

  const filtered = filterChangeSetExclusions(mockCs, ["dogfood-run.json", "custom output.json", "測.json", "old-telemetry.json"]);

  // files filtering: exact match on exclusions only (nested preserved, rename into source preserved)
  assert.equal(filtered.files.length, 3);
  assert.equal(filtered.files[0].path, "src/core/harness.mjs");
  assert.equal(filtered.files[1].path, "nested/dogfood-run.json");
  assert.equal(filtered.files[2].path, "src/recovered.mjs");

  // excludedFiles tracking
  assert.deepEqual(filtered.excludedFiles, ["dogfood-run.json", "custom output.json", "測.json"]);

  // diffHunks filtering: telemetry hunks dropped, rename from source into telemetry retained
  assert.ok(filtered.diffHunks.includes("src/core/harness.mjs"));
  assert.ok(filtered.diffHunks.includes("src/recovered.mjs"));
  assert.ok(filtered.diffHunks.includes("rename from source into telemetry retained"));
  assert.ok(!filtered.diffHunks.includes("telemetry edit"));
  assert.ok(!filtered.diffHunks.includes("quoted telemetry edit"));
  assert.ok(!filtered.diffHunks.includes("octal escaped telemetry edit"));
  assert.ok(!filtered.diffHunks.includes("rename between two telemetry dropped"));

  // counts and digest updated
  assert.equal(filtered.totalAdditions, 40);
  assert.equal(filtered.totalDeletions, 13);
  assert.notEqual(filtered.contentDigest, "sha256:olddigest");
  assert.match(filtered.contentDigest, /^[a-f0-9]{64}$/i);
});

test("Contract 13: Fails G4 and marks incomplete when verifierAdapter fails (PRRT_kwDOUWarIc6oOUW6)", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-verif-fail-"));

  const failingVerifierAdapter = {
    providerName: "claude",
    verifyFindings: async () => ({
      ok: false,
      error: "Verifier connection timed out",
      evaluations: []
    })
  };

  try {
    await assembleEvidence0010({
      mock: true,
      verifierAdapter: failingVerifierAdapter,
      outDir: tempDir,
      log: false
    });

    const results = JSON.parse(fs.readFileSync(path.join(tempDir, "benchmark-results.json"), "utf8"));
    const readme = fs.readFileSync(path.join(tempDir, "README-EVIDENCE.md"), "utf8");

    // All cases must be marked incomplete due to verifier failure
    assert.equal(results.metrics.incompleteCasesCount, 5, "All cases must be incomplete when verifier fails");
    assert.equal(results.metrics.incompleteRate, 1.0);

    // Every affected case must assert incomplete, status, verifierFailed, passed === false
    assert.equal(results.caseResults.length, 5);
    for (const c of results.caseResults) {
      assert.equal(c.incomplete, true, `Case ${c.caseId} must be incomplete`);
      assert.equal(c.status, "incomplete", `Case ${c.caseId} status must be incomplete`);
      assert.equal(c.verifierFailed, true, `Case ${c.caseId} verifierFailed must be true`);
      assert.equal(c.passed, false, `Case ${c.caseId} passed must be false`);
    }

    // README must report FAIL on Incomplete Runs gate
    assert.ok(
      readme.includes("| **Incomplete Runs** | 0/5 cases (zero incomplete runs) | **100.0%** (5/5) | **FAIL** |"),
      "Must fail Incomplete Runs gate when verifier fails"
    );
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
});

