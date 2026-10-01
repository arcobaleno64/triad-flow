/**
 * Test Suite: Verifier CLI Integration & Fan-in Boundary Assurance (TF-SPEC-RECEIPT-v1.0.0 Section 7)
 *
 * Verifies:
 * 1. Strict canonical validation for --verify-with (rejection of arbitrary shell strings, metacharacters, non-canonical profiles)
 * 2. Producer / Verifier Decoupling & Fan-in boundary immutability
 * 3. Generation of verification-record.json and disagreement-ledger.json
 * 4. Manifest bundle integration (--manifest registers verification-record.json and disagreement-ledger.json)
 * 5. Tamper detection on verification records within manifest bundles
 * 6. bin/triad-flow.mjs benchmark subcommand CLI integration
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  validateVerifierCommand,
  createMockVerifierAdapter,
  buildDisagreementLedgerDocument,
  validateVerificationRecord,
  DISAGREEMENT_CLASSIFICATIONS
} from "../src/core/independent-verifier.mjs";
import { verifyManifestBundle } from "../src/core/manifest-bundle.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

const execFileAsync = promisify(execFile);

test("validateVerifierCommand: accepts canonical providers (claude, agy, codex)", () => {
  const claudeProfile = validateVerifierCommand("claude");
  assert.equal(claudeProfile.id, "claude");
  assert.equal(claudeProfile.profileStatus, "canonical");

  const agyProfile = validateVerifierCommand("agy");
  assert.equal(agyProfile.id, "agy");
  assert.equal(agyProfile.profileStatus, "canonical");

  const codexProfile = validateVerifierCommand("codex");
  assert.equal(codexProfile.id, "codex");
  assert.equal(codexProfile.profileStatus, "canonical");
});

test("validateVerifierCommand: rejects arbitrary shell strings, spaces, and CLI flags", () => {
  const invalidInputs = [
    "claude --tools=bash",
    "claude -p",
    "agy --print",
    "--mode=plan",
    "-p",
    "claude; rm -rf /",
    "agy && whoami",
    "claude | cat",
    "$(whoami)",
    "`id`",
    "claude\n",
    "claude\r",
    "'claude'",
    "\"claude\""
  ];

  for (const input of invalidInputs) {
    assert.throws(
      () => validateVerifierCommand(input),
      /contains disallowed characters, spaces, or CLI flags/i,
      `Expected input '${input}' to be rejected`
    );
  }
});

test("validateVerifierCommand: rejects non-canonical or generic provider profiles", () => {
  const nonCanonical = ["generic-tool", "gemini-cli", "bash", "python", "custom-script"];
  for (const name of nonCanonical) {
    assert.throws(
      () => validateVerifierCommand(name),
      /does not resolve to a canonical provider profile/i,
      `Expected non-canonical '${name}' to be rejected`
    );
  }
});

test("validateVerifierCommand: rejects empty or non-string inputs", () => {
  assert.throws(() => validateVerifierCommand(""), /non-empty string/);
  assert.throws(() => validateVerifierCommand(null), /non-empty string/);
  assert.throws(() => validateVerifierCommand(undefined), /non-empty string/);
});

test("CLI Script Integration: scripts/run-real-benchmark.mjs rejects invalid or dangerous --verify-with", async () => {
  const benchScript = path.resolve("scripts/run-real-benchmark.mjs");

  // Case 1: Arbitrary shell string with flags
  await assert.rejects(
    async () => {
      await execFileAsync(process.execPath, [benchScript, "--verify-with=claude --danger"]);
    },
    (err) => {
      assert.equal(err.code, 1);
      assert.ok(err.stderr.includes("contains disallowed characters, spaces, or CLI flags"));
      return true;
    }
  );

  // Case 2: Non-canonical provider
  await assert.rejects(
    async () => {
      await execFileAsync(process.execPath, [benchScript, "--verify-with=generic-tool"]);
    },
    (err) => {
      assert.equal(err.code, 1);
      assert.ok(err.stderr.includes("does not resolve to a canonical provider profile"));
      return true;
    }
  );
});

test("CLI Script Integration: --verify-with=claude generates verification record and disagreement ledger offline", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bench-verify-"));
  try {
    const benchScript = path.resolve("scripts/run-real-benchmark.mjs");
    const reportPath = path.join(tmpDir, "benchmark-results.json");
    const verificationPath = path.join(tmpDir, "verification-record.json");

    const { stdout } = await execFileAsync(process.execPath, [
      benchScript,
      "--case=BENCH-REAL-001",
      `--report=${reportPath}`,
      "--verify-with=claude",
      `--verification-report=${verificationPath}`
    ]);

    assert.ok(stdout.includes("Initiating Independent Verification with 'claude'"));

    // Verify all files created on disk
    assert.ok(fs.existsSync(reportPath), "benchmark-results.json must exist");
    assert.ok(fs.existsSync(path.join(tmpDir, "audit-receipt.json")), "audit-receipt.json must exist");
    assert.ok(fs.existsSync(verificationPath), "verification-record.json must exist");
    assert.ok(fs.existsSync(path.join(tmpDir, "disagreement-ledger.json")), "disagreement-ledger.json must exist");

    // Validate verification record structure and schema
    const record = JSON.parse(fs.readFileSync(verificationPath, "utf8"));
    const val = validateVerificationRecord(record);
    assert.equal(val.valid, true, `Verification record must be valid: ${val.errors.join(", ")}`);
    assert.equal(record.verifier.providerName, "claude");
    assert.equal(record.producer.findingsCount, 1);
    assert.equal(record.evaluations.length, 1);
    assert.equal(record.evaluations[0].verdict, "SUPPORTED");
    assert.equal(record.evaluations[0].classification, DISAGREEMENT_CLASSIFICATIONS.SUPPORTED);

    // Validate producer findings immutability: producer findings are not modified or stripped
    const results = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    const actualFinding = results.caseResults[0].actualFindings[0];
    assert.deepEqual(record.producer.findings[0], actualFinding);

    // Validate disagreement ledger
    const ledgerDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "disagreement-ledger.json"), "utf8"));
    assert.equal(ledgerDoc.schemaVersion, "1.0.0");
    assert.equal(ledgerDoc.producer.providerName, "agy");
    assert.equal(ledgerDoc.verifier.providerName, "claude");
    assert.ok(Array.isArray(ledgerDoc.ledger));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Manifest Bundle Integration: --verify-with + --manifest creates 5-artifact cryptographically verifiable bundle", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bench-verify-manifest-"));
  try {
    const benchScript = path.resolve("scripts/run-real-benchmark.mjs");
    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    const reportPath = path.join(tmpDir, "benchmark-results.json");

    await execFileAsync(process.execPath, [
      benchScript,
      "--case=BENCH-REAL-001",
      `--report=${reportPath}`,
      "--verify-with=claude",
      "--manifest"
    ]);

    // Check all 5 files exist
    assert.ok(fs.existsSync(path.join(tmpDir, "benchmark-results.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "audit-receipt.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "verification-record.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "disagreement-ledger.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "summary.md")));
    assert.ok(fs.existsSync(path.join(tmpDir, "artifact-manifest.json")));

    // Programmatic verification of the 5-artifact bundle
    const verifyRes = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verifyRes.valid, true);
    assert.equal(verifyRes.errors.length, 0);
    assert.ok(verifyRes.verifiedArtifacts.includes("verification-record.json"));
    assert.ok(verifyRes.verifiedArtifacts.includes("disagreement-ledger.json"));
    assert.equal(verifyRes.verifiedArtifacts.length, 5);

    // Verify summary.md lists verification-record.json
    const summaryMd = fs.readFileSync(path.join(tmpDir, "summary.md"), "utf8");
    assert.ok(summaryMd.includes("verification-record.json"));
    assert.ok(summaryMd.includes("disagreement-ledger.json"));

    // CLI script verification succeeds
    const verCliRes = await execFileAsync(process.execPath, [verScript, tmpDir]);
    assert.ok(verCliRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));
    assert.ok(verCliRes.stdout.includes("Verified Artifacts (5)"));
    assert.ok(verCliRes.stdout.includes("verification-record.json"));
    assert.ok(verCliRes.stdout.includes("disagreement-ledger.json"));

    // Tamper Detection: mutate verification-record.json and ensure verifier fails
    const verRecordFile = path.join(tmpDir, "verification-record.json");
    fs.appendFileSync(verRecordFile, "\n// unauthorized edit\n", "utf8");

    await assert.rejects(
      async () => {
        await execFileAsync(process.execPath, [verScript, tmpDir]);
      },
      (err) => {
        assert.equal(err.code, 1);
        assert.ok(err.stderr.includes("Digest mismatch for artifact 'verification-record.json'"));
        return true;
      }
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Subcommand Integration: bin/triad-flow.mjs benchmark --verify-with=claude --manifest", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-bin-verify-manifest-"));
  try {
    const binScript = path.resolve("bin/triad-flow.mjs");
    const verScript = path.resolve("scripts/verify-artifact-manifest.mjs");
    const reportPath = path.join(tmpDir, "benchmark-results.json");

    await execFileAsync(process.execPath, [
      binScript,
      "benchmark",
      "--case=BENCH-REAL-001",
      `--report=${reportPath}`,
      "--verify-with=claude",
      "--manifest"
    ]);

    assert.ok(fs.existsSync(path.join(tmpDir, "verification-record.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "disagreement-ledger.json")));
    assert.ok(fs.existsSync(path.join(tmpDir, "artifact-manifest.json")));

    const verCliRes = await execFileAsync(process.execPath, [verScript, tmpDir]);
    assert.ok(verCliRes.stdout.includes("Manifest Bundle Verification SUCCEEDED"));
    assert.ok(verCliRes.stdout.includes("Verified Artifacts (5)"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI Subcommand Security: bin/triad-flow.mjs rejects shell injection in --verify-with", async () => {
  const binScript = path.resolve("bin/triad-flow.mjs");

  await assert.rejects(
    async () => {
      await execFileAsync(process.execPath, [
        binScript,
        "benchmark",
        "--verify-with=claude --rm-rf"
      ]);
    },
    (err) => {
      assert.equal(err.code, EXIT_CODES.USAGE_ERROR);
      assert.ok(err.stderr.includes("contains disallowed characters, spaces, or CLI flags"));
      return true;
    }
  );
});

test("Programmatic CLI: runCli handles custom verifierAdapter with dissents into disagreement ledger", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-runcli-verify-"));
  try {
    const reportPath = path.join(tmpDir, "benchmark-results.json");
    const verificationPath = path.join(tmpDir, "verification-record.json");

    let stdoutData = "";
    let stderrData = "";
    const mockIo = {
      stdout: { write: (d) => { stdoutData += d; } },
      stderr: { write: (d) => { stderrData += d; } }
    };

    // Custom verifier adapter that contests a finding and reports an omission
    const customVerifierAdapter = {
      providerName: "claude",
      modelName: "claude-test-adversarial",
      executeVerification: async (input) => {
        const findingId = input.producerFindings[0]?.id || "finding-1";
        return {
          ok: true,
          evaluations: [
            {
              findingId,
              verdict: "CONTESTED",
              locatorAccurate: true,
              typeAccurate: false,
              severityAccurate: false,
              reasoning: "Contested: parameter is internal integer ID, injection impossible.",
              dissent: "Severity should be low or dismissed entirely."
            }
          ],
          verifierOmissions: [
            {
              title: "Unchecked database connection pool leak",
              severity: "medium",
              file: "src/db/user-repo.js",
              line_start: 3,
              line_end: 5,
              recommendation: "Release connection back to pool"
            }
          ]
        };
      }
    };

    const code = await runCli(
      [
        "benchmark",
        "--case=BENCH-REAL-001",
        `--report=${reportPath}`,
        "--verify-with=claude",
        `--verification-report=${verificationPath}`,
        "--manifest"
      ],
      mockIo,
      {
        verifierAdapter: customVerifierAdapter
      }
    );

    assert.equal(code, EXIT_CODES.SUCCESS);

    // Verify verification-record.json
    const record = JSON.parse(fs.readFileSync(verificationPath, "utf8"));
    assert.equal(record.evaluations[0].verdict, "CONTESTED");
    assert.equal(record.evaluations[0].classification, DISAGREEMENT_CLASSIFICATIONS.CONTRADICTED);
    assert.equal(record.disagreementLedger.length, 1);
    assert.equal(record.disagreementLedger[0].classification, DISAGREEMENT_CLASSIFICATIONS.CONTRADICTED);
    assert.equal(record.verifierOmissions.length, 1);
    assert.equal(record.verifierOmissions[0].classification, DISAGREEMENT_CLASSIFICATIONS.MISSED_BY_PRODUCER);

    // Verify disagreement-ledger.json
    const ledgerDoc = JSON.parse(fs.readFileSync(path.join(tmpDir, "disagreement-ledger.json"), "utf8"));
    assert.equal(ledgerDoc.ledger.length, 1);
    assert.equal(ledgerDoc.ledger[0].verdict, "CONTESTED");
    assert.equal(ledgerDoc.summary.contestedCount, 1);
    assert.equal(ledgerDoc.summary.omissionsCount, 1);

    // Verify manifest verification passes with all 5 artifacts
    const verifyRes = verifyManifestBundle({ targetDir: tmpDir });
    assert.equal(verifyRes.valid, true);
    assert.equal(verifyRes.verifiedArtifacts.length, 5);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
