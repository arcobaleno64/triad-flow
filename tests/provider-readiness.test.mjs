/**
 * Provider Readiness Contract & Benchmark Audit Receipt Test Suite (TF-SPEC-RECEIPT-v1.0.0 Phase 2 Beta)
 *
 * Enforces:
 * - 7-Point Provider Readiness Contract:
 *   Point 1: Binary detected (command found in PATH)
 *   Point 2: Version parsed (regex matches semver)
 *   Point 3: Canonical profile matched (profile exists with profileStatus === "canonical")
 *   Point 4: Mandatory safety args verified (mandatory flags cannot be stripped or overridden)
 *   Point 5: Live invocation succeeds (benign probe runs and exits 0 within timeout)
 *   Point 6: Output contract validates (validates against validateProviderOutput)
 *   Point 7: Working tree unchanged (git status --porcelain is empty and HEAD matches pre-invocation)
 * - Doctor Integration: Doctor only reports READY when all 7 points pass; offline probe marks live as unverified.
 * - Benchmark Runner Audit Receipt Integration:
 *   - evaluateCorpusSuite returns receipt via buildAuditReceipt
 *   - Identity generated via createCorpusIdentity(corpus)
 *   - providerProvenance records actualModel with strict trust tiers ({ value: null, source: "unavailable" })
 *   - Token usage records usageSource: "authoritative" | "unavailable" with null preservation
 *   - scripts/run-real-benchmark.mjs saves audit-receipt.json alongside benchmark-results.json
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import {
  verifyProviderReadiness,
  resolveProviderProfile,
  assembleProviderArgs,
  PROVIDER_PROFILES
} from "../src/adapters/provider-profiles.mjs";
import {
  probeInstalledReviewers,
  evaluateQuorumReadiness,
  isReviewerOperationalReady,
  collectDoctorReport,
  formatDoctorReport,
  QUORUM_STATUS
} from "../src/core/doctor.mjs";
import { TOOL_VERSION } from "../src/core/review-run-report.mjs";
import {
  evaluateCorpusSuite,
  runThreeWayRealComparison
} from "../src/core/real-benchmark-runner.mjs";
import {
  validateAuditReceipt,
  parseAuditReceipt
} from "../src/core/audit-receipt.mjs";
import {
  createCorpusIdentity
} from "../src/core/canonical-digest.mjs";
import {
  TF_RBC_V0_CASES,
  createMockCorpusAdapters
} from "./fixtures/real-corpus-fixtures.mjs";

test("Point 3: Canonical profile matched for agy and claude; generic for codex and unpromoted tools", () => {
  const agyRes = verifyProviderReadiness("agy", { live: false });
  assert.equal(agyRes.points.point3_canonicalProfileMatched.pass, true);
  assert.equal(agyRes.points.point3_canonicalProfileMatched.profileStatus, "canonical");
  assert.equal(agyRes.points.point3_canonicalProfileMatched.id, "agy");
  assert.equal(agyRes.points.point3_canonicalProfileMatched.family, "google");

  const claudeRes = verifyProviderReadiness("claude", { live: false });
  assert.equal(claudeRes.points.point3_canonicalProfileMatched.pass, true);
  assert.equal(claudeRes.points.point3_canonicalProfileMatched.profileStatus, "canonical");
  assert.equal(claudeRes.points.point3_canonicalProfileMatched.id, "claude");
  assert.equal(claudeRes.points.point3_canonicalProfileMatched.family, "anthropic");

  const codexRes = verifyProviderReadiness("codex", { live: false });
  assert.equal(codexRes.points.point3_canonicalProfileMatched.pass, false);
  assert.equal(codexRes.points.point3_canonicalProfileMatched.profileStatus, "generic");
  assert.match(codexRes.points.point3_canonicalProfileMatched.error, /expected 'canonical'/i);

  const customRes = verifyProviderReadiness("custom-tool", { live: false });
  assert.equal(customRes.points.point3_canonicalProfileMatched.pass, false);
  assert.equal(customRes.points.point3_canonicalProfileMatched.profileStatus, "generic");
});

test("Point 4: Mandatory safety args verified (cannot be stripped or overridden)", () => {
  const agyRes = verifyProviderReadiness("agy", { live: false });
  assert.equal(agyRes.points.point4_mandatorySafetyArgsVerified.pass, true);
  assert.deepEqual(agyRes.points.point4_mandatorySafetyArgsVerified.mandatorySafetyArgs, [
    "--mode=plan",
    "--disable-slash-commands"
  ]);

  const claudeRes = verifyProviderReadiness("claude", { live: false });
  assert.equal(claudeRes.points.point4_mandatorySafetyArgsVerified.pass, true);
  assert.deepEqual(claudeRes.points.point4_mandatorySafetyArgsVerified.mandatorySafetyArgs, [
    "--tools="
  ]);

  // Non-canonical generic tool has no mandatory safety args
  const codexRes = verifyProviderReadiness("codex", { live: false });
  assert.equal(codexRes.points.point4_mandatorySafetyArgsVerified.pass, false);
  assert.match(codexRes.points.point4_mandatorySafetyArgsVerified.error, /no mandatory safety args defined/i);
});

test("Point 1 & Point 2: Binary detected and semver parsed accurately via mock execFn", () => {
  // Scenario A: Binary detected with valid semver
  const mockValid = (cmd, args) => {
    assert.deepEqual(args, ["--version"]);
    return { status: 0, stdout: "agy v1.2.3 (google-gemini)\n", stderr: "", error: null };
  };
  const resValid = verifyProviderReadiness("agy", { execFn: mockValid, live: false });
  assert.equal(resValid.points.point1_binaryDetected.pass, true);
  assert.equal(resValid.points.point2_versionParsed.pass, true);
  assert.equal(resValid.points.point2_versionParsed.version, "1.2.3");

  // Scenario B: Binary missing (ENOENT)
  const mockMissing = () => {
    return { status: null, stdout: "", stderr: "", error: new Error("spawnSync agy ENOENT") };
  };
  const resMissing = verifyProviderReadiness("agy", { execFn: mockMissing, live: false });
  assert.equal(resMissing.points.point1_binaryDetected.pass, false);
  assert.equal(resMissing.points.point2_versionParsed.pass, false);
  assert.match(resMissing.points.point1_binaryDetected.error, /ENOENT/);

  // Scenario C: Binary detected but version output is non-semver
  const mockNonSemver = () => {
    return { status: 0, stdout: "build-hash-only-abcdef\n", stderr: "", error: null };
  };
  const resNonSemver = verifyProviderReadiness("agy", { execFn: mockNonSemver, live: false });
  assert.equal(resNonSemver.points.point1_binaryDetected.pass, true);
  assert.equal(resNonSemver.points.point2_versionParsed.pass, false);
  assert.match(resNonSemver.points.point2_versionParsed.error, /did not contain valid semver/i);
});

test("Offline / Non-Live Invariant: Points 5, 6, 7 are marked 'unverified' and ready is false", () => {
  const mockExec = (cmd, args) => {
    assert.deepEqual(args, ["--version"]);
    return { status: 0, stdout: "1.2.2\n", stderr: "", error: null };
  };

  const res = verifyProviderReadiness("agy", { execFn: mockExec, live: false });

  // Points 1-4 pass
  assert.equal(res.points.point1_binaryDetected.pass, true);
  assert.equal(res.points.point2_versionParsed.pass, true);
  assert.equal(res.points.point3_canonicalProfileMatched.pass, true);
  assert.equal(res.points.point4_mandatorySafetyArgsVerified.pass, true);

  // Points 5, 6, 7 are unverified
  assert.equal(res.points.point5_liveInvocationSucceeds.pass, false);
  assert.equal(res.points.point5_liveInvocationSucceeds.status, "unverified");
  assert.equal(res.points.point5_liveInvocationSucceeds.verified, false);

  assert.equal(res.points.point6_outputContractValidates.pass, false);
  assert.equal(res.points.point6_outputContractValidates.status, "unverified");
  assert.equal(res.points.point6_outputContractValidates.verified, false);

  assert.equal(res.points.point7_workingTreeUnchanged.pass, false);
  assert.equal(res.points.point7_workingTreeUnchanged.status, "unverified");
  assert.equal(res.points.point7_workingTreeUnchanged.verified, false);

  // Overall readiness is strictly false (fail-closed, no hallucinated readiness)
  assert.equal(res.ready, false);
  assert.match(res.summary, /UNVERIFIED/);
});

test("Full 7-Point Readiness: When all 7 points pass, ready is true", () => {
  const validOutputJson = JSON.stringify({
    findings: [],
    coverage: { coveredFiles: ["sample.js"], omittedFiles: [] },
    usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15 }
  });

  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "2.1.270\n", stderr: "", error: null };
    }
    // Benign probe
    return { status: 0, stdout: validOutputJson, stderr: "", error: null };
  };

  const mockGitState = () => ({
    ok: true,
    repository: { currentBranch: "main", commitSha: "abcdef1234567890abcdef1234567890abcdef12" }
  });

  const res = verifyProviderReadiness("claude", {
    execFn: mockExec,
    live: true,
    getGitState: mockGitState
  });

  assert.equal(res.points.point1_binaryDetected.pass, true);
  assert.equal(res.points.point2_versionParsed.pass, true);
  assert.equal(res.points.point3_canonicalProfileMatched.pass, true);
  assert.equal(res.points.point4_mandatorySafetyArgsVerified.pass, true);
  assert.equal(res.points.point5_liveInvocationSucceeds.pass, true);
  assert.equal(res.points.point6_outputContractValidates.pass, true);
  assert.equal(res.points.point7_workingTreeUnchanged.pass, true);

  assert.equal(res.ready, true);
  assert.match(res.summary, /READY \(All 7 points verified\)/);
  assert.equal(res.errors.length, 0);
});

test("Point 5 Failure: Live probe execution non-zero exit fails Point 5 and Point 6", () => {
  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "1.2.2\n" };
    }
    // Probe fails
    return { status: 1, stderr: "Process crash during probe\n", error: new Error("Process exited with code 1") };
  };

  const res = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({ ok: true, repository: { commitSha: "abc" } })
  });

  assert.equal(res.points.point5_liveInvocationSucceeds.pass, false);
  assert.equal(res.points.point6_outputContractValidates.pass, false);
  assert.equal(res.ready, false);
  assert.match(res.points.point5_liveInvocationSucceeds.error, /Process exited with code 1/);
});

test("Point 6 Failure: Live probe succeeds but returns non-JSON or malformed findings", () => {
  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "1.2.2\n" };
    }
    // Non-JSON output
    return { status: 0, stdout: "I am a helpful assistant but not returning JSON!", stderr: "" };
  };

  const res = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({ ok: true, repository: { commitSha: "abc" } })
  });

  assert.equal(res.points.point5_liveInvocationSucceeds.pass, true);
  assert.equal(res.points.point6_outputContractValidates.pass, false);
  assert.equal(res.ready, false);
  assert.match(res.points.point6_outputContractValidates.error, /output contract failed/i);
});

test("Point 7 Failure: Working tree dirty or git state failure fails Point 7 and ready", () => {
  const validJson = JSON.stringify({
    findings: [],
    coverage: { coveredFiles: [], omittedFiles: [] }
  });

  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "1.2.2\n" };
    }
    return { status: 0, stdout: validJson };
  };

  const res = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({ ok: false, error: "Repository has uncommitted changes" })
  });

  assert.equal(res.points.point5_liveInvocationSucceeds.pass, true);
  assert.equal(res.points.point6_outputContractValidates.pass, true);
  assert.equal(res.points.point7_workingTreeUnchanged.pass, false);
  assert.equal(res.ready, false);
  assert.match(res.points.point7_workingTreeUnchanged.error, /check failed|invariant violated/i);
});

test("Doctor Integration: probeInstalledReviewers attaches readiness and formats unverified live probe", () => {
  const mockExec = (cmd, args) => {
    assert.deepEqual(args, ["--version"]);
    if (cmd === "agy") return { status: 0, stdout: "1.2.2\n" };
    if (cmd === "claude") return { status: 0, stdout: "2.1.270\n" };
    return { status: -1, error: new Error("not found") };
  };

  const reviewers = probeInstalledReviewers({
    execFn: mockExec,
    reviewers: ["agy", "claude"]
  });

  assert.equal(reviewers.length, 2);

  // In offline probe (default live: false), operationalReady is false and Points 5-7 are unverified
  for (const r of reviewers) {
    assert.ok(r.readiness, "Reviewer must have readiness attached");
    assert.equal(r.operationalReady, false);
    assert.equal(r.stage, "PROFILED");
    assert.equal(r.readiness.points.point5_liveInvocationSucceeds.status, "unverified");
    assert.equal(isReviewerOperationalReady(r), false);
  }

  // Quorum readiness
  const quorum = evaluateQuorumReadiness(reviewers);
  assert.equal(quorum.status, QUORUM_STATUS.BINARY_QUORUM_READY);
  assert.equal(quorum.operationalReady, false);
  assert.equal(quorum.all7PointsVerified, false);
  assert.equal(quorum.hasUnverifiedLive, true);
  assert.match(quorum.note, /live probe: unverified/);

  // Formatter displays live probe: unverified
  const report = collectDoctorReport({
    execFn: mockExec,
    reviewers: ["agy", "claude"],
    getGitState: () => ({ ok: true, repository: { root: "/repo", currentBranch: "main" } })
  });

  const formatted = formatDoctorReport(report, "text");
  assert.match(formatted, /live probe: unverified/);
  assert.match(formatted, /✔ Google agy: v1\.2\.2 \(Profile: read-only \[--mode=plan, --disable-slash-commands\]; live probe: unverified\)/);
  assert.match(formatted, /✔ Anthropic claude: v2\.1\.270 \(Profile: read-only \[--tools=\]; live probe: unverified\)/);

  // When require7Points is enforced, evaluateQuorumReadiness rejects non-live as not ready
  const strictQuorum = evaluateQuorumReadiness(reviewers, { require7Points: true });
  assert.equal(strictQuorum.ready, false);
  assert.equal(strictQuorum.operationalReady, false);
});

test("Doctor Integration: When all 7 points pass, Doctor reports operationalReady: true", () => {
  const validJson = JSON.stringify({
    findings: [],
    coverage: { coveredFiles: [], omittedFiles: [] },
    usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15 }
  });

  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: cmd === "agy" ? "1.2.2\n" : "2.1.270\n" };
    }
    return { status: 0, stdout: validJson };
  };

  const reviewers = probeInstalledReviewers({
    execFn: mockExec,
    live: true,
    reviewers: ["agy", "claude"],
    getGitState: () => ({ ok: true, repository: { commitSha: "abc" } })
  });

  assert.equal(reviewers[0].operationalReady, true);
  assert.equal(reviewers[1].operationalReady, true);
  assert.equal(isReviewerOperationalReady(reviewers[0]), true);

  const quorum = evaluateQuorumReadiness(reviewers, { require7Points: true });
  assert.equal(quorum.ready, true);
  assert.equal(quorum.operationalReady, true);
  assert.equal(quorum.all7PointsVerified, true);
  assert.match(quorum.summary, /All 7 points verified/);
});

test("Benchmark Runner Integration: evaluateCorpusSuite generates valid audit receipt via buildAuditReceipt", async () => {
  const mockAdapters = createMockCorpusAdapters();

  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockAdapters, {
    limit: 2,
    mode: "single",
    virtual: true
  });

  assert.ok(report.receipt, "evaluateCorpusSuite must return 'receipt'");
  const receipt = report.receipt;

  // Contract 1: Schema Version
  assert.equal(receipt.schemaVersion, "1.0.0");

  // Contract 2: Identity Tier
  assert.ok(receipt.identity, "Receipt must contain 'identity' tier");
  assert.ok(receipt.identity.corpusVersion, "Identity must contain corpusVersion");
  assert.match(receipt.identity.corpusDigest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(receipt.identity.caseDigests, "Identity must contain caseDigests map");

  // Verify identity matches createCorpusIdentity(corpus)
  const expectedIdentity = createCorpusIdentity(TF_RBC_V0_CASES);
  assert.equal(receipt.identity.corpusDigest, expectedIdentity.corpusDigest);
  assert.equal(receipt.identity.corpusVersion, expectedIdentity.corpusVersion);

  // Contract 2: Run Tier
  assert.ok(receipt.run, "Receipt must contain 'run' tier");
  assert.ok(receipt.run.runId);
  assert.ok(receipt.run.startedAt);
  assert.ok(receipt.run.environment);

  // System Provenance
  assert.ok(receipt.systemProvenance);
  assert.equal(receipt.systemProvenance.triadFlowVersion, TOOL_VERSION);

  // Contract 4: Provider Provenance
  assert.ok(receipt.providerProvenance);
  assert.ok(receipt.providerProvenance.macro);
  const macroProv = receipt.providerProvenance.macro;

  // actualModel trust tier: { value: string|null, source: string }
  assert.ok(macroProv.actualModel);
  assert.equal(macroProv.actualModel.source, "unavailable");
  assert.equal(macroProv.actualModel.value, null);

  // Usage source and token preservation
  assert.equal(macroProv.usageSource, "authoritative");
  assert.ok(macroProv.totalTokens > 0);

  // Strict normative validation of the receipt
  const validation = validateAuditReceipt(receipt);
  assert.equal(validation.valid, true);
  assert.equal(validation.errors.length, 0);

  // parseAuditReceipt roundtrip
  const parsed = parseAuditReceipt(JSON.stringify(receipt));
  assert.equal(parsed.schemaVersion, "1.0.0");
});

test("Benchmark Runner Integration: Token usage missing preserves null without coercion to 0", async () => {
  // Mock adapter that reports null usage
  const nullUsageAdapters = {
    macro: {
      providerName: "mock-null-tokens",
      modelName: "test-model",
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: [], omittedFiles: [] },
        usage: { promptTokens: null, completionTokens: null, totalTokens: null },
        providerIdentity: { provider: "mock-null-tokens" }
      })
    }
  };

  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, nullUsageAdapters, {
    limit: 1,
    mode: "single",
    virtual: true
  });

  const receipt = report.receipt;
  assert.ok(receipt);
  const macroProv = receipt.providerProvenance.macro;
  assert.equal(macroProv.usageSource, "unavailable");
  assert.equal(macroProv.promptTokens, null);
  assert.equal(macroProv.completionTokens, null);
  assert.equal(macroProv.totalTokens, null);

  const validation = validateAuditReceipt(receipt);
  assert.equal(validation.valid, true);
});

test("Three-Way Comparison Integration: runThreeWayRealComparison constructs comparative receipt", async () => {
  const mockAdapters = createMockCorpusAdapters();

  const threeWayReport = await runThreeWayRealComparison(TF_RBC_V0_CASES.slice(0, 2), mockAdapters, { virtual: true });
  assert.ok(threeWayReport.receipt, "Three-way comparison must contain 'receipt'");

  const receipt = threeWayReport.receipt;
  assert.equal(receipt.schemaVersion, "1.0.0");
  assert.ok(receipt.identity.corpusDigest);
  assert.equal(receipt.results.mode, "all");
  assert.ok(receipt.results.metrics);

  const validation = validateAuditReceipt(receipt);
  assert.equal(validation.valid, true);
});

test("CLI Script Integration: scripts/run-real-benchmark.mjs saves audit-receipt.json when --report or --receipt is given", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-receipt-test-"));
  const reportPath = path.join(tmpDir, "benchmark-results.json");
  const receiptPath = path.join(tmpDir, "audit-receipt.json");
  const customReceiptPath = path.join(tmpDir, "custom-audit-receipt.json");

  try {
    // 1. Run with --report: saves both report and audit-receipt.json alongside it
    const cliRes1 = spawnSync(process.execPath, [
      "scripts/run-real-benchmark.mjs",
      "--limit=1",
      `--report=${reportPath}`
    ], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    assert.equal(cliRes1.status, 0, `CLI failed: ${cliRes1.stderr}`);
    assert.ok(fs.existsSync(reportPath), "benchmark-results.json must exist");
    assert.ok(fs.existsSync(receiptPath), "audit-receipt.json must be saved alongside report");

    const receiptJson = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    const validation = validateAuditReceipt(receiptJson);
    assert.equal(validation.valid, true);

    // 2. Run with explicit --receipt=<path>
    const cliRes2 = spawnSync(process.execPath, [
      "scripts/run-real-benchmark.mjs",
      "--limit=1",
      `--receipt=${customReceiptPath}`
    ], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    assert.equal(cliRes2.status, 0, `CLI failed: ${cliRes2.stderr}`);
    assert.ok(fs.existsSync(customReceiptPath), "Custom audit receipt must exist");
    const customReceiptJson = JSON.parse(fs.readFileSync(customReceiptPath, "utf8"));
    assert.equal(validateAuditReceipt(customReceiptJson).valid, true);

    // 3. Run with space-separated --receipt <path>
    const spaceReceiptPath = path.join(tmpDir, "space-audit-receipt.json");
    const cliRes3 = spawnSync(process.execPath, [
      "scripts/run-real-benchmark.mjs",
      "--limit=1",
      "--receipt",
      spaceReceiptPath
    ], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    assert.equal(cliRes3.status, 0, `CLI failed: ${cliRes3.stderr}`);
    assert.ok(fs.existsSync(spaceReceiptPath), "Space-separated custom audit receipt must exist");
    const spaceReceiptJson = JSON.parse(fs.readFileSync(spaceReceiptPath, "utf8"));
    assert.equal(validateAuditReceipt(spaceReceiptJson).valid, true);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Point 6 Robustness: Preamble and non-fenced model text properly extracted by extractJsonFromText", () => {
  const outputWithPreamble = `
Note: system notification or CLI greeting
{"findings":[],"coverage":{"coveredFiles":[],"omittedFiles":[]},"usage":{"promptTokens":10,"completionTokens":5,"totalTokens":15}}
Post-amble text
`;

  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "1.2.2\n" };
    }
    return { status: 0, stdout: outputWithPreamble };
  };

  const res = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({ ok: true, repository: { commitSha: "abc" } })
  });

  assert.equal(res.points.point5_liveInvocationSucceeds.pass, true);
  assert.equal(res.points.point6_outputContractValidates.pass, true);
  assert.equal(res.points.point7_workingTreeUnchanged.pass, true);
  assert.equal(res.ready, true);
});

test("Point 7 Robustness: getGitState dirty files detection and pre-invocation dirty failure", () => {
  const validJson = JSON.stringify({
    findings: [],
    coverage: { coveredFiles: [], omittedFiles: [] }
  });

  const mockExec = (cmd, args) => {
    if (args.includes("--version")) {
      return { status: 0, stdout: "1.2.2\n" };
    }
    return { status: 0, stdout: validJson };
  };

  // Case A: getGitState reports uncommitted files
  const resDirtyFiles = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({
      ok: true,
      repository: { commitSha: "abc" },
      files: [{ path: "modified.js" }]
    })
  });
  assert.equal(resDirtyFiles.points.point7_workingTreeUnchanged.pass, false);
  assert.equal(resDirtyFiles.ready, false);
  assert.match(resDirtyFiles.points.point7_workingTreeUnchanged.error, /dirty prior to invocation/i);

  // Case B: getGitState reports isDirty: true
  const resIsDirty = verifyProviderReadiness("agy", {
    execFn: mockExec,
    live: true,
    getGitState: () => ({
      ok: true,
      repository: { commitSha: "abc" },
      isDirty: true
    })
  });
  assert.equal(resIsDirty.points.point7_workingTreeUnchanged.pass, false);
  assert.equal(resIsDirty.ready, false);
});

test("Dual-Mode Token Provenance: Separates macro and micro tokens without double-counting", async () => {
  const mockDualAdapters = {
    macro: {
      providerName: "agy",
      modelName: "gemini-flash",
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["a.js"], omittedFiles: [] },
        usage: { promptTokens: 100, completionTokens: 40, totalTokens: 140 },
        providerIdentity: { provider: "agy" }
      })
    },
    micro: {
      providerName: "claude",
      modelName: "claude-haiku",
      executeReview: async () => ({
        ok: true,
        executionStatus: "success",
        findings: [],
        coverage: { coveredFiles: ["a.js"], omittedFiles: [] },
        usage: { promptTokens: 200, completionTokens: 60, totalTokens: 260 },
        providerIdentity: { provider: "claude" }
      })
    }
  };

  const report = await evaluateCorpusSuite(TF_RBC_V0_CASES, mockDualAdapters, {
    limit: 1,
    mode: "dual",
    virtual: true
  });

  const receipt = report.receipt;
  assert.ok(receipt);
  const prov = receipt.providerProvenance;
  assert.ok(prov.macro);
  assert.ok(prov.micro);

  // Macro gets only macro's tokens
  assert.equal(prov.macro.promptTokens, 100);
  assert.equal(prov.macro.completionTokens, 40);
  assert.equal(prov.macro.totalTokens, 140);

  // Micro gets only micro's tokens
  assert.equal(prov.micro.promptTokens, 200);
  assert.equal(prov.micro.completionTokens, 60);
  assert.equal(prov.micro.totalTokens, 260);

  // Total across suite is sum (400), but each provider records only its own
  assert.equal(report.metrics.tokens.totalTokens, 400);

  const validation = validateAuditReceipt(receipt);
  assert.equal(validation.valid, true);
});

test("Doctor Robustness: 3 trusted reviewers where 2 pass all 7 points satisfies binary quorum", () => {
  const reviewers = [
    {
      id: "agy",
      family: "google",
      installed: true,
      available: true,
      reviewProfileReady: true,
      readiness: { ready: true, points: { point5_liveInvocationSucceeds: { pass: true, status: 0 } } }
    },
    {
      id: "claude",
      family: "anthropic",
      installed: true,
      available: true,
      reviewProfileReady: true,
      readiness: { ready: true, points: { point5_liveInvocationSucceeds: { pass: true, status: 0 } } }
    },
    {
      id: "extra-reviewer",
      family: "custom",
      installed: true,
      available: true,
      reviewProfileReady: true,
      readiness: { ready: false, points: { point5_liveInvocationSucceeds: { status: "unverified" } } }
    }
  ];

  const quorum = evaluateQuorumReadiness(reviewers, { require7Points: true });
  assert.equal(quorum.ready, true);
  assert.equal(quorum.all7PointsVerified, true);
  assert.equal(quorum.operationalReady, true);
});

test("Doctor Formatter: Formats live probe failures visibly", () => {
  const failedReviewerReport = {
    runtime: { nodeVersion: "v22.0.0" },
    git: { ok: true },
    safetyCore: { loaded: true, components: ["Harness", "Loop", "Graph"] },
    reviewers: [
      {
        id: "agy",
        family: "google",
        installed: true,
        available: true,
        version: "1.2.2",
        readOnlyFlags: ["--mode=plan"],
        reviewProfileReady: true,
        readiness: {
          ready: false,
          points: {
            point5_liveInvocationSucceeds: { pass: false, error: "crash on probe" }
          }
        }
      }
    ],
    quorum: { status: "PARTIAL", summary: "PARTIAL (Google)" },
    readiness: {
      all7PointsVerified: false,
      operationalReady: false,
      status: "NOT_READY"
    }
  };

  const text = formatDoctorReport(failedReviewerReport, "text");
  assert.match(text, /live probe: FAILED \(crash on probe\)/);
  assert.match(text, /Operational Readiness: NOT_READY/);
});
