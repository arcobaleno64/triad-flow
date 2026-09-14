import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import {
  buildReviewRunReport,
  REVIEW_RUN_STATUS,
  STATUS_EXIT_CODES
} from "../src/core/review-run-report.mjs";
import { formatSarifReport, validateSarifStructure, evaluateGateDecision } from "../src/core/harness.mjs";
import { aggregateConsensus, OodaLoopController } from "../src/core/loop.mjs";
import { OfflineReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function makeMockChangeSet(overrides = {}) {
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "revision-range",
    repository: { root: "/repo", baseSha: "abc111", headSha: "def222" },
    contentDigest: crypto.createHash("sha256").update("test-content").digest("hex"),
    totalFiles: 1,
    totalAdditions: 12,
    totalDeletions: 3,
    files: [{ path: "src/api.js", additions: 12, deletions: 3 }],
    diffHunks: "+ export function api() {}",
    ...overrides
  };
}

test("REVIEW_RUN_STATUS and STATUS_EXIT_CODES mapping preserves exit code invariants", () => {
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.REVIEWED_CLEAN], 0);
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.NO_CHANGES], 0);
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.REVIEWED_WITH_FINDINGS], 1);
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.INCOMPLETE], 1);
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.CONFIGURATION_ERROR], 2);
  assert.equal(STATUS_EXIT_CODES[REVIEW_RUN_STATUS.EXECUTION_ERROR], 3);
});

test("buildReviewRunReport produces canonical immutable audit data without capability leakage", () => {
  const cs = makeMockChangeSet();
  const report = buildReviewRunReport({
    runId: "run-xyz-789",
    status: REVIEW_RUN_STATUS.REVIEWED_CLEAN,
    changeSet: cs,
    policy: { id: "SINGLE_SENTRY", strict: false },
    routing: { mode: "single", highestRisk: 2, reason: "Small diff" },
    providers: [
      {
        role: "macro",
        provider: "cli-sentry",
        model: "agy-fast",
        transport: "cli",
        executionStatus: "empty",
        coverage: { coveredFiles: ["src/api.js"], omittedFiles: [] },
        usage: { promptTokens: 120, completionTokens: 10, totalTokens: 130 }
      }
    ],
    gate: { decision: "approve", reason: "All checks passed" }
  });

  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.runId, "run-xyz-789");
  assert.equal(report.status, REVIEW_RUN_STATUS.REVIEWED_CLEAN);
  assert.equal(report.exitCode, 0);
  assert.equal(report.scope.contentDigest, cs.contentDigest);
  assert.equal(report.scope.base, "abc111");
  assert.equal(report.scope.head, "def222");
  assert.equal(report.providers.length, 1);
  assert.equal(report.providers[0].usage.totalTokens, 130);

  // Security Invariant: report is deeply frozen and does not carry capability authority
  assert.equal(Object.isFrozen(report), true);
  assert.equal(report.__trustedCapabilityNonce, undefined);
  assert.equal(report.authority, undefined);
  assert.throws(() => {
    report.status = "tampered";
  });
});

test("validateSarifStructure validates compliant SARIF 2.1.0 output from formatSarifReport", () => {
  const findings = [
    {
      title: "Hardcoded Token",
      severity: "critical",
      file: "src/auth/jwt.js",
      line_start: 10,
      line_end: 12,
      recommendation: "Load token from process.env",
      ruleId: "TF-SEC-001"
    },
    {
      title: "Missing input check",
      severity: "medium",
      file: "src/calc.js",
      line_start: 5,
      line_end: 5,
      recommendation: "Validate parameter"
    }
  ];

  // 1. Approved run SARIF
  const approvedSarif = formatSarifReport(findings, { executionSuccessful: true });
  const validation1 = validateSarifStructure(approvedSarif);
  assert.equal(validation1.valid, true, `Validation failed: ${validation1.errors.join("; ")}`);

  // 2. Blocked run with failed invocation SARIF
  const blockedSarif = formatSarifReport(findings, {
    executionSuccessful: false,
    failureReason: "Blocking vulnerabilities found"
  });
  const validation2 = validateSarifStructure(blockedSarif);
  assert.equal(validation2.valid, true, `Validation failed: ${validation2.errors.join("; ")}`);
});

test("validateSarifStructure rejects malformed SARIF structures", () => {
  assert.equal(validateSarifStructure(null).valid, false);
  assert.equal(validateSarifStructure({ version: "2.0.0" }).valid, false);

  const corruptedSarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Triad" } }, // missing version & rules
        results: [
          {
            ruleId: "UNKNOWN-RULE", // not in driver.rules
            ruleIndex: 99,
            level: "invalid-level",
            message: {},
            locations: []
          }
        ]
      }
    ]
  };

  const res = validateSarifStructure(corruptedSarif);
  assert.equal(res.valid, false);
  assert.ok(res.errors.length >= 3);
});

test("Gate and OODA warning/strict policy alignment: advisories exit green unless strict is set", () => {
  // Sentry report with only medium findings (non-blocking advisories)
  const advisoryReport = aggregateConsensus({
    macro: { provider: "agy", findings: [{ title: "Naming style advisory", severity: "medium", file: "src/calc.js" }] },
    micro: { provider: "claude", findings: [{ title: "Naming style advisory", severity: "medium", file: "src/calc.js" }] }
  });

  assert.equal(advisoryReport.verdict, "warning");

  // Default mode (non-strict):
  // 1. Gate approves
  const gateDefault = evaluateGateDecision(advisoryReport, { strict: false });
  assert.equal(gateDefault.decision, "approve");

  // 2. OODA exits green without triggering endless patch loops
  const oodaDefault = new OodaLoopController({ strict: false });
  const stepDefault = oodaDefault.step(advisoryReport);
  assert.equal(stepDefault.status, "completed");
  assert.equal(stepDefault.action, "exit_green");

  // Strict mode:
  // 1. Gate blocks
  const gateStrict = evaluateGateDecision(advisoryReport, { strict: true });
  assert.equal(gateStrict.decision, "block");

  // 2. OODA attempts remediation
  const oodaStrict = new OodaLoopController({ strict: true });
  const stepStrict = oodaStrict.step(advisoryReport);
  assert.equal(stepStrict.status, "remediating");
  assert.equal(stepStrict.action, "apply_patch");
});

test("runCli review emits JSON review-run report via --format=json and saves file via --report", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-report-test-"));
  const reportPath = path.join(tmpDir, "review-run.json");

  const mockChangeSet = makeMockChangeSet();
  const mockAdapter = new OfflineReviewAdapter({
    fixture: { findings: [] },
    providerName: "cli-clean-macro"
  });

  const stdout = new MockStream();
  const stderr = new MockStream();

  const code = await runCli(["review", "--format=json", `--report=${reportPath}`], { stdout, stderr }, {
    getChangeSet: () => mockChangeSet,
    reviewAdapters: { macro: mockAdapter }
  });

  assert.equal(code, EXIT_CODES.SUCCESS);

  // 1. stdout contains valid JSON review-run report
  const parsedStdout = JSON.parse(stdout.buffer);
  assert.equal(parsedStdout.schemaVersion, "1.0.0");
  assert.equal(parsedStdout.status, REVIEW_RUN_STATUS.REVIEWED_CLEAN);
  assert.equal(parsedStdout.exitCode, 0);
  assert.equal(parsedStdout.scope.contentDigest, mockChangeSet.contentDigest);

  // 2. File was saved and contains identical valid JSON
  assert.ok(fs.existsSync(reportPath));
  const parsedFile = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  assert.equal(parsedFile.status, REVIEW_RUN_STATUS.REVIEWED_CLEAN);
  assert.equal(parsedFile.exitCode, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
