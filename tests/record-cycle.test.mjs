import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  appendReceipt,
  buildCycleReceipt,
  classifyDiscrepancy,
  recurrenceCount,
  verificationStatus,
  parseArgs,
  readLedger,
  recordCycle,
  renderSummary,
  validateFailureFamily
} from "../scripts/record-cycle.mjs";

function baseRun(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    runId: "dogfood-source-001",
    timestamp: "2026-10-04T02:00:00.000Z",
    repository: {
      commitSha: "a".repeat(40),
      branch: "feature/example"
    },
    changeSetSummary: {
      totalFiles: 2,
      totalAdditions: 12,
      totalDeletions: 3,
      riskTier: 2,
      files: [{ path: "src/a.mjs" }, { path: "tests/a.test.mjs" }]
    },
    providerTelemetry: {
      agy: { latencyMs: 100, executionStatus: "success" },
      claude: { latencyMs: 200, executionStatus: "success" },
      codex: { latencyMs: 300, executionStatus: "success" }
    },
    consensus: {
      quorumReached: true,
      totalFindings: 0,
      findings: []
    },
    advisoryGate: { decision: "approve" },
    telemetryMetrics: {
      totalDurationMs: 350,
      avgProviderLatencyMs: 200,
      executionComplete: true,
      malformedOutputCount: 0,
      timeoutCount: 0,
      authFailureCount: 0,
      otherFailureCount: 0
    },
    verificationRecord: null,
    ...overrides
  };
}

function meta(overrides = {}) {
  return {
    cycleId: "CYCLE-0001",
    executionMode: "live",
    repository: "arcobaleno64/triad-flow",
    prNumber: 33,
    humanDisposition: "APPROVE",
    humanFinalizedAt: "2026-10-04T01:00:00Z",
    failureFamily: "NONE",
    ...overrides
  };
}

test("parseArgs accepts ingestion-only metadata and rejects legacy live runner flags", () => {
  const parsed = parseArgs([
    "--from=dogfood.json", "--cycle-id=CYCLE-0001", "--execution-mode=live",
    "--repository=arcobaleno64/triad-flow", "--human=APPROVE",
    "--human-finalized-at=2026-10-04T01:00:00Z", "--family=deadline-budget", "--pr=33"
  ]);
  assert.equal(parsed.from, "dogfood.json");
  assert.equal(parsed.executionMode, "live");
  assert.equal(parsed.prNumber, 33);
  assert.throws(() => parseArgs(["--live"]), /Unknown argument/);
});

test("truth table keeps binary false rates separate from abstention/escalation outcomes", () => {
  assert.equal(classifyDiscrepancy("APPROVE", "APPROVE"), "MATCH");
  assert.equal(classifyDiscrepancy("APPROVE", "REQUEST_CHANGES"), "FALSE_ADVANCE");
  assert.equal(classifyDiscrepancy("APPROVE", "HOLD"), "FALSE_ADVANCE");
  assert.equal(classifyDiscrepancy("BLOCK", "APPROVE"), "FALSE_HOLD");
  assert.equal(classifyDiscrepancy("BLOCK", "REQUEST_CHANGES"), "MATCH");
  assert.equal(classifyDiscrepancy("BLOCK", "HOLD"), "MATCH");
  assert.equal(classifyDiscrepancy("DEGRADED", "HOLD"), "MATCH");
  assert.equal(classifyDiscrepancy("DEGRADED", "APPROVE"), "NEUTRAL_DISAGREEMENT");
  assert.equal(classifyDiscrepancy("INCOMPLETE", "REQUEST_CHANGES"), "NEUTRAL_DISAGREEMENT");
  assert.equal(classifyDiscrepancy("HUMAN_REVIEW_REQUIRED", "APPROVE"), "MATCH");
  assert.equal(classifyDiscrepancy("HUMAN_REVIEW_REQUIRED", "REQUEST_CHANGES"), "MATCH");
});

test("human oracle timestamp must precede Triad result", () => {
  assert.throws(() => buildCycleReceipt(baseRun(), meta({ humanFinalizedAt: "2026-10-04T02:00:00Z" })), /must be finalized before/);
  const receipt = buildCycleReceipt(baseRun(), meta());
  assert.equal(receipt.humanOracleFinalizedAt, "2026-10-04T01:00:00.000Z");
  assert.equal(receipt.sourceRunTimestamp, "2026-10-04T02:00:00.000Z");
});

test("live real change counts once; mock and zero-change receipts do not count", () => {
  const live = buildCycleReceipt(baseRun(), meta());
  const mock = buildCycleReceipt(baseRun(), meta({ cycleId: "CYCLE-0002", executionMode: "mock" }));
  const zero = buildCycleReceipt(baseRun({ changeSetSummary: { totalFiles: 0, totalAdditions: 0, totalDeletions: 0, riskTier: 2, files: [] } }), meta({ cycleId: "CYCLE-0003" }));
  assert.equal(live.countsTowardMaturity, true);
  assert.equal(mock.countsTowardMaturity, false);
  assert.equal(zero.countsTowardMaturity, false);
});

test("verificationStatus distinguishes not attempted, success, and failure", () => {
  assert.equal(verificationStatus(null), "NOT_ATTEMPTED");
  assert.equal(verificationStatus({ ok: true }), "SUCCESS");
  assert.equal(verificationStatus({ ok: false }), "FAILED");
});

test("failure family requires canonical slug", () => {
  assert.equal(validateFailureFamily("literal-backslash"), "literal-backslash");
  assert.equal(validateFailureFamily("NONE"), "NONE");
  assert.throws(() => validateFailureFamily("literal_backslash"), /canonical lowercase kebab-case/);
  assert.throws(() => validateFailureFamily("Backslash-Path"), /canonical lowercase kebab-case/);
});

test("recurrence counts only maturity-qualifying historical receipts", () => {
  const prior = [
    { countsTowardMaturity: true, failureFamily: "deadline-budget" },
    { countsTowardMaturity: false, failureFamily: "deadline-budget" },
    { countsTowardMaturity: true, failureFamily: "literal-backslash" }
  ];
  assert.equal(recurrenceCount(prior, "deadline-budget", true), 2);
  assert.equal(recurrenceCount(prior, "deadline-budget", false), 1);
});

test("append-only ledger rejects duplicate cycleId without modifying existing bytes", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-ledger-"));
  try {
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const r1 = buildCycleReceipt(baseRun(), meta());
    appendReceipt(ledger, r1, []);
    const before = fs.readFileSync(ledger, "utf8");
    assert.throws(() => appendReceipt(ledger, r1), /Duplicate cycleId/);
    assert.equal(fs.readFileSync(ledger, "utf8"), before);

    const r2 = buildCycleReceipt(baseRun({ runId: "dogfood-source-002" }), meta({ cycleId: "CYCLE-0002", failureFamily: "deadline-budget" }), readLedger(ledger));
    appendReceipt(ledger, r2);
    const after = fs.readFileSync(ledger, "utf8");
    assert.ok(after.startsWith(before), "Existing canonical receipt bytes must remain unchanged");
    assert.equal(readLedger(ledger).length, 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("recordCycle ingests existing result, appends ledger, and regenerates derived summary", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-recorder-"));
  try {
    const source = path.join(tmp, "dogfood-run.json");
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const summary = path.join(tmp, "shadow.md");
    fs.writeFileSync(source, JSON.stringify(baseRun()), "utf8");

    const receipt = recordCycle({
      from: source,
      cycleId: "CYCLE-0001",
      executionMode: "live",
      repository: "arcobaleno64/triad-flow",
      prNumber: 33,
      human: "APPROVE",
      humanFinalizedAt: "2026-10-04T01:00:00Z",
      humanNotes: "Human disposition fixed before Triad run",
      family: "NONE",
      telemetryOnly: false,
      ledger,
      summary,
      dryRun: false
    });

    assert.equal(receipt.discrepancy, "MATCH");
    assert.equal(receipt.assurance.verificationStatus, "NOT_ATTEMPTED");
    assert.equal(readLedger(ledger).length, 1);
    const derived = fs.readFileSync(summary, "utf8");
    assert.match(derived, /derived projection only/);
    assert.match(derived, /Maturity-counting cycles: \*\*1 \/ 20–30\*\*/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("dry-run validates receipt but does not write canonical ledger or summary", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-dry-"));
  try {
    const source = path.join(tmp, "dogfood-run.json");
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const summary = path.join(tmp, "shadow.md");
    fs.writeFileSync(source, JSON.stringify(baseRun()), "utf8");
    const receipt = recordCycle({
      from: source,
      cycleId: "CYCLE-MOCK-0001",
      executionMode: "mock",
      repository: "arcobaleno64/triad-flow",
      human: "APPROVE",
      humanFinalizedAt: "2026-10-04T01:00:00Z",
      family: "NONE",
      telemetryOnly: false,
      ledger,
      summary,
      dryRun: true
    });
    assert.equal(receipt.countsTowardMaturity, false);
    assert.equal(fs.existsSync(ledger), false);
    assert.equal(fs.existsSync(summary), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("summary false rates exclude DEGRADED and INCOMPLETE neutral outcomes", () => {
  const receipts = [
    { cycleId: "CYCLE-1", executionMode: "live", countsTowardMaturity: true, humanDisposition: "APPROVE", triadDisposition: "DEGRADED", discrepancy: "NEUTRAL_DISAGREEMENT", assurance: { verificationStatus: "FAILED" }, failureFamily: "NONE", recurrenceCount: 0, escalationAction: "NONE", robustness: { timeoutCount: 1 }, efficiency: { totalWallClockMs: 100 } },
    { cycleId: "CYCLE-2", executionMode: "live", countsTowardMaturity: true, humanDisposition: "APPROVE", triadDisposition: "APPROVE", discrepancy: "MATCH", assurance: { verificationStatus: "NOT_ATTEMPTED" }, failureFamily: "NONE", recurrenceCount: 0, escalationAction: "NONE", robustness: { timeoutCount: 0 }, efficiency: { totalWallClockMs: 200 } }
  ];
  const md = renderSummary(receipts);
  assert.match(md, /False advance: \*\*0\*\*/);
  assert.match(md, /False hold: \*\*0\*\*/);
});
