import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import {
  appendReceipt,
  buildCycleReceipt,
  classifyDiscrepancy,
  parseArgs,
  parseStrictIso,
  readLedger,
  rebuildSummary,
  recordCycle,
  recurrenceCount,
  renderSummary,
  validateFailureFamily,
  verificationStatus
} from "../scripts/record-cycle.mjs";

function baseRun(overrides = {}) {
  return {
    schemaVersion: "1.1.0",
    runId: "dogfood-source-001",
    executionMode: "live",
    runStartedAt: "2026-10-04T00:30:00.000Z",
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
      files: [{ path: "scripts/a.mjs" }, { path: "tests/a.test.mjs" }]
    },
    providerTelemetry: {
      agy: { latencyMs: 100, executionStatus: "success", stagedFallbackUsed: false },
      claude: { latencyMs: 200, executionStatus: "success", stagedFallbackUsed: false },
      codex: { latencyMs: 300, executionStatus: "success", stagedFallbackUsed: false }
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
      reviewerTimeoutCount: 0,
      verifierTimeoutCount: 0,
      timeoutCount: 0,
      authFailureCount: 0,
      otherFailureCount: 0,
      stagedFallbackUsed: false,
      chunkCount: null
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
    humanFinalizedAt: "2026-10-04T00:20:00Z",
    failureFamily: "NONE",
    ...overrides
  };
}

test("parseArgs accepts ingestion metadata and strict positive decimal PR syntax", () => {
  const parsed = parseArgs([
    "--from=dogfood.json", "--cycle-id=CYCLE-0001", "--execution-mode=live",
    "--repository=arcobaleno64/triad-flow", "--human=APPROVE",
    "--human-finalized-at=2026-10-04T00:20:00Z", "--family=deadline-budget", "--pr=33"
  ]);
  assert.equal(parsed.from, "dogfood.json");
  assert.equal(parsed.executionMode, "live");
  assert.equal(parsed.prNumber, 33);
  assert.throws(() => parseArgs(["--live"]), /Unknown argument/);
  for (const malformed of ["33x", "1.5", "+33", "01", "0", "-1"]) {
    assert.throws(() => parseArgs([`--pr=${malformed}`]), /Invalid --pr value/);
  }
});

test("strict ISO validation rejects parseable-but-non-ISO timestamp text", () => {
  assert.equal(parseStrictIso("2026-10-04T00:20:00Z", "t").value, "2026-10-04T00:20:00.000Z");
  assert.throws(() => parseStrictIso("October 4, 2026 00:20 UTC", "t"), /strict ISO-8601/);
  assert.throws(() => parseStrictIso("2026-10-04 00:20:00Z", "t"), /strict ISO-8601/);
  assert.throws(() => parseStrictIso("2026-10-04T00:20:00+08:00", "t", { utc: true }), /UTC/);
  assert.throws(() => parseStrictIso("2026-02-30T00:00:00Z", "t"), /valid ISO-8601 calendar timestamp/);
  assert.throws(() => parseStrictIso("2026-01-01T24:00:00Z", "t"), /valid ISO-8601 calendar timestamp/);
  assert.throws(() => parseStrictIso("2026-13-01T00:00:00Z", "t"), /valid ISO-8601 calendar timestamp/);
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
});

test("mock source cannot be elevated by CLI live metadata", () => {
  const mockRun = baseRun({ executionMode: "mock" });
  assert.throws(() => buildCycleReceipt(mockRun, meta({ executionMode: "live" })), /does not match producer mode/);
  const receipt = buildCycleReceipt(mockRun, meta({ cycleId: "CYCLE-MOCK", executionMode: "mock" }));
  assert.equal(receipt.executionMode, "mock");
  assert.equal(receipt.countsTowardMaturity, false);
});

test("live source rejects CLI mock mismatch", () => {
  assert.throws(() => buildCycleReceipt(baseRun(), meta({ executionMode: "mock" })), /does not match producer mode/);
});

test("human oracle after runStartedAt fails closed", () => {
  assert.throws(
    () => buildCycleReceipt(baseRun(), meta({ humanFinalizedAt: "2026-10-04T00:30:00.001Z" })),
    /finalized before producer runStartedAt/
  );
});

test("human oracle before runStartedAt qualifies a live real change", () => {
  const receipt = buildCycleReceipt(baseRun(), meta());
  assert.equal(receipt.humanOracleFinalizedAt, "2026-10-04T00:20:00.000Z");
  assert.equal(receipt.sourceRunStartedAt, "2026-10-04T00:30:00.000Z");
  assert.equal(receipt.countsTowardMaturity, true);
});

test("sourceRunId comes from source and override attempts fail closed", () => {
  const receipt = buildCycleReceipt(baseRun(), meta({ sourceRunId: "dogfood-source-001" }));
  assert.equal(receipt.sourceRunId, "dogfood-source-001");
  assert.throws(
    () => buildCycleReceipt(baseRun(), meta({ sourceRunId: "operator-substitute" })),
    /sourceRunId override rejected/
  );
});

test("commit provenance accepts exactly 40 or 64 hex chars", () => {
  assert.equal(buildCycleReceipt(baseRun(), meta()).repository.commitSha.length, 40);
  const sixtyFour = buildCycleReceipt(
    baseRun({ repository: { commitSha: "b".repeat(64), branch: "feature/sha256" } }),
    meta({ cycleId: "CYCLE-0064" })
  );
  assert.equal(sixtyFour.repository.commitSha.length, 64);
  for (const bad of ["0".repeat(40), "0".repeat(64), "c".repeat(39), "c".repeat(41), "c".repeat(63), "c".repeat(65), "g".repeat(40)]) {
    assert.throws(
      () => buildCycleReceipt(baseRun({ repository: { commitSha: bad, branch: "bad" } }), meta({ cycleId: `CYCLE-BAD-${bad.length}` })),
      /40\/64 hex commit SHA/
    );
  }
});

test("source timestamps require strict ISO syntax", () => {
  assert.throws(
    () => buildCycleReceipt(baseRun({ runStartedAt: "2026-10-04 00:30:00Z" }), meta()),
    /strict ISO-8601/
  );
  assert.throws(
    () => buildCycleReceipt(baseRun({ timestamp: "Sun, 04 Oct 2026 02:00:00 GMT" }), meta()),
    /strict ISO-8601/
  );
});

test("same live change cannot enter maturity ledger twice under a different cycleId", () => {
  const first = buildCycleReceipt(baseRun(), meta());
  assert.throws(() => buildCycleReceipt(
    baseRun({ runId: "dogfood-source-retry" }),
    meta({ cycleId: "CYCLE-RETRY-0001" }),
    [first]
  ), /Canonical live change already recorded/);
});

test("commit identity is canonicalized before duplicate comparison", () => {
  const first = buildCycleReceipt(baseRun(), meta());
  const upper = "A".repeat(40);
  assert.throws(() => buildCycleReceipt(
    baseRun({
      runId: "dogfood-source-case-retry",
      repository: { commitSha: upper, branch: "feature/example" }
    }),
    meta({ cycleId: "CYCLE-CASE-RETRY" }),
    [first]
  ), /Canonical live change already recorded/);
});

test("verificationStatus distinguishes not attempted, success, and failure", () => {
  assert.equal(verificationStatus(null), "NOT_ATTEMPTED");
  assert.equal(verificationStatus({ ok: true }), "SUCCESS");
  assert.equal(verificationStatus({ ok: false }), "FAILED");
});

test("verifierOverturns inspects classification independently from verdict", () => {
  const receipt = buildCycleReceipt(baseRun({
    verificationRecord: {
      ok: true,
      disagreementLedger: [],
      evaluations: [{ verdict: "SUPPORTED", classification: "CONTRADICTED" }]
    }
  }), meta());
  assert.equal(receipt.assurance.verifierOverturns, 1);
});

test("absent producer chunkCount remains null", () => {
  const run = baseRun({ telemetryMetrics: { ...baseRun().telemetryMetrics } });
  delete run.telemetryMetrics.chunkCount;
  const receipt = buildCycleReceipt(run, meta());
  assert.equal(receipt.routing.chunkCount, null);
});

test("staged fallback signal derives only from preserved producer telemetry", () => {
  const run = baseRun({
    providerTelemetry: {
      agy: { latencyMs: 100, stagedFallbackUsed: false },
      claude: { latencyMs: 100 },
      codex: { latencyMs: 100 }
    },
    telemetryMetrics: { ...baseRun().telemetryMetrics, stagedFallbackUsed: true, chunkCount: 3 }
  });
  const receipt = buildCycleReceipt(run, meta());
  assert.equal(receipt.robustness.stagedFallbackUsed, true);
  assert.equal(receipt.routing.chunkCount, 3);
});

test("producer timeoutCount including verifier timeout is preserved", () => {
  const run = baseRun({
    telemetryMetrics: {
      ...baseRun().telemetryMetrics,
      reviewerTimeoutCount: 0,
      verifierTimeoutCount: 1,
      timeoutCount: 1
    }
  });
  const receipt = buildCycleReceipt(run, meta());
  assert.equal(receipt.robustness.timeoutCount, 1);
});

test("failure family requires canonical slug and recurrence counts qualifying receipts only", () => {
  assert.equal(validateFailureFamily("literal-backslash"), "literal-backslash");
  assert.equal(validateFailureFamily("NONE"), "NONE");
  assert.throws(() => validateFailureFamily("literal_backslash"), /canonical lowercase kebab-case/);
  const prior = [
    { countsTowardMaturity: true, failureFamily: "deadline-budget" },
    { countsTowardMaturity: false, failureFamily: "deadline-budget" }
  ];
  assert.equal(recurrenceCount(prior, "deadline-budget", true), 2);
});

test("unterminated JSONL receives a separator before append", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-unterminated-"));
  try {
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const first = buildCycleReceipt(baseRun(), meta());
    fs.writeFileSync(ledger, JSON.stringify(first), "utf8");

    const second = buildCycleReceipt(
      baseRun({ runId: "dogfood-source-002", repository: { commitSha: "b".repeat(40), branch: "feature/two" } }),
      meta({ cycleId: "CYCLE-0002" }),
      [first]
    );
    appendReceipt(ledger, second);
    const raw = fs.readFileSync(ledger, "utf8");
    assert.ok(raw.includes("}\n{"), "Appender must insert LF between existing unterminated JSON and new receipt");
    assert.equal(readLedger(ledger).length, 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("concurrent duplicate attempts serialize duplicate check plus append", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-concurrent-"));
  try {
    const source = path.join(tmp, "dogfood-run.json");
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const summary = path.join(tmp, "shadow.md");
    fs.writeFileSync(source, JSON.stringify(baseRun()), "utf8");
    const script = path.resolve("scripts/record-cycle.mjs");
    const args = [
      script, "--from", source, "--cycle-id", "CYCLE-CONCURRENT", "--execution-mode", "live",
      "--repository", "arcobaleno64/triad-flow", "--human", "APPROVE",
      "--human-finalized-at", "2026-10-04T00:20:00Z", "--ledger", ledger, "--summary", summary
    ];
    const run = () => new Promise(resolve => {
      const child = spawn(process.execPath, args, { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      child.stderr.on("data", d => { stderr += d; });
      child.on("close", code => resolve({ code, stderr }));
    });

    const results = await Promise.all([run(), run()]);
    assert.deepEqual(results.map(r => r.code).sort(), [0, 1]);
    assert.equal(readLedger(ledger).length, 1);
    assert.ok(results.some(r => /Duplicate cycleId rejected/.test(r.stderr)));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("stale crashed-owner ledger lock is recovered before append", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-stale-lock-"));
  try {
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    fs.writeFileSync(`${ledger}.lock`, "2147483647", "utf8");
    appendReceipt(ledger, buildCycleReceipt(baseRun(), meta()));
    assert.equal(readLedger(ledger).length, 1);
    assert.equal(fs.existsSync(`${ledger}.lock`), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hard-link summary alias to ledger is rejected without truncating canonical bytes", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-hardlink-"));
  try {
    const ledger = path.join(tmp, "ledger.jsonl");
    const summary = path.join(tmp, "summary.md");
    appendReceipt(ledger, buildCycleReceipt(baseRun(), meta()));
    const before = fs.readFileSync(ledger, "utf8");
    fs.linkSync(ledger, summary);
    assert.throws(() => rebuildSummary(ledger, summary), /aliases the canonical ledger/);
    assert.equal(fs.readFileSync(ledger, "utf8"), before);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("symlink summary alias to ledger is rejected without truncating canonical bytes", (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-symlink-"));
  try {
    const ledger = path.join(tmp, "ledger.jsonl");
    const summary = path.join(tmp, "summary.md");
    appendReceipt(ledger, buildCycleReceipt(baseRun(), meta()));
    const before = fs.readFileSync(ledger, "utf8");
    try {
      fs.symlinkSync(ledger, summary, "file");
    } catch (err) {
      if (["EPERM", "EACCES"].includes(err?.code)) {
        t.skip("Host does not permit file symlink creation");
        return;
      }
      throw err;
    }
    assert.throws(() => rebuildSummary(ledger, summary), /aliases the canonical ledger/);
    assert.equal(fs.readFileSync(ledger, "utf8"), before);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("recordCycle regenerates derived summary from canonical ledger", () => {
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
      humanFinalizedAt: "2026-10-04T00:20:00Z",
      family: "NONE",
      telemetryOnly: false,
      ledger,
      summary,
      dryRun: false
    });

    assert.equal(receipt.countsTowardMaturity, true);
    assert.match(fs.readFileSync(summary, "utf8"), /Maturity-counting cycles: \*\*1 \/ 20–30\*\*/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("summary rebuild is idempotent and recovers a deleted projection", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-rebuild-"));
  try {
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const summary = path.join(tmp, "shadow.md");
    appendReceipt(ledger, buildCycleReceipt(baseRun(), meta()));

    assert.equal(rebuildSummary(ledger, summary), 1);
    const first = fs.readFileSync(summary, "utf8");
    fs.unlinkSync(summary);
    assert.equal(rebuildSummary(ledger, summary), 1);
    const second = fs.readFileSync(summary, "utf8");
    assert.equal(second, first);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("dry-run validates but performs no ledger or summary write", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-dry-"));
  try {
    const source = path.join(tmp, "dogfood-run.json");
    const ledger = path.join(tmp, "dogfood-receipts.jsonl");
    const summary = path.join(tmp, "shadow.md");
    fs.writeFileSync(source, JSON.stringify(baseRun({ executionMode: "mock" })), "utf8");
    const receipt = recordCycle({
      from: source,
      cycleId: "CYCLE-MOCK-0001",
      executionMode: "mock",
      repository: "arcobaleno64/triad-flow",
      human: "APPROVE",
      humanFinalizedAt: "2026-10-04T00:20:00Z",
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

test("ledger path cannot equal summary path", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tf-cycle-collision-"));
  try {
    const source = path.join(tmp, "dogfood-run.json");
    const target = path.join(tmp, "collision-file.txt");
    fs.writeFileSync(source, JSON.stringify(baseRun()), "utf8");
    fs.writeFileSync(target, "{\"existing\":\"data\"}\n", "utf8");
    const before = fs.readFileSync(target, "utf8");

    assert.throws(() => recordCycle({
      from: source,
      cycleId: "CYCLE-COLLISION",
      executionMode: "live",
      repository: "arcobaleno64/triad-flow",
      human: "APPROVE",
      humanFinalizedAt: "2026-10-04T00:20:00Z",
      family: "NONE",
      ledger: target,
      summary: target,
      dryRun: false
    }), /must use different paths/);
    assert.equal(fs.readFileSync(target, "utf8"), before);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("summary false rates exclude neutral DEGRADED outcomes", () => {
  const receipts = [
    { cycleId: "CYCLE-1", executionMode: "live", countsTowardMaturity: true, humanDisposition: "APPROVE", triadDisposition: "DEGRADED", discrepancy: "NEUTRAL_DISAGREEMENT", assurance: { verificationStatus: "FAILED" }, failureFamily: "NONE", recurrenceCount: 0, escalationAction: "NONE", robustness: { timeoutCount: 1 }, efficiency: { totalWallClockMs: 100 } },
    { cycleId: "CYCLE-2", executionMode: "live", countsTowardMaturity: true, humanDisposition: "APPROVE", triadDisposition: "APPROVE", discrepancy: "MATCH", assurance: { verificationStatus: "NOT_ATTEMPTED" }, failureFamily: "NONE", recurrenceCount: 0, escalationAction: "NONE", robustness: { timeoutCount: 0 }, efficiency: { totalWallClockMs: 200 } }
  ];
  const md = renderSummary(receipts);
  assert.match(md, /False advance: \*\*0\*\*/);
  assert.match(md, /False hold: \*\*0\*\*/);
});
