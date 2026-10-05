#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const DEFAULT_LEDGER = "docs/benchmarks/dogfood-receipts.jsonl";
export const DEFAULT_SUMMARY = "docs/benchmarks/shadow-dogfood-observation.md";
const HUMAN = new Set(["APPROVE", "REQUEST_CHANGES", "HOLD"]);
const TRIAD = new Set(["APPROVE", "BLOCK", "DEGRADED", "INCOMPLETE", "HUMAN_REVIEW_REQUIRED"]);
const EXECUTION_MODES = new Set(["live", "mock"]);
const FAMILY_RE = /^(?:NONE|[a-z0-9]+(?:-[a-z0-9]+)*)$/;
const CYCLE_RE = /^CYCLE-[A-Z0-9][A-Z0-9._-]*$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const num = (v, fallback = 0) => Number.isFinite(v) ? Number(v) : fallback;
const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

export function parseStrictIso(value, label, { utc = false } = {}) {
  if (typeof value !== "string" || !(utc ? ISO_UTC_RE : ISO_RE).test(value)) {
    throw new Error(`${label} must use strict ISO-8601 syntax${utc ? " in UTC (Z)" : ""}`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error(`${label} must be a valid ISO-8601 timestamp`);
  return { ms, value: new Date(ms).toISOString() };
}

export function parseArgs(argv = process.argv.slice(2)) {
  const o = {
    family: "NONE",
    ledger: DEFAULT_LEDGER,
    summary: DEFAULT_SUMMARY,
    dryRun: false,
    telemetryOnly: false,
    rebuildSummary: false
  };
  const aliases = {
    "from": "from", "cycle-id": "cycleId", "execution-mode": "executionMode",
    "source-run-id": "sourceRunId", "repository": "repository", "pr": "prNumber",
    "human": "human", "human-finalized-at": "humanFinalizedAt", "human-notes": "humanNotes",
    "family": "family", "estimated-cost-usd": "estimatedCostUsd", "ledger": "ledger", "summary": "summary"
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { o.help = true; continue; }
    if (a === "--dry-run") { o.dryRun = true; continue; }
    if (a === "--telemetry-only") { o.telemetryOnly = true; continue; }
    if (a === "--rebuild-summary") { o.rebuildSummary = true; continue; }
    if (!a.startsWith("--")) throw new Error(`Unknown argument: '${a}'`);

    const eq = a.indexOf("=");
    const key = a.slice(2, eq < 0 ? undefined : eq);
    const prop = aliases[key];
    if (!prop) throw new Error(`Unknown argument: '${a}'`);
    let value = eq < 0 ? argv[++i] : a.slice(eq + 1);
    if (value === undefined || value.startsWith("--")) throw new Error(`Missing value for --${key}`);

    if (key === "pr") {
      if (!/^[1-9]\d*$/.test(value)) throw new Error("Invalid --pr value: must be a full positive decimal integer");
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed)) throw new Error("Invalid --pr value: exceeds safe integer range");
      value = parsed;
    }
    if (key === "estimated-cost-usd") {
      value = Number(value);
      if (!Number.isFinite(value) || value < 0) throw new Error("Invalid --estimated-cost-usd value");
    }
    o[prop] = value;
  }
  return o;
}

export function classifyDiscrepancy(triad, human) {
  if (!TRIAD.has(triad) || !HUMAN.has(human)) throw new Error("Unsupported disposition");
  if (triad === "APPROVE") return human === "APPROVE" ? "MATCH" : "FALSE_ADVANCE";
  if (triad === "BLOCK") return human === "APPROVE" ? "FALSE_HOLD" : "MATCH";
  if (triad === "HUMAN_REVIEW_REQUIRED") return "MATCH";
  return human === "HOLD" ? "MATCH" : "NEUTRAL_DISAGREEMENT";
}

export function deriveTriadDisposition(run) {
  if (TRIAD.has(run?.triadDisposition)) return run.triadDisposition;
  const t = run?.telemetryMetrics || {};
  const gate = String(run?.advisoryGate?.decision || "").toLowerCase();
  if (t.executionComplete !== true) {
    if (run?.consensus?.quorumReached !== true) return "INCOMPLETE";
    const failures = num(t.malformedOutputCount) + num(t.timeoutCount) + num(t.authFailureCount) + num(t.otherFailureCount);
    if (failures > 0 || (run?.verificationRecord && run.verificationRecord.ok !== true)) return "DEGRADED";
    return "INCOMPLETE";
  }
  if (gate === "block") return "BLOCK";
  if (gate === "approve" || gate === "pass") return "APPROVE";
  return "HUMAN_REVIEW_REQUIRED";
}

export function verificationStatus(record) {
  if (record == null) return "NOT_ATTEMPTED";
  return record.ok === true ? "SUCCESS" : "FAILED";
}

export function validateFailureFamily(value = "NONE") {
  const v = String(value).trim();
  if (!FAMILY_RE.test(v)) throw new Error("failureFamily must be NONE or canonical lowercase kebab-case");
  return v;
}

export function readLedger(file) {
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf8");
  if (!raw.trim()) return [];
  return raw.split(/\r?\n/).filter(Boolean).map((line, i) => {
    try { return JSON.parse(line); }
    catch (e) { throw new Error(`Canonical ledger malformed at line ${i + 1}: ${e.message}`); }
  });
}

export function recurrenceCount(receipts, family, counts) {
  if (family === "NONE") return 0;
  return receipts.filter(r => r.countsTowardMaturity === true && r.failureFamily === family).length + (counts ? 1 : 0);
}

function escalation(discrepancy, recurrence, telemetryOnly) {
  if (discrepancy === "FALSE_ADVANCE") return "IMMEDIATE_BLOCKER";
  if (discrepancy === "FALSE_HOLD") return "RELIABILITY_PRIORITY";
  if (recurrence >= 2) return "ELEVATE_PRIORITY";
  if (telemetryOnly) return "DEFER";
  return "NONE";
}

function validateCanonicalAppend(prior, receipt) {
  if (prior.some(r => r.cycleId === receipt.cycleId)) {
    throw new Error(`Duplicate cycleId rejected: ${receipt.cycleId}`);
  }
  if (
    receipt.countsTowardMaturity === true &&
    prior.some(r =>
      r.countsTowardMaturity === true &&
      r?.repository?.name === receipt.repository.name &&
      r?.repository?.commitSha === receipt.repository.commitSha
    )
  ) {
    throw new Error(`Canonical live change already recorded for ${receipt.repository.name}@${receipt.repository.commitSha}`);
  }
}

function withLedgerLock(file, fn, timeoutMs = 5000) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lockPath = `${file}.lock`;
  const deadline = Date.now() + timeoutMs;
  let fd = null;

  while (fd === null) {
    try {
      fd = fs.openSync(lockPath, "wx");
      fs.writeFileSync(fd, String(process.pid), "utf8");
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
      if (Date.now() >= deadline) throw new Error(`Timed out waiting for canonical ledger lock: ${lockPath}`);
      sleepSync(10);
    }
  }

  try {
    return fn();
  } finally {
    try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

function appendReceiptUnlocked(file, receipt, prior) {
  validateCanonicalAppend(prior, receipt);
  const existing = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const separator = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  fs.appendFileSync(file, separator + JSON.stringify(receipt) + "\n", "utf8");
}

export function appendReceipt(file, receipt) {
  return withLedgerLock(file, () => {
    const prior = readLedger(file);
    appendReceiptUnlocked(file, receipt, prior);
    return [...prior, receipt];
  });
}

export function buildCycleReceipt(run, m, prior = []) {
  if (!run || typeof run !== "object" || Array.isArray(run)) throw new Error("Source run must be a JSON object");

  const cycleId = String(m.cycleId || "").trim();
  if (!CYCLE_RE.test(cycleId)) throw new Error("cycleId must use CYCLE-... form");
  if (prior.some(r => r.cycleId === cycleId)) throw new Error(`Duplicate cycleId rejected: ${cycleId}`);

  const sourceMode = String(run.executionMode || "").toLowerCase();
  if (!EXECUTION_MODES.has(sourceMode)) throw new Error("Source run executionMode must be authoritative live or mock");
  const requestedMode = String(m.executionMode || "").toLowerCase();
  if (requestedMode && !EXECUTION_MODES.has(requestedMode)) throw new Error("executionMode must be live or mock");
  if (requestedMode && requestedMode !== sourceMode) {
    throw new Error(`CLI executionMode '${requestedMode}' does not match producer mode '${sourceMode}'`);
  }

  const human = String(m.humanDisposition || "").toUpperCase();
  if (!HUMAN.has(human)) throw new Error("humanDisposition must be APPROVE, REQUEST_CHANGES, or HOLD");

  const hTime = parseStrictIso(m.humanFinalizedAt, "humanFinalizedAt");
  const runStarted = parseStrictIso(run.runStartedAt, "source runStartedAt", { utc: true });
  const runFinished = parseStrictIso(run.timestamp, "source run timestamp", { utc: true });
  if (hTime.ms >= runStarted.ms) {
    throw new Error("Human oracle must be finalized before producer runStartedAt");
  }

  const sourceRunId = typeof run.runId === "string" ? run.runId.trim() : "";
  if (!sourceRunId) throw new Error("Source run requires an authoritative runId");
  if (m.sourceRunId !== undefined && String(m.sourceRunId).trim() !== sourceRunId) {
    throw new Error("sourceRunId override rejected: receipt identity must come from source run");
  }

  const repoName = String(m.repository || run?.repository?.name || "").trim();
  const sha = String(run?.repository?.commitSha || "").trim();
  const branch = String(run?.repository?.branch || "").trim();
  if (!repoName || !branch || !SHA_RE.test(sha)) {
    throw new Error("Source run identity/provenance is incomplete: repository, branch, and exact 40/64 hex commit SHA are required");
  }

  const c = run.changeSetSummary || {};
  const files = num(c.totalFiles, Array.isArray(c.files) ? c.files.length : 0);
  const counts = sourceMode === "live" && files > 0;
  if (
    counts &&
    prior.some(r =>
      r.countsTowardMaturity === true &&
      r?.repository?.name === repoName &&
      r?.repository?.commitSha === sha
    )
  ) {
    throw new Error(`Canonical live change already recorded for ${repoName}@${sha}`);
  }

  const triad = deriveTriadDisposition(run);
  const discrepancy = classifyDiscrepancy(triad, human);
  const family = validateFailureFamily(m.failureFamily);
  if (m.telemetryOnly && family === "NONE") throw new Error("telemetry-only requires a failure family");
  const recurrence = recurrenceCount(prior, family, counts);

  const providerLatencies = Object.fromEntries(
    Object.entries(run.providerTelemetry || {}).flatMap(([k, v]) =>
      Number.isFinite(v?.latencyMs) ? [[k, Number(v.latencyMs)]] : []
    )
  );
  const findings = Array.isArray(run?.consensus?.findings) ? run.consensus.findings : [];
  const staged = run?.telemetryMetrics?.stagedFallbackUsed === true;
  const disagreement = Array.isArray(run?.verificationRecord?.disagreementLedger)
    ? run.verificationRecord.disagreementLedger.length
    : num(run?.telemetryMetrics?.disagreementCount);
  const evaluations = Array.isArray(run?.verificationRecord?.evaluations) ? run.verificationRecord.evaluations : [];
  const overturns = evaluations.filter(e => {
    const verdict = String(e?.verdict || "").toUpperCase();
    const classification = String(e?.classification || "").toUpperCase();
    return ["CONTRADICTED", "FALSE_POSITIVE"].includes(verdict) ||
      ["CONTRADICTED", "FALSE_POSITIVE"].includes(classification);
  }).length;
  const gateSource = String(run?.advisoryGate?.decision || "").toLowerCase();
  const chunkCount = Number.isInteger(run?.telemetryMetrics?.chunkCount) && run.telemetryMetrics.chunkCount >= 0
    ? Number(run.telemetryMetrics.chunkCount)
    : null;

  return {
    schemaVersion: "1.1.0",
    cycleId,
    timestamp: new Date().toISOString(),
    executionMode: sourceMode,
    sourceRunId,
    sourceRunStartedAt: runStarted.value,
    sourceRunTimestamp: runFinished.value,
    humanOracleFinalizedAt: hTime.value,
    canonicalForCycle: true,
    countsTowardMaturity: counts,
    repository: {
      name: repoName,
      commitSha: sha,
      ...(m.prNumber ? { prNumber: m.prNumber } : {}),
      branch,
      diffStat: { files, additions: num(c.totalAdditions), deletions: num(c.totalDeletions) }
    },
    humanDisposition: human,
    ...(m.humanNotes ? { humanNotes: String(m.humanNotes) } : {}),
    triadDisposition: triad,
    gateDecision: gateSource === "approve" || gateSource === "pass" || triad === "APPROVE" ? "pass" : "block",
    discrepancy,
    robustness: {
      executionComplete: run?.telemetryMetrics?.executionComplete === true,
      malformedOutputCount: num(run?.telemetryMetrics?.malformedOutputCount),
      timeoutCount: num(run?.telemetryMetrics?.timeoutCount),
      authFailureCount: num(run?.telemetryMetrics?.authFailureCount),
      stagedFallbackUsed: staged
    },
    assurance: {
      disagreementCount: disagreement,
      solitaryBlockerCount: findings.filter(f =>
        ["critical", "high"].includes(String(f?.severity || "").toLowerCase()) &&
        num(f?.corroborations, 1) <= 1
      ).length,
      verifierOverturns: overturns,
      verificationStatus: verificationStatus(run.verificationRecord)
    },
    efficiency: {
      totalWallClockMs: num(run?.telemetryMetrics?.totalDurationMs),
      avgProviderLatencyMs: num(run?.telemetryMetrics?.avgProviderLatencyMs),
      providerLatencies,
      ...(Number.isFinite(m.estimatedCostUsd ?? run?.telemetryMetrics?.estimatedCostUsd)
        ? { estimatedCostUsd: Number(m.estimatedCostUsd ?? run.telemetryMetrics.estimatedCostUsd) }
        : {})
    },
    routing: {
      riskTier: [1, 2, 3, 4].includes(c.riskTier) ? c.riskTier : null,
      chunkCount,
      totalFindings: num(run?.consensus?.totalFindings, findings.length),
      corroboratedFindings: findings.filter(f => num(f?.corroborations, 1) >= 2).length
    },
    failureFamily: family,
    recurrenceCount: recurrence,
    escalationAction: escalation(discrepancy, recurrence, Boolean(m.telemetryOnly))
  };
}

export function renderSummary(receipts) {
  const m = receipts.filter(r => r.countsTowardMaturity === true);
  const fa = m.filter(r => r.discrepancy === "FALSE_ADVANCE").length;
  const fh = m.filter(r => r.discrepancy === "FALSE_HOLD").length;
  const timeouts = m.filter(r => num(r?.robustness?.timeoutCount) > 0).length;
  const lat = m.map(r => num(r?.efficiency?.totalWallClockMs)).filter(Boolean);
  const avg = lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : 0;
  const families = new Map();
  for (const r of m) {
    if (r.failureFamily && r.failureFamily !== "NONE") {
      families.set(r.failureFamily, (families.get(r.failureFamily) || 0) + 1);
    }
  }
  const pct = m.length ? `${((timeouts / m.length) * 100).toFixed(1)}%` : "0.0%";

  const lines = [
    "# Triad-Flow Shadow Dogfood Observation", "",
    "> **Authority boundary:** `dogfood-receipts.jsonl` is the canonical append-only observation ledger. This Markdown file is a derived projection only, may be deleted and regenerated, and has no independent evidence authority.", "",
    "## Operational Baseline", "",
    "- Release: `v2.7.0`",
    "- Canonical release commit: `fdcabf861368edbe552a0427efcb89da47fd4cb7`",
    "- Stage: `SHADOW_DOGFOOD`",
    "- Runtime merge authority: `NONE`",
    "- Maturity target: `SHADOW -> ADVISORY` after 20–30 qualifying real change cycles", "",
    "## Scorecard", "",
    `- Ledger receipts: **${receipts.length}**`,
    `- Maturity-counting cycles: **${m.length} / 20–30**`,
    `- False advance: **${fa}**`,
    `- False hold: **${fh}**`,
    `- Timeout-cycle rate: **${pct}**`,
    `- Average wall-clock latency: **${avg} ms**`, "",
    "False-advance/false-hold rates use only binary autonomous Triad outcomes (`APPROVE` / `BLOCK`). `DEGRADED`, `INCOMPLETE`, and `HUMAN_REVIEW_REQUIRED` never enter those rates automatically.", "",
    "## Cycle Receipts", "",
    "| Cycle | Mode | Counts | Human | Triad | Discrepancy | Verify | Family | Recurrence | Escalation |",
    "|---|---|---:|---|---|---|---|---|---:|---|"
  ];

  for (const r of receipts) {
    lines.push(`| ${r.cycleId} | ${r.executionMode} | ${r.countsTowardMaturity ? "yes" : "no"} | ${r.humanDisposition} | ${r.triadDisposition} | ${r.discrepancy} | ${r.assurance?.verificationStatus || "NOT_ATTEMPTED"} | ${r.failureFamily || "NONE"} | ${r.recurrenceCount || 0} | ${r.escalationAction || "NONE"} |`);
  }
  if (!receipts.length) lines.push("| _none yet_ |  |  |  |  |  |  |  |  |  |");

  lines.push("", "## Active Failure Families", "", "| Failure family | Qualifying occurrences |", "|---|---:|");
  if (!families.size) lines.push("| _none yet_ | 0 |");
  else for (const [k, v] of [...families].sort()) lines.push(`| ${k} | ${v} |`);

  lines.push(
    "", "## SHADOW -> ADVISORY Maturity Gate", "",
    `- [${m.length >= 20 ? "x" : " "}] At least 20 qualifying real change cycles (target range 20–30).`,
    `- [${m.length > 0 && fa === 0 ? "x" : " "}] No observed false advance in the qualifying sample.`,
    "- [ ] No known systemic false-approve path.",
    "- [ ] No new P0/P1 authority, provenance, or coverage truthfulness family.",
    "- [ ] PASS / BLOCK / DEGRADED / INCOMPLETE / HUMAN_REVIEW_REQUIRED classification is operationally stable.",
    "- [ ] False-hold / override / latency / cost baseline has been reviewed by human authority.", "",
    "Promotion remains a human governance decision. This projection never promotes Triad-Flow automatically.", ""
  );
  return lines.join("\n");
}

function assertDistinctPaths(ledger, summary) {
  if (ledger === summary) {
    throw new Error("Canonical ledger and derived summary must use different paths");
  }
}

function writeSummary(summary, receipts) {
  fs.mkdirSync(path.dirname(summary), { recursive: true });
  fs.writeFileSync(summary, renderSummary(receipts), "utf8");
}

export function rebuildSummary(ledgerPath = DEFAULT_LEDGER, summaryPath = DEFAULT_SUMMARY) {
  const ledger = path.resolve(ledgerPath);
  const summary = path.resolve(summaryPath);
  assertDistinctPaths(ledger, summary);
  return withLedgerLock(ledger, () => {
    const receipts = readLedger(ledger);
    writeSummary(summary, receipts);
    return receipts.length;
  });
}

export function recordCycle(o) {
  if (o.rebuildSummary) {
    return { rebuiltReceipts: rebuildSummary(o.ledger || DEFAULT_LEDGER, o.summary || DEFAULT_SUMMARY) };
  }

  for (const k of ["from", "cycleId", "executionMode", "human", "humanFinalizedAt"]) {
    if (!o[k]) throw new Error(`--${k.replace(/[A-Z]/g, x => `-${x.toLowerCase()}`)} is required`);
  }

  const run = JSON.parse(fs.readFileSync(path.resolve(o.from), "utf8"));
  const ledger = path.resolve(o.ledger || DEFAULT_LEDGER);
  const summary = path.resolve(o.summary || DEFAULT_SUMMARY);
  assertDistinctPaths(ledger, summary);

  const metadata = {
    cycleId: o.cycleId,
    executionMode: o.executionMode,
    sourceRunId: o.sourceRunId,
    repository: o.repository,
    prNumber: o.prNumber,
    humanDisposition: o.human,
    humanFinalizedAt: o.humanFinalizedAt,
    humanNotes: o.humanNotes,
    failureFamily: o.family,
    telemetryOnly: o.telemetryOnly,
    estimatedCostUsd: o.estimatedCostUsd
  };

  if (o.dryRun) {
    return buildCycleReceipt(run, metadata, readLedger(ledger));
  }

  return withLedgerLock(ledger, () => {
    const prior = readLedger(ledger);
    const receipt = buildCycleReceipt(run, metadata, prior);
    appendReceiptUnlocked(ledger, receipt, prior);
    writeSummary(summary, [...prior, receipt]);
    return receipt;
  });
}

export function printHelp() {
  console.log("Usage: node scripts/record-cycle.mjs --from dogfood-run.json --cycle-id CYCLE-0001 --execution-mode live --repository owner/repo --human APPROVE --human-finalized-at <ISO> [--pr N] [--family slug|NONE] [--dry-run]\n       node scripts/record-cycle.mjs --rebuild-summary [--ledger file] [--summary file]");
}

async function main() {
  try {
    const o = parseArgs();
    if (o.help) return printHelp();
    process.stdout.write(JSON.stringify(recordCycle(o), null, 2) + "\n");
  } catch (e) {
    console.error(`record-cycle: ${e.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
