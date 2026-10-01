/**
 * Tri-Party Heterogeneous Quorum & Consensus Engine Tests (RFC-027-02 Section 18.2)
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  QuorumPolicies,
  aggregateConsensus
} from "../src/core/loop.mjs";
import {
  evaluateGateDecision
} from "../src/core/harness.mjs";

function makeReport(role, family, healthy = true, findings = [], error = null) {
  return {
    id: `rep-${role}`,
    name: role,
    source: role,
    provider: role,
    family,
    healthy,
    error,
    findings
  };
}

test("test_tri_party_quorum_formation_truth_table: validates Q-01 through Q-08 topologies", () => {
  const policy = QuorumPolicies.TRI_PARTY_HETEROGENEOUS;

  // Q-01: 3 of 3 Nominal (Google, Anthropic, OpenAI)
  const metaQ01 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: true },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: true },
    r3: { id: "r3", source: "codex", family: "openai", healthy: true }
  };
  const q01 = policy(metaQ01);
  assert.equal(q01.quorumReached, true);
  assert.equal(q01.topology, "3_OF_3_NOMINAL");
  assert.equal(q01.selectedReportIds.length, 3);

  // Q-02: 2 of 3 Degraded (Google + Anthropic, OpenAI down)
  const metaQ02 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: true },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: true },
    r3: { id: "r3", source: "codex", family: "openai", healthy: false, error: "TIMEOUT" }
  };
  const q02 = policy(metaQ02);
  assert.equal(q02.quorumReached, true);
  assert.equal(q02.topology, "2_OF_3_DEGRADED");
  assert.deepEqual(q02.selectedReportIds, ["r1", "r2"]);

  // Q-03: 2 of 3 Degraded (Google + OpenAI, Anthropic down)
  const metaQ03 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: true },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: false, error: "AUTH_FAILURE" },
    r3: { id: "r3", source: "codex", family: "openai", healthy: true }
  };
  const q03 = policy(metaQ03);
  assert.equal(q03.quorumReached, true);
  assert.equal(q03.topology, "2_OF_3_DEGRADED");
  assert.deepEqual(q03.selectedReportIds, ["r1", "r3"]);

  // Q-04: 2 of 3 Degraded (Anthropic + OpenAI, Google down)
  const metaQ04 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: false, error: "CRASH" },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: true },
    r3: { id: "r3", source: "codex", family: "openai", healthy: true }
  };
  const q04 = policy(metaQ04);
  assert.equal(q04.quorumReached, true);
  assert.equal(q04.topology, "2_OF_3_DEGRADED");
  assert.deepEqual(q04.selectedReportIds, ["r2", "r3"]);

  // Q-05A: 1 of 3 on Tier 1 (High-Risk) changeset fails closed
  const metaQ05 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: true },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: false },
    r3: { id: "r3", source: "codex", family: "openai", healthy: false }
  };
  const q05A = policy(metaQ05, { tier: 1 });
  assert.equal(q05A.quorumReached, false);
  assert.equal(q05A.topology, "QUORUM_FAILED");
  assert.match(q05A.reason, /Tier 1/);

  // Q-05B: 1 of 3 on Tier 2/3 (Low-Risk) changeset permits Single Sentry
  const q05B = policy(metaQ05, { tier: 2 });
  assert.equal(q05B.quorumReached, true);
  assert.equal(q05B.topology, "1_OF_3_SINGLE_SENTRY");
  assert.deepEqual(q05B.selectedReportIds, ["r1"]);

  // Q-08: 0 of 3 all unhealthy
  const metaQ08 = {
    r1: { id: "r1", source: "agy", family: "google", healthy: false },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: false },
    r3: { id: "r3", source: "codex", family: "openai", healthy: false }
  };
  const q08 = policy(metaQ08);
  assert.equal(q08.quorumReached, false);
  assert.equal(q08.topology, "QUORUM_FAILED");
});

test("test_tri_party_solitary_blocker_veto: single provider reporting Critical/High blocks gate (V-02..V-04)", () => {
  const criticalFinding = {
    id: "f-rce-1",
    title: "Remote Code Execution via child_process.exec",
    severity: "critical",
    file: "src/server.js",
    line_start: 45,
    cwe: "CWE-78"
  };

  // Case V-02: Google reports Critical, Claude and Codex report Clean (0 findings)
  const consensusV02 = aggregateConsensus({
    agy: makeReport("agy", "google", true, [criticalFinding]),
    claude: makeReport("claude", "anthropic", true, []),
    codex: makeReport("codex", "openai", true, [])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensusV02.verdict, "needs-attention");
  assert.equal(consensusV02.deduplicatedFindings.length, 1);
  assert.equal(consensusV02.deduplicatedFindings[0].corroborations, 1);
  const gateV02 = evaluateGateDecision(consensusV02);
  assert.equal(gateV02.decision, "block", "Solitary Critical finding must block Gate (V-02)");

  // Case V-03: Claude reports High, Google and Codex report Clean
  const highFinding = {
    id: "f-sqli-1",
    title: "SQL Injection in User Lookup",
    severity: "high",
    file: "src/db.js",
    line_start: 10,
    cwe: "CWE-89"
  };
  const consensusV03 = aggregateConsensus({
    agy: makeReport("agy", "google", true, []),
    claude: makeReport("claude", "anthropic", true, [highFinding]),
    codex: makeReport("codex", "openai", true, [])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensusV03.verdict, "needs-attention");
  const gateV03 = evaluateGateDecision(consensusV03);
  assert.equal(gateV03.decision, "block", "Solitary High finding must block Gate (V-03)");

  // Case V-04: Codex reports Critical, Google and Claude report Clean
  const consensusV04 = aggregateConsensus({
    agy: makeReport("agy", "google", true, []),
    claude: makeReport("claude", "anthropic", true, []),
    codex: makeReport("codex", "openai", true, [criticalFinding])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensusV04.verdict, "needs-attention");
  const gateV04 = evaluateGateDecision(consensusV04);
  assert.equal(gateV04.decision, "block", "Solitary Codex Critical finding must block Gate (V-04)");
});

test("test_tri_party_corroboration_accumulation: records multi-sentry agreement (V-05, V-06)", () => {
  const sqliAgy = {
    title: "SQL Injection via string interpolation",
    severity: "high",
    file: "src/db.js",
    line_start: 15,
    cwe: "CWE-89"
  };
  const sqliClaude = {
    title: "SQLi parameter concatenation",
    severity: "high",
    file: "src/db.js",
    line_start: 18, // Within +/- 15 lines window
    cwe: "89"       // Bare numeric CWE normalized to cwe-89
  };
  const sqliCodex = {
    title: "Unescaped SQL query",
    severity: "high",
    file: "src/db.js",
    line_start: 16,
    cwe: "cwe-89"
  };

  // V-05: 2 providers corroborate (corroborations = 2)
  const consensusV05 = aggregateConsensus({
    agy: makeReport("agy", "google", true, [sqliAgy]),
    claude: makeReport("claude", "anthropic", true, [sqliClaude]),
    codex: makeReport("codex", "openai", true, [])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensusV05.deduplicatedFindings.length, 1);
  assert.equal(consensusV05.deduplicatedFindings[0].corroborations, 2);
  assert.deepEqual([...consensusV05.deduplicatedFindings[0].sources].sort(), ["agy", "claude"]);

  // V-06: 3 providers corroborate unanimously (corroborations = 3)
  const consensusV06 = aggregateConsensus({
    agy: makeReport("agy", "google", true, [sqliAgy]),
    claude: makeReport("claude", "anthropic", true, [sqliClaude]),
    codex: makeReport("codex", "openai", true, [sqliCodex])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensusV06.deduplicatedFindings.length, 1);
  assert.equal(consensusV06.deduplicatedFindings[0].corroborations, 3);
  assert.deepEqual([...consensusV06.deduplicatedFindings[0].sources].sort(), ["agy", "claude", "codex"]);
});

test("test_tri_party_severity_preservation: max(severity) is preserved across differing ratings (V-10)", () => {
  const agyMed = {
    title: "Denial of service via regex",
    severity: "medium",
    file: "src/parser.js",
    line_start: 30,
    cwe: "CWE-1333"
  };
  const claudeHigh = {
    title: "ReDoS vulnerability in route parser",
    severity: "high",
    file: "src/parser.js",
    line_start: 32,
    cwe: "1333"
  };
  const codexLow = {
    title: "Catastrophic backtracking issue",
    severity: "low",
    file: "src/parser.js",
    line_start: 28,
    cwe: "cwe-1333"
  };

  const consensus = aggregateConsensus({
    agy: makeReport("agy", "google", true, [agyMed]),
    claude: makeReport("claude", "anthropic", true, [claudeHigh]),
    codex: makeReport("codex", "openai", true, [codexLow])
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensus.deduplicatedFindings.length, 1);
  assert.equal(consensus.deduplicatedFindings[0].severity, "high", "Consensus must preserve highest severity (high)");
  assert.equal(consensus.deduplicatedFindings[0].corroborations, 3);
});

test("test_pairwise_sybil_rejection: identical object reference between roles triggers immediate Sybil block", () => {
  const sharedReport = makeReport("shared", "google", true, []);

  const consensus = aggregateConsensus({
    agy: sharedReport,
    codex: sharedReport // Identical object reference!
  }, { policy: "TRI_PARTY_HETEROGENEOUS" });

  assert.equal(consensus.verdict, "error");
  assert.match(consensus.consensusProof, /Sybil inflation rejected/);
  assert.equal(consensus.quorumResult.quorumReached, false);

  const gate = evaluateGateDecision(consensus);
  assert.equal(gate.decision, "block");
});
