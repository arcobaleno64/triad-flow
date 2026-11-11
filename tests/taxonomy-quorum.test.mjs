/**
 * Triad-Flow v2.12 Pillar 4: Taxonomy-Aware Heterogeneous Quorum Calibration Tests
 * (RFC-028-04 / Architecture Charter)
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import {
  TaxonomyQuorumCalibrator,
  classifyTaxonomyDomain,
  resolveProviderFamily,
  VULNERABILITY_DOMAINS,
  DEFAULT_DOMAIN_WEIGHTS,
  DYNAMIC_TIER_THRESHOLDS,
  DOMAIN_RISK_COEFFICIENTS,
  MEMORY_SAFETY_CWES,
  CONCURRENCY_LOGIC_CWES,
  GLOBAL_ARCHITECTURE_CWES
} from "../src/core/taxonomy-quorum.mjs";

import { RISK_TIERS } from "../src/core/graph-router.mjs";
import {
  issueConsensusFromEvidence,
  isTrustedConsensus,
  assertTrustedConsensus,
  validateConsensusSemantics
} from "../src/core/consensus-state.mjs";

test("Contract Invariant: Zero external runtime npm dependencies", () => {
  const pkgPath = path.resolve("package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  assert.deepEqual(pkg.dependencies || {}, {}, "Production dependencies must strictly be empty ({})");
});

test("Domain Taxonomy Classification: maps CWEs and keywords to canonical domains", () => {
  // 1. Memory Safety (底層記憶體安全)
  const memCwes = ["CWE-119", "CWE-416", "CWE-190", "CWE-120", "CWE-787", "cwe-476"];
  for (const cwe of memCwes) {
    const res = classifyTaxonomyDomain(cwe);
    assert.equal(res.domain, VULNERABILITY_DOMAINS.MEMORY_SAFETY, `Expected ${cwe} to be MEMORY_SAFETY`);
  }

  // Keyword heuristic for memory safety
  const memKw = classifyTaxonomyDomain({ title: "Heap buffer overflow in network packet unpacker", file: "src/net.c" });
  assert.equal(memKw.domain, VULNERABILITY_DOMAINS.MEMORY_SAFETY);

  // 2. Concurrency, State & Business Logic (業務邏輯、並行競爭與狀態機)
  const concurCwes = ["CWE-362", "CWE-835", "CWE-755", "cwe-662", "CWE-366"];
  for (const cwe of concurCwes) {
    const res = classifyTaxonomyDomain(cwe);
    assert.equal(res.domain, VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC, `Expected ${cwe} to be CONCURRENCY_LOGIC`);
  }

  // Keyword heuristic for concurrency
  const concurKw = classifyTaxonomyDomain({ title: "Data race in worker thread synchronization mutex", file: "src/worker.js" });
  assert.equal(concurKw.domain, VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC);

  // 3. Global Architecture & Monorepo Context (全域架構掃描與跨模組 Monorepo 上下文)
  const archCwes = ["CWE-1021", "CWE-94", "CWE-693", "CWE-284", "CWE-918"];
  for (const cwe of archCwes) {
    const res = classifyTaxonomyDomain(cwe);
    assert.equal(res.domain, VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE, `Expected ${cwe} to be GLOBAL_ARCHITECTURE`);
  }

  // Keyword heuristic for architecture
  const archKw = classifyTaxonomyDomain({ title: "Cross-module boundary violation in monorepo import dependency cycle" });
  assert.equal(archKw.domain, VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE);

  // 4. General fallback
  const gen = classifyTaxonomyDomain("CWE-79");
  assert.equal(gen.domain, VULNERABILITY_DOMAINS.GENERAL_SECURITY);
});

test("Provider Family Resolution: handles LLM and static analysis sentries", () => {
  assert.equal(resolveProviderFamily("claude-3-7-sonnet"), "anthropic");
  assert.equal(resolveProviderFamily("codex-davinci-002"), "openai");
  assert.equal(resolveProviderFamily("gpt-4o"), "openai");
  assert.equal(resolveProviderFamily("antigravity-cli"), "google");
  assert.equal(resolveProviderFamily("gemini-2.5-pro"), "google");
  assert.equal(resolveProviderFamily("semgrep-core"), "static");
  assert.equal(resolveProviderFamily("codeql-scanner"), "static");
  assert.equal(resolveProviderFamily("sast-analyzer"), "static");
  assert.equal(resolveProviderFamily("custom-tool", "openai"), "openai");
  assert.equal(resolveProviderFamily("unknown-alien-agent"), "unknown");
});

test("Domain-Specialized Model Weights: verifies domain expertise matrix", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Memory Safety: OpenAI Codex (2.0) and Static Analyzer (1.8) prioritize over Claude (1.0) and AGY (1.0)
  const codexMem = calibrator.getModelWeight("codex", VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  const staticMem = calibrator.getModelWeight("semgrep", VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  const claudeMem = calibrator.getModelWeight("claude", VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  const agyMem = calibrator.getModelWeight("agy", VULNERABILITY_DOMAINS.MEMORY_SAFETY);

  assert.equal(codexMem, 2.0);
  assert.equal(staticMem, 1.8);
  assert.equal(claudeMem, 1.0);
  assert.equal(agyMem, 1.0);
  assert.ok(codexMem > claudeMem && staticMem > claudeMem);

  // Concurrency & Logic: Anthropic Claude Code (2.0) prioritizes over Codex (1.2) and AGY (1.2)
  const claudeConcur = calibrator.getModelWeight("claude", VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC);
  const codexConcur = calibrator.getModelWeight("codex", VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC);
  const agyConcur = calibrator.getModelWeight("agy", VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC);

  assert.equal(claudeConcur, 2.0);
  assert.equal(codexConcur, 1.2);
  assert.equal(agyConcur, 1.2);
  assert.ok(claudeConcur > codexConcur);

  // Global Architecture: Google AGY (2.0) prioritizes over Claude (1.3) and Codex (1.0)
  const agyArch = calibrator.getModelWeight("agy", VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE);
  const claudeArch = calibrator.getModelWeight("claude", VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE);
  const codexArch = calibrator.getModelWeight("codex", VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE);

  assert.equal(agyArch, 2.0);
  assert.equal(claudeArch, 1.3);
  assert.equal(codexArch, 1.0);
  assert.ok(agyArch > claudeArch && agyArch > codexArch);
});

test("Custom Domain Weights Override: respects constructor configurations", () => {
  const calibrator = new TaxonomyQuorumCalibrator({
    domainWeights: {
      [VULNERABILITY_DOMAINS.MEMORY_SAFETY]: {
        static: 3.5
      }
    }
  });

  const customWeight = calibrator.getModelWeight("semgrep", VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  assert.equal(customWeight, 3.5);
  // Default for codex remains intact
  assert.equal(calibrator.getModelWeight("codex", VULNERABILITY_DOMAINS.MEMORY_SAFETY), 2.0);
});

test("Dynamic Threshold Calculation: scales by risk tier, vulnerability domain, and diff size", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Tier 3 Docs baseline = 0.50
  const tier3Threshold = calibrator.calculateDynamicThreshold({ riskTier: RISK_TIERS.TIER_3_DOCS });
  assert.equal(tier3Threshold, 0.50);

  // Tier 2 Source baseline = 0.65
  const tier2Threshold = calibrator.calculateDynamicThreshold({ riskTier: RISK_TIERS.TIER_2_SOURCE });
  assert.equal(tier2Threshold, 0.65);

  // Tier 1 Critical baseline = 0.80
  const tier1Threshold = calibrator.calculateDynamicThreshold({ riskTier: RISK_TIERS.TIER_1_CRITICAL });
  assert.equal(tier1Threshold, 0.80);

  // Tier 1 with Memory Safety domain elevation: 0.80 * 1.15 = 0.92
  const tier1MemThreshold = calibrator.calculateDynamicThreshold({
    riskTier: RISK_TIERS.TIER_1_CRITICAL,
    detectedDomains: [VULNERABILITY_DOMAINS.MEMORY_SAFETY]
  });
  assert.equal(tier1MemThreshold, 0.92);

  // Clamping check: maximum threshold cannot exceed 0.95
  const clampedThreshold = calibrator.calculateDynamicThreshold({
    riskTier: RISK_TIERS.TIER_1_CRITICAL,
    detectedDomains: [VULNERABILITY_DOMAINS.MEMORY_SAFETY, VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC],
    fileCount: 10,
    lineCount: 500
  });
  assert.ok(clampedThreshold <= 0.95);
});

test("Tier-1 Security Invariants: Fails closed on Single-Sentry or Homogeneous Vendors", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Case A: Single Sentry on Tier 1 file (e.g. auth/login.js) -> FAIL CLOSED
  const singleSentryReports = [
    { id: "r1", provider: "claude", family: "anthropic", healthy: true, verdict: "approve" }
  ];
  const qSingle = calibrator.calibrateQuorum({
    reports: singleSentryReports,
    files: [{ path: "src/auth/jwt-signer.js", additions: 10, deletions: 2 }]
  });

  assert.equal(qSingle.quorumReached, false);
  assert.equal(qSingle.verdict, "error");
  assert.match(qSingle.reason, /Tier 1/);

  // Case B: Dual Sentry but SAME VENDOR (e.g. gpt-4o + codex, both OpenAI) -> FAIL CLOSED
  const sameVendorReports = [
    { id: "r1", provider: "gpt-4o", family: "openai", healthy: true, verdict: "approve" },
    { id: "r2", provider: "codex", family: "openai", healthy: true, verdict: "approve" }
  ];
  const qHomogeneous = calibrator.calibrateQuorum({
    reports: sameVendorReports,
    riskTier: RISK_TIERS.TIER_1_CRITICAL
  });

  assert.equal(qHomogeneous.quorumReached, false);
  assert.equal(qHomogeneous.verdict, "error");
  assert.match(qHomogeneous.reason, /heterogeneous provider families/);

  // Case C: Dual Sentry HETEROGENEOUS (Anthropic + Google) on Tier 1 -> PASS QUORUM
  const diverseReports = [
    { id: "r1", provider: "claude", family: "anthropic", healthy: true, verdict: "approve" },
    { id: "r2", provider: "agy", family: "google", healthy: true, verdict: "approve" }
  ];
  const qDiverse = calibrator.calibrateQuorum({
    reports: diverseReports,
    riskTier: RISK_TIERS.TIER_1_CRITICAL
  });

  assert.equal(qDiverse.quorumReached, true);
  assert.equal(qDiverse.verdict, "approve");
  assert.equal(qDiverse.selectedReportIds.length, 2);
});

test("Domain Expert Arbitration: Memory Safety Conflict (Codex vs AGY)", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Scenario: OpenAI Codex discovers CWE-416 (Use After Free) in C code.
  // Google AGY missed it and voted "approve".
  const reports = [
    {
      id: "rep-codex",
      provider: "codex",
      healthy: true,
      verdict: "error",
      findings: [
        {
          file: "src/driver/buffer.c",
          cwe: "CWE-416",
          title: "Use After Free in packet deallocator",
          severity: "critical"
        }
      ]
    },
    {
      id: "rep-agy",
      provider: "agy",
      healthy: true,
      verdict: "approve",
      findings: []
    }
  ];

  const result = calibrator.calibrateQuorum({
    reports,
    files: [{ path: "src/driver/buffer.c" }]
  });

  // Since CWE-416 is Memory Safety, Codex weight is 2.0 vs AGY weight 1.0.
  // Finding is confirmed, and is critical blocking -> cannot approve!
  assert.equal(result.quorumReached, true);
  assert.equal(result.verdict, "needs-attention");
  assert.notEqual(result.verdict, "approve");
  assert.equal(result.dominantDomain, VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  assert.equal(result.blockingFindings.length, 1);
  assert.equal(result.blockingFindings[0].cwe, "CWE-416");
  assert.equal(result.blockingFindings[0].taxonomyDomain, VULNERABILITY_DOMAINS.MEMORY_SAFETY);
  assert.ok(result.blockingFindings[0].isBlocking);
});

test("Domain Expert Arbitration: Concurrency & State Machine (Claude vs Static Analyzer)", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Scenario: Anthropic Claude spots CWE-362 (Race Condition) in async event emitter.
  // Static SAST analyzer does not catch it and reports clean.
  const reports = [
    {
      id: "rep-claude",
      provider: "claude",
      healthy: true,
      verdict: "error",
      findings: [
        {
          file: "src/events/dispatcher.js",
          cwe: "CWE-362",
          title: "Race Condition in shared event queue",
          severity: "high"
        }
      ]
    },
    {
      id: "rep-static",
      provider: "semgrep",
      healthy: true,
      verdict: "approve",
      findings: []
    }
  ];

  const result = calibrator.calibrateQuorum({
    reports,
    files: [{ path: "src/events/dispatcher.js" }]
  });

  assert.equal(result.dominantDomain, VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC);
  assert.equal(result.blockingFindings.length, 1);
  assert.equal(result.blockingFindings[0].cwe, "CWE-362");
  assert.equal(result.verdict, "needs-attention");
  assert.notEqual(result.verdict, "approve");
});

test("Domain Expert Arbitration: Monorepo Global Architecture (AGY 1M Context vs Micro)", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Scenario: Google AGY with 1M context identifies CWE-693 / Cross-module boundary violation across packages.
  // Micro reviewer with local view sees no issue.
  const reports = [
    {
      id: "rep-agy",
      provider: "agy",
      healthy: true,
      verdict: "error",
      findings: [
        {
          file: "packages/core/auth.js",
          cwe: "CWE-693",
          title: "Protection Mechanism Failure: Cross-package bypass of token validator",
          severity: "high"
        }
      ]
    },
    {
      id: "rep-micro",
      provider: "codex",
      healthy: true,
      verdict: "approve",
      findings: []
    }
  ];

  const result = calibrator.calibrateQuorum({
    reports,
    files: [{ path: "packages/core/auth.js" }]
  });

  assert.equal(result.dominantDomain, VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE);
  assert.equal(result.blockingFindings.length, 1);
  assert.equal(result.blockingFindings[0].cwe, "CWE-693");
  assert.equal(result.verdict, "needs-attention");
  assert.notEqual(result.verdict, "approve");
});

test("Consensus State Compatibility: Calibrator output integrates with issueConsensusFromEvidence", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  const reportsMap = new Map([
    ["r1", { id: "r1", provider: "agy", family: "google", healthy: true, verdict: "approve" }],
    ["r2", { id: "r2", provider: "claude", family: "anthropic", healthy: true, verdict: "approve" }]
  ]);

  const calibratedQuorum = calibrator.calibrateQuorum({
    reports: reportsMap,
    riskTier: RISK_TIERS.TIER_2_SOURCE
  });

  assert.equal(calibratedQuorum.quorumReached, true);
  assert.equal(calibratedQuorum.verdict, "approve");

  // Mint trusted consensus capability using consensus-state.mjs
  const trustedConsensus = issueConsensusFromEvidence({
    validatedReportsMap: reportsMap,
    quorumResult: calibratedQuorum,
    invocationNonce: "test-nonce-12345",
    deduplicatedFindings: calibratedQuorum.findings,
    verdict: calibratedQuorum.verdict,
    consensusProof: calibratedQuorum.consensusProof
  });

  assert.ok(isTrustedConsensus(trustedConsensus));
  assert.doesNotThrow(() => assertTrustedConsensus(trustedConsensus));
  assert.equal(trustedConsensus.verdict, "approve");
  assert.equal(trustedConsensus.quorumReached, true);
});

test("createQuorumPolicy Adapter: functions as standard Triad-Flow Quorum Policy", () => {
  const calibrator = new TaxonomyQuorumCalibrator();
  const policyFn = calibrator.createQuorumPolicy();

  const metadataMap = {
    r1: { id: "r1", source: "agy", family: "google", healthy: true },
    r2: { id: "r2", source: "claude", family: "anthropic", healthy: true },
    r3: { id: "r3", source: "codex", family: "openai", healthy: true }
  };

  const quorumRes = policyFn(metadataMap, { tier: 1 });
  assert.equal(quorumRes.quorumReached, true);
  assert.equal(quorumRes.selectedReportIds.length, 3);
  assert.ok(typeof quorumRes.consensusProof === "string");
});

test("Immutability & Defense-in-Depth: Output objects are deeply frozen", () => {
  const calibrator = new TaxonomyQuorumCalibrator();
  const result = calibrator.calibrateQuorum({
    reports: [
      { id: "r1", provider: "claude", family: "anthropic", healthy: true, verdict: "approve" },
      { id: "r2", provider: "agy", family: "google", healthy: true, verdict: "approve" }
    ],
    riskTier: RISK_TIERS.TIER_2_SOURCE
  });

  assert.ok(Object.isFrozen(result));
  assert.throws(() => { result.verdict = "tampered"; }, TypeError);
  assert.throws(() => { result.findings.push({ fake: true }); }, TypeError);
  assert.throws(() => { result.selectedReportIds.push("fake"); }, TypeError);
});

test("Tier-3 Low-Risk Permissiveness: Single Sentry permitted on documentation/configs", () => {
  const calibrator = new TaxonomyQuorumCalibrator();
  const singleDocSentry = [
    { id: "r1", provider: "agy", family: "google", healthy: true, verdict: "approve" }
  ];

  const result = calibrator.calibrateQuorum({
    reports: singleDocSentry,
    files: [{ path: "docs/readme.md", additions: 5, deletions: 1 }]
  });

  assert.equal(result.riskTier, RISK_TIERS.TIER_3_DOCS);
  assert.equal(result.quorumReached, true);
  assert.equal(result.verdict, "approve");
});

test("Hostile & Malformed Inputs: Fails closed gracefully without crashing", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // Null input
  const resNull = calibrator.calibrateQuorum(null);
  assert.equal(resNull.quorumReached, false);
  assert.equal(resNull.verdict, "error");

  // Empty reports
  const resEmpty = calibrator.calibrateQuorum({ reports: [] });
  assert.equal(resEmpty.quorumReached, false);
  assert.equal(resEmpty.verdict, "error");

  // Unhealthy reports only
  const resUnhealthy = calibrator.calibrateQuorum({
    reports: [
      { id: "r1", provider: "claude", healthy: false, error: "TIMEOUT" },
      { id: "r2", provider: "codex", healthy: false, error: "CRASH" }
    ]
  });
  assert.equal(resUnhealthy.quorumReached, false);
  assert.equal(resUnhealthy.verdict, "error");
});

