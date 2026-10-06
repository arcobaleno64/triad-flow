import test from "node:test";
import assert from "node:assert/strict";
import { evaluateGateDecision, evaluatePostVerificationGate } from "../src/core/harness.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { deriveTriadDisposition, classifyDiscrepancy } from "../scripts/record-cycle.mjs";

function makeTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
      ...f,
      id: f.id,
      title: f.title,
      severity: f.severity,
      file: f.file,
      line_start: f.line_start || f.line || 1
    };
    const sources = Array.isArray(f.sources) && f.sources.length > 0
      ? f.sources
      : (f.corroborations >= 2 ? ["agy", "claude"] : ["codex"]);

    if (sources.includes("agy")) agyFindings.push(rawF);
    if (sources.includes("claude")) claudeFindings.push(rawF);
    if (sources.includes("codex")) codexFindings.push(rawF);
  }

  const rawReports = {
    agy: {
      provider: "agy",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: agyFindings
    },
    claude: {
      provider: "claude",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: claudeFindings
    },
    codex: {
      provider: "codex",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: codexFindings
    }
  };

  return aggregateConsensus(rawReports, {
    policy: "TRI_PARTY_HETEROGENEOUS",
    tier
  });
}

// ==============================================================================
// Group 1: Deterministic Replays of Historical Dogfood Cycles
// ==============================================================================

test("LOOP2-REMEDIATION-001 Replay: CYCLE-0008 produces HUMAN_REVIEW_REQUIRED, eliminating false hold", () => {
  const finding = {
    id: "finding-1",
    title: "Unbounded numeric input can still terminate the statusline",
    severity: "medium",
    file: "examples/statusline/statusline.sh",
    line: 117,
    corroborations: 1,
    sources: ["codex"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 1 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "INSUFFICIENT_EVIDENCE",
        classification: "UNVERIFIABLE",
        locatorAccurate: false,
        typeAccurate: true,
        severityAccurate: false,
        reasoning: "Locator inaccurate and termination under set -e is unproven."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 1, verificationRecord });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /INSUFFICIENT_EVIDENCE/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "HUMAN_REVIEW_REQUIRED");

  // With Human Oracle APPROVE, HUMAN_REVIEW_REQUIRED is a non-discrepant MATCH
  const discrepancy = classifyDiscrepancy(triadDisposition, "APPROVE");
  assert.equal(discrepancy, "MATCH", "CYCLE-0008 replay must eliminate false hold");
});

test("LOOP2-REMEDIATION-001 Replay: CYCLE-0009 produces APPROVE with advisory findings in Tier 2", () => {
  const findings = [
    {
      id: "finding-1",
      title: "Stdin read has a hard 0.25s timeout",
      severity: "low",
      file: "examples/statusline/statusline.sh",
      line: 30,
      corroborations: 1,
      sources: ["claude"]
    },
    {
      id: "finding-2",
      title: "Timed-out reads can pass incomplete JSON to jq",
      severity: "medium",
      file: "examples/statusline/statusline.sh",
      line: 31,
      corroborations: 1,
      sources: ["codex"]
    }
  ];
  const consensus = makeTrustedConsensus(findings, { tier: 2 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Low severity fits."
      },
      {
        findingId: "finding-2",
        verdict: "SUPPORTED",
        classification: "PARTIALLY_SUPPORTED",
        locatorAccurate: false,
        typeAccurate: true,
        severityAccurate: false, // Explicitly downgraded from Medium to Low
        reasoning: "Duplicates finding-1. Medium severity is too high; Low is right level."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord });
  assert.equal(gate.decision, "approve");
  assert.match(gate.reason, /No blocking vulnerabilities/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "APPROVE");

  const discrepancy = classifyDiscrepancy(triadDisposition, "APPROVE");
  assert.equal(discrepancy, "MATCH", "CYCLE-0009 replay must eliminate false hold");
});

test("LOOP2-REMEDIATION-001 Replay: CYCLE-0003 maintains strictly BLOCK on genuine security authority risk", () => {
  const finding = {
    id: "finding-1",
    title: "Unauthorized authority escalation in consumer OAuth workflow",
    severity: "high",
    file: "src/auth.mjs",
    line: 45,
    corroborations: 1,
    sources: ["claude"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 1 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Authentic privilege escalation."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 1, verificationRecord });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /critical\/high/i);
  assert.equal(gate.criticals.length, 1);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "BLOCK");

  const discrepancy = classifyDiscrepancy(triadDisposition, "REQUEST_CHANGES");
  assert.equal(discrepancy, "MATCH", "CYCLE-0003 genuine BLOCK must be preserved");
});

test("LOOP2-REMEDIATION-001 Replay: CYCLE-0005 maintains strictly BLOCK on privacy boundary hole", () => {
  const finding = {
    id: "finding-1",
    title: "Security mode allows link tags to leak external HTTP requests",
    severity: "medium",
    file: "src/SecurityMode.cs",
    line: 88,
    corroborations: 2,
    sources: ["agy", "claude"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 1 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Link tags leak network egress."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 1, verificationRecord });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /verified medium/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "BLOCK");

  const discrepancy = classifyDiscrepancy(triadDisposition, "REQUEST_CHANGES");
  assert.equal(discrepancy, "MATCH", "CYCLE-0005 genuine BLOCK must be preserved");
});

test("LOOP2-REMEDIATION-002 Replay: CYCLE-0021 produces BLOCK on verified objective-falsifying low finding, eliminating false advance", () => {
  const finding = {
    id: "finding-1",
    title: "Failure in one mounted transport still skips the remaining mounts",
    severity: "low",
    file: "httpx/_client.py",
    line_start: 1270,
    line_end: 1275,
    ruleId: "RESOURCE-CLEANUP-PARTIAL",
    cwe: "CWE-404",
    type: "resource-leak",
    recommendation: "try/finally protects only the main transport. If any mounted transport's close()/__exit__/aclose()/__aexit__ raises, the loop aborts and later mounts are never closed...",
    corroborations: 1,
    sources: ["claude"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 2 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        classification: "PARTIALLY_SUPPORTED",
        locatorAccurate: false,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "The diff shows try/finally wrapping only the main transport. The mounts loop sits inside `finally` with no per-transport guard. If one mounted transport's close()/__exit__/aclose()/__aexit__ raises, the loop aborts and the remaining mounts are never closed, so their connections can leak. This is the same partial-cleanup problem the patch targets, just one level down, and the diff does not address it. CWE-404 and the resource-leak classification fit. Low severity is reasonable because the trigger is an exception during transport close, which is rare. The reported lines 1270-1275 match only the sync Client.close hunk (new-file lines 1267-1275). The recommendation also cites other locations, so the locator is only partly accurate. The recommendation's extra point also holds: an exception raised inside `finally` replaces the in-flight exception from the main transport's close. In __exit__, it can also mask the original exc_value."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /falsifies patch objective/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "BLOCK");

  // With Human Oracle REQUEST_CHANGES, Triad BLOCK is a non-discrepant MATCH
  const discrepancy = classifyDiscrepancy(triadDisposition, "REQUEST_CHANGES");
  assert.equal(discrepancy, "MATCH", "CYCLE-0021 replay must eliminate false advance and match REQUEST_CHANGES");
});

test("LOOP2-REMEDIATION-002 Replay: CYCLE-0010 produces APPROVE on advisory verified low finding in Tier 2", () => {
  const finding = {
    id: "finding-1",
    title: "IPv4 分支新增對 parsed.port 的存取，可能對畸形連接埠拋出 ValueError",
    severity: "low",
    file: "src/requests/utils.py",
    line: 840,
    corroborations: 1,
    sources: ["claude"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 2 });

  const verificationRecord = {
    ok: true,
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        acceptanceRelevance: "ADVISORY",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "The diff adds `if parsed.port:` at lines 840-842 inside the `is_ipv4_address(hostname)` branch. Low severity is reasonable, because requests' normal flow calls `prepare_url`, which rejects invalid ports with InvalidURL first. The exposure is only direct callers of the public `should_bypass_proxies` helper."
      }
    ]
  };

  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord });
  assert.equal(gate.decision, "approve");
  assert.match(gate.reason, /No blocking vulnerabilities/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "APPROVE");

  const discrepancy = classifyDiscrepancy(triadDisposition, "APPROVE");
  assert.equal(discrepancy, "MATCH", "CYCLE-0010 replay must preserve APPROVE on advisory low finding");
});

// ==============================================================================
// Group 2: Synthetic Authority Matrix Tests (Exhaustive Coverage)
// ==============================================================================

test("Synthetic Matrix 1: SUPPORTED Critical/High always BLOCK", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "RCE", severity: "critical", file: "a.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block");
});

test("Synthetic Matrix 2: Tier 1 SUPPORTED Medium and Low always BLOCK", () => {
  const consensusMed = makeTrustedConsensus([
    { id: "f1", title: "ReDoS", severity: "medium", file: "regex.js", corroborations: 1 }
  ], { tier: 1 });
  const recMed = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  };
  assert.equal(evaluateGateDecision(consensusMed, { tier: 1, verificationRecord: recMed }).decision, "block");

  const consensusLow = makeTrustedConsensus([
    { id: "f2", title: "Missing header", severity: "low", file: "header.js", corroborations: 1 }
  ], { tier: 1 });
  const recLow = {
    ok: true,
    evaluations: [{ findingId: "f2", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  };
  assert.equal(evaluateGateDecision(consensusLow, { tier: 1, verificationRecord: recLow }).decision, "block");
});

test("Synthetic Matrix 3: Tier 2 SUPPORTED Medium blocks, but Tier 2 only Low passes as advisory", () => {
  // Tier 2 with SUPPORTED Medium -> block
  const consensusMed = makeTrustedConsensus([
    { id: "f1", title: "Timing attack", severity: "medium", file: "hash.js", corroborations: 1 }
  ], { tier: 2 });
  const recMed = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  };
  assert.equal(evaluateGateDecision(consensusMed, { tier: 2, verificationRecord: recMed }).decision, "block");

  // Tier 2 with only SUPPORTED Low -> approve (advisory)
  const consensusLow = makeTrustedConsensus([
    { id: "f2", title: "Formatting bug", severity: "low", file: "fmt.js", corroborations: 1 }
  ], { tier: 2 });
  const recLow = {
    ok: true,
    evaluations: [{ findingId: "f2", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  };
  assert.equal(evaluateGateDecision(consensusLow, { tier: 2, verificationRecord: recLow }).decision, "approve");
});

test("Synthetic Matrix 4: Solitary finding + verifier CONTESTED is removed from blocking set", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Phantom SQLi", severity: "medium", file: "db.js", corroborations: 1, sources: ["agy"] }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Prepared statements are used." }]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "approve", "Solitary contested finding must be removed from blocking set");
});

test("Synthetic Matrix 5: Corroborated finding + verifier CONTESTED requires HUMAN_REVIEW_REQUIRED", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Contested Auth Hole", severity: "medium", file: "auth.js", corroborations: 2, sources: ["agy", "codex"] }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Verifier disagrees with both models." }]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required", "Single verifier cannot silently overturn corroborated finding");
});

test("Synthetic Matrix 6: Critical/High finding contested by verifier requires HUMAN_REVIEW_REQUIRED", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Critical Buffer Overflow", severity: "critical", file: "parser.c", corroborations: 1, sources: ["codex"] }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Bounds check exists earlier." }]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required", "Contested Critical cannot silently approve");
});

test("Synthetic Matrix 7: Corroborated finding with INSUFFICIENT_EVIDENCE fails closed as BLOCK", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Cross-Site Scripting", severity: "medium", file: "view.js", corroborations: 2, sources: ["agy", "claude"] }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "INSUFFICIENT_EVIDENCE", classification: "UNVERIFIABLE", locatorAccurate: false, typeAccurate: false, severityAccurate: false }]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block", "Corroborated unverified finding must fail closed");
});

test("Synthetic Matrix 8: Structural failures never approve regardless of verifier output", () => {
  // 1. Coverage failure
  const consensusCov = makeTrustedConsensus([], { tier: 2 });
  const rec = { ok: true, evaluations: [] };
  assert.equal(evaluateGateDecision(consensusCov, { tier: 2, coverageOk: false, verificationRecord: rec }).decision, "block");

  // 2. Quorum failure
  const consensusQuorum = makeTrustedConsensus([], { tier: 2, quorumReached: false });
  assert.equal(evaluateGateDecision(consensusQuorum, { tier: 2, verificationRecord: rec }).decision, "block");

  // 3. Verifier execution failure
  const brokenRec = { ok: false, error: "TIMEOUT" };
  const consensusClean = makeTrustedConsensus([{ id: "f1", title: "Low finding", file: "a.js", severity: "low", corroborations: 1 }], { tier: 2 });
  assert.equal(evaluateGateDecision(consensusClean, { tier: 2, verificationRecord: brokenRec }).decision, "block");
});

test("Synthetic Matrix 9: Tier 2 Low finding with explicit acceptanceRelevance: BLOCKING blocks", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Defect violates patch goal", severity: "low", file: "helper.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [
      {
        findingId: "f1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        acceptanceRelevance: "BLOCKING",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Defect prevents patch from achieving its contract."
      }
    ]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /falsifies patch objective/i);
});

test("Synthetic Matrix 10: Tier 2 Low finding with explicit acceptanceRelevance: ADVISORY passes as advisory", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Incidental edge case", severity: "low", file: "helper.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [
      {
        findingId: "f1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        acceptanceRelevance: "ADVISORY",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Minor edge case does not affect patch goal."
      }
    ]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord: rec });
  assert.equal(gate.decision, "approve");
});

test("Synthetic Matrix 11: Tier 2 Low finding with falsifiesPatchObjective: true blocks", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Contract bypass", severity: "low", file: "helper.js", corroborations: 1, falsifiesPatchObjective: true }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [
      {
        findingId: "f1",
        verdict: "SUPPORTED",
        classification: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Confirmed contract bypass."
      }
    ]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /falsifies patch objective/i);
});

test("Synthetic Matrix 12: Tier 2 Low finding with INSUFFICIENT_EVIDENCE and BLOCKING relevance produces HUMAN_REVIEW_REQUIRED", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Claimed objective break", severity: "low", file: "helper.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [
      {
        findingId: "f1",
        verdict: "INSUFFICIENT_EVIDENCE",
        classification: "UNVERIFIABLE",
        acceptanceRelevance: "BLOCKING",
        locatorAccurate: false,
        typeAccurate: false,
        severityAccurate: false,
        reasoning: "Cannot verify whether objective is broken from diff alone."
      }
    ]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /blocking acceptance relevance requires adjudication/i);
});

test("Synthetic Matrix 13: Tier 2 Low finding with CONTESTED and BLOCKING relevance is removed from blocking set", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Refuted claim", severity: "low", file: "helper.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = {
    ok: true,
    evaluations: [
      {
        findingId: "f1",
        verdict: "CONTESTED",
        classification: "CONTRADICTED",
        acceptanceRelevance: "BLOCKING",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Claim is completely refuted by line 42."
      }
    ]
  };
  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord: rec });
  assert.equal(gate.decision, "approve");
});
