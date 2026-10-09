import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  registerTrustedVerificationRecord,
  RunContext
} from "../src/core/harness.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { deriveTriadDisposition, classifyDiscrepancy } from "../scripts/record-cycle.mjs";

function makeTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
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

  const verificationRecord = registerTrustedVerificationRecord({
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
  });

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

  const verificationRecord = registerTrustedVerificationRecord({
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
  });

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

  const verificationRecord = registerTrustedVerificationRecord({
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
  });

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

  const verificationRecord = registerTrustedVerificationRecord({
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
  });

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

test("CYCLE-0021 Replay: Tier 2 SUPPORTED Low directly falsifying patch objective BLOCKS", () => {
  const finding = {
    id: "finding-1",
    title: "Mounted cleanup stops after the first mounted transport failure",
    severity: "low",
    file: "httpx/_client.py",
    line: 1275,
    corroborations: 1,
    sources: ["codex"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 2 });
  const verificationRecord = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Ensure all mounted transports are closed even if the main transport raises.",
    evaluations: [{
      findingId: "finding-1",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "A mounted close failure aborts the loop, so later mounted transports are not closed despite the stated all-transports cleanup objective."
    }]
  });

  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /falsifies stated patch objective/i);

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "BLOCK");
  assert.equal(classifyDiscrepancy(triadDisposition, "REQUEST_CHANGES"), "MATCH");
});

test("CYCLE-0010 receipt-signature replay: Tier 2 verified Low remains APPROVE when it does not falsify the patch objective", () => {
  // The canonical CYCLE-0010 receipt records Tier 2, one finding, successful verification,
  // zero disagreement, and final APPROVE. The historical run artifact does not retain the
  // finding text here, so this replay intentionally preserves that gate-relevant signature.
  const finding = {
    id: "finding-1",
    title: "Verified advisory issue outside the IPv4 no_proxy port fix objective",
    severity: "low",
    file: "src/requests/utils.py",
    line: 840,
    corroborations: 1,
    sources: ["codex"]
  };
  const consensus = makeTrustedConsensus([finding], { tier: 2 });
  const verificationRecord = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Honor host:port entries for IPv4 addresses in no_proxy while preserving existing matching.",
    evaluations: [{
      findingId: "finding-1",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "The advisory issue does not invalidate the stated IPv4 no_proxy host:port behavior."
    }]
  });

  const gate = evaluateGateDecision(consensus, { tier: 2, strict: false, verificationRecord });
  assert.equal(gate.decision, "approve");

  const triadDisposition = deriveTriadDisposition({
    advisoryGate: gate,
    telemetryMetrics: { executionComplete: true },
    consensus: { quorumReached: true }
  });
  assert.equal(triadDisposition, "APPROVE");
  assert.equal(classifyDiscrepancy(triadDisposition, "APPROVE"), "MATCH");
});

// ==============================================================================
// Group 2: Synthetic Authority Matrix Tests (Exhaustive Coverage)
// ==============================================================================

test("Synthetic Matrix 1: SUPPORTED Critical/High always BLOCK", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "RCE", severity: "critical", file: "a.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  });
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block");
});

test("Synthetic Matrix 2: Tier 1 SUPPORTED Medium and Low always BLOCK", () => {
  const consensusMed = makeTrustedConsensus([
    { id: "f1", title: "ReDoS", severity: "medium", file: "regex.js", corroborations: 1 }
  ], { tier: 1 });
  const recMed = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  });
  assert.equal(evaluateGateDecision(consensusMed, { tier: 1, verificationRecord: recMed }).decision, "block");

  const consensusLow = makeTrustedConsensus([
    { id: "f2", title: "Missing header", severity: "low", file: "header.js", corroborations: 1 }
  ], { tier: 1 });
  const recLow = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f2", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  });
  assert.equal(evaluateGateDecision(consensusLow, { tier: 1, verificationRecord: recLow }).decision, "block");
});

test("Synthetic Matrix 3: Tier 2 SUPPORTED Medium blocks, but Tier 2 only Low passes as advisory", () => {
  // Tier 2 with SUPPORTED Medium -> block
  const consensusMed = makeTrustedConsensus([
    { id: "f1", title: "Timing attack", severity: "medium", file: "hash.js", corroborations: 1 }
  ], { tier: 2 });
  const recMed = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  });
  assert.equal(evaluateGateDecision(consensusMed, { tier: 2, verificationRecord: recMed }).decision, "block");

  // Tier 2 with only SUPPORTED Low -> approve (advisory)
  const consensusLow = makeTrustedConsensus([
    { id: "f2", title: "Formatting bug", severity: "low", file: "fmt.js", corroborations: 1 }
  ], { tier: 2 });
  const recLow = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f2", verdict: "SUPPORTED", classification: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }]
  });
  assert.equal(evaluateGateDecision(consensusLow, { tier: 2, verificationRecord: recLow }).decision, "approve");
});

test("Synthetic Matrix 4: Solitary finding + verifier CONTESTED is removed from blocking set", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Phantom SQLi", severity: "medium", file: "db.js", corroborations: 1, sources: ["agy"] }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Prepared statements are used." }]
  });
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "approve", "Solitary contested finding must be removed from blocking set");
});

test("Synthetic Matrix 5: Corroborated finding + verifier CONTESTED requires HUMAN_REVIEW_REQUIRED", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Contested Auth Hole", severity: "medium", file: "auth.js", corroborations: 2, sources: ["agy", "codex"] }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Verifier disagrees with both models." }]
  });
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required", "Single verifier cannot silently overturn corroborated finding");
});

test("Synthetic Matrix 6: Critical/High finding contested by verifier requires HUMAN_REVIEW_REQUIRED", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Critical Buffer Overflow", severity: "critical", file: "parser.c", corroborations: 1, sources: ["codex"] }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "CONTESTED", classification: "CONTRADICTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, reasoning: "Bounds check exists earlier." }]
  });
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required", "Contested Critical cannot silently approve");
});

test("Synthetic Matrix 7: Corroborated finding with INSUFFICIENT_EVIDENCE fails closed as BLOCK", () => {
  const consensus = makeTrustedConsensus([
    { id: "f1", title: "Cross-Site Scripting", severity: "medium", file: "view.js", corroborations: 2, sources: ["agy", "claude"] }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{ findingId: "f1", verdict: "INSUFFICIENT_EVIDENCE", classification: "UNVERIFIABLE", locatorAccurate: false, typeAccurate: false, severityAccurate: false }]
  });
  const gate = evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block", "Corroborated unverified finding must fail closed");
});

test("Synthetic Matrix 8: Structural failures never approve regardless of verifier output", () => {
  // 1. Coverage failure
  const consensusCov = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({ ok: true, evaluations: [] });
  assert.equal(evaluateGateDecision(consensusCov, { tier: 2, coverageOk: false, verificationRecord: rec }).decision, "block");

  // 2. Quorum failure
  const consensusQuorum = makeTrustedConsensus([], { tier: 2, quorumReached: false });
  assert.equal(evaluateGateDecision(consensusQuorum, { tier: 2, verificationRecord: rec }).decision, "block");

  // 3. Verifier execution failure
  const brokenRec = registerTrustedVerificationRecord({ ok: false, error: "TIMEOUT" });
  const consensusClean = makeTrustedConsensus([{ id: "f1", title: "Low finding", file: "a.js", severity: "low", corroborations: 1 }], { tier: 2 });
  assert.equal(evaluateGateDecision(consensusClean, { tier: 2, verificationRecord: brokenRec }).decision, "block");
});


test("Synthetic Objective Boundary 1: ordinary Tier 2 SUPPORTED Low remains advisory", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-low", title: "Minor formatting defect", severity: "low", file: "fmt.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Implement the stated behavior without changing unrelated output formatting.",
    evaluations: [{
      findingId: "f-low",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "approve");
});

test("Synthetic Objective Boundary 2: missing objectiveImpact preserves legacy Tier 2 Low advisory behavior", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-low", title: "Legacy low finding", severity: "low", file: "legacy.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{
      findingId: "f-low",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "approve");
});

test("Synthetic Objective Boundary 3: severity downgrade cannot hide a verified objective falsification", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-med", title: "Patch still violates its contract", severity: "medium", file: "api.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Guarantee the patched API contract in all documented cases.",
    evaluations: [{
      findingId: "f-med",
      verdict: "SUPPORTED",
      classification: "PARTIALLY_SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: false,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "block");
});

test("Synthetic Objective Boundary 4: objective marker alone cannot override a CONTESTED verdict", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-low", title: "Contested objective claim", severity: "low", file: "api.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Guarantee the patched API contract in all documented cases.",
    evaluations: [{
      findingId: "f-low",
      verdict: "CONTESTED",
      classification: "CONTRADICTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "approve");
});

test("Synthetic Objective Boundary 5: objective marker alone cannot override INSUFFICIENT_EVIDENCE", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-low", title: "Unverified objective claim", severity: "low", file: "api.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Guarantee the patched API contract in all documented cases.",
    evaluations: [{
      findingId: "f-low",
      verdict: "INSUFFICIENT_EVIDENCE",
      classification: "UNVERIFIABLE",
      locatorAccurate: false,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "approve");
});

test("Synthetic Objective Boundary 6: Medium still blocks on severity even when objective is unaffected", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-med", title: "Independent medium-impact defect", severity: "medium", file: "api.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Implement the primary behavior change.",
    evaluations: [{
      findingId: "f-med",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "block");
});

test("Synthetic Objective Boundary 7: FALSIFIES marker without a bound patchObjective cannot block", () => {
  const consensus = makeTrustedConsensus([
    { id: "f-low-unbound", title: "Unbound relevance assertion", severity: "low", file: "api.js", corroborations: 1 }
  ], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [{
      findingId: "f-low-unbound",
      verdict: "SUPPORTED",
      classification: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE"
    }]
  });
  assert.equal(evaluateGateDecision(consensus, { tier: 2, verificationRecord: rec }).decision, "approve");
});

// ==============================================================================
// Group 4: Milestone 1 Acceptance Matrix (007-B and 007-C Test Contracts)
// ==============================================================================

test("007-B-01: Clean Challenge completes successfully with 0 omissions -> decision approve", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: []
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "approve");
  assert.match(gate.reason, /Clean Challenge passed/i);
});

test("007-B-02: Clean Challenge encounters timeout budget exhaustion -> fails closed BLOCK", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: false,
    error: "TIMEOUT: Verification execution budget exceeded"
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /TIMEOUT/i);
});

test("007-B-03: Clean Challenge emits malformed or unparseable JSON -> fails closed BLOCK", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: false,
    error: "Malformed JSON output from verifier process"
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Malformed JSON/i);
});

test("007-B-04: 0 Findings consensus but Clean Challenge missing / null record -> fails closed BLOCK", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  // Explicitly requested via cleanChallenge or null verificationRecord
  const gateNull = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: null });
  assert.equal(gateNull.decision, "block");
  assert.match(gateNull.reason, /Clean Challenge missing/i);

  const gateCleanChallengeFlag = evaluateGateDecision(cleanConsensus, { tier: 2, cleanChallenge: true });
  assert.equal(gateCleanChallengeFlag.decision, "block");
  assert.match(gateCleanChallengeFlag.reason, /Clean Challenge missing/i);
});

test("007-C-01: Clean Challenge reports confirmed FALSIFIES_PATCH_OBJECTIVE omission -> decision block", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Preserve rows whose missing map keys evaluate to default values",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "All-zero FixedString needle drops absent-key rows",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/Storages/MergeTree/MergeTreeIndexConditionText.cpp",
        line_start: 1487,
        line_end: 1487,
        reasoning: "traverseMapElementValueNode rejects default map value, causing absent key rows to be dropped."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /falsifies stated patch objective/i);
});

test("007-C-02: Clean Challenge reports solitary unconfirmed Critical omission (INSUFFICIENT_EVIDENCE) -> human_review_required", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Theoretical buffer overflow in parser",
        severity: "critical",
        evidenceSupport: "INSUFFICIENT_EVIDENCE",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: false,
        file: "src/parser.c",
        line_start: 10,
        line_end: 10,
        reasoning: "No counterexample provided; theoretical possibility only."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /Insufficient Evidence/i);
});

test("007-C-03: In-process capability forgery probe (plain object with matching fields rejected) -> UNTRUSTED_VERIFICATION_RECORD", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const plainObject = {
    ok: true,
    evaluations: [],
    verifierOmissions: []
  };
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: plainObject });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /UNTRUSTED_VERIFICATION_RECORD/i);
});

test("007-C-04: Verification record with mismatched changeSetDigest, patchObjective, or headSha -> FORGED_OR_STALE_RECORD", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const runContext = new RunContext({
    runId: "run-001",
    headSha: "18f9c9d0db2fb7374b0545f3fa9542809107702a",
    contentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    patchObjective: "Preserve absent key rows"
  });

  // 1. Digest mismatch
  const recBadDigest = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    headSha: "18f9c9d0db2fb7374b0545f3fa9542809107702a",
    patchObjective: "Preserve absent key rows"
  });
  const gateBadDigest = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadDigest, runContext });
  assert.equal(gateBadDigest.decision, "block");
  assert.match(gateBadDigest.reason, /FORGED_OR_STALE_RECORD/i);

  // 2. Objective mismatch
  const recBadObjective = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "18f9c9d0db2fb7374b0545f3fa9542809107702a",
    patchObjective: "Completely different objective"
  });
  const gateBadObj = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadObjective, runContext });
  assert.equal(gateBadObj.decision, "block");
  assert.match(gateBadObj.reason, /FORGED_OR_STALE_RECORD/i);

  // 3. Head SHA mismatch
  const recBadSha = registerTrustedVerificationRecord({
    ok: true,
    changeSetDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    headSha: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    patchObjective: "Preserve absent key rows"
  });
  const gateBadSha = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recBadSha, runContext });
  assert.equal(gateBadSha.decision, "block");
  assert.match(gateBadSha.reason, /FORGED_OR_STALE_RECORD/i);
});

test("007-C-05: Clean Challenge reports verified Low omission (DOES_NOT_FALSIFY_PATCH_OBJECTIVE) in Tier 2 -> decision approve + Advisory finding", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "Preserve absent key rows",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Stylistic comment indentation",
        severity: "low",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/style.cpp",
        line_start: 5,
        line_end: 5,
        reasoning: "Indentation issue counterexample."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "approve");
  assert.equal(gate.advisoryFindings.length, 1);
});

test("007-C-06: Clean Challenge reports CONTESTED omission in Tier 2 -> Advisory pass (decision approve)", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Contested null dereference claim",
        severity: "medium",
        evidenceSupport: "CONTESTED",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: true,
        file: "src/ptr.cpp",
        line_start: 12,
        line_end: 12,
        reasoning: "Guard at line 5 prevents null pointer reachability."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "approve");
  assert.equal(gate.advisoryFindings.length, 1);
});

test("007-C-07: Clean Challenge reports verified Medium omission (DOES_NOT_FALSIFY) in Tier 1 -> decision block", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 1 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "General bugfix",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Resource leak in error path",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/resource.cpp",
        line_start: 55,
        line_end: 55,
        reasoning: "Observable fd leak when socket fails."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 1, verificationRecord: rec });
  assert.equal(gate.decision, "block");
  assert.match(gate.reason, /Tier 1/i);
});

test("007-C-08: Clean Challenge reports verified Medium omission (DOES_NOT_FALSIFY) in Tier 2 -> decision human_review_required", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  const rec = registerTrustedVerificationRecord({
    ok: true,
    patchObjective: "General bugfix",
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Resource leak in secondary error path",
        severity: "medium",
        evidenceSupport: "SUPPORTED",
        objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
        locatorAccurate: true,
        file: "src/resource.cpp",
        line_start: 55,
        line_end: 55,
        reasoning: "Observable fd leak when socket fails."
      }
    ]
  });
  const gate = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: rec });
  assert.equal(gate.decision, "human_review_required");
  assert.match(gate.reason, /human adjudication/i);
});

test("007-C-09: Clean Challenge reports UNCERTAIN omission or state -> decision human_review_required", () => {
  const cleanConsensus = makeTrustedConsensus([], { tier: 2 });
  // 1. Omission with evidenceSupport: "UNCERTAIN"
  const recOmissionUncertain = registerTrustedVerificationRecord({
    ok: true,
    evaluations: [],
    verifierOmissions: [
      {
        findingId: "omission-1",
        title: "Unknown callee macro side-effects",
        severity: "medium",
        evidenceSupport: "UNCERTAIN",
        objectiveImpact: "NOT_ASSESSED",
        locatorAccurate: true,
        file: "src/macro.cpp",
        line_start: 80,
        line_end: 80,
        reasoning: "Callee definition not resolved in diff."
      }
    ]
  });
  const gate1 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recOmissionUncertain });
  assert.equal(gate1.decision, "human_review_required");
  assert.match(gate1.reason, /UNCERTAIN/i);

  // 2. Record with overallStatus: "UNCERTAIN"
  const recOverallUncertain = registerTrustedVerificationRecord({
    ok: true,
    overallStatus: "UNCERTAIN",
    evaluations: [],
    verifierOmissions: []
  });
  const gate2 = evaluateGateDecision(cleanConsensus, { tier: 2, verificationRecord: recOverallUncertain });
  assert.equal(gate2.decision, "human_review_required");
  assert.match(gate2.reason, /UNCERTAIN/i);
});
