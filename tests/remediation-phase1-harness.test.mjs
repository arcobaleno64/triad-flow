/**
 * Phase 1 Remediation Acceptance Test Suite (PR #39)
 *
 * Implements authoritative negative regression contracts PHASE1-NEG-01 through PHASE1-NEG-08
 * and positive control contract PHASE1-POS-01 as specified in PR #39 remediation dispatch.
 *
 * Test Matrix:
 *   PHASE1-NEG-01: Mandatory RunContext binding (UNTRUSTED_OR_MISSING_RUN_CONTEXT)
 *   PHASE1-NEG-02: Collision-free finding signatures (JSON array serialization)
 *   PHASE1-NEG-03: Platform-aware case-sensitive exclusions (POSIX casing preserved)
 *   PHASE1-NEG-03-PLATFORM-OVERRIDE: Platform override segregation (P1-HARNESS-EXCLUSION-PLATFORM-OVERRIDE-01)
 *   PHASE1-NEG-04: RunContext construction error containment (try/catch conversion failure)
 *   PHASE1-NEG-05: Malformed non-empty headSha and contentDigest validation (hex checks)
 *   PHASE1-NEG-06: Post-verification consensus capability integrity (UNTRUSTED_OR_MISSING_CONSENSUS)
 *   PHASE1-NEG-07: Strict verificationMode validation for non-empty consensus (producer_verification)
 *   PHASE1-NEG-08: Provider-local finding ID namespacing (multi-provider finding-1 collision)
 *   PHASE1-POS-01: Positive control for clean challenge and non-empty advisory passing
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  evaluateIsolatedTestGate,
  evaluateIsolatedTestPostVerificationGate,
  issueVerificationRecordFromOutput,
  normalizeExclusionPath,
  getFindingSignature,
  validateSentryReport,
  RunContext
} from "../src/core/harness.mjs";
import { isTrustedConsensus } from "../src/core/consensus-state.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import {
  conductIndependentVerification,
  createMockVerifierAdapter
} from "../src/core/independent-verifier.mjs";

// Helper: build authentic trusted consensus
function createTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
      ...f,
      id: f.id || f.findingId,
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

  const reports = {
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
  return aggregateConsensus(reports, { policy: "TRI_PARTY_HETEROGENEOUS", tier });
}

// ============================================================================
// PHASE1-NEG-01: Mandatory RunContext Binding (PRRT_kwDOUWarIc6sU7ZN)
// ============================================================================
test("PHASE1-NEG-01: Verification record provided without RunContext fails closed with UNTRUSTED_OR_MISSING_RUN_CONTEXT", async () => {
  const cleanConsensus = createTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const cleanRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "clean_challenge" }
  );

  // 1. evaluateGateDecision with options.runContext omitted
  const res1 = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: cleanRecord
  });
  assert.equal(res1.decision, "block");
  assert.match(res1.reason, /UNTRUSTED_OR_MISSING_RUN_CONTEXT/i);

  // 2. evaluateGateDecision with options.runContext = null
  const res2 = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: cleanRecord,
    runContext: null
  });
  assert.equal(res2.decision, "block");
  assert.match(res2.reason, /UNTRUSTED_OR_MISSING_RUN_CONTEXT/i);

  // 3. evaluatePostVerificationGate with options.runContext omitted
  const res3 = evaluatePostVerificationGate(cleanConsensus, cleanRecord, {
    tier: 2
  });
  assert.equal(res3.decision, "block");
  assert.match(res3.reason, /UNTRUSTED_OR_MISSING_RUN_CONTEXT/i);

  // 4. UNCERTAIN status bypass: when verifier status is UNCERTAIN, Row 11 routes to human review
  const uncertainRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    createMockVerifierAdapter("claude", {
      executeVerification: async () => ({
        ok: true,
        fileCoverageComplete: true,
        overallStatus: "UNCERTAIN",
        evaluations: [],
        verifierOmissions: []
      })
    }),
    { verificationMode: "clean_challenge" }
  );
  const resUncertain = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: uncertainRecord
  });
  assert.equal(resUncertain.decision, "human_review_required");
});

// ============================================================================
// PHASE1-NEG-02: Collision-Free Finding Signatures (PRRT_kwDOUWarIc6rvCBL)
// ============================================================================
test("PHASE1-NEG-02: Delimiter collision probe produces distinct signatures and prevents evaluation hijacking", () => {
  const findingA = {
    id: "finding-1",
    ruleId: "rule-1",
    title: "SQL Injection | src/db.js",
    file: "main.js",
    line_start: 1,
    line_end: 10,
    severity: "high",
    cwe: "CWE-89",
    type: "sql_injection",
    recommendation: "Use parameterized queries."
  };
  const findingB = {
    id: "finding-1",
    ruleId: "rule-1",
    title: "SQL Injection",
    file: "src/db.js|main.js",
    line_start: 1,
    line_end: 10,
    severity: "high",
    cwe: "CWE-89",
    type: "sql_injection",
    recommendation: "Use parameterized queries."
  };

  const sigA = getFindingSignature(findingA);
  const sigB = getFindingSignature(findingB);

  assert.notEqual(sigA, sigB, "Signatures for delimiter-colliding findings must be distinct");

  // Verify signature structure is canonical JSON array
  const parsedA = JSON.parse(sigA);
  assert.ok(Array.isArray(parsedA), "Signature must serialize to a JSON array");
  assert.equal(parsedA[2], "SQL Injection | src/db.js");
  assert.equal(parsedA[3], "main.js");

  // Gate Integration probe: Attempt to substitute findingB for findingA in boundProducerFindings
  const consensus = createTrustedConsensus([findingA], { tier: 2 });
  const validRunContext = new RunContext({
    headSha: "a".repeat(40),
    contentDigest: "b".repeat(64)
  });
  const tamperedRecord = issueVerificationRecordFromOutput({
    ok: true,
    verificationMode: "producer_verification",
    headSha: "a".repeat(40),
    changeSetDigest: "b".repeat(64),
    producerFindings: [findingB],
    evaluations: [
      {
        findingId: "finding-1",
        verdict: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Confirmed injection"
      }
    ],
    verifierOmissions: []
  });

  const gateDecision = evaluateIsolatedTestGate(consensus, {
    verificationRecord: tamperedRecord,
    runContext: validRunContext
  });

  assert.equal(gateDecision.decision, "block");
  assert.match(gateDecision.reason, /FINDING_SET_BINDING_MISMATCH/i);
});

// ============================================================================
// PHASE1-NEG-03: Platform-Aware Case-Sensitive Exclusions (PRRT_kwDOUWarIc6rsKB_)
// ============================================================================
test("PHASE1-NEG-03: Exclusion binding rejects cross-scope verification when paths differ only by case on case-sensitive platforms", () => {
  const cleanConsensus = createTrustedConsensus([], { tier: 2 });

  const rcLinux = new RunContext({
    runId: "run-neg-03-linux",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    patchObjective: "Fix authentication bypass",
    exclusions: ["src/Admin.js"]
  });

  const vrDifferingCase = issueVerificationRecordFromOutput({
    ok: true,
    verificationMode: "clean_challenge",
    overallStatus: "CLEAN",
    headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
    changeSetDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    patchObjective: "Fix authentication bypass",
    runId: "run-neg-03-linux",
    exclusions: ["src/admin.js"],
    evaluations: [],
    verifierOmissions: []
  });

  // 1. Explicit platform: "linux" check (runs identically on all platforms including Windows)
  const decisionLinux = evaluateIsolatedTestGate(cleanConsensus, {
    verificationRecord: vrDifferingCase,
    runContext: rcLinux,
    platform: "linux"
  });

  assert.equal(decisionLinux.decision, "block");
  assert.match(decisionLinux.reason, /FORGED_OR_STALE_RECORD.*Exclusion path mismatch/i);

  // Post verification gate also fails closed on linux
  const postDecisionLinux = evaluateIsolatedTestPostVerificationGate(cleanConsensus, vrDifferingCase, {
    runContext: rcLinux,
    platform: "linux"
  });
  assert.equal(postDecisionLinux.decision, "block");
  assert.match(postDecisionLinux.reason, /FORGED_OR_STALE_RECORD.*Exclusion path mismatch/i);

  // 2. Windows platform treats differing case as matching
  const decisionWin = evaluateIsolatedTestGate(cleanConsensus, {
    verificationRecord: vrDifferingCase,
    runContext: rcLinux,
    platform: "win32"
  });
  assert.notEqual(decisionWin.reason, "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD: Exclusion path mismatch).");
});

// ============================================================================
// PHASE1-NEG-03-PLATFORM-OVERRIDE: Platform Override Segregation (P1-HARNESS-EXCLUSION-PLATFORM-OVERRIDE-01)
// ============================================================================
test("PHASE1-NEG-03-PLATFORM-OVERRIDE: Formal gate entry points strictly bind to host process.platform and reject caller options.platform override", async () => {
  const cleanConsensus = createTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const cleanRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      headSha: "93a63e30a039239212d54db501ce2b0655f3bd49",
      patchObjective: "Fix authentication bypass",
      exclusions: ["src/admin.js"]
    }
  );

  const rcDifferingCase = new RunContext({
    runId: cleanRecord.runId,
    headSha: cleanRecord.headSha,
    contentDigest: cleanRecord.changeSetDigest,
    patchObjective: cleanRecord.patchObjective,
    exclusions: ["src/Admin.js"]
  });

  const originalPlatform = process.platform;
  try {
    // Simulate host running on case-sensitive platform (linux)
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });

    // 1. Formal evaluateGateDecision must ignore options.platform: "win32" and fail closed
    const resFormalGate = evaluateGateDecision(cleanConsensus, {
      tier: 2,
      verificationRecord: cleanRecord,
      runContext: rcDifferingCase,
      platform: "win32"
    });
    assert.equal(resFormalGate.decision, "block");
    assert.match(resFormalGate.reason, /FORGED_OR_STALE_RECORD.*Exclusion path mismatch/i);

    // 2. Formal evaluatePostVerificationGate must ignore options.platform: "win32" and fail closed
    const resFormalPostGate = evaluatePostVerificationGate(cleanConsensus, cleanRecord, {
      tier: 2,
      runContext: rcDifferingCase,
      platform: "win32"
    });
    assert.equal(resFormalPostGate.decision, "block");
    assert.match(resFormalPostGate.reason, /FORGED_OR_STALE_RECORD.*Exclusion path mismatch/i);

    // 3. Isolated test gate (allowSynthetic: true) permits explicit platform simulation
    const resTestGate = evaluateIsolatedTestGate(cleanConsensus, {
      tier: 2,
      verificationRecord: cleanRecord,
      runContext: rcDifferingCase,
      platform: "win32"
    });
    assert.equal(resTestGate.decision, "approve");

    const resTestPostGate = evaluateIsolatedTestPostVerificationGate(cleanConsensus, cleanRecord, {
      tier: 2,
      runContext: rcDifferingCase,
      platform: "win32"
    });
    assert.equal(resTestPostGate.decision, "approve");
  } finally {
    Object.defineProperty(process, "platform", { value: originalPlatform, configurable: true });
  }
});

// ============================================================================
// PHASE1-NEG-04: RunContext Construction Error Containment (PRRT_kwDOUWarIc6riPTv)
// ============================================================================
test("PHASE1-NEG-04: Plain runContext with invalid runId fails closed deterministically without uncaught throw in both gate entry points", async () => {
  const cleanConsensus = createTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const cleanRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "clean_challenge" }
  );

  const traversalContext = {
    runId: "../escape_attempt",
    contentDigest: cleanRecord.changeSetDigest
  };

  // 1. evaluateGateDecision must not throw and must return block
  assert.doesNotThrow(() => {
    const res = evaluateGateDecision(cleanConsensus, {
      tier: 2,
      verificationRecord: cleanRecord,
      runContext: traversalContext
    });
    assert.equal(res.decision, "block");
    assert.match(res.reason, /MALFORMED_RUN_CONTEXT_CONVERSION_FAILED/i);
  });

  // 2. evaluatePostVerificationGate must not throw and must return block
  assert.doesNotThrow(() => {
    const res = evaluatePostVerificationGate(cleanConsensus, cleanRecord, {
      tier: 2,
      runContext: traversalContext
    });
    assert.equal(res.decision, "block");
    assert.match(res.reason, /MALFORMED_RUN_CONTEXT_CONVERSION_FAILED/i);
  });
});

// ============================================================================
// PHASE1-NEG-05: Malformed Non-Empty Head & Digest Field Handling (PRRT_kwDOUWarIc6rvCBG)
// ============================================================================
test("PHASE1-NEG-05: Plain runContext with non-empty invalid headSha / contentDigest fails closed and does not bypass binding checks", async () => {
  const cleanConsensus = createTrustedConsensus([], { tier: 2 });
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const cleanRecord = await conductIndependentVerification(
    { totalFiles: 1, files: ["src/index.js"], diffHunks: "" },
    [],
    mockAdapter,
    { verificationMode: "clean_challenge" }
  );

  // Case A: Malformed non-hex contentDigest
  const badDigestContext = {
    contentDigest: "not-a-valid-hex-digest-at-all",
    headSha: "a".repeat(40)
  };
  const resA = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: cleanRecord,
    runContext: badDigestContext
  });
  assert.equal(resA.decision, "block");
  assert.match(resA.reason, /MALFORMED_RUN_CONTEXT_BINDING/i);

  // Case B: Malformed non-hex headSha
  const badHeadShaContext = {
    contentDigest: cleanRecord.changeSetDigest,
    headSha: "not-a-valid-commit-sha!!"
  };
  const resB = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: cleanRecord,
    runContext: badHeadShaContext
  });
  assert.equal(resB.decision, "block");
  assert.match(resB.reason, /MALFORMED_RUN_CONTEXT_BINDING/i);

  // Case C: evaluatePostVerificationGate enforces identical fail-closed check
  const resC = evaluatePostVerificationGate(cleanConsensus, cleanRecord, {
    tier: 2,
    runContext: badDigestContext
  });
  assert.equal(resC.decision, "block");
  assert.match(resC.reason, /MALFORMED_RUN_CONTEXT_BINDING/i);
});

// ============================================================================
// PHASE1-NEG-06: Post-Verification Consensus Integrity (PRRT_kwDOUWarIc6sPmw9)
// ============================================================================
test("PHASE1-NEG-06: evaluatePostVerificationGate fails closed on null, undefined, or untrusted consensus", async () => {
  const changeSet = { totalFiles: 1, files: ["src/index.js"], diffHunks: "@@ -1 +1 @@\n-old\n+new" };
  const mockAdapter = {
    provider: "claude",
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  };
  const trustedRecord = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "run-neg-06",
    headSha: "a".repeat(40),
    patchObjective: "Security hardening"
  });
  const rc = new RunContext({
    runId: "run-neg-06",
    headSha: "a".repeat(40),
    contentDigest: trustedRecord.changeSetDigest,
    patchObjective: "Security hardening"
  });

  // Vector 1: null consensus
  const resNull = evaluatePostVerificationGate(null, trustedRecord, { runContext: rc });
  assert.equal(resNull.decision, "block");
  assert.match(resNull.reason, /UNTRUSTED_OR_MISSING_CONSENSUS|Untrusted or missing consensus/i);

  // Vector 2: undefined consensus
  const resUndef = evaluatePostVerificationGate(undefined, trustedRecord, { runContext: rc });
  assert.equal(resUndef.decision, "block");
  assert.match(resUndef.reason, /UNTRUSTED_OR_MISSING_CONSENSUS|Untrusted or missing consensus/i);

  // Vector 3: untrusted plain mock object
  const plainMockConsensus = { findings: [], quorumReached: true, verdict: "clean" };
  assert.equal(isTrustedConsensus(plainMockConsensus), false);
  const resPlain = evaluatePostVerificationGate(plainMockConsensus, trustedRecord, { runContext: rc });
  assert.equal(resPlain.decision, "block");
  assert.match(resPlain.reason, /UNTRUSTED_OR_MISSING_CONSENSUS|Untrusted or missing consensus/i);

  // Vector 4: cloned or forged consensus
  const realConsensus = createTrustedConsensus([], { tier: 2 });
  const clonedConsensus = { ...realConsensus };
  assert.equal(isTrustedConsensus(clonedConsensus), false);
  const resCloned = evaluatePostVerificationGate(clonedConsensus, trustedRecord, { runContext: rc });
  assert.equal(resCloned.decision, "block");
  assert.match(resCloned.reason, /UNTRUSTED_OR_MISSING_CONSENSUS|Untrusted or missing consensus/i);
});

// ============================================================================
// PHASE1-NEG-07: Strict Verification Mode Validation for Non-Empty Consensus (PRRT_kwDOUWarIc6sPGEP, PRRT_kwDOUWarIc6ra7kY)
// ============================================================================
test("PHASE1-NEG-07: Non-empty findings consensus paired with invalid or typo verificationMode fails closed", async () => {
  const sampleFinding = {
    id: "finding-sec-01",
    file: "src/index.js",
    line_start: 1,
    line_end: 1,
    title: "Insecure buffer allocation",
    severity: "low",
    type: "security",
    recommendation: "Use Buffer.allocSafe"
  };
  const nonemptyConsensus = createTrustedConsensus([sampleFinding], { tier: 2 });
  const changeSet = { totalFiles: 1, files: ["src/index.js"], diffHunks: "@@ -1 +1 @@\n-old\n+new" };

  async function makeRecordWithMode(mode) {
    const isClean = mode === "clean_challenge";
    const mockAdapter = {
      provider: "claude",
      executeVerification: async () => ({
        ok: true,
        fileCoverageComplete: true,
        overallStatus: isClean ? "CLEAN" : "DEFECTS_FOUND",
        evaluations: isClean ? [] : [
          {
            findingId: "finding-sec-01",
            verdict: "SUPPORTED",
            objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
            locatorAccurate: true,
            typeAccurate: true,
            severityAccurate: true,
            reasoning: "Valid advisory finding."
          }
        ],
        verifierOmissions: []
      })
    };
    return conductIndependentVerification(changeSet, nonemptyConsensus.findings, mockAdapter, {
      verificationMode: mode,
      runId: "run-neg-07",
      headSha: "b".repeat(40),
      patchObjective: "Security hardening"
    });
  }

  // Vector 1: custom_mode
  const recCustom = await makeRecordWithMode("custom_mode");
  const rcCustom = new RunContext({
    runId: "run-neg-07",
    headSha: "b".repeat(40),
    contentDigest: recCustom.changeSetDigest,
    patchObjective: "Security hardening"
  });
  const gateCustom = evaluateGateDecision(nonemptyConsensus, { tier: 2, verificationRecord: recCustom, runContext: rcCustom });
  assert.equal(gateCustom.decision, "block");
  assert.match(gateCustom.reason, /requires 'producer_verification' mode \(got: 'custom_mode'\)/i);
  const postCustom = evaluatePostVerificationGate(nonemptyConsensus, recCustom, { tier: 2, runContext: rcCustom });
  assert.equal(postCustom.decision, "block");
  assert.match(postCustom.reason, /requires 'producer_verification' mode \(got: 'custom_mode'\)/i);

  // Vector 2: typo mode
  const recTypo = await makeRecordWithMode("producer_verification_typo");
  const rcTypo = new RunContext({
    runId: "run-neg-07",
    headSha: "b".repeat(40),
    contentDigest: recTypo.changeSetDigest,
    patchObjective: "Security hardening"
  });
  const gateTypo = evaluateGateDecision(nonemptyConsensus, { tier: 2, verificationRecord: recTypo, runContext: rcTypo });
  assert.equal(gateTypo.decision, "block");
  assert.match(gateTypo.reason, /requires 'producer_verification' mode \(got: 'producer_verification_typo'\)/i);

  // Vector 3: clean_challenge mode on non-empty findings
  const recCleanMode = await makeRecordWithMode("clean_challenge");
  const rcClean = new RunContext({
    runId: "run-neg-07",
    headSha: "b".repeat(40),
    contentDigest: recCleanMode.changeSetDigest,
    patchObjective: "Security hardening"
  });
  const gateCleanMode = evaluateGateDecision(nonemptyConsensus, { tier: 2, verificationRecord: recCleanMode, runContext: rcClean });
  assert.equal(gateCleanMode.decision, "block");
  assert.match(gateCleanMode.reason, /requires 'producer_verification' mode \(got: 'clean_challenge'\)/i);
});

// ============================================================================
// PHASE1-NEG-08: Provider-Local Finding ID Namespacing (PRRT_kwDOUWarIc6rsKB8)
// ============================================================================
test("PHASE1-NEG-08: Multiple providers reporting same local finding ID are namespaced without throwing DUPLICATE_FINDING_ID", async () => {
  const reportA = {
    name: "macro-sentry",
    sentry: "sentry-a",
    provider: "agy",
    findings: [
      {
        id: "finding-1",
        title: "Path Traversal",
        file: "src/server.js",
        line_start: 15,
        line_end: 20,
        severity: "high",
        recommendation: "Sanitize path input."
      }
    ]
  };

  const reportB = {
    name: "micro-sentry",
    sentry: "sentry-b",
    provider: "claude",
    findings: [
      {
        id: "finding-1",
        title: "SQL Injection",
        file: "src/db.js",
        line_start: 42,
        line_end: 45,
        severity: "critical",
        recommendation: "Use parameterized queries."
      }
    ]
  };

  // 1. validateSentryReport namespacing check
  const validatedA = validateSentryReport(reportA);
  const validatedB = validateSentryReport(reportB);
  assert.equal(validatedA.valid, true);
  assert.equal(validatedB.valid, true);
  assert.equal(validatedA.report.findings[0].id, "sentry-a:finding-1");
  assert.equal(validatedB.report.findings[0].id, "sentry-b:finding-1");

  // 2. aggregateConsensus retains both findings with distinct namespaced IDs
  const consensus = aggregateConsensus({
    macro: reportA,
    micro: reportB
  });

  assert.equal(consensus.findings.length, 2);
  const ids = consensus.findings.map(f => f.id);
  assert.ok(ids.includes("sentry-a:finding-1"), "Sentry A finding must be namespaced");
  assert.ok(ids.includes("sentry-b:finding-1"), "Sentry B finding must be namespaced");

  // 3. conductIndependentVerification does NOT throw unhandled DUPLICATE_FINDING_ID
  const changeSet = {
    totalFiles: 2,
    files: [{ path: "src/server.js" }, { path: "src/db.js" }],
    diffHunks: "+ server;\n+ db;"
  };

  const mockAdapter = {
    provider: "claude",
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "DEFECTS_FOUND",
      evaluations: [
        {
          findingId: "sentry-a:finding-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Confirmed path traversal"
        },
        {
          findingId: "sentry-b:finding-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Confirmed sql injection"
        }
      ],
      verifierOmissions: []
    })
  };

  let record;
  try {
    record = await conductIndependentVerification(changeSet, consensus.findings, mockAdapter, {
      verificationMode: "producer_verification"
    });
  } catch (err) {
    assert.fail(`conductIndependentVerification threw unexpectedly: ${err.message}`);
  }

  assert.equal(record.ok, true);

  // 4. Intra-provider duplicate check: If a SINGLE provider duplicates IDs, it must still fail closed
  const singleProviderDupe = {
    name: "macro-sentry",
    sentry: "sentry-a",
    provider: "agy",
    findings: [
      { id: "finding-1", title: "Issue 1", file: "src/a.js", severity: "high" },
      { id: "finding-1", title: "Issue 2", file: "src/b.js", severity: "high" }
    ]
  };
  const valDupe = validateSentryReport(singleProviderDupe);
  assert.equal(valDupe.valid, true);
  const consensusDupe = aggregateConsensus({
    macro: singleProviderDupe,
    micro: { name: "micro-sentry", sentry: "sentry-b", provider: "claude", fileCoverageComplete: true, findings: [] }
  });
  const rcDupe = new RunContext({
    runId: "run-dupe",
    contentDigest: "d".repeat(64),
    headSha: "e".repeat(40)
  });
  const gateDupe = evaluateIsolatedTestGate(consensusDupe, {
    tier: 2,
    runContext: rcDupe,
    verificationRecord: issueVerificationRecordFromOutput({
      ok: true,
      verificationMode: "producer_verification",
      evaluations: [
        {
          findingId: "sentry-a:finding-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Valid"
        }
      ],
      verifierOmissions: []
    })
  });
  assert.equal(gateDupe.decision, "block");
  assert.match(gateDupe.reason, /DUPLICATE_FINDING_ID/i);
});

// ============================================================================
// PHASE1-POS-01: Positive Control for Legitimate End-to-End Reviews
// ============================================================================
test("PHASE1-POS-01: Legitimate RunContext, valid verification records, and clean consensus evaluate clean without false holds", async () => {
  const headSha = "f".repeat(40);
  const patchObjective = "Fix authentication bypass vulnerability in login handler";
  const changeSet = {
    totalFiles: 1,
    files: ["src/auth.js"],
    diffHunks: "@@ -10,2 +10,4 @@\n-const auth = false;\n+const auth = true;"
  };

  // --- Scenario A: Zero-Finding Clean Challenge ---
  const cleanConsensus = createTrustedConsensus([], { tier: 2, quorumReached: true });
  assert.equal(isTrustedConsensus(cleanConsensus), true);

  const mockCleanAdapter = {
    provider: "claude",
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  };

  const cleanRecord = await conductIndependentVerification(changeSet, [], mockCleanAdapter, {
    verificationMode: "clean_challenge",
    runId: "run-pos-clean-01",
    headSha,
    patchObjective,
    exclusions: ["docs/**"]
  });

  const rcClean = new RunContext({
    runId: "run-pos-clean-01",
    headSha,
    contentDigest: cleanRecord.changeSetDigest,
    patchObjective,
    exclusions: ["docs/**"]
  });

  const gateDecisionClean = evaluateGateDecision(cleanConsensus, {
    tier: 2,
    verificationRecord: cleanRecord,
    runContext: rcClean
  });
  assert.equal(gateDecisionClean.decision, "approve");
  assert.match(gateDecisionClean.reason, /Clean Challenge passed/i);
  assert.equal(gateDecisionClean.criticals.length, 0);
  assert.equal(gateDecisionClean.advisoryFindings.length, 0);

  const postGateDecisionClean = evaluatePostVerificationGate(cleanConsensus, cleanRecord, {
    tier: 2,
    runContext: rcClean
  });
  assert.equal(postGateDecisionClean.decision, "approve");
  assert.match(postGateDecisionClean.reason, /Clean Challenge passed/i);

  // --- Scenario B: Non-Empty Consensus (Advisory Low Finding in Tier 2) ---
  const lowFinding = {
    id: "finding-style-01",
    file: "src/auth.js",
    line_start: 11,
    line_end: 11,
    title: "Explicit boolean conversion preferred",
    severity: "low",
    type: "style",
    recommendation: "Use Boolean(auth)"
  };

  const nonemptyConsensus = createTrustedConsensus([lowFinding], { tier: 2, quorumReached: true });
  assert.equal(isTrustedConsensus(nonemptyConsensus), true);

  const mockProducerAdapter = {
    provider: "claude",
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "DEFECTS_FOUND",
      evaluations: [
        {
          findingId: "finding-style-01",
          verdict: "SUPPORTED",
          objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Valid style comment, does not impact security objective."
        }
      ],
      verifierOmissions: []
    })
  };

  const producerRecord = await conductIndependentVerification(changeSet, nonemptyConsensus.findings, mockProducerAdapter, {
    verificationMode: "producer_verification",
    runId: "run-pos-producer-01",
    headSha,
    patchObjective
  });

  const rcProducer = new RunContext({
    runId: "run-pos-producer-01",
    headSha,
    contentDigest: producerRecord.changeSetDigest,
    patchObjective
  });

  const gateDecisionProducer = evaluateGateDecision(nonemptyConsensus, {
    tier: 2,
    verificationRecord: producerRecord,
    runContext: rcProducer
  });
  assert.equal(gateDecisionProducer.decision, "approve");
  assert.match(gateDecisionProducer.reason, /No blocking vulnerabilities found/i);
  assert.equal(gateDecisionProducer.criticals.length, 0);
  assert.equal(gateDecisionProducer.advisoryFindings.length, 1);

  const postGateDecisionProducer = evaluatePostVerificationGate(nonemptyConsensus, producerRecord, {
    tier: 2,
    runContext: rcProducer
  });
  assert.equal(postGateDecisionProducer.decision, "approve");
  assert.match(postGateDecisionProducer.reason, /No blocking vulnerabilities found/i);
});
